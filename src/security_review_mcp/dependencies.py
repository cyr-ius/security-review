"""Parse dependency manifests and lockfiles, and run offline hygiene checks.

Supported files: requirements*.txt, pyproject.toml, poetry.lock, Pipfile.lock, uv.lock (PyPI);
package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock (npm);
pom.xml, build.gradle, build.gradle.kts (Maven);
go.mod (Go); Cargo.lock, Cargo.toml (crates.io);
packages.lock.json, *.csproj / *.fsproj / *.vbproj, Directory.Packages.props,
Directory.Build.props, packages.config, nuget.config (NuGet);
CycloneDX SBOMs in JSON or XML (bom.json, bom.xml, *.cdx.json...), any of these ecosystems.

Lockfiles and SBOMs list the exact resolved versions, including transitive dependencies: they
are the most reliable input for vulnerability matching. An SBOM is the only way to check the
transitive dependencies of a Maven or Gradle project.
"""

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import partial
from pathlib import PurePosixPath
from urllib.parse import unquote

from .models import Severity

SUPPORTED_FILES = (
    "requirements*.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "Cargo.lock",
    "Cargo.toml",
    "packages.lock.json",
    "*.csproj",
    "*.fsproj",
    "*.vbproj",
    "Directory.Packages.props",
    "Directory.Build.props",
    "packages.config",
    "nuget.config",
    "bom.json",
    "bom.xml",
    "*.cdx.json",
    "*.cdx.xml",
)

# rule id -> (title, severity, cwe)
HYGIENE_RULES: dict[str, tuple[str, Severity, str]] = {
    "DEP-001": ("Loose or missing version constraint", Severity.LOW, "CWE-1357"),
    "DEP-002": ("Wildcard, latest or dynamic version", Severity.MEDIUM, "CWE-1357"),
    "DEP-003": ("Dependency from a VCS, URL or local path", Severity.MEDIUM, "CWE-829"),
    "DEP-004": ("Packages fetched over insecure HTTP", Severity.HIGH, "CWE-319"),
    "DEP-005": ("Extra package index (dependency confusion risk)", Severity.MEDIUM, "CWE-829"),
    "DEP-006": ("Install-time script", Severity.LOW, "CWE-829"),
    "DEP-007": ("System-scoped or local-file dependency", Severity.LOW, "CWE-829"),
    "DEP-008": ("Package index trust checks disabled", Severity.HIGH, "CWE-295"),
    "DEP-009": ("Version managed outside this file", Severity.INFO, "CWE-1357"),
}
# Rules whose occurrences are always merged into one issue (otherwise merged above 5)
_ALWAYS_AGGREGATED = {"DEP-001", "DEP-009"}
_AGGREGATE_ABOVE = 5

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")


@dataclass
class Component:
    """A dependency found in a file."""

    ecosystem: str
    name: str
    version: str | None  # None when the file only holds a range or a managed version
    spec: str | None = None
    line: int | None = None
    dev: bool = False
    kind: str = "dependency"  # "dependency" or "parent" (Maven parent POM)


@dataclass
class Issue:
    """A hygiene issue found without any advisory database."""

    rule_id: str
    title: str
    severity: Severity
    cwe: str
    message: str
    line: int | None = None
    package: str | None = None


@dataclass
class Parsed:
    """The content of a dependency file."""

    file_type: str
    ecosystem: str
    is_lockfile: bool
    components: list[Component] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class _Builder:
    """Collects components and issues, then merges noisy issues when finishing."""

    def __init__(self, file_type: str, ecosystem: str, is_lockfile: bool) -> None:
        self.parsed = Parsed(file_type, ecosystem, is_lockfile)
        self._raw: list[tuple[str, str, int | None, str | None]] = []

    def component(self, name: str, version: str | None, **kwargs: object) -> Component:
        """Add a component."""
        item = Component(self.parsed.ecosystem, name, version, **kwargs)  # type: ignore[arg-type]
        self.parsed.components.append(item)
        return item

    def issue(
        self, rule_id: str, message: str, line: int | None = None, package: str | None = None
    ) -> None:
        """Record an occurrence of a hygiene rule."""
        self._raw.append((rule_id, message, line, package))

    def finish(self) -> Parsed:
        """Merge the occurrences and add the notes."""
        grouped: dict[str, list[tuple[str, int | None, str | None]]] = defaultdict(list)
        for rule_id, message, line, package in self._raw:
            grouped[rule_id].append((message, line, package))
        for rule_id, entries in grouped.items():
            title, severity, cwe = HYGIENE_RULES[rule_id]
            if rule_id in _ALWAYS_AGGREGATED or len(entries) > _AGGREGATE_ABOVE:
                names = [pkg or msg for msg, _, pkg in entries]
                shown = ", ".join(names[:10]) + (", ..." if len(names) > 10 else "")
                self.parsed.issues.append(
                    Issue(
                        rule_id,
                        title,
                        severity,
                        cwe,
                        f"{len(entries)} occurrence(s): {shown}",
                        entries[0][1],
                    )
                )
            else:
                for message, line, package in entries:
                    self.parsed.issues.append(
                        Issue(rule_id, title, severity, cwe, message, line, package)
                    )
        unresolved = sum(1 for c in self.parsed.components if c.version is None)
        if unresolved and not self.parsed.is_lockfile:
            self.parsed.notes.append(
                f"{unresolved} dependency version(s) are ranges or managed elsewhere and cannot be "
                "checked against advisories: scan the lockfile (package-lock.json, poetry.lock, "
                "Pipfile.lock, uv.lock, yarn.lock, Cargo.lock, packages.lock.json) or a "
                "CycloneDX SBOM (bom.json) instead."
            )
        return self.parsed


def _is_insecure_url(url: str) -> bool:
    """Tell whether a URL uses plain HTTP towards a non-local host."""
    lowered = url.strip().lower()
    return lowered.startswith("http://") and not any(
        lowered.startswith(f"http://{host}") for host in _LOCAL_HOSTS
    )


# ── Python ───────────────────────────────────────────────────────────────────

_REQ_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*(?P<rest>.*)$"
)
_PIN_RE = re.compile(r"===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)")
_PY_INDEX_RE = re.compile(r"^(--index-url|-i|--extra-index-url|--find-links|-f)[\s=]+(\S+)")


def _add_requirement(builder: _Builder, text: str, line: int | None, dev: bool = False) -> None:
    """Parse one PEP 508 requirement string."""
    text = re.sub(r"\s--hash[=\s]\S+", "", text).split(";", 1)[0].strip()
    match = _REQ_RE.match(text)
    if not match:
        return
    name, rest = match.group("name"), match.group("rest").strip()
    if rest.startswith("@"):
        builder.component(name, None, spec=rest, line=line, dev=dev)
        builder.issue("DEP-003", f"{name} is installed from {rest[1:].strip()[:80]}", line, name)
        if _is_insecure_url(rest[1:]):
            builder.issue("DEP-004", f"{name} is downloaded over HTTP", line, name)
        return
    spec = rest.replace(" ", "")
    pinned = _PIN_RE.fullmatch(spec)
    if pinned and "*" not in spec:
        builder.component(name, pinned.group(1), spec=spec, line=line, dev=dev)
        return
    builder.component(name, None, spec=spec or None, line=line, dev=dev)
    if "*" in spec:
        builder.issue("DEP-002", f"{name}{spec} uses a wildcard", line, name)
    else:
        builder.issue("DEP-001", spec or "no version constraint", line, name)


# URL, VCS or local path requirement without a project name (no version to check)
_DIRECT_REFERENCE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://|file:|\.{1,2}/|/)")


def _logical_lines(content: str) -> list[tuple[int, str]]:
    """Join the lines that end with a backslash; returns (first line number, text)."""
    result: list[tuple[int, str]] = []
    buffer, start = "", None
    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.rstrip()
        if start is None:
            start = number
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        result.append((start, buffer + line))
        buffer, start = "", None
    if buffer and start is not None:
        result.append((start, buffer))
    return result


def parse_requirements(content: str) -> Parsed:
    """Parse a pip requirements file."""
    builder = _Builder("requirements", "PyPI", False)
    for number, raw in _logical_lines(content):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement", "-c ", "--constraint")):
            builder.parsed.notes.append(
                f"line {number}: includes another file ({line}); scan it too"
            )
            continue
        index = _PY_INDEX_RE.match(line)
        if index:
            option, url = index.groups()
            if _is_insecure_url(url):
                builder.issue("DEP-004", f"{option} {url}", number)
            if option == "--extra-index-url":
                builder.issue("DEP-005", f"extra index {url}", number)
            continue
        if line.startswith("--trusted-host"):
            builder.issue("DEP-008", line, number)
            continue
        if line.startswith(("-e ", "--editable")):
            builder.issue("DEP-003", f"editable install: {line[:80]}", number)
            continue
        if line.startswith("-"):
            continue
        if _DIRECT_REFERENCE.match(line):
            builder.issue("DEP-003", f"installed from {line[:80]}", number)
            if _is_insecure_url(line.split("+", 1)[-1]):
                builder.issue("DEP-004", f"downloaded over HTTP: {line[:80]}", number)
            continue
        _add_requirement(builder, line, number)
    return builder.finish()


def _load_toml(content: str) -> dict:
    """Parse TOML or raise a clear ValueError."""
    try:
        return tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML: {exc}") from exc
    except RecursionError as exc:
        raise ValueError("Invalid TOML: nesting too deep") from exc


def _load_json(content: str) -> dict:
    """Parse a JSON object or raise a clear ValueError."""
    try:
        data = json.loads(content.removeprefix("\ufeff"))  # BOM of files written on Windows
    except ValueError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    except RecursionError as exc:
        raise ValueError("Invalid JSON: nesting too deep") from exc
    if not isinstance(data, dict):
        raise ValueError("Invalid JSON: an object was expected")
    return data


# Extras that only serve development: the other extras (postgres, s3...) are installed in
# production and are reported as runtime dependencies
_DEV_EXTRA_RE = re.compile(
    r"(dev|devel|develop|development|tests?|testing|docs?|lint|linting|typing|types|mypy|style"
    r"|ci|coverage|qa|bench|benchmarks?)",
    re.IGNORECASE,
)


def _is_dev_extra(name: object) -> bool:
    """Tell whether an optional-dependencies group only serves development (tests, docs...)."""
    return isinstance(name, str) and any(
        _DEV_EXTRA_RE.fullmatch(part) for part in re.split(r"[-_.]", name) if part
    )


def parse_pyproject(content: str) -> Parsed:
    """Parse the dependencies of a pyproject.toml (PEP 621, PEP 735 and Poetry)."""
    data = _load_toml(content)
    builder = _Builder("pyproject", "PyPI", False)

    def add_list(items: object, dev: bool) -> None:
        for item in items if isinstance(items, list) else []:
            if isinstance(item, str):
                _add_requirement(builder, item, None, dev)

    project = data.get("project", {})
    add_list(project.get("dependencies"), False)
    for extra, group in (project.get("optional-dependencies") or {}).items():
        add_list(group, _is_dev_extra(extra))
    for group in (data.get("dependency-groups") or {}).values():
        add_list(group, True)
    add_list(data.get("build-system", {}).get("requires"), True)

    poetry = data.get("tool", {}).get("poetry", {})
    tables = [
        (poetry.get("dependencies") or {}, False),
        (poetry.get("dev-dependencies") or {}, True),
    ]
    tables += [(g.get("dependencies") or {}, True) for g in (poetry.get("group") or {}).values()]
    for table, dev in tables:
        for name, spec in table.items():
            if name.lower() == "python":
                continue
            if isinstance(spec, dict):
                if any(key in spec for key in ("git", "path", "url")):
                    builder.component(name, None, spec="vcs/path", dev=dev)
                    builder.issue(
                        "DEP-003", f"{name} is installed from a VCS, URL or path", None, name
                    )
                    continue
                spec = spec.get("version", "*")
            spec = str(spec).strip()
            if re.fullmatch(r"\d[\w.+!-]*", spec):  # Poetry treats a bare version as exact
                builder.component(name, spec, spec=spec, dev=dev)
            elif spec in ("*", ""):
                builder.component(name, None, spec=spec, dev=dev)
                builder.issue("DEP-002", f'{name} = "{spec or "*"}"', None, name)
            else:
                builder.component(name, None, spec=spec, dev=dev)  # caret/tilde: normal with a lock
    return builder.finish()


def parse_poetry_lock(content: str) -> Parsed:
    """Parse a poetry.lock file."""
    data = _load_toml(content)
    builder = _Builder("poetry.lock", "PyPI", True)
    for package in data.get("package", []):
        name, version = package.get("name"), package.get("version")
        if not name or not version:
            continue
        builder.component(str(name), str(version))
        source = package.get("source") or {}
        if source.get("type") in ("git", "url", "directory", "file"):
            builder.issue("DEP-003", f"{name} comes from a {source.get('type')} source", None, name)
        if _is_insecure_url(str(source.get("url", ""))):
            builder.issue("DEP-004", f"{name} is downloaded over HTTP", None, name)
    return builder.finish()


def parse_pipfile_lock(content: str) -> Parsed:
    """Parse a Pipfile.lock file."""
    data = _load_json(content)
    builder = _Builder("Pipfile.lock", "PyPI", True)
    for source in (data.get("_meta") or {}).get("sources", []):
        if _is_insecure_url(str(source.get("url", ""))):
            builder.issue("DEP-004", f"source {source.get('name', '')} uses HTTP")
        if source.get("verify_ssl") is False:
            builder.issue("DEP-008", f"source {source.get('name', '')} has verify_ssl=false")
    for section, dev in (("default", False), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            meta = meta if isinstance(meta, dict) else {}
            version = str(meta.get("version", "")).lstrip("=").strip() or None
            builder.component(name, version, dev=dev)
            if any(key in meta for key in ("git", "path", "file")):
                builder.issue("DEP-003", f"{name} comes from a VCS or local path", None, name)
    return builder.finish()


def parse_uv_lock(content: str) -> Parsed:
    """Parse a uv.lock file.

    The project itself and its workspace members (editable or virtual sources) are not
    dependencies and are skipped.
    """
    data = _load_toml(content)
    builder = _Builder("uv.lock", "PyPI", True)
    members = set((data.get("manifest") or {}).get("members", []))
    for package in data.get("package", []):
        name, version = package.get("name"), package.get("version")
        if not name:
            continue
        source = package.get("source") or {}
        local = source.get("editable", source.get("virtual"))
        if local is not None and (local == "." or name in members):
            continue
        if not version:
            continue
        builder.component(str(name), str(version))
        kind = next((k for k in ("git", "url", "path", "directory", "editable") if k in source), "")
        if kind:
            builder.issue("DEP-003", f"{name} comes from a {kind} source", None, name)
        artifacts = [package.get("sdist") or {}, *(package.get("wheels") or [])]
        urls = [source.get("registry", ""), source.get("url", "")]
        urls += [item.get("url", "") for item in artifacts]
        if any(_is_insecure_url(str(url)) for url in urls):
            builder.issue("DEP-004", f"{name} is downloaded over HTTP", None, name)
    return builder.finish()


# ── npm ──────────────────────────────────────────────────────────────────────

_NPM_EXACT = re.compile(r"=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)")
_NPM_VCS = re.compile(
    r"(git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|[\w.-]+/[\w.-]+(#.*)?$)"
)
_NPM_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")


def _add_npm_spec(builder: _Builder, name: str, spec: object, dev: bool) -> None:
    """Classify the version specifier of a package.json dependency."""
    text = str(spec).strip()
    exact = _NPM_EXACT.fullmatch(text)
    if exact:
        builder.component(name, exact.group(1), spec=text, dev=dev)
        return
    builder.component(name, None, spec=text, dev=dev)
    if text in ("", "*", "x", "latest", "next") or text.startswith(("latest", "next")):
        builder.issue("DEP-002", f'{name}: "{text or "*"}"', None, name)
    elif _NPM_VCS.match(text):
        builder.issue("DEP-003", f"{name}: {text[:80]}", None, name)
        if _is_insecure_url(text):
            builder.issue("DEP-004", f"{name} is downloaded over HTTP", None, name)
    elif re.fullmatch(r">=?\s*[\d.]+", text):
        builder.issue("DEP-001", f"{name}: {text} has no upper bound", None, name)
    # caret, tilde and bounded ranges are normal practice when a lockfile is committed


def parse_package_json(content: str) -> Parsed:
    """Parse a package.json file."""
    data = _load_json(content)
    builder = _Builder("package.json", "npm", False)
    for section, dev in (
        ("dependencies", False),
        ("devDependencies", True),
        ("optionalDependencies", False),
    ):
        for name, spec in (data.get(section) or {}).items():
            _add_npm_spec(builder, name, spec, dev)
    scripts = data.get("scripts") or {}
    for hook in _NPM_HOOKS:
        command = scripts.get(hook)
        if isinstance(command, str):
            builder.issue("DEP-006", f"{hook}: {command[:120]}", None, hook)
            if re.search(r"(curl|wget)[^|]*\|\s*(ba)?sh", command):
                builder.issue("DEP-002", f"{hook} downloads and executes a script", None, hook)
    return builder.finish()


def parse_package_lock(content: str) -> Parsed:
    """Parse a package-lock.json / npm-shrinkwrap.json file (lockfile v1, v2 and v3)."""
    data = _load_json(content)
    builder = _Builder("package-lock.json", "npm", True)

    def inspect(name: str, meta: dict, dev: bool) -> None:
        version = meta.get("version")
        if isinstance(version, str) and not meta.get("link"):
            builder.component(name, version, dev=dev)
        resolved = str(meta.get("resolved", ""))
        if _is_insecure_url(resolved):
            builder.issue("DEP-004", f"{name} is downloaded over HTTP", None, name)
        elif resolved.startswith(("git+", "git:", "github:")):
            builder.issue("DEP-003", f"{name} comes from {resolved[:80]}", None, name)

    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue  # "" is the root project
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            inspect(name, meta, bool(meta.get("dev")))
    else:  # lockfile v1: nested "dependencies"
        stack = [(n, m) for n, m in (data.get("dependencies") or {}).items()]
        while stack:
            name, meta = stack.pop()
            if not isinstance(meta, dict):
                continue
            inspect(name, meta, bool(meta.get("dev")))
            stack.extend((n, m) for n, m in (meta.get("dependencies") or {}).items())
    return builder.finish()


_YARN_VERSION_RE = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')
_YARN_RESOLVED_RE = re.compile(r'^\s+(?:resolved|resolution):?\s+"?([^"\s]+)"?\s*$')


def parse_yarn_lock(content: str) -> Parsed:
    """Parse a yarn.lock file (classic v1 and berry)."""
    builder = _Builder("yarn.lock", "npm", True)
    name: str | None = None
    for number, line in enumerate(content.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            name = None
            header = line.rstrip().rstrip(":").split(",")[0].strip().strip('"')
            if header and header != "__metadata":
                at = header.find("@", 1)
                name = header[:at] if at > 0 else None
            continue
        if name is None:
            continue
        version = _YARN_VERSION_RE.match(line)
        if version:
            builder.component(name, version.group(1), line=number)
            continue
        resolved = _YARN_RESOLVED_RE.match(line)
        if resolved and _is_insecure_url(resolved.group(1)):
            builder.issue("DEP-004", f"{name} is downloaded over HTTP", number, name)
    return builder.finish()


# ── Maven / Gradle ───────────────────────────────────────────────────────────


def _local(tag: str) -> str:
    """Return an XML tag without its namespace."""
    return tag.rsplit("}", 1)[-1]


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    """Return the direct children with a given local name."""
    return [child for child in element if _local(child.tag) == name]


def _text(element: ET.Element, name: str) -> str:
    """Return the stripped text of a direct child, or an empty string."""
    found = _children(element, name)
    return (found[0].text or "").strip() if found else ""


def _load_xml(content: str, file_type: str) -> ET.Element:
    """Parse XML or raise a clear ValueError; DTDs are refused (entity expansion, XXE)."""
    if re.search(r"<!(DOCTYPE|ENTITY)", content, re.IGNORECASE):
        raise ValueError(
            f"{file_type} contains a DOCTYPE or ENTITY declaration: refusing to parse it"
        )
    try:
        return ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc


_TRANSITIVE_NOTE = (
    "{file} only lists the direct dependencies: generate a CycloneDX SBOM of the resolved "
    "dependency tree (bom.json) and scan it to check the transitive dependencies."
)


def parse_pom(content: str) -> Parsed:
    """Parse a Maven pom.xml file (the effective POM is not computed)."""
    root = _load_xml(content, "pom.xml")
    builder = _Builder("pom.xml", "Maven", False)
    properties: dict[str, str] = {}
    for block in _children(root, "properties"):
        for prop in block:
            properties[_local(prop.tag)] = (prop.text or "").strip()
    parent = (_children(root, "parent") or [None])[0]
    project_version = _text(root, "version") or (
        _text(parent, "version") if parent is not None else ""
    )
    properties.setdefault("project.version", project_version)
    properties.setdefault("version", project_version)

    def resolve(value: str) -> str:
        for _ in range(5):
            replaced = re.sub(
                r"\$\{([^}]+)\}", lambda m: properties.get(m.group(1), m.group(0)), value
            )
            if replaced == value:
                break
            value = replaced
        return value

    if parent is not None and _text(parent, "artifactId"):
        name = f"{_text(parent, 'groupId')}:{_text(parent, 'artifactId')}"
        version = resolve(_text(parent, "version"))
        builder.component(name, version if version and "${" not in version else None, kind="parent")

    managed: dict[str, str] = {}
    for management in _children(root, "dependencyManagement"):
        for deps in _children(management, "dependencies"):
            for dep in _children(deps, "dependency"):
                key = f"{_text(dep, 'groupId')}:{_text(dep, 'artifactId')}"
                if _text(dep, "version"):
                    managed[key] = resolve(_text(dep, "version"))

    for deps in _children(root, "dependencies"):
        for dep in _children(deps, "dependency"):
            group, artifact = _text(dep, "groupId"), _text(dep, "artifactId")
            if not group or not artifact:
                continue
            name = f"{group}:{artifact}"
            scope = _text(dep, "scope")
            version = (
                resolve(_text(dep, "version")) if _text(dep, "version") else managed.get(name, "")
            )
            dev = scope == "test"
            if scope == "system":
                builder.issue(
                    "DEP-007",
                    f"{name} uses system scope ({_text(dep, 'systemPath')[:60]})",
                    None,
                    name,
                )
            if not version or "${" in version:
                builder.component(name, None, dev=dev)
                builder.issue("DEP-009", "version managed by a parent or BOM", None, name)
            elif version.upper() in ("LATEST", "RELEASE") or version[0] in "[(" or "," in version:
                builder.component(name, None, spec=version, dev=dev)
                builder.issue("DEP-002", f"{name} uses the dynamic version {version}", None, name)
            else:
                builder.component(name, version, dev=dev)
                if version.upper().endswith("-SNAPSHOT"):
                    builder.issue("DEP-002", f"{name} {version} is a mutable SNAPSHOT", None, name)

    for block_name, item_name in (
        ("repositories", "repository"),
        ("pluginRepositories", "pluginRepository"),
    ):
        for block in _children(root, block_name):
            for repo in _children(block, item_name):
                if _is_insecure_url(_text(repo, "url")):
                    builder.issue(
                        "DEP-004",
                        f"repository {_text(repo, 'url')}",
                        None,
                        _text(repo, "id") or None,
                    )
    builder.parsed.notes.append(_TRANSITIVE_NOTE.format(file="pom.xml"))
    return builder.finish()


_GRADLE_CONFIG_RE = re.compile(
    r"\b(implementation|api|compile\w*|runtime\w*|testImplementation|testRuntimeOnly|"
    r"annotationProcessor|classpath|kapt|developmentOnly|platform|enforcedPlatform|testCompile\w*)\b"
)
_GRADLE_COORD_RE = re.compile(r"""["']([\w.\-]+):([\w.\-]+)(?::([^"':\s]+))?(?::[\w.\-]+)?["']""")
_GRADLE_MAP_RE = re.compile(
    r"""group\s*[:=]\s*["']([^"']+)["']\s*,\s*name\s*[:=]\s*["']([^"']+)["']"""
    r"""(?:\s*,\s*version\s*[:=]\s*["']([^"']+)["'])?"""
)


def parse_gradle(content: str) -> Parsed:
    """Parse a build.gradle or build.gradle.kts file (string and map notations)."""
    builder = _Builder("build.gradle", "Maven", False)
    for number, line in enumerate(content.splitlines(), start=1):
        if re.search(r"http://", line) and re.search(r"url|maven|allowInsecureProtocol", line):
            if _is_insecure_url(line[line.index("http://") :].split('"')[0].split("'")[0]):
                builder.issue("DEP-004", line.strip()[:100], number)
        if "allowInsecureProtocol" in line and "true" in line:
            builder.issue("DEP-004", "allowInsecureProtocol = true", number)
        config = _GRADLE_CONFIG_RE.search(line)
        if not config:
            continue
        dev = config.group(1).lower().startswith("test")
        found = [m.groups() for m in _GRADLE_COORD_RE.finditer(line)] + [
            m.groups() for m in _GRADLE_MAP_RE.finditer(line)
        ]
        for group, artifact, version in found:
            name = f"{group}:{artifact}"
            if not version or "$" in version:
                builder.component(name, None, line=number, dev=dev)
                builder.issue("DEP-009", "version managed by a platform or variable", number, name)
            elif "+" in version or version.startswith("latest") or version[0] in "[(":
                builder.component(name, None, spec=version, line=number, dev=dev)
                builder.issue("DEP-002", f"{name}:{version} is a dynamic version", number, name)
            else:
                builder.component(name, version, line=number, dev=dev)
    builder.parsed.notes.append(_TRANSITIVE_NOTE.format(file="build.gradle"))
    return builder.finish()


# ── Go ───────────────────────────────────────────────────────────────────────

_GO_REQUIRE_RE = re.compile(r'^"?([^\s"]+)"?\s+"?(v[^\s"]+)"?$')
_GO_REPLACE_RE = re.compile(
    r'^"?([^\s"]+)"?(?:\s+"?(v[^\s"]+)"?)?\s*=>\s*"?([^\s"]+)"?(?:\s+"?(v[^\s"]+)"?)?$'
)
_GO_LOCAL_PATH = re.compile(r"^(\.{1,2}/|/|[A-Za-z]:[\\/])")


def _go_directives(content: str) -> Iterator[tuple[int, str, str]]:
    """Yield ``(line, verb, arguments)`` for each directive of a go.mod, blocks expanded."""
    block: str | None = None
    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block is not None:
            if line == ")":
                block = None
            else:
                yield number, block, line
            continue
        verb, _, rest = line.partition(" ")
        rest = rest.strip()
        if rest == "(":
            block = verb
        elif rest:
            yield number, verb, rest


def parse_go_mod(content: str) -> Parsed:
    """Parse a go.mod file.

    Since Go 1.17, go.mod lists every module needed to build the main module (``// indirect``
    included) at its selected version: it is matched like a lockfile. ``replace`` directives
    are applied; the standard library (``go`` and ``toolchain`` directives) is not checked.
    """
    builder = _Builder("go.mod", "Go", True)
    requires: list[tuple[int, str, str]] = []
    replaces: dict[tuple[str, str | None], tuple[str, str | None]] = {}
    for number, verb, args in _go_directives(content):
        if verb == "require" and (found := _GO_REQUIRE_RE.match(args)):
            requires.append((number, found.group(1), found.group(2)))
        elif verb == "replace" and (found := _GO_REPLACE_RE.match(args)):
            old, old_version, new, new_version = found.groups()
            replaces[(old, old_version)] = (new, new_version)
    for number, name, version in requires:
        target = replaces.get((name, version)) or replaces.get((name, None))
        if target is None:
            builder.component(name, version, line=number)
            continue
        new, new_version = target
        if new_version is None or _GO_LOCAL_PATH.match(new):
            builder.component(name, None, spec=f"=> {new[:80]}", line=number)
            builder.issue(
                "DEP-007", f"{name} is replaced by the local path {new[:80]}", number, name
            )
            continue
        builder.component(new, new_version, spec=f"replaces {name}", line=number)
        if new != name:
            builder.issue("DEP-003", f"{name} is replaced by {new} {new_version}", number, name)
    return builder.finish()


# ── Rust (Cargo) ─────────────────────────────────────────────────────────────

_CRATES_IO_SOURCES = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)
_CARGO_SECTIONS = (
    ("dependencies", False),
    ("dev-dependencies", True),
    ("build-dependencies", False),
)
_CARGO_EXACT = re.compile(r"=\s*(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)")


def parse_cargo_lock(content: str) -> Parsed:
    """Parse a Cargo.lock file (every crate of the build, transitive included)."""
    data = _load_toml(content)
    builder = _Builder("Cargo.lock", "crates.io", True)
    for package in data.get("package") or []:
        name, version = package.get("name"), package.get("version")
        source = str(package.get("source") or "")
        if not isinstance(name, str) or not isinstance(version, str) or not source:
            continue  # no source: a member of the workspace, the project itself
        builder.component(name, version)
        if source.startswith("git+"):
            builder.issue("DEP-003", f"{name} comes from {source[:80]}", None, name)
        elif not source.startswith(_CRATES_IO_SOURCES):
            builder.issue("DEP-005", f"{name} comes from {source[:80]}", None, name)
        if _is_insecure_url(source.split("+", 1)[-1]):
            builder.issue("DEP-004", f"{name} is downloaded over HTTP", None, name)
    return builder.finish()


def _add_cargo_dependency(builder: _Builder, name: str, spec: object, dev: bool) -> None:
    """Classify a dependency of a Cargo.toml (a version string or a table)."""
    table = spec if isinstance(spec, dict) else {"version": spec}
    if table.get("workspace") is True:
        builder.component(name, None, spec="workspace", dev=dev)
        builder.issue("DEP-009", f"{name} (workspace)", None, name)
        return
    if "git" in table:
        url = str(table["git"])
        builder.component(name, None, spec=url[:80], dev=dev)
        builder.issue("DEP-003", f"{name}: {url[:80]}", None, name)
        if _is_insecure_url(url):
            builder.issue("DEP-004", f"{name} is downloaded over HTTP", None, name)
        return
    if "path" in table and "version" not in table:
        builder.component(name, None, spec=str(table["path"])[:80], dev=dev)
        builder.issue("DEP-007", f"{name}: path {str(table['path'])[:80]}", None, name)
        return
    text = str(table.get("version", "")).strip()
    exact = _CARGO_EXACT.fullmatch(text)
    builder.component(name, exact.group(1) if exact else None, spec=text, dev=dev)
    if text in ("", "*"):
        builder.issue("DEP-002", f'{name}: "{text or "*"}"', None, name)
    elif re.fullmatch(r">=?\s*[\d.]+", text):
        builder.issue("DEP-001", f"{name}: {text} has no upper bound", None, name)
    if "registry" in table:
        builder.issue(
            "DEP-005", f"{name} comes from the registry {str(table['registry'])[:40]}", None, name
        )
    # "1.2" is a caret range, the normal practice when Cargo.lock is committed


def parse_cargo_toml(content: str) -> Parsed:
    """Parse a Cargo.toml file (versions are ranges: Cargo.lock holds the resolved ones)."""
    data = _load_toml(content)
    builder = _Builder("Cargo.toml", "crates.io", False)
    tables = [data, data.get("workspace") or {}]
    tables += [t for t in (data.get("target") or {}).values() if isinstance(t, dict)]
    for table in tables:
        for section, dev in _CARGO_SECTIONS:
            for name, spec in (table.get(section) or {}).items():
                _add_cargo_dependency(builder, name, spec, dev)
    for registry, patches in (data.get("patch") or {}).items():
        for name, spec in (patches or {}).items():
            where = str(spec.get("git") or spec.get("path") if isinstance(spec, dict) else spec)
            builder.issue(
                "DEP-003", f"{name} is patched ({registry[:40]}) with {where[:80]}", None, name
            )
    return builder.finish()


# ── NuGet (.NET) ─────────────────────────────────────────────────────────────

_NUGET_EXACT = re.compile(r"\[?\s*(\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?)\s*\]?")
_MSBUILD_PROPERTY = re.compile(r"\$\(")


def parse_packages_lock(content: str) -> Parsed:
    """Parse a NuGet packages.lock.json (every package of each target framework)."""
    data = _load_json(content)
    builder = _Builder("packages.lock.json", "NuGet", True)
    seen: set[tuple[str, str]] = set()
    for framework in (data.get("dependencies") or {}).values():
        for name, meta in (framework or {}).items():
            if not isinstance(meta, dict) or meta.get("type") == "Project":
                continue  # a project of the solution, not a package
            version = meta.get("resolved")
            if not isinstance(version, str):
                continue
            if (name.lower(), version) not in seen:
                seen.add((name.lower(), version))
                builder.component(name, version)
    return builder.finish()


def _add_nuget_reference(builder: _Builder, name: str, version: str, dev: bool) -> None:
    """Classify a NuGet version: ``1.2.3`` is the version restored (lowest applicable)."""
    text = version.strip()
    if not text:
        builder.component(name, None, dev=dev)
        builder.issue("DEP-009", name, None, name)
        return
    if _MSBUILD_PROPERTY.search(text):
        builder.component(name, None, spec=text, dev=dev)
        builder.issue("DEP-009", f"{name} ({text})", None, name)
        return
    exact = _NUGET_EXACT.fullmatch(text)
    builder.component(name, exact.group(1) if exact else None, spec=text, dev=dev)
    if "*" in text:
        builder.issue("DEP-002", f'{name}: "{text}" is a floating version', None, name)
    elif re.fullmatch(r"\[\s*[\d.]+\s*,\s*\)", text):
        builder.issue("DEP-001", f"{name}: {text} has no upper bound", None, name)


def parse_msbuild_project(content: str, file_type: str) -> Parsed:
    """Parse the NuGet references of an MSBuild file (*.csproj, Directory.Packages.props...)."""
    root = _load_xml(content, file_type)
    builder = _Builder(file_type, "NuGet", False)
    for element in root.iter():
        tag = _local(element.tag)
        if tag not in ("PackageReference", "PackageVersion", "GlobalPackageReference"):
            continue
        name = element.get("Include") or element.get("Update")
        if not name:
            continue
        version = (
            element.get("VersionOverride") or element.get("Version") or _text(element, "Version")
        )
        assets = (element.get("PrivateAssets") or _text(element, "PrivateAssets")).lower()
        _add_nuget_reference(builder, name, version, dev=assets == "all")
    return builder.finish()


def parse_packages_config(content: str) -> Parsed:
    """Parse a legacy NuGet packages.config (exact versions of every package)."""
    root = _load_xml(content, "packages.config")
    builder = _Builder("packages.config", "NuGet", True)
    for element in root.iter():
        if _local(element.tag) == "package" and (name := element.get("id")):
            dev = (element.get("developmentDependency") or "").lower() == "true"
            _add_nuget_reference(builder, name, element.get("version") or "", dev)
    return builder.finish()


def parse_nuget_config(content: str) -> Parsed:
    """Check the package sources of a nuget.config (no component)."""
    root = _load_xml(content, "nuget.config")
    builder = _Builder("nuget.config", "NuGet", False)
    sources = [
        (element.get("key") or "", element.get("value") or "")
        for block in root.iter()
        if _local(block.tag) == "packageSources"
        for element in block
        if _local(element.tag) == "add"
    ]
    for key, url in sources:
        if _is_insecure_url(url):
            builder.issue("DEP-004", f"source {key} uses HTTP: {url[:80]}", None, key)
    mapped = any(_local(e.tag) == "packageSourceMapping" for e in root.iter())
    if len(sources) > 1 and not mapped:
        names = ", ".join(key for key, _ in sources)
        builder.issue(
            "DEP-005",
            f"{len(sources)} package sources ({names}) without packageSourceMapping",
            None,
            "packageSources",
        )
    return builder.finish()


# ── CycloneDX SBOM ───────────────────────────────────────────────────────────

# Package URL type -> advisory ecosystem; the other types (gem, composer...) are not checked
_PURL_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
}
_CYCLONEDX_XML_NS = "http://cyclonedx.org/schema/bom/"  # secreview:ignore GEN-004 XML namespace


def _parse_purl(purl: str) -> tuple[str, str, str | None] | None:
    """Return the type, the ecosystem name and the version of a package URL, or None.

    ``pkg:maven/org.apache/commons@1.0`` gives ``("maven", "org.apache:commons", "1.0")`` and
    ``pkg:npm/%40angular/core@17.0.0`` gives ``("npm", "@angular/core", "17.0.0")``.
    """
    if not purl.startswith("pkg:"):
        return None
    path = purl[4:].split("#", 1)[0].split("?", 1)[0].strip("/")
    kind, _, path = path.partition("/")
    version = None
    # The version follows the last "@" of the last segment (an unencoded npm scope is "@x/")
    head, slash, last = path.rpartition("/")
    if "@" in last:
        last, version = last.rsplit("@", 1)
        version = unquote(version).strip() or None
    segments = [unquote(segment) for segment in f"{head}{slash}{last}".split("/") if segment]
    kind = kind.lower()
    if not segments or not kind:
        return None
    if kind == "maven":
        if len(segments) < 2:
            return None
        return kind, f"{'.'.join(segments[:-1])}:{segments[-1]}", version
    if kind in ("npm", "golang"):  # the namespace is part of the name (@scope, github.com/x)
        return kind, "/".join(segments), version
    return kind, segments[-1], version


def _json_sbom_entries(components: object) -> Iterator[tuple[object, object, object]]:
    """Yield the purl, version and scope of the components of a JSON SBOM, nested included.

    The walk is iterative: a deeply nested SBOM cannot exhaust the Python stack.
    """
    stack = list(reversed(components)) if isinstance(components, list) else []
    while stack:
        item = stack.pop()
        if not isinstance(item, dict):
            continue
        yield item.get("purl"), item.get("version"), item.get("scope")
        nested = item.get("components")
        if isinstance(nested, list):
            stack.extend(reversed(nested))


def _xml_sbom_entries(root: ET.Element) -> Iterator[tuple[object, object, object]]:
    """Yield the purl, version and scope of the components of an XML SBOM, nested included."""

    def components_of(element: ET.Element) -> list[ET.Element]:
        return [
            c for block in _children(element, "components") for c in _children(block, "component")
        ]

    stack = list(reversed(components_of(root)))
    while stack:
        item = stack.pop()
        yield _text(item, "purl"), _text(item, "version"), _text(item, "scope")
        stack.extend(reversed(components_of(item)))


def _parse_sbom(entries: Iterator[tuple[object, object, object]], file_type: str) -> Parsed:
    """Turn the components of a CycloneDX SBOM into a Parsed (several ecosystems possible)."""
    builder = _Builder(file_type, "", True)
    unsupported: Counter[str] = Counter()
    unidentified = 0
    for purl, version, scope in entries:
        identity = _parse_purl(purl.strip()) if isinstance(purl, str) else None
        if identity is None:
            unidentified += 1
            continue
        kind, name, purl_version = identity
        ecosystem = _PURL_ECOSYSTEMS.get(kind)
        if ecosystem is None:
            unsupported[kind] += 1
            continue
        if isinstance(version, str) and version.strip():
            purl_version = version.strip()
        builder.parsed.components.append(
            Component(ecosystem, name, purl_version, dev=scope == "excluded")
        )
        if ecosystem == "Maven" and (purl_version or "").upper().endswith("-SNAPSHOT"):
            builder.issue("DEP-002", f"{name} {purl_version} is a mutable SNAPSHOT", None, name)

    components = builder.parsed.components
    ecosystems = sorted({c.ecosystem for c in components})
    builder.parsed.ecosystem = ", ".join(ecosystems) or "none"
    notes = builder.parsed.notes
    if not components:
        notes.append("The SBOM lists no component of a supported ecosystem: nothing was checked.")
    if missing := sum(1 for c in components if c.version is None):
        notes.append(f"{missing} component(s) have no version and cannot be checked.")
    if unsupported:
        types = ", ".join(f"{kind} ({count})" for kind, count in sorted(unsupported.items()))
        notes.append(f"Package types without advisories, not checked: {types}.")
    if unidentified:
        notes.append(
            f"{unidentified} component(s) have no package URL (purl) and cannot be checked."
        )
    return builder.finish()


def parse_cyclonedx_json(content: str) -> Parsed:
    """Parse a CycloneDX SBOM in JSON (``bomFormat: CycloneDX``)."""
    data = _load_json(content)
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("Not a CycloneDX SBOM: bomFormat must be 'CycloneDX'")
    return _parse_sbom(_json_sbom_entries(data.get("components")), "CycloneDX")


def parse_cyclonedx_xml(content: str) -> Parsed:
    """Parse a CycloneDX SBOM in XML (``<bom xmlns="http://cyclonedx.org/schema/bom/...">``)."""
    root = _load_xml(content, "SBOM")
    if _local(root.tag) != "bom" or not root.tag.startswith("{" + _CYCLONEDX_XML_NS):
        raise ValueError("Not a CycloneDX SBOM: the root must be a CycloneDX <bom> element")
    return _parse_sbom(_xml_sbom_entries(root), "CycloneDX")


# ── Dispatch ─────────────────────────────────────────────────────────────────

_PARSERS = {
    "pyproject.toml": parse_pyproject,
    "poetry.lock": parse_poetry_lock,
    "pipfile.lock": parse_pipfile_lock,
    "uv.lock": parse_uv_lock,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pom.xml": parse_pom,
    "build.gradle": parse_gradle,
    "build.gradle.kts": parse_gradle,
    "go.mod": parse_go_mod,
    "cargo.lock": parse_cargo_lock,
    "cargo.toml": parse_cargo_toml,
    "packages.lock.json": parse_packages_lock,
    "packages.config": parse_packages_config,
    "nuget.config": parse_nuget_config,
    "directory.packages.props": partial(
        parse_msbuild_project, file_type="Directory.Packages.props"
    ),
    "directory.build.props": partial(parse_msbuild_project, file_type="Directory.Build.props"),
}
_MSBUILD_PROJECTS = (".csproj", ".fsproj", ".vbproj")
_REQUIREMENTS_NAME = re.compile(r"^[\w.-]*(requirements|constraints)[\w.-]*\.(txt|in)$")
# CycloneDX SBOMs: bom.json, sbom.xml, app-bom.json, app.cdx.json...
_SBOM_NAME = re.compile(r"^(?:[\w.-]*[._-])?(?:s?bom|cdx)\.(json|xml)$")


def parse_dependency_file(content: str, filename: str) -> Parsed:
    """Parse a dependency file chosen by its name.

    Raises:
        ValueError: If the file type is not supported or the content is invalid.
    """
    path = PurePosixPath(filename.replace("\\", "/").lower())
    base = path.name
    parser = _PARSERS.get(base)
    if parser is None and base.endswith(_MSBUILD_PROJECTS):
        parser = partial(parse_msbuild_project, file_type=f"*{path.suffix}")
    if parser is None and (sbom := _SBOM_NAME.match(base)):
        parser = parse_cyclonedx_json if sbom.group(1) == "json" else parse_cyclonedx_xml
    if parser is not None:
        try:
            return parser(content)
        except (AttributeError, TypeError, KeyError, IndexError) as exc:
            # Well-formed JSON / TOML whose nodes have unexpected types (a string where a
            # table is expected...): report a data error instead of an internal failure. The
            # message never echoes file content, which may hold secrets.
            raise ValueError(
                f"Invalid {path.name} structure: a value has an unexpected type "
                f"({type(exc).__name__})"
            ) from exc
    in_requirements_dir = base.endswith((".txt", ".in")) and path.parent.name in {
        "requirements",
        "constraints",
    }
    if _REQUIREMENTS_NAME.match(base) or in_requirements_dir:
        return parse_requirements(content)
    raise ValueError(f"Unsupported file '{filename}'. Supported: {', '.join(SUPPORTED_FILES)}")
