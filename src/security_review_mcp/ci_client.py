"""Lightweight pipeline client of the controller (Jenkins, GitLab CI, GitHub Actions...).

``security-review-ci`` runs the security gate, downloads the SARIF log, prints the trend of a
project and runs the code and dependency scans through the pipeline routes of the controller
REST API (``/api/v1/ci/``), with a ``ci`` token restricted to the projects the pipeline may see.
It is the only command line for these pipeline commands (the controller CLI does not run them)
and opens no database: no database driver, no SQLModel, no database URL in the pipeline.

``scan-code`` lists the files of a directory (``git ls-files`` or a walk of the tree) and
``scan-deps`` reads the dependency files given by the operator; both send the content to the
controller, which scans it with its rules or its advisory database and stores the report with
``--save``. Symbolic links are never followed: the content leaves the build agent.

The module only uses the Python standard library and imports nothing from the package, so it
can also be copied alone to a build agent and run with ``python3 ci_client.py``. That is why it
reads its two variables (``SECREVIEW_CONTROLLER_URL``, ``SECREVIEW_TOKEN``) from the environment
itself instead of through ``config.Settings``, and ignores the ``.env`` file. The file listing
(``detect_language``...) is defined here and reused by ``codescan`` on the controller.

Exit codes are those of the other commands: 0 success (gate passed, scan below the threshold),
1 blocked, 2 usage, connection or data error (written as JSON on stderr). The token is never
written anywhere.
"""

import argparse
import fnmatch
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from urllib.parse import urlencode, urlsplit

EXIT_PASSED = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2

CI_PATH = "/api/v1/ci"
DEFAULT_TIMEOUT = 60.0
# Bound of an answer read from the controller (a SARIF log of a large project included)
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
# Bound of a dependency file read by scan-deps (the controller applies its own limit)
MAX_DEPENDENCY_FILE_BYTES = 50 * 1024 * 1024
# Bound of the error messages taken from the controller
MAX_ERROR_CHARS = 500
# Plain HTTP is only accepted to these hosts (the token travels in the request)
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
SEVERITIES = ["info", "low", "medium", "high", "critical"]

URL_VARIABLE = "SECREVIEW_CONTROLLER_URL"
TOKEN_VARIABLE = "SECREVIEW_TOKEN"

# Explanation added to the refusals of the controller
_REFUSAL_HINTS = {
    401: f"missing or invalid token ({TOKEN_VARIABLE} or --token-stdin)",
    403: "the token may not use this pipeline route (gate, sarif, trend: role ci, reader, "
    "triager or admin; scans: role ci or admin)",
    404: "unknown project or report, or outside the projects of the token",
    413: "request too large for the controller (SECREVIEW_MAX_SCAN_REQUEST_MB): exclude files",
    503: "authentication is not configured on the controller",
}

# Sends a request (method, URL, headers, JSON body or None) and returns (HTTP status, content
# type, body); tests replace it
Fetch = Callable[[str, str, dict[str, str], bytes | None], tuple[int, str, bytes]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: the token must never be sent elsewhere (or over HTTP)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        """Return None so that urllib raises an HTTPError for the 3xx answer."""
        return None


def controller_endpoint(controller_url: str, route: str, allow_http: bool = False) -> str:
    """Return the URL of a pipeline route of a controller given by its base URL.

    Plain HTTP is refused except on a loopback address or with ``allow_http``, and so are
    credentials in the URL: the token is the only credential and goes in a header.
    """
    parts = urlsplit(controller_url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(
            f"Invalid controller URL '{controller_url}' (expected https://host[:port])"
        )
    if parts.username or parts.password:
        raise ValueError("The controller URL must not contain credentials")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS and not allow_http:
        raise ValueError("Refusing to send the token over plain HTTP (see --allow-http)")
    # The base URL may be given with the path of the web interface or of the API
    path = parts.path.rstrip("/")
    for suffix in ("/ui", "/api/v1", "/api"):
        path = path.removesuffix(suffix)
    return f"{parts.scheme}://{parts.netloc}{path}{CI_PATH}/{route}"


def urllib_fetch(cafile: str | None = None, timeout: float = DEFAULT_TIMEOUT) -> Fetch:
    """Return a fetch function that verifies the certificate with ``cafile`` (default: the
    system CA bundle), follows no redirect and reads at most MAX_RESPONSE_BYTES."""
    context = ssl.create_default_context(cafile=cafile)
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=context)
    )

    def fetch(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, str, bytes]:
        """Send a request and return its status, content type and bounded body."""
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with opener.open(request, timeout=timeout) as response:
                return (
                    response.status,
                    response.headers.get("Content-Type", ""),
                    response.read(MAX_RESPONSE_BYTES + 1),
                )
        except urllib.error.HTTPError as exc:
            with exc:
                body = exc.read(MAX_RESPONSE_BYTES + 1)
            return exc.code, exc.headers.get("Content-Type", "") if exc.headers else "", body
        except (urllib.error.URLError, OSError) as exc:
            # The message never holds the token: it is only in the request headers
            reason = getattr(exc, "reason", exc)
            raise ValueError(f"Cannot reach {url}: {reason}") from exc

    return fetch


def _error_detail(body: bytes) -> str:
    """Extract the error message of a FastAPI or middleware answer, bounded."""
    try:
        answer = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(answer, dict):
        return ""
    detail = answer.get("detail") or answer.get("error_description") or ""
    if isinstance(detail, list):
        # Pydantic validation errors
        detail = "; ".join(str(item.get("msg", item)) for item in detail if isinstance(item, dict))
    return str(detail)[:MAX_ERROR_CHARS]


def call(
    controller_url: str,
    route: str,
    params: dict[str, str | int | bool | None],
    token: str,
    fetch: Fetch,
    allow_http: bool = False,
    payload: dict | None = None,
) -> tuple[str, bytes]:
    """Call a pipeline route and return the content type and body of a successful answer.

    ``payload`` is sent as a JSON body with a POST request (the scans), otherwise the route is
    read with a GET request.

    Raises:
        ValueError: Invalid URL, unreachable controller, refused request or oversized answer.
    """
    query = {
        key: str(value).lower() if isinstance(value, bool) else value
        for key, value in params.items()
        if value is not None
    }
    url = controller_endpoint(controller_url, route, allow_http)
    if query:
        url = f"{url}?{urlencode(query)}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    status, content_type, body = fetch("GET" if data is None else "POST", url, headers, data)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError(f"Answer of {route} too large (> {MAX_RESPONSE_BYTES} bytes)")
    if status != 200:
        detail = _error_detail(body) or _REFUSAL_HINTS.get(status, "no detail")
        raise ValueError(f"The controller refused the request ({status}): {detail}")
    return content_type, body


def printable(text: str) -> str:
    """Remove the control characters (terminal escapes) of a text answer, except new lines and
    tabs: project names and titles come from the reports."""
    return "".join(c for c in text if c in "\n\t" or (c.isprintable() and c != "\x7f"))


def _json(body: bytes, route: str) -> dict:
    """Decode a JSON object answered by a pipeline route."""
    try:
        answer = json.loads(body)
    except ValueError as exc:
        raise ValueError(f"Unexpected answer of {route}: not JSON") from exc
    if not isinstance(answer, dict):
        raise ValueError(f"Unexpected answer of {route}: not a JSON object")
    return answer


# ── File listing (scan-code, scan-deps) ──────────────────────────────────────

DEFAULT_MAX_FILE_BYTES = 1024 * 1024
_BINARY_SNIFF_BYTES = 8192

# Skipped when the tree is walked without git
SKIPPED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "node_modules",
        "bower_components",
        ".angular",
        "dist",
        "build",
        "target",
        "out",
        "coverage",
        ".gradle",
        "obj",  # .NET intermediate output
        ".vs",
        ".idea",
    }
)

# Generated files: huge and never hand-written
SKIPPED_NAMES = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "uv.lock"}
)

_EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".java": "java",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".cs": "csharp",
    ".csx": "csharp",
    ".cshtml": "csharp",  # Razor views (Html.Raw...)
    ".razor": "csharp",
    ".rs": "rust",
    ".html": "angular",  # Angular templates ([innerHTML], bypassSecurityTrust...)
    ".yml": "yaml",
    ".yaml": "yaml",
    ".properties": "config",
    ".ini": "config",
    ".cfg": "config",
    ".conf": "config",
    ".toml": "config",
    ".env": "config",
    ".groovy": "jenkins",
    ".jenkinsfile": "jenkins",
    ".dockerfile": "docker",
}

# Files that steer an AI assistant: scanned for hidden characters and injected instructions
_AGENT_INSTRUCTION_NAMES = frozenset(
    {
        "agents.md",
        "claude.md",
        "gemini.md",
        "copilot-instructions.md",
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
    }
)
_AGENT_INSTRUCTION_DIRS = frozenset({".claude", ".cursor", ".windsurf", ".clinerules"})


def detect_language(path: str) -> str | None:
    """Return the scanner language of a file from its name, or None when it is not scanned."""
    name = PurePosixPath(path).name
    lower = name.lower()
    if name in SKIPPED_NAMES or lower.endswith((".min.js", ".d.ts")):
        return None
    if lower in ("dockerfile", "containerfile") or lower.startswith(
        ("dockerfile.", "containerfile.")
    ):
        return "docker"
    if lower == "jenkinsfile" or lower.startswith("jenkinsfile."):
        return "jenkins"
    if lower == ".gitlab-ci.yml" or (
        lower.endswith((".yml", ".yaml")) and ".gitlab-ci" in PurePosixPath(path).parts[:-1]
    ):
        return "gitlab-ci"
    if lower == ".env" or lower.startswith(".env."):
        return "config"
    if (
        lower in _AGENT_INSTRUCTION_NAMES
        or lower.endswith((".mdc", ".instructions.md", ".prompt.md"))
        or (lower.endswith(".md") and _AGENT_INSTRUCTION_DIRS & set(PurePosixPath(path).parts))
    ):
        return "agent-instructions"
    return _EXTENSIONS.get(PurePosixPath(lower).suffix)


# The scanned repository's .git/config is untrusted: some keys make git run a command
# (core.fsmonitor). Options given with -c override the repository configuration.
_GIT_SAFE_OPTIONS = ("-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false")


def _git_files(root: Path) -> list[str] | None:
    """List tracked and untracked (not ignored) files with git, or None if git is unusable."""
    try:
        completed = subprocess.run(
            ["git", *_GIT_SAFE_OPTIONS, "ls-files", "-z", "--cached", "--others"]
            + ["--exclude-standard"],
            cwd=root,
            capture_output=True,
            check=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    names = completed.stdout.decode("utf-8", errors="replace").split("\0")
    return sorted({name for name in names if name})


def _walk_files(root: Path) -> list[str]:
    """List files under root, skipping dependency, build and VCS directories."""
    found: list[str] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIPPED_DIRS)
        base = Path(current).relative_to(root)
        found.extend((base / name).as_posix() for name in sorted(files))
    return found


def list_files(root: Path, use_git: bool = True) -> tuple[list[str], str]:
    """Return the relative paths of the files to consider and the listing method used."""
    if use_git:
        names = _git_files(root)
        if names is not None:
            return names, "git"
    return _walk_files(root), "walk"


def _excluded(path: str, patterns: list[str]) -> bool:
    """Tell whether a relative path matches one of the exclusion globs."""
    return any(
        fnmatch.fnmatch(path, pattern) or path.startswith(pattern.rstrip("/") + "/")
        for pattern in patterns
    )


def _read_source(path: Path, max_bytes: int) -> tuple[str | None, str | None]:
    """Read a text file; return ``(content, None)`` or ``(None, reason it was skipped)``."""
    if path.is_symlink():
        return None, "symbolic link"
    if not path.is_file():
        return None, "not a regular file"
    size = path.stat().st_size
    if size > max_bytes:
        return None, f"larger than {max_bytes} bytes"
    data = path.read_bytes()
    if b"\0" in data[:_BINARY_SNIFF_BYTES]:
        return None, "binary file"
    return data.decode("utf-8", errors="replace"), None


def collect_sources(
    root: str | Path,
    excludes: list[str] | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    use_git: bool = True,
) -> dict:
    """Read every supported file under ``root``, ready to be sent to the code scan route.

    Args:
        root: Directory to scan.
        excludes: Glob patterns (relative to root) of files or directories to skip.
        max_file_bytes: Files above this size are skipped and reported.
        use_git: List files with ``git ls-files`` when possible.

    Returns:
        The listing method, the files read (relative path with forward slashes and content),
        the files skipped with their reason (excluded ones are only counted) and the number of
        files of an unsupported type.

    Raises:
        ValueError: If root is not a directory.
    """
    base = Path(root).resolve()
    if not base.is_dir():
        raise ValueError(f"Not a directory: {root}")
    patterns = list(excludes or [])
    names, method = list_files(base, use_git)
    files: list[dict] = []
    skipped: list[dict] = []
    excluded = unsupported = 0
    for name in names:
        if detect_language(name) is None:
            unsupported += 1
            continue
        if _excluded(name, patterns):
            excluded += 1
            continue
        try:
            content, reason = _read_source(base / name, max_file_bytes)
        except OSError as exc:
            content, reason = None, f"unreadable: {exc.strerror or exc}"
        if content is None:
            skipped.append({"file": name, "reason": reason})
        else:
            files.append({"path": name, "content": content})
    return {
        "listing": method,
        "files": files,
        "skipped": skipped,
        "excluded": excluded,
        "unsupported": unsupported,
    }


def read_dependency_file(name: str) -> dict:
    """Read a dependency file given by the operator (never through a symbolic link: the content
    leaves the machine), bounded by MAX_DEPENDENCY_FILE_BYTES."""
    path = Path(name)
    if path.is_symlink():
        raise ValueError(f"Refusing to read a symbolic link: {path}")
    if not path.is_file():
        raise ValueError(f"File not found: {path}")
    if path.stat().st_size > MAX_DEPENDENCY_FILE_BYTES:
        raise ValueError(f"File too large (> {MAX_DEPENDENCY_FILE_BYTES} bytes): {path}")
    return {"path": path.name, "content": path.read_text(encoding="utf-8", errors="replace")}


# ── Output of the scans ──────────────────────────────────────────────────────


def _clean(value: object) -> str:
    """Return ``value`` as text without control characters (terminal escape sequences): scan
    results come from advisories, from file names or from a remote server."""
    return "".join(c if c.isprintable() else "?" for c in str(value))


def print_code_text(result: dict, fail_on: str) -> None:
    """Print a short human-readable summary of a code scan answered by the controller."""
    for entry in result["files"]:
        for match in entry["matches"]:
            line = (
                f"{entry['file']}:{match['line']} [{match['severity'].upper()}] "
                f"{match['rule_id']} {match['title']}"
            )
            print(_clean(line))
    for entry in result["skipped"]:
        print(_clean(f"skipped: {entry['file']} ({entry['reason']})"), file=sys.stderr)
    counts = ", ".join(f"{k}: {v}" for k, v in result["by_severity"].items() if v)
    print(
        _clean(
            f"{result['files_scanned']} file(s) scanned ({result['lines_scanned']} lines, listed "
            f"with {result['listing']}), {result['files_skipped']} skipped, "
            f"{result['matches_count']} match(es){f' ({counts})' if counts else ''}, "
            f"{result['suppressed_count']} suppressed"
        )
    )
    blocked = result["blocking_findings"]
    print(f"RESULT: {f'BLOCKED ({blocked} match(es) >= {fail_on})' if blocked else 'OK'}")


def print_deps_text(results: list[dict], blocked: int, fail_on: str) -> None:
    """Print a short human-readable summary of dependency scans (also used by scan-deps)."""
    for result in results:
        kind = "lockfile" if result["is_lockfile"] else "manifest"
        print(
            _clean(
                f"{result['file']} ({result['ecosystem']}, {kind}): {result['components_total']} "
                f"component(s), vulnerability check: {result['vulnerability_check']}"
            )
        )
        for vuln in result["vulnerabilities"]:
            upgrade = vuln["recommended_upgrade"]
            fix = f" -> upgrade to {upgrade}" if upgrade else ""
            line = (
                f"[{vuln['severity'].upper()}] {vuln['package']} {vuln['version']} "
                f"{vuln['advisory_id']}{fix}"
            )
            print(f"  {_clean(line)}")
        for issue in result["hygiene"]:
            line = f"[{issue['severity'].upper()}] {issue['rule_id']} {issue['message']}"
            print(f"  {_clean(line)}")
        for note in result["notes"]:
            print(f"  note: {_clean(note)}")
    verdict = f"BLOCKED ({blocked} finding(s) >= {fail_on})" if blocked else "OK"
    print(f"RESULT: {verdict}")


def warn_unchecked(results: list[dict]) -> list[str]:
    """Warn on stderr about the files whose vulnerability check did not run; return them."""
    skipped = [r["file"] for r in results if r["vulnerability_check"] != "performed"]
    if skipped:
        print(
            _clean(
                f"warning: vulnerability check did not run for: {', '.join(skipped)} "
                "(no advisory database for this ecosystem)"
            ),
            file=sys.stderr,
        )
    return skipped


def _write_output(text: str, output: str | None, message: str) -> None:
    """Print ``text`` or write it to ``output`` (then print ``message`` on stderr)."""
    if not output:
        print(text)
        return
    Path(output).write_text(text + "\n", encoding="utf-8")
    print(message, file=sys.stderr)


# ── Command line ─────────────────────────────────────────────────────────────


def _fail(message: str, **fields: object) -> int:
    """Print an error as JSON on stderr and return the error exit code."""
    print(json.dumps(fields | {"error": message}), file=sys.stderr)
    return EXIT_ERROR


def _add_report_options(parser: argparse.ArgumentParser) -> None:
    """Options of the scans that store their result as a report of the project."""
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="high",
        help="lowest blocking severity (default: high)",
    )
    parser.add_argument("--save", action="store_true", help="store the result as a report")
    parser.add_argument("--repository", help="repository URL stored with the report")
    parser.add_argument("--branch", help="branch stored with the report")
    parser.add_argument("--commit", help="commit stored with the report")
    parser.add_argument(
        "--author", help="username of the developer, stored with the report (with --save)"
    )
    parser.add_argument(
        "--skip-unconfigured",
        action="store_true",
        help=f"exit 0 with a warning when {URL_VARIABLE} is not set (shared commit hooks)",
    )


def _parser() -> argparse.ArgumentParser:
    """Build the parser of ``security-review-ci`` and its sub-commands."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--url",
        default=os.environ.get(URL_VARIABLE) or None,
        help=f"controller URL, for example https://secreview.example.com (default: {URL_VARIABLE})",
    )
    common.add_argument("--project", required=True, help="project name used for the reports")
    common.add_argument(
        "--token-stdin",
        action="store_true",
        help=f"read the token on stdin (default: {TOKEN_VARIABLE})",
    )
    common.add_argument("--cafile", help="CA bundle used to verify the controller certificate")
    common.add_argument(
        "--allow-http",
        action="store_true",
        help="allow plain HTTP to a non-loopback controller (the token would travel in clear)",
    )
    common.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT, help="seconds (default: 60)"
    )

    parser = argparse.ArgumentParser(
        prog="security-review-ci",
        description="Pipeline client of the security-review controller: gate, SARIF export, "
        "trend, code scan and dependency scan of a project through the REST API, with a ci "
        "token restricted to its projects. No database access.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    gate = commands.add_parser(
        "gate", parents=[common], help="fail when open findings reach a severity threshold"
    )
    gate.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="high",
        help="lowest blocking severity (default: high)",
    )
    gate.add_argument("--report-id", type=int, default=None, help="check a single report")
    exporter = commands.add_parser(
        "sarif", parents=[common], help="download the findings as a SARIF 2.1.0 log"
    )
    exporter.add_argument("--include-resolved", action="store_true")
    exporter.add_argument("--output", "-o", help="file to write (default: standard output)")
    trend = commands.add_parser("trend", parents=[common], help="print the trend of a project")
    trend.add_argument("--days", type=int, default=90)
    trend.add_argument("--granularity", choices=["day", "week", "month"], default="week")
    trend.add_argument("--format", choices=["markdown", "json"], default="markdown")

    code = commands.add_parser(
        "scan-code",
        parents=[common],
        help="pattern-scan a whole codebase with the rules of the controller",
    )
    code.add_argument("path", nargs="?", default=".", help="directory to scan (default: .)")
    code.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="file or directory glob to skip, relative to the path; repeat the option",
    )
    code.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="skip larger files (default: 1 MiB)",
    )
    code.add_argument(
        "--no-git", action="store_true", help="walk the tree instead of using git ls-files"
    )
    code.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    code.add_argument("--output", "-o", help="file to write (default: standard output)")
    _add_report_options(code)

    deps = commands.add_parser(
        "scan-deps",
        parents=[common],
        help="scan dependency manifests and lockfiles with the advisories of the controller",
    )
    deps.add_argument("files", nargs="+", help="manifests or lockfiles")
    deps.add_argument("--format", choices=["text", "json"], default="text")
    deps.add_argument(
        "--require-database",
        action="store_true",
        help="exit 2 when the vulnerability check could not run (no advisory database)",
    )
    _add_report_options(deps)
    return parser


def _read_token(from_stdin: bool) -> str:
    """Return the token from stdin or from SECREVIEW_TOKEN (never from the command line, where
    it would show in the process list and the job log)."""
    token = sys.stdin.readline().strip() if from_stdin else os.environ.get(TOKEN_VARIABLE, "")
    if not token.strip():
        source = "stdin" if from_stdin else TOKEN_VARIABLE
        raise ValueError(f"No token: {source} is empty")
    return token.strip()


def _report_fields(args: argparse.Namespace) -> dict:
    """Fields of a scan request shared by scan-code and scan-deps."""
    return {
        "project": args.project,
        "fail_on": args.fail_on,
        "save": args.save,
        "repository": args.repository,
        "branch": args.branch,
        "commit_sha": args.commit,
        "author": args.author,
    }


def print_saved_line(result: dict, project: str) -> None:
    """Print the id of the stored report, if any."""
    saved = result.get("saved_report")
    if saved:
        print(_clean(f"Report #{saved['report_id']} saved for project {project}"))


def _scan_code(args: argparse.Namespace, send: Callable[[str, dict], bytes]) -> int:
    """Run ``scan-code``: read the files, scan them on the controller, print the result."""
    sources = collect_sources(args.path, args.exclude, args.max_file_bytes, not args.no_git)
    payload = _report_fields(args) | {
        "root": args.path,
        "listing": sources["listing"],
        "files": sources["files"],
        "skipped": sources["skipped"],
        "excluded": sources["excluded"],
        "unsupported": sources["unsupported"],
        "sarif": args.format == "sarif",
    }
    result = _json(send("scan/code", payload), "scan/code")
    if not isinstance(result.get("blocked"), bool):
        raise ValueError("Unexpected answer of scan/code: no 'blocked' field")
    code = EXIT_BLOCKED if result["blocked"] else EXIT_PASSED
    if args.format == "text":
        print_code_text(result, args.fail_on)
        print_saved_line(result, args.project)
        return code
    log = result.pop("sarif", None)
    document = log if args.format == "sarif" else result
    if not isinstance(document, dict):
        raise ValueError("Unexpected answer of scan/code: no SARIF log")
    message = f"{result['matches_count']} match(es) written to {args.output}"
    _write_output(json.dumps(document, indent=2), args.output, message)
    return code


def _scan_deps(args: argparse.Namespace, send: Callable[[str, dict], bytes]) -> int:
    """Run ``scan-deps``: read the files, scan them on the controller, print the result."""
    files = [read_dependency_file(name) for name in args.files]
    payload = _report_fields(args) | {
        "files": files,
        "require_database": args.require_database,
    }
    result = _json(send("scan/deps", payload), "scan/deps")
    if not isinstance(result.get("blocked"), bool) or not isinstance(result.get("files"), list):
        raise ValueError("Unexpected answer of scan/deps: no 'blocked' or 'files' field")
    warn_unchecked(result["files"])
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print_deps_text(result["files"], result["blocking_findings"], args.fail_on)
        print_saved_line(result, args.project)
    return EXIT_BLOCKED if result["blocked"] else EXIT_PASSED


def main(argv: list[str] | None = None, fetch: Fetch | None = None) -> int:
    """Run ``security-review-ci`` and return its exit code (``fetch``: tests)."""
    argv = sys.argv[1:] if argv is None else argv
    parser = _parser()
    if not argv:
        # No sub-command: show the help rather than a bare usage error, still failing the step.
        parser.print_help()
        return EXIT_ERROR
    args = parser.parse_args(argv)
    if not args.url and getattr(args, "skip_unconfigured", False):
        print(f"warning: {args.command} skipped ({URL_VARIABLE} is not set)", file=sys.stderr)
        return EXIT_PASSED
    try:
        if not args.url:
            raise ValueError(f"No controller URL: give --url or set {URL_VARIABLE}")
        token = _read_token(args.token_stdin)
        fetch = fetch or urllib_fetch(args.cafile, args.timeout)

        def send(route: str, payload: dict) -> bytes:
            """POST a scan request to the controller and return the answer."""
            return call(args.url, route, {}, token, fetch, args.allow_http, payload)[1]

        if args.command == "scan-code":
            return _scan_code(args, send)
        if args.command == "scan-deps":
            return _scan_deps(args, send)
        if args.command == "gate":
            params: dict[str, str | int | bool | None] = {
                "project": args.project,
                "fail_on": args.fail_on,
                "report_id": args.report_id,
            }
        elif args.command == "sarif":
            params = {"project": args.project, "include_resolved": args.include_resolved}
        else:
            params = {
                "project": args.project,
                "days": args.days,
                "granularity": args.granularity,
                "format": args.format,
            }
        _, body = call(args.url, args.command, params, token, fetch, args.allow_http)
        if args.command == "gate":
            result = _json(body, "gate")
            if not isinstance(result.get("passed"), bool):
                raise ValueError("Unexpected answer of gate: no 'passed' field")
            print(json.dumps(result, indent=2))
            return EXIT_PASSED if result["passed"] else EXIT_BLOCKED
        if args.command == "sarif":
            log = _json(body, "sarif")
            runs = log.get("runs") or [{}]
            count = len(runs[0].get("results") or []) if isinstance(runs[0], dict) else 0
            message = f"{count} result(s) written to {args.output}"
            _write_output(json.dumps(log, indent=2), args.output, message)
            return EXIT_PASSED
        text = printable(body.decode("utf-8", errors="replace"))
        if args.format == "json":
            text = json.dumps(_json(body, "trend"), indent=2) + "\n"
        print(text, end="")
        return EXIT_PASSED
    except (ValueError, OSError, KeyError, TypeError) as exc:
        detail = (
            f"Unexpected answer of the controller: {exc!r}"
            if isinstance(exc, (KeyError, TypeError))
            else str(exc)
        )
        return _fail(detail, **({"passed": False} if args.command == "gate" else {}))


if __name__ == "__main__":
    sys.exit(main())
