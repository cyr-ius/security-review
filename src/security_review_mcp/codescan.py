"""Whole-codebase pattern scan, run from the command line on a directory chosen by the operator.

The MCP server never reads the disk; this module is only used by the ``code scan`` CLI command.
Files are listed with ``git ls-files`` when the directory is a git work tree (so ``.gitignore``
is honoured), otherwise by walking the tree and skipping the usual build and dependency folders.
Like ``scan_code``, the matches are leads to verify, not confirmed vulnerabilities.
"""

import fnmatch
import os
import subprocess
from pathlib import Path, PurePosixPath

from . import registry
from .models import SEVERITY_RANK, FindingCreate, FindingPublic, FindingStatus, Severity

DEFAULT_MAX_FILE_BYTES = 1024 * 1024
MAX_MATCHES_PER_FILE = 200
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
    except OSError, subprocess.SubprocessError:
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


def scan_tree(
    root: str | Path,
    excludes: list[str] | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    use_git: bool = True,
) -> dict:
    """Scan every supported file under ``root`` with the active rules.

    Args:
        root: Directory to scan.
        excludes: Glob patterns (relative to root) of files or directories to skip.
        max_file_bytes: Files above this size are skipped and reported.
        use_git: List files with ``git ls-files`` when possible.

    Returns:
        The matches per file, the suppressed matches, the files skipped with their reason,
        and totals. Paths are relative to ``root``, with forward slashes.

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
    unsupported = 0
    for name in names:
        language = detect_language(name)
        if language is None:
            unsupported += 1
            continue
        if _excluded(name, patterns):
            skipped.append({"file": name, "reason": "excluded"})
            continue
        try:
            content, reason = _read_source(base / name, max_file_bytes)
        except OSError as exc:
            content, reason = None, f"unreadable: {exc.strerror or exc}"
        if content is None:
            skipped.append({"file": name, "reason": reason})
            continue
        matches, suppressed = registry.scan(content, language, MAX_MATCHES_PER_FILE)
        files.append(
            {
                "file": name,
                "language": language,
                "lines": len(content.splitlines()),
                "matches": matches,
                "suppressed": suppressed,
                "truncated": len(matches) >= MAX_MATCHES_PER_FILE,
            }
        )

    matches_count = sum(len(f["matches"]) for f in files)
    by_severity = {s.value: 0 for s in Severity}
    for entry in files:
        for match in entry["matches"]:
            by_severity[match["severity"]] += 1
    return {
        "root": str(base),
        "listing": method,
        "files_scanned": len(files),
        "files_skipped": len(skipped),
        "files_unsupported": unsupported,
        "lines_scanned": sum(f["lines"] for f in files),
        "matches_count": matches_count,
        "suppressed_count": sum(len(f["suppressed"]) for f in files),
        "by_severity": by_severity,
        "files": files,
        "skipped": skipped,
    }


def blocking_count(result: dict, fail_on: Severity) -> int:
    """Count the matches whose severity reaches the threshold."""
    threshold = SEVERITY_RANK[fail_on]
    return sum(
        1
        for entry in result["files"]
        for match in entry["matches"]
        if SEVERITY_RANK[Severity(match["severity"])] >= threshold
    )


_SECRET_CWES = frozenset({"CWE-259", "CWE-321", "CWE-798"})


def _category(language: str, cwe: str | None) -> str:
    """Pick the finding category from the file language and the rule CWE."""
    if cwe in _SECRET_CWES:
        return "secret"
    if language in ("config", "yaml", "docker", "gitlab-ci", "jenkins"):
        return "configuration"
    return "code"


def to_findings(result: dict) -> list[FindingCreate]:
    """Convert the matches to findings, most severe first (ready for ``save_report``)."""
    findings: list[FindingCreate] = []
    for entry in result["files"]:
        for match in entry["matches"]:
            findings.append(
                FindingCreate(
                    title=match["title"],
                    severity=Severity(match["severity"]),
                    rule_id=match["rule_id"],
                    category=_category(entry["language"], match["cwe"]),
                    cwe=match["cwe"] or None,
                    file_path=entry["file"],
                    line_start=match["line"],
                    line_end=match["line"],
                    description=(
                        f"{match['title']}: pattern match found by the codebase scan. "
                        "It is a lead: confirm it by reading the surrounding code."
                    ),
                    evidence=match["excerpt"],
                    recommendation=match["advice"],
                )
            )
    findings.sort(key=lambda f: -SEVERITY_RANK[f.severity])
    return findings


def to_public(findings: list[FindingCreate]) -> list[FindingPublic]:
    """Give unsaved findings temporary ids so that they can be exported as SARIF."""
    return [
        FindingPublic(**f.model_dump(), id=index, report_id=0, status=FindingStatus.OPEN)
        for index, f in enumerate(findings, start=1)
    ]
