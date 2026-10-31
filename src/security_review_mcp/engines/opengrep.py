"""OpenGrep adapter for controller-side whole-codebase scans.

The adapter writes the already bounded source payload to a private temporary workspace,
executes OpenGrep without a shell, and returns normalized matches. It never executes scanned
source files. Rule packs are supplied by the operator in the configured rules directory.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from ..config import get_settings
from ..rules.scanner import redact_secrets

logger = logging.getLogger(__name__)

_SEVERITY = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "INVENTORY": "info",
}
_CWE = re.compile(r"CWE-?([0-9]+)", re.IGNORECASE)


class OpenGrepError(RuntimeError):
    """OpenGrep could not complete a scan or returned invalid output."""


def _safe_relative_path(value: str) -> PurePosixPath:
    """Validate a client-provided source path before writing it into the workspace."""
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("Invalid source path in code scan")
    if path.parts[0].endswith(":"):
        raise ValueError("Invalid source path in code scan")
    return path


def _cwe(metadata: Any) -> str | None:
    """Extract one CWE identifier from OpenGrep rule metadata."""
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("cwe")
    values = value if isinstance(value, list) else [value]
    for item in values:
        if isinstance(item, str):
            match = _CWE.search(item)
            if match:
                return f"CWE-{match.group(1)}"
    return None


def _normalize_result(item: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Convert one OpenGrep JSON result to the internal per-file match format."""
    path = item.get("path")
    extra = item.get("extra")
    start = item.get("start")
    end = item.get("end")
    if not isinstance(path, str) or not isinstance(extra, dict) or not isinstance(start, dict):
        return None
    line = start.get("line")
    if not isinstance(line, int) or line < 1:
        return None
    message = extra.get("message")
    check_id = item.get("check_id")
    if not isinstance(message, str) or not isinstance(check_id, str):
        return None
    severity_name = str(extra.get("severity", "WARNING")).upper()
    severity = _SEVERITY.get(severity_name, "medium")
    metadata = extra.get("metadata")
    lines = extra.get("lines")
    evidence = redact_secrets(lines) if isinstance(lines, str) else ""
    end_line = end.get("line") if isinstance(end, dict) else line
    if not isinstance(end_line, int) or end_line < line:
        end_line = line
    return path, {
        "title": message[:200],
        "severity": severity,
        "rule_id": f"OPENGREP:{check_id}"[:60],
        "cwe": _cwe(metadata),
        "line": line,
        "line_end": end_line,
        "excerpt": evidence[:2000],
        "advice": "Review the matched code and apply the remediation described by the OpenGrep rule.",
    }


def scan_files(files: list[tuple[str, str]]) -> dict[str, list[dict[str, Any]]]:
    """Run OpenGrep on bounded source files and return matches indexed by relative path.

    Raises:
        OpenGrepError: If enabled but the executable, rules or scan output are unavailable.
    """
    settings = get_settings()
    if not settings.opengrep_enabled:
        return {}
    binary = shutil.which(settings.opengrep_binary) if os.sep not in settings.opengrep_binary else settings.opengrep_binary
    if not binary or not Path(binary).is_file():
        raise OpenGrepError("OpenGrep is enabled but its executable is unavailable")
    rules_dir = Path(settings.opengrep_rules_dir)
    if not rules_dir.is_dir() or not any(rules_dir.rglob("*.y*ml")):
        raise OpenGrepError("OpenGrep is enabled but no YAML rules are installed")

    matches: dict[str, list[dict[str, Any]]] = {}
    try:
        with tempfile.TemporaryDirectory(prefix="secreview-opengrep-") as temporary:
            workspace = Path(temporary) / "source"
            workspace.mkdir(mode=0o700)
            for name, content in files:
                relative = _safe_relative_path(name)
                destination = workspace.joinpath(*relative.parts)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                destination.write_text(content, encoding="utf-8", errors="replace")
            command = [binary, "scan", "--json", "--config", str(rules_dir), str(workspace)]
            try:
                process = subprocess.run(
                    command,
                    cwd=workspace,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=settings.opengrep_timeout_seconds,
                    check=False,
                    env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": temporary, "NO_COLOR": "1"},
                )
            except subprocess.TimeoutExpired as exc:
                raise OpenGrepError("OpenGrep scan exceeded its configured time limit") from exc
            if process.returncode not in (0, 1):
                logger.warning("OpenGrep exited with status %s", process.returncode)
                raise OpenGrepError("OpenGrep scan failed; see controller logs")
            try:
                payload = json.loads(process.stdout)
            except json.JSONDecodeError as exc:
                raise OpenGrepError("OpenGrep returned invalid JSON") from exc
            results = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(results, list):
                raise OpenGrepError("OpenGrep JSON output has no results list")
            for item in results:
                if not isinstance(item, dict):
                    continue
                normalized = _normalize_result(item)
                if normalized is None:
                    continue
                result_path, finding = normalized
                absolute = Path(result_path)
                try:
                    relative_path = absolute.resolve().relative_to(workspace.resolve()).as_posix()
                except (OSError, ValueError):
                    continue
                matches.setdefault(relative_path, []).append(finding)
    except (OSError, ValueError) as exc:
        if isinstance(exc, OpenGrepError):
            raise
        raise OpenGrepError("Could not prepare the OpenGrep scan workspace") from exc
    return matches
