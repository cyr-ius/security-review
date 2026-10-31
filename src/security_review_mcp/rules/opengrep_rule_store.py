"""Safe file-backed management of administrator-owned OpenGrep YAML rules."""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from ..config import get_settings

logger = logging.getLogger(__name__)
RULE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}$")
YAML_RULE_ID = re.compile(r"(?m)^\s*-\s*id:\s*['\"]?([a-zA-Z0-9][a-zA-Z0-9._-]{2,79})['\"]?\s*$")
MAX_RULE_CHARS = 262_144


def rules_dir() -> Path:
    """Return the configured rules directory, creating it with restrictive permissions."""
    directory = Path(get_settings().opengrep_rules_dir).expanduser()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory.resolve(strict=True)


def rule_path(rule_id: str) -> Path:
    """Resolve an identifier to a regular YAML file, never a path or symlink."""
    if not RULE_ID.fullmatch(rule_id):
        raise ValueError("Invalid OpenGrep rule identifier")
    path = rules_dir() / f"{rule_id}.yaml"
    if path.is_symlink():
        raise ValueError("Symbolic links are not accepted for OpenGrep rules")
    return path


def _validate_id(rule_id: str, content: str) -> None:
    """Require one rule whose id matches the managed file name."""
    if len(content) > MAX_RULE_CHARS or not content.strip():
        raise ValueError("The YAML rule is empty or exceeds the 256 KiB limit")
    identifiers = YAML_RULE_ID.findall(content)
    if len(identifiers) != 1 or identifiers[0] != rule_id:
        raise ValueError("Each file must contain one rule and its YAML id must match the file id")


def validate_rule(rule_id: str, content: str) -> str:
    """Validate the rule with the configured OpenGrep executable."""
    _validate_id(rule_id, content)
    binary = shutil.which(get_settings().opengrep_binary)
    if binary is None:
        raise RuntimeError("The configured OpenGrep executable is unavailable")
    try:
        with tempfile.TemporaryDirectory(prefix="secreview-opengrep-validate-") as temporary:
            source = Path(temporary) / "rule.yaml"
            source.write_text(content, encoding="utf-8")
            result = subprocess.run(
                [binary, "validate", str(source)],
                cwd=temporary,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=get_settings().opengrep_timeout_seconds,
                check=False,
                env={
                    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                    "HOME": temporary,
                    "NO_COLOR": "1",
                },
            )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("OpenGrep rule validation exceeded its time limit") from exc
    except OSError as exc:
        logger.warning("OpenGrep rule validation could not start: %s", type(exc).__name__)
        raise RuntimeError("Could not run OpenGrep rule validation") from exc
    output = (result.stdout + "\n" + result.stderr).strip()[-4000:]
    if result.returncode != 0:
        raise ValueError(output or "OpenGrep rejected the YAML rule")
    return output or "Configuration is valid"


def list_rules() -> list[dict[str, str]]:
    """List regular YAML rule files in the configured directory."""
    result: list[dict[str, str]] = []
    directory = rules_dir()
    for path in sorted((*directory.glob("*.yaml"), *directory.glob("*.yml"))):
        if path.is_symlink() or not path.is_file() or not RULE_ID.fullmatch(path.stem):
            continue
        try:
            stat = path.stat()
            result.append({
                "id": path.stem,
                "content": path.read_text(encoding="utf-8"),
                "updated_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
            })
        except (OSError, UnicodeError):
            logger.warning("Could not read OpenGrep rule file %s", path.name)
    return result


def get_rule(rule_id: str) -> dict[str, str]:
    """Read one YAML rule file."""
    path = rule_path(rule_id)
    if not path.is_file():
        path = path.with_suffix(".yml")
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError("OpenGrep rule not found")
    stat = path.stat()
    return {
        "id": rule_id,
        "content": path.read_text(encoding="utf-8"),
        "updated_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
    }


def save_rule(rule_id: str, content: str, *, create: bool) -> dict[str, str]:
    """Validate and atomically create or replace one YAML rule file."""
    path = rule_path(rule_id)
    validate_rule(rule_id, content)
    if create and (path.exists() or path.with_suffix(".yml").exists()):
        raise FileExistsError("OpenGrep rule already exists")
    if not create and not path.is_file():
        path = path.with_suffix(".yml")
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError("OpenGrep rule not found")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".opengrep-", suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return get_rule(rule_id)


def delete_rule(rule_id: str) -> None:
    """Delete one managed YAML rule file."""
    path = rule_path(rule_id)
    if not path.is_file():
        path = path.with_suffix(".yml")
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError("OpenGrep rule not found")
    path.unlink()
