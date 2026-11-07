"""Safe file-backed management of administrator-owned OpenGrep YAML rules."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from ..config import get_settings
from ..engines.opengrep import subprocess_env

logger = logging.getLogger(__name__)
RULE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}$")
# Blanks limited to the current line: \s would also match newlines, in quadratic time (ReDoS)
YAML_RULE_ID = re.compile(
    r"(?m)^[ \t]*-[ \t]*id:[ \t]*['\"]?([a-zA-Z0-9][a-zA-Z0-9._-]{2,79})['\"]?[ \t]*$"
)
MAX_RULE_CHARS = 262_144
# Default rules shipped with the package (one sub-directory per language), installed at the
# start of the Controller server while OpenGrep is enabled, or by the opengrep command
BUNDLED_DIR = Path(__file__).parent / "opengrep"
# Digests of the installed default rules: tells an untouched rule from an edited or deleted one
MANIFEST_NAME = ".secreview-default-rules.json"


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


def check_rule_file(rule_id: str, content: str) -> None:
    """Require one rule whose id matches the managed file name."""
    if len(content) > MAX_RULE_CHARS or not content.strip():
        raise ValueError("The YAML rule is empty or exceeds the 256 KiB limit")
    identifiers = YAML_RULE_ID.findall(content)
    if len(identifiers) != 1 or identifiers[0] != rule_id:
        raise ValueError("Each file must contain one rule and its YAML id must match the file id")


# Keys that do not change what a rule matches, ignored with their sub-tree by detection_signature
_DESCRIPTIVE_KEYS = frozenset({"id", "message", "metadata", "severity", "fix"})
# Indentation, optional list dash, key and value of a "key: value" YAML line
_YAML_KEY = re.compile(r"^([ \t]*(?:-[ \t]+)?)([A-Za-z0-9_-]+):(.*)$")


def detection_signature(content: str) -> str:
    """Digest of what a YAML rule matches, to tell two copies of the same rule apart.

    The lines of the rule are kept without its id, message, metadata, severity and fix (with
    their nested lines), comments, blank lines, indentation, repeated blanks and the quotes
    around a value: two rules with the same signature detect the same code.
    """
    lines: list[str] = []
    skip_deeper_than: int | None = None
    for raw in content.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" \t"))
        if skip_deeper_than is not None:
            if indent > skip_deeper_than:
                continue
            skip_deeper_than = None
        match = _YAML_KEY.match(raw)
        if match and match.group(2) in _DESCRIPTIVE_KEYS:
            # Nested lines are deeper than the key itself (after a list dash)
            skip_deeper_than = len(match.group(1))
            continue
        if match:
            value = match.group(3).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            stripped = f"{match.group(1).strip()} {match.group(2)}: {value}".strip()
        lines.append(" ".join(stripped.split()))
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def known_rules() -> dict[str, str]:
    """Contents of the default rules shipped with the package and of the installed rules, by id.

    Unlike rules_dir, the rules directory is not created: the MCP server may not see it.
    """
    known = {
        path.stem: path.read_text(encoding="utf-8")
        for files in bundled_rules().values()
        for path in files
    }
    directory = Path(get_settings().opengrep_rules_dir).expanduser()
    if directory.is_symlink() or not directory.is_dir():
        return known
    for path in sorted((*directory.glob("*.yaml"), *directory.glob("*.yml"))):
        if path.is_symlink() or not path.is_file() or not RULE_ID.fullmatch(path.stem):
            continue
        try:
            known[path.stem] = path.read_text(encoding="utf-8")
        except OSError, UnicodeError:
            logger.warning("Could not read OpenGrep rule file %s", path.name)
    return known


def validate_rule(rule_id: str, content: str) -> str:
    """Validate the rule with the configured OpenGrep executable."""
    check_rule_file(rule_id, content)
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
                env=subprocess_env(temporary),
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
            result.append(
                {
                    "id": path.stem,
                    "content": path.read_text(encoding="utf-8"),
                    "updated_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                }
            )
        except OSError, UnicodeError:
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
    _write_atomic(path, content)
    return get_rule(rule_id)


def bundled_rules(languages: list[str] | None = None) -> dict[str, list[Path]]:
    """Return the default rule files shipped with the package, by language directory.

    Raises:
        ValueError: If a requested language has no bundled rules.
    """
    available = {
        directory.name: sorted(directory.glob("*.yaml"))
        for directory in sorted(BUNDLED_DIR.iterdir())
        if directory.is_dir()
    }
    if languages:
        unknown = sorted(set(languages) - set(available))
        if unknown:
            raise ValueError(
                f"No bundled OpenGrep rules for: {', '.join(unknown)} "
                f"(available: {', '.join(available)})"
            )
        available = {name: files for name, files in available.items() if name in languages}
    return available


def install_bundled(
    languages: list[str] | None = None, *, overwrite: bool = False
) -> dict[str, list[str]]:
    """Copy the bundled default rules into the rules directory.

    A rule file that already exists is kept (an administrator may have edited it) unless
    ``overwrite`` is set. The rules are checked by the test suite, so OpenGrep is not needed.
    """
    result: dict[str, list[str]] = {"installed": [], "replaced": [], "skipped": []}
    manifest = _read_manifest()
    for files in bundled_rules(languages).values():
        for source in files:
            content = source.read_text(encoding="utf-8")
            check_rule_file(source.stem, content)
            path = _installed_path(source.stem)
            current = path.read_text(encoding="utf-8") if path.is_file() else None
            if current is not None and not overwrite:
                if current == content:
                    manifest[source.stem] = _digest(content)
                result["skipped"].append(source.stem)
                continue
            _write_atomic(path, content)
            manifest[source.stem] = _digest(content)
            result["installed" if current is None else "replaced"].append(source.stem)
    _write_manifest(manifest)
    return result


def sync_bundled() -> dict[str, list[str]]:
    """Bring the rules directory up to date with the bundled default rules, at start-up.

    Like the default TOML rules: a new rule is installed and a rule left as installed is
    updated, but a rule edited or deleted by an administrator is left alone. The digest of
    each installed version is kept in a manifest of the rules directory (MANIFEST_NAME).
    """
    result: dict[str, list[str]] = {"installed": [], "updated": [], "kept": []}
    manifest = _read_manifest()
    for files in bundled_rules().values():
        for source in files:
            rule_id = source.stem
            content = source.read_text(encoding="utf-8")
            check_rule_file(rule_id, content)
            path = _installed_path(rule_id)
            recorded = manifest.get(rule_id)
            if not path.is_file():
                if recorded is None:  # never installed; recorded and missing: deleted
                    _write_atomic(path, content)
                    manifest[rule_id] = _digest(content)
                    result["installed"].append(rule_id)
                continue
            current = path.read_text(encoding="utf-8")
            if current == content:
                manifest[rule_id] = _digest(content)
            elif recorded == _digest(current):
                _write_atomic(path, content)
                manifest[rule_id] = _digest(content)
                result["updated"].append(rule_id)
            else:
                result["kept"].append(rule_id)
    _write_manifest(manifest)
    return result


def _installed_path(rule_id: str) -> Path:
    """Path of an installed rule: its ``.yaml`` file, or an existing ``.yml`` one."""
    path = rule_path(rule_id)
    legacy = path.with_suffix(".yml")
    if not path.exists() and legacy.exists():
        if legacy.is_symlink():
            raise ValueError("Symbolic links are not accepted for OpenGrep rules")
        return legacy
    return path


def _digest(content: str) -> str:
    """SHA-256 of a rule file, as recorded in the manifest."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _read_manifest() -> dict[str, str]:
    """Digests of the default rules installed in the rules directory (empty when unreadable)."""
    path = rules_dir() / MANIFEST_NAME
    if path.is_symlink() or not path.is_file():
        return {}
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except OSError, UnicodeError, json.JSONDecodeError:
        logger.warning("Ignoring the unreadable OpenGrep default rules manifest")
        return {}
    if not isinstance(manifest, dict):
        return {}
    return {
        key: value
        for key, value in manifest.items()
        if isinstance(key, str) and isinstance(value, str) and RULE_ID.fullmatch(key)
    }


def _write_manifest(manifest: dict[str, str]) -> None:
    """Store the digests of the installed default rules."""
    path = rules_dir() / MANIFEST_NAME
    if path.is_symlink():
        raise ValueError("Symbolic links are not accepted for OpenGrep rules")
    _write_atomic(path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def _write_atomic(path: Path, content: str) -> None:
    """Write a rule file through a temporary file and an atomic replacement (mode 0600)."""
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".opengrep-",
            suffix=".tmp",
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


def delete_rule(rule_id: str) -> None:
    """Delete one managed YAML rule file."""
    path = rule_path(rule_id)
    if not path.is_file():
        path = path.with_suffix(".yml")
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError("OpenGrep rule not found")
    path.unlink()
