"""OpenGrep YAML rules stored in the database, managed by the administrators.

The database is the source of the rules (table ``OpenGrepRule``), like the internal rules: every
Controller replica sees the same rules, and nothing is lost with the container. OpenGrep only
reads files, so each process that runs it writes a copy of the rules into its working directory
(SECREVIEW_OPENGREP_RULES_DIR, a cache, see engines.opengrep_snapshots): the Controller server
from the database (local_snapshot), a scan engine from the REST API of the Controller server.

The default rules shipped with the package (``rules/opengrep/<language>/*.yaml``) are copied
into the database at the start of the Controller server (seed_defaults): a new rule is added
and a rule left as installed is updated, but a rule edited or deleted by an administrator is
left alone (``DefaultSeed`` of kind "opengrep" keeps the digest of each version installed). At
its first start after an upgrade, the Controller server imports the rule files of an existing
rules directory once, with the manifest of the default rules installed there.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, select

from ..config import get_settings
from ..engines.opengrep import OpenGrepError, subprocess_env
from ..engines.opengrep_snapshots import RuleSnapshots, SnapshotChangedError, remove
from ..storage.database import session_scope
from ..storage.models import DefaultSeed, OpenGrepRule, utcnow

logger = logging.getLogger(__name__)
RULE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}$")
# Blanks limited to the current line: \s would also match newlines, in quadratic time (ReDoS)
YAML_RULE_ID = re.compile(
    r"(?m)^[ \t]*-[ \t]*id:[ \t]*['\"]?([a-zA-Z0-9][a-zA-Z0-9._-]{2,79})['\"]?[ \t]*$"
)
MAX_RULE_CHARS = 262_144
# Rules installed at most: the bound of the manifest the scan engines download (MAX_ENGINE_RULES)
MAX_RULES = 5000
# Default rules shipped with the package (one sub-directory per language), copied into the
# database at the start of the Controller server, or by the opengrep command
BUNDLED_DIR = Path(__file__).parent / "opengrep"
# Kind of the DefaultSeed rows of the default OpenGrep rules
SEED_KIND = "opengrep"
# Digests of the default rules installed in a rules directory by the versions that kept the rules
# in files: read once, when the files of that directory are imported
LEGACY_MANIFEST_NAME = ".secreview-default-rules.json"


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
    """Contents of the default rules shipped with the package and of the installed rules, by id."""
    known = {
        path.stem: path.read_text(encoding="utf-8")
        for files in bundled_rules().values()
        for path in files
    }
    known.update(installed_rules())
    return known


def installed_rules() -> dict[str, str]:
    """Contents of the installed rules, by id."""
    with session_scope() as session:
        rows = session.exec(select(OpenGrepRule.id, OpenGrepRule.content)).all()
    return dict(rows)


def manifest() -> dict[str, str]:
    """SHA-256 of each installed rule, by id: what a copy of the rules is compared with."""
    with session_scope() as session:
        rows = session.exec(select(OpenGrepRule.id, OpenGrepRule.digest)).all()
    return dict(rows)


def contents(ids: list[str]) -> dict[str, str]:
    """Contents of the installed rules ``ids`` (a rule deleted meanwhile is left out)."""
    if not ids:
        return {}
    with session_scope() as session:
        rows = session.exec(
            select(OpenGrepRule.id, OpenGrepRule.content).where(col(OpenGrepRule.id).in_(ids))
        ).all()
    return dict(rows)


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


def _public(row: OpenGrepRule) -> dict[str, str]:
    """The fields of a rule returned to the web interface."""
    return {"id": row.id, "content": row.content, "updated_at": row.updated_at.isoformat()}


def list_rules() -> list[dict[str, str]]:
    """List the installed rules, by id."""
    with session_scope() as session:
        rows = session.exec(select(OpenGrepRule).order_by(col(OpenGrepRule.id))).all()
        return [_public(row) for row in rows]


def get_rule(rule_id: str) -> dict[str, str]:
    """Read one installed rule.

    Raises:
        ValueError: If the identifier is invalid.
        FileNotFoundError: If no rule has this id.
    """
    _check_id(rule_id)
    with session_scope() as session:
        row = session.get(OpenGrepRule, rule_id)
        if row is None:
            raise FileNotFoundError("OpenGrep rule not found")
        return _public(row)


def save_rule(
    rule_id: str, content: str, *, create: bool, session: Session | None = None
) -> dict[str, str]:
    """Validate a rule with OpenGrep, then create or replace it.

    ``session`` stores the rule in the transaction of the caller (an approved proposal).

    Raises:
        ValueError: If the identifier or the rule is invalid, or too many rules are installed.
        FileExistsError: If ``create`` and a rule has this id.
        FileNotFoundError: If not ``create`` and no rule has this id.
        RuntimeError: If OpenGrep is unavailable.
    """
    _check_id(rule_id)
    validate_rule(rule_id, content)
    if session is not None:
        return _store(session, rule_id, content, create)
    try:
        with session_scope() as own:
            return _store(own, rule_id, content, create)
    except IntegrityError as exc:
        # Created at the same time by another request
        raise FileExistsError("OpenGrep rule already exists") from exc


def _store(session: Session, rule_id: str, content: str, create: bool) -> dict[str, str]:
    """Create or replace a validated rule in ``session``."""
    row = session.get(OpenGrepRule, rule_id)
    if create and row is not None:
        raise FileExistsError("OpenGrep rule already exists")
    if not create and row is None:
        raise FileNotFoundError("OpenGrep rule not found")
    if row is None:
        if session.exec(select(func.count()).select_from(OpenGrepRule)).one() >= MAX_RULES:
            raise ValueError(f"Too many OpenGrep rules: the limit is {MAX_RULES}")
        row = OpenGrepRule(id=rule_id, content=content, digest=_digest(content))
    else:
        row.content, row.digest, row.updated_at = content, _digest(content), utcnow()
    session.add(row)
    session.flush()
    return _public(row)


def delete_rule(rule_id: str) -> None:
    """Delete one installed rule.

    Raises:
        ValueError: If the identifier is invalid.
        FileNotFoundError: If no rule has this id.
    """
    _check_id(rule_id)
    with session_scope() as session:
        row = session.get(OpenGrepRule, rule_id)
        if row is None:
            raise FileNotFoundError("OpenGrep rule not found")
        session.delete(row)


def _check_id(rule_id: str) -> None:
    if not RULE_ID.fullmatch(rule_id):
        raise ValueError("Invalid OpenGrep rule identifier")


# ── Default rules ────────────────────────────────────────────────────────────


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
    """Copy the bundled default rules into the database.

    A rule that already exists is kept (an administrator may have edited it) unless
    ``overwrite`` is set. The rules are checked by the test suite, so OpenGrep is not needed.
    """
    result: dict[str, list[str]] = {"installed": [], "replaced": [], "skipped": []}
    with session_scope() as session:
        seeds = _seeds(session)
        for rule_id, content in _bundled_contents(languages).items():
            row = session.get(OpenGrepRule, rule_id)
            if row is not None and not overwrite:
                if row.content == content:
                    _record_seed(session, seeds, rule_id, content)
                result["skipped"].append(rule_id)
                continue
            _write(session, rule_id, content, row)
            _record_seed(session, seeds, rule_id, content)
            result["installed" if row is None else "replaced"].append(rule_id)
    return result


def seed_defaults() -> dict[str, list[str]]:
    """Bring the database up to date with the bundled default rules, at start-up.

    Like the default TOML rules: a new rule is installed and a rule left as installed is
    updated, but a rule edited or deleted by an administrator is left alone, and a default rule
    no longer shipped is deleted unless it was edited. The first time, the rule files of the
    rules directory of a previous version are imported first (see import_directory). Several
    replicas may start at the same time: the loser of a concurrent insert retries once.
    """
    for attempt in range(2):
        try:
            with session_scope() as session:
                return _seed(session)
        except IntegrityError:
            if attempt:
                raise
    raise AssertionError("unreachable")


def _seed(session: Session) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {
        "imported": [],
        "installed": [],
        "updated": [],
        "kept": [],
        "removed": [],
    }
    seeds = _seeds(session)
    if not seeds and not session.exec(select(func.count()).select_from(OpenGrepRule)).one():
        result["imported"] = import_directory(session, seeds)
    bundled = _bundled_contents()
    for rule_id, content in bundled.items():
        new = _digest(content)
        row = session.get(OpenGrepRule, rule_id)
        seed = seeds.get(rule_id)
        if seed is not None and seed.digest == new:
            continue
        if seed is None:
            # Never installed: added, unless a rule already has this id (kept as is)
            replace = row is None
        else:
            # Newer default: replaces the rule only while it still is the previous default
            replace = row is not None and row.digest == seed.digest
        if replace:
            _write(session, rule_id, content, row)
            result["installed" if row is None else "updated"].append(rule_id)
        elif row is not None and row.digest != new:
            result["kept"].append(rule_id)
        _record_seed(session, seeds, rule_id, content)
    for rule_id, seed in seeds.items():
        if rule_id in bundled:
            continue
        # Retired default rule: deleted unless an administrator edited it
        row = session.get(OpenGrepRule, rule_id)
        if row is not None and row.digest == seed.digest:
            session.delete(row)
            result["removed"].append(rule_id)
        session.delete(seed)
    return result


def import_directory(session: Session, seeds: dict[str, DefaultSeed]) -> list[str]:
    """Import the rule files of SECREVIEW_OPENGREP_RULES_DIR, where the previous versions kept
    the rules, and the digests of the default rules they had installed there.

    Only regular ``<id>.yaml`` and ``<id>.yml`` files directly in the directory (a ``.yaml``
    file wins), holding one rule with that id; the files are left in place. A default rule
    deleted by an administrator is recorded as deleted, so that it is not installed again.
    """
    directory = Path(get_settings().opengrep_rules_dir).expanduser()
    if directory.is_symlink() or not directory.is_dir():
        return []
    files: dict[str, str] = {}
    for path in (*sorted(directory.glob("*.yml")), *sorted(directory.glob("*.yaml"))):
        if path.is_symlink() or not path.is_file() or not RULE_ID.fullmatch(path.stem):
            continue
        try:
            # UTF-8 takes at most 4 bytes per character: never read a file far above the bound
            if path.stat().st_size > MAX_RULE_CHARS * 4:
                raise ValueError("above 256 KiB")
            content = path.read_text(encoding="utf-8")
            check_rule_file(path.stem, content)
        except (OSError, UnicodeError, ValueError) as exc:
            logger.warning("Not importing the OpenGrep rule file %s: %s", path.name, exc)
            continue
        files[path.stem] = content
    for rule_id, content in list(files.items())[:MAX_RULES]:
        _write(session, rule_id, content, None)
    for rule_id, digest in _read_legacy_manifest(directory).items():
        seed = DefaultSeed(kind=SEED_KIND, key=rule_id, digest=digest)
        session.add(seed)
        seeds[rule_id] = seed
    session.flush()
    if files:
        logger.info(
            "Imported %d OpenGrep rule file(s) of %s into the database: the files are no longer "
            "read and may be deleted",
            len(files),
            directory,
        )
    return sorted(files)


def _seeds(session: Session) -> dict[str, DefaultSeed]:
    """The default rules installed, by id."""
    rows = session.exec(select(DefaultSeed).where(DefaultSeed.kind == SEED_KIND)).all()
    return {seed.key: seed for seed in rows}


def _record_seed(
    session: Session, seeds: dict[str, DefaultSeed], rule_id: str, content: str
) -> None:
    """Record ``content`` as the version of the default rule ``rule_id`` installed."""
    seed = seeds.get(rule_id)
    if seed is None:
        seed = DefaultSeed(kind=SEED_KIND, key=rule_id, digest=_digest(content))
        seeds[rule_id] = seed
    else:
        seed.digest, seed.seeded_at = _digest(content), utcnow()
    session.add(seed)


def _bundled_contents(languages: list[str] | None = None) -> dict[str, str]:
    """Contents of the bundled default rules, by id, each checked."""
    result: dict[str, str] = {}
    for files in bundled_rules(languages).values():
        for source in files:
            content = source.read_text(encoding="utf-8")
            check_rule_file(source.stem, content)
            result[source.stem] = content
    return result


def _write(session: Session, rule_id: str, content: str, row: OpenGrepRule | None) -> None:
    """Store a rule already checked (a default or imported rule: no OpenGrep validation)."""
    if row is None:
        row = OpenGrepRule(id=rule_id, content=content, digest=_digest(content))
    else:
        row.content, row.digest, row.updated_at = content, _digest(content), utcnow()
    session.add(row)


def _digest(content: str) -> str:
    """SHA-256 of a rule, as in the manifest of the rules."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _read_legacy_manifest(directory: Path) -> dict[str, str]:
    """Digests of the default rules installed in a rules directory (empty when unreadable)."""
    path = directory / LEGACY_MANIFEST_NAME
    if path.is_symlink() or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError, UnicodeError, json.JSONDecodeError:
        logger.warning("Ignoring the unreadable OpenGrep default rules manifest")
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        key: value
        for key, value in data.items()
        if isinstance(key, str)
        and isinstance(value, str)
        and RULE_ID.fullmatch(key)
        and re.fullmatch(r"[0-9a-f]{64}", value)
    }


# ── Copy of the rules for OpenGrep on the Controller server ──────────────────

# Snapshots of this process, by SECREVIEW_OPENGREP_RULES_DIR
_snapshots: dict[Path, RuleSnapshots] = {}
_snapshots_lock = threading.Lock()


def _local_snapshots() -> RuleSnapshots:
    """The snapshots of this process, in a directory of its own under
    SECREVIEW_OPENGREP_RULES_DIR (deleted when the process exits): the directory may be shared
    by several processes without them deleting the copy of another."""
    base = Path(get_settings().opengrep_rules_dir).expanduser()
    with _snapshots_lock:
        snapshots = _snapshots.get(base)
        if snapshots is None:
            name = re.sub(r"[^A-Za-z0-9.-]", "-", socket.gethostname())[:60]
            directory = base / f"controller-{name}-{os.getpid()}"
            snapshots = _snapshots[base] = RuleSnapshots(directory)
            atexit.register(remove, directory)
        return snapshots


@contextmanager
def local_snapshot() -> Iterator[Path]:
    """Copy the installed rules on disk, if they changed, and hold that copy for one OpenGrep
    scan of the Controller server.

    Raises:
        OpenGrepError: If the copy cannot be written.
    """
    snapshots = _local_snapshots()
    for attempt in range(2):
        try:
            fetched, removed = snapshots.update(manifest(), contents)
            if fetched or removed:
                logger.info(
                    "OpenGrep rules copied for the scans: %d written, %d removed", fetched, removed
                )
            break
        except SnapshotChangedError:
            # A rule changed during the copy: once more with the new manifest
            if attempt:
                raise
        except OSError as exc:
            snapshots.reset()
            raise OpenGrepError(
                f"Could not copy the OpenGrep rules into SECREVIEW_OPENGREP_RULES_DIR: "
                f"{type(exc).__name__}"
            ) from exc
    with snapshots.use() as path:
        assert path is not None
        yield path
