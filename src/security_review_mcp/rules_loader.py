"""Load internal rule packs (TOML) so that teams can extend the server without code changes.

A rule pack is a ``*.toml`` file placed in ``SECREVIEW_RULES_DIR``::

    disabled_rules = ["PY-008"]            # built-in rules to switch off

    [[rules]]                              # a scan rule
    id = "ACME-001"
    title = "Direct use of the legacy crypto helper"
    severity = "high"                      # critical | high | medium | low | info
    cwe = "CWE-327"                        # optional
    languages = ["python", "java"]         # or ["*"]
    pattern = '''LegacyCrypto\\.encrypt\\('''
    advice = "Use CryptoService instead."
    ignore_case = true                     # optional (default true)

    [[checklist]]                          # a checklist item (new domains allowed)
    domain = "company"                     # "company" is added to every review prompt
    id = "ACME-CL-01"
    title = "Tenant isolation"
    what_to_look_for = "Every query is filtered by tenant id."
    cwe = "CWE-639"

A rule with the id of a built-in rule replaces it. Invalid entries are skipped and reported in
``LoadResult.errors``; one broken pack never prevents the server from starting.
Rule packs are trusted administrator content: a pathological regex can slow the scanner down.
"""

import logging
import os
import re
import tempfile
import threading
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import tomlkit

from .checklists import CheckItem
from .models import Severity
from .scanner import SUPPORTED_LANGUAGES, Rule

logger = logging.getLogger(__name__)

MAX_PACK_BYTES = 256 * 1024
MAX_PATTERN_CHARS = 500
_management_lock = threading.Lock()
_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_DOMAIN_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")
# Heuristic for catastrophic backtracking: a quantified group that itself contains a quantifier
_NESTED_QUANTIFIER_RE = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")


@dataclass
class LoadResult:
    """Everything read from the rules directory."""

    rules: list[Rule] = field(default_factory=list)
    checklist: dict[str, list[CheckItem]] = field(default_factory=dict)
    disabled_rules: set[str] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    rule_sources: dict[str, str] = field(default_factory=dict)


def _parse_rule(entry: dict) -> Rule:
    """Validate one ``[[rules]]`` entry and build the Rule.

    Raises:
        ValueError: With a message that explains what is wrong.
    """
    rule_id = str(entry.get("id", ""))
    if not _ID_RE.match(rule_id):
        raise ValueError(f"invalid id '{rule_id}' (expected e.g. ACME-001)")
    title = str(entry.get("title", "")).strip()
    if not title:
        raise ValueError("missing title")
    try:
        severity = Severity(str(entry.get("severity", "")).lower())
    except ValueError as exc:
        raise ValueError(f"invalid severity '{entry.get('severity')}'") from exc
    cwe = str(entry.get("cwe", "")).strip().upper()
    if cwe and not _CWE_RE.match(cwe):
        raise ValueError(f"invalid cwe '{cwe}' (expected CWE-123)")

    languages = entry.get("languages", ["*"])
    if not isinstance(languages, list) or not languages:
        raise ValueError("languages must be a non-empty list")
    languages = [str(item).lower() for item in languages]
    unknown = [item for item in languages if item != "*" and item not in SUPPORTED_LANGUAGES]
    if unknown:
        raise ValueError(f"unknown languages {unknown}; supported: {list(SUPPORTED_LANGUAGES)}")

    pattern = str(entry.get("pattern", ""))
    if not pattern:
        raise ValueError("missing pattern")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise ValueError(f"pattern longer than {MAX_PATTERN_CHARS} characters")
    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise ValueError("pattern rejected: nested quantifiers risk catastrophic backtracking")
    flags = re.IGNORECASE if entry.get("ignore_case", True) else 0
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc
    if compiled.search(""):
        raise ValueError("pattern matches the empty string")

    return Rule(
        id=rule_id,
        title=title,
        severity=severity,
        cwe=cwe,
        languages=frozenset(languages),
        pattern=compiled,
        advice=str(entry.get("advice", "")).strip(),
    )


def _parse_check_item(entry: dict) -> tuple[str, CheckItem]:
    """Validate one ``[[checklist]]`` entry."""
    domain = str(entry.get("domain", "")).lower()
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"invalid domain '{domain}' (lowercase letters, digits, - and _)")
    item_id = str(entry.get("id", ""))
    if not _ID_RE.match(item_id):
        raise ValueError(f"invalid id '{item_id}'")
    title = str(entry.get("title", "")).strip()
    what = str(entry.get("what_to_look_for", "")).strip()
    if not title or not what:
        raise ValueError("title and what_to_look_for are required")
    cwe = str(entry.get("cwe", "")).strip().upper()
    if cwe and not _CWE_RE.match(cwe):
        raise ValueError(f"invalid cwe '{cwe}'")
    return domain, CheckItem(item_id, title, what, cwe)


def load_rules_dir(directory: str | Path | None) -> LoadResult:
    """Load every ``*.toml`` pack of a directory (sorted by name; later files win)."""
    result = LoadResult()
    if not directory:
        return result
    path = Path(directory)
    if not path.is_dir():
        result.errors.append(f"rules directory not found: {path}")
        logger.warning("Rules directory not found: %s", path)
        return result

    seen_rules: dict[str, str] = {}
    for file in sorted(path.glob("*.toml")):
        name = file.name
        try:
            if file.stat().st_size > MAX_PACK_BYTES:
                raise ValueError(f"file larger than {MAX_PACK_BYTES} bytes")
            data = tomllib.loads(file.read_text(encoding="utf-8"))
        except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
            result.errors.append(f"{name}: {exc}")
            continue
        result.sources.append(name)

        disabled = data.get("disabled_rules", [])
        if isinstance(disabled, list):
            result.disabled_rules.update(str(item) for item in disabled)
        elif disabled:
            result.errors.append(f"{name}: disabled_rules must be a list")

        for index, entry in enumerate(data.get("rules", []), start=1):
            try:
                rule = _parse_rule(entry)
            except (ValueError, TypeError, AttributeError) as exc:
                result.errors.append(f"{name}: rules[{index}]: {exc}")
                continue
            if rule.id in seen_rules:
                result.errors.append(
                    f"{name}: rule {rule.id} already defined in {seen_rules[rule.id]} (replaced)"
                )
                result.rules = [r for r in result.rules if r.id != rule.id]
            seen_rules[rule.id] = name
            result.rule_sources[rule.id] = name
            result.rules.append(rule)

        for index, entry in enumerate(data.get("checklist", []), start=1):
            try:
                domain, item = _parse_check_item(entry)
            except (ValueError, TypeError, AttributeError) as exc:
                result.errors.append(f"{name}: checklist[{index}]: {exc}")
                continue
            items = result.checklist.setdefault(domain, [])
            items[:] = [existing for existing in items if existing.id != item.id]
            items.append(item)

    for message in result.errors:
        logger.warning("Rule pack problem: %s", message)
    logger.info(
        "Loaded %d custom rules and %d checklist domains from %s",
        len(result.rules),
        len(result.checklist),
        path,
    )
    return result


def _rules_directory(directory: str | Path | None) -> Path:
    """Return the configured rule directory, requiring it to exist for mutations."""
    if not directory:
        raise ValueError("SECREVIEW_RULES_DIR must be configured to manage rules")
    path = Path(directory)
    if not path.is_dir():
        raise ValueError(f"Rules directory does not exist: {path}")
    return path


def _read_document(path: Path):
    """Read a bounded TOML document for a managed mutation."""
    if path.is_symlink():
        raise ValueError(f"Refusing to edit symlinked rule pack: {path.name}")
    if path.stat().st_size > MAX_PACK_BYTES:
        raise ValueError(f"Rule pack is larger than {MAX_PACK_BYTES} bytes: {path.name}")
    try:
        return tomlkit.parse(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, tomlkit.exceptions.TOMLKitError) as exc:
        raise ValueError(f"Cannot edit invalid rule pack {path.name}: {exc}") from exc


def _write_document(path: Path, document) -> None:
    """Atomically replace a rule pack while preserving its permissions and formatting."""
    content = tomlkit.dumps(document)
    if len(content.encode("utf-8")) > MAX_PACK_BYTES:
        raise ValueError(f"Rule pack would exceed {MAX_PACK_BYTES} bytes")
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = temporary.name
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


def _rule_tables(document):
    """Return a pack's array of rule tables, creating it when needed."""
    rules = document.get("rules")
    if rules is None:
        rules = tomlkit.aot()
        document["rules"] = rules
    if not isinstance(rules, list):
        raise ValueError("rules must be an array of tables")
    return rules


def _toml_rule(entry: dict):
    """Build a TOML rule table from already validated fields."""
    table = tomlkit.table()
    for key, value in entry.items():
        table[key] = value
    return table


def create_rule(directory: str | Path | None, entry: dict) -> None:
    """Add a validated rule to the web-managed rule pack."""
    rule = _parse_rule(entry)
    with _management_lock:
        root = _rules_directory(directory)
        loaded = load_rules_dir(root)
        if rule.id in loaded.rule_sources:
            raise ValueError(f"Rule {rule.id} already exists in {loaded.rule_sources[rule.id]}")
        path = root / "web-managed.toml"
        document = _read_document(path) if path.exists() else tomlkit.document()
        if any(item.get("id") == rule.id for item in _rule_tables(document)):
            raise ValueError(f"Rule {rule.id} already exists in {path.name}")
        _rule_tables(document).append(_toml_rule(entry))
        _write_document(path, document)


def update_rule(directory: str | Path | None, rule_id: str, entry: dict) -> None:
    """Update a custom rule in its source pack without changing its id."""
    rule = _parse_rule(entry)
    if rule.id != rule_id:
        raise ValueError("A rule id cannot be changed")
    with _management_lock:
        root = _rules_directory(directory)
        loaded = load_rules_dir(root)
        source = loaded.rule_sources.get(rule_id)
        if source is None:
            raise ValueError(f"Custom rule {rule_id} was not found")
        path = root / source
        document = _read_document(path)
        for index, item in enumerate(_rule_tables(document)):
            if item.get("id") == rule_id:
                document["rules"][index] = _toml_rule(entry)
        _write_document(path, document)


def delete_rule(directory: str | Path | None, rule_id: str) -> None:
    """Remove a custom rule from every pack so an earlier duplicate cannot reappear."""
    with _management_lock:
        root = _rules_directory(directory)
        found = False
        for path in sorted(root.glob("*.toml")):
            if path.is_symlink():
                continue
            document = _read_document(path)
            rules = _rule_tables(document)
            kept = [item for item in rules if item.get("id") != rule_id]
            disabled = document.get("disabled_rules", [])
            kept_disabled = (
                [item for item in disabled if item != rule_id]
                if isinstance(disabled, list)
                else None
            )
            if len(kept) != len(rules):
                found = True
                document["rules"] = tomlkit.aot()
                for item in kept:
                    document["rules"].append(item)
            if kept_disabled is not None and len(kept_disabled) != len(disabled):
                document["disabled_rules"] = kept_disabled
            if len(kept) != len(rules) or (
                kept_disabled is not None and len(kept_disabled) != len(disabled)
            ):
                _write_document(path, document)
        if not found:
            raise ValueError(f"Custom rule {rule_id} was not found")


def set_rule_enabled(directory: str | Path | None, rule_id: str, enabled: bool) -> None:
    """Enable or disable a rule by updating the pack-level disabled_rules list."""
    with _management_lock:
        root = _rules_directory(directory)
        loaded = load_rules_dir(root)
        if rule_id not in loaded.rule_sources:
            raise ValueError(f"Custom rule {rule_id} was not found")
        if (root / loaded.rule_sources[rule_id]).is_symlink():
            raise ValueError("Refusing to edit a symlinked rule pack")
        paths = sorted(root.glob("*.toml"))
        if enabled:
            for path in paths:
                if path.is_symlink():
                    continue
                document = _read_document(path)
                disabled = document.get("disabled_rules", [])
                if not isinstance(disabled, list):
                    raise ValueError(f"disabled_rules must be a list in {path.name}")
                updated = [item for item in disabled if item != rule_id]
                if len(updated) != len(disabled):
                    document["disabled_rules"] = updated
                    _write_document(path, document)
        else:
            path = root / "web-managed.toml"
            document = _read_document(path) if path.exists() else tomlkit.document()
            disabled = document.get("disabled_rules")
            if disabled is None:
                document["disabled_rules"] = [rule_id]
            elif not isinstance(disabled, list):
                raise ValueError("disabled_rules must be a list in web-managed.toml")
            elif rule_id not in disabled:
                disabled.append(rule_id)
            _write_document(path, document)
