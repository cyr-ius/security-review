"""Validate internal rules and parse rule packs (TOML) imported into the database.

A rule pack is the TOML exchange format of ``security-review-controller rules import|export``. The
default rules and checklists shipped with the package (``default_rules.toml``, see
``default_content``) use the same format::

    disabled_rules = ["PY-008"]            # rules to switch off (built-in or custom)

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

A rule with the id of a default rule replaces it. Invalid entries are reported in
``LoadResult.errors``. Rules are trusted administrator content: a pathological regex can slow
the scanner down, so patterns with nested quantifiers are rejected.
"""

import functools
import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources

from ..storage.models import Severity
from .checklists import CheckItem
from .scanner import SUPPORTED_LANGUAGES, Rule

DEFAULT_RULES_FILE = "default_rules.toml"
MAX_PACK_BYTES = 256 * 1024
MAX_PATTERN_CHARS = 500
MAX_ID_CHARS = 50
MAX_TITLE_CHARS = 300
MAX_TEXT_CHARS = 5000
_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_DOMAIN_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")
# Heuristic for catastrophic backtracking: a quantified group that itself contains a quantifier
_NESTED_QUANTIFIER_RE = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")


@dataclass
class LoadResult:
    """Content read from a rule pack or from the database."""

    rules: list[Rule] = field(default_factory=list)
    checklist: dict[str, list[CheckItem]] = field(default_factory=dict)
    disabled_rules: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)


def validate_id(value: str) -> str:
    """Return a rule or checklist item id, or raise ValueError when it is malformed."""
    if len(value) > MAX_ID_CHARS or not _ID_RE.match(value):
        raise ValueError(f"invalid id '{value[:MAX_ID_CHARS]}' (expected e.g. ACME-001)")
    return value


def _cwe(entry: dict) -> str:
    """Return the normalized optional CWE of an entry."""
    cwe = str(entry.get("cwe", "")).strip().upper()
    if cwe and not _CWE_RE.match(cwe):
        raise ValueError(f"invalid cwe '{cwe[:20]}' (expected CWE-123)")
    return cwe


def _text(entry: dict, key: str, limit: int, required: bool = True) -> str:
    """Return a stripped text field, bounded in size."""
    value = str(entry.get(key, "")).strip()
    if required and not value:
        raise ValueError(f"missing {key}")
    if len(value) > limit:
        raise ValueError(f"{key} longer than {limit} characters")
    return value


def parse_rule(entry: dict) -> Rule:
    """Validate one rule entry and build the Rule.

    Raises:
        ValueError: With a message that explains what is wrong.
    """
    rule_id = validate_id(str(entry.get("id", "")))
    title = _text(entry, "title", MAX_TITLE_CHARS)
    try:
        severity = Severity(str(entry.get("severity", "")).lower())
    except ValueError as exc:
        raise ValueError(f"invalid severity '{entry.get('severity')}'") from exc
    cwe = _cwe(entry)

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
        advice=_text(entry, "advice", MAX_TEXT_CHARS, required=False),
    )


def parse_check_item(entry: dict) -> tuple[str, CheckItem]:
    """Validate one checklist entry and return ``(domain, item)``."""
    domain = str(entry.get("domain", "")).lower()
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"invalid domain '{domain[:31]}' (lowercase letters, digits, - and _)")
    item_id = validate_id(str(entry.get("id", "")))
    title = _text(entry, "title", MAX_TITLE_CHARS)
    what = _text(entry, "what_to_look_for", MAX_TEXT_CHARS)
    return domain, CheckItem(item_id, title, what, _cwe(entry))


def rule_entry(rule: Rule) -> dict:
    """Return the pack representation of a validated rule (inverse of parse_rule)."""
    return {
        "id": rule.id,
        "title": rule.title,
        "severity": rule.severity.value,
        "cwe": rule.cwe,
        "languages": sorted(rule.languages),
        "pattern": rule.pattern.pattern,
        "advice": rule.advice,
        "ignore_case": bool(rule.pattern.flags & re.IGNORECASE),
    }


def parse_pack(text: str, name: str) -> LoadResult:
    """Parse a TOML rule pack; every invalid entry is reported in ``errors`` with its place."""
    result = LoadResult()
    if len(text.encode("utf-8")) > MAX_PACK_BYTES:
        result.errors.append(f"{name}: file larger than {MAX_PACK_BYTES} bytes")
        return result
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        result.errors.append(f"{name}: {exc}")
        return result
    except RecursionError:
        result.errors.append(f"{name}: values nested too deeply")
        return result

    disabled = data.get("disabled_rules", [])
    if not isinstance(disabled, list):
        result.errors.append(f"{name}: disabled_rules must be a list")
    else:
        for item in disabled:
            try:
                result.disabled_rules.add(validate_id(str(item)))
            except ValueError as exc:
                result.errors.append(f"{name}: disabled_rules: {exc}")

    for key in ("rules", "checklist"):
        if not isinstance(data.get(key, []), list):
            result.errors.append(f"{name}: {key} must be an array of tables")
            data[key] = []

    for index, entry in enumerate(data.get("rules", []), start=1):
        try:
            rule = parse_rule(entry)
        except (ValueError, TypeError, AttributeError) as exc:
            result.errors.append(f"{name}: rules[{index}]: {exc}")
            continue
        # A later entry with the same id replaces the earlier one
        result.rules = [existing for existing in result.rules if existing.id != rule.id]
        result.rules.append(rule)

    for index, entry in enumerate(data.get("checklist", []), start=1):
        try:
            domain, item = parse_check_item(entry)
        except (ValueError, TypeError, AttributeError) as exc:
            result.errors.append(f"{name}: checklist[{index}]: {exc}")
            continue
        items = result.checklist.setdefault(domain, [])
        items[:] = [existing for existing in items if existing.id != item.id]
        items.append(item)
    return result


@functools.cache
def default_content() -> LoadResult:
    """Return the default rules and checklists shipped with the package (``default_rules.toml``).

    Raises:
        RuntimeError: If the shipped file is invalid (a packaging error, never user input).
    """
    text = resources.files(__package__).joinpath(DEFAULT_RULES_FILE).read_text(encoding="utf-8")
    result = parse_pack(text, DEFAULT_RULES_FILE)
    if result.errors:
        raise RuntimeError("Invalid default rules: " + "; ".join(result.errors[:5]))
    return result
