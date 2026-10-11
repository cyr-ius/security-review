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
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .checklists import CheckItem
from .models import Severity
from .scanner import SUPPORTED_LANGUAGES, Rule

logger = logging.getLogger(__name__)

MAX_PACK_BYTES = 256 * 1024
MAX_PATTERN_CHARS = 500
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
