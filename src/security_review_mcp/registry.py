"""Active rules and checklists: built-in content merged with the internal rules of the database."""

import logging
import threading
import time
from dataclasses import dataclass

from sqlalchemy.exc import SQLAlchemyError

from . import rule_store
from .checklists import CHECKLISTS, CheckItem
from .rules_loader import LoadResult
from .rules_platform import PLATFORM_RULES
from .scanner import RULES, Rule, scan_content_detailed

logger = logging.getLogger(__name__)

# Checklist domain appended to every review prompt (company-wide requirements)
COMPANY_DOMAIN = "company"
# How often a cached snapshot checks the database revision (changes made by another process)
REFRESH_SECONDS = 5.0

BUILTIN_RULES: tuple[Rule, ...] = RULES + PLATFORM_RULES


@dataclass(frozen=True)
class Snapshot:
    """An immutable view of the merged content (swapped atomically on reload)."""

    rules: tuple[Rule, ...]
    catalog: tuple[Rule, ...]
    custom_rule_ids: frozenset[str]
    disabled_rule_ids: frozenset[str]
    checklists: dict[str, tuple[CheckItem, ...]]
    errors: tuple[str, ...]
    revision: int | None


_lock = threading.Lock()
_snapshot: Snapshot | None = None
_checked_at = 0.0


def _build(loaded: LoadResult, revision: int | None) -> Snapshot:
    """Merge built-in and custom content: a custom id replaces a built-in one."""
    custom_ids = {rule.id for rule in loaded.rules}
    merged = tuple(r for r in BUILTIN_RULES if r.id not in custom_ids) + tuple(loaded.rules)
    active = tuple(r for r in merged if r.id not in loaded.disabled_rules)

    checklists = {domain: list(items) for domain, items in CHECKLISTS.items()}
    for domain, items in loaded.checklist.items():
        existing = checklists.setdefault(domain, [])
        replaced = {item.id for item in items}
        existing[:] = [item for item in existing if item.id not in replaced] + items

    return Snapshot(
        rules=active,
        catalog=merged,
        custom_rule_ids=frozenset(custom_ids),
        disabled_rule_ids=frozenset(loaded.disabled_rules),
        checklists={domain: tuple(items) for domain, items in checklists.items()},
        errors=tuple(loaded.errors),
        revision=revision,
    )


def _load() -> tuple[LoadResult, int | None]:
    """Read the internal rules; an unavailable database leaves the built-in rules only."""
    try:
        loaded, revision = rule_store.load()
    except SQLAlchemyError as exc:
        # The message may contain the database URL: only the error type is reported
        message = f"internal rules unavailable: database error ({type(exc).__name__})"
        logger.warning("%s", message)
        loaded, revision = LoadResult(errors=[message]), None
    for message in loaded.errors:
        logger.warning("Internal rules problem: %s", message)
    return loaded, revision


def reload() -> Snapshot:
    """(Re)read the internal rules from the database and publish a new snapshot."""
    global _snapshot, _checked_at
    snapshot = _build(*_load())
    with _lock:
        _snapshot = snapshot
        _checked_at = time.monotonic()
    return snapshot


def snapshot() -> Snapshot:
    """Return the current snapshot, reloading it when another process changed the rules."""
    global _checked_at
    current = _snapshot
    if current is None:
        return reload()
    if time.monotonic() - _checked_at < REFRESH_SECONDS:
        return current
    _checked_at = time.monotonic()
    try:
        latest = rule_store.revision()
    except SQLAlchemyError:
        return current
    return reload() if latest != current.revision else current


def reset() -> None:
    """Forget the loaded content (used by tests)."""
    global _snapshot
    with _lock:
        _snapshot = None


# ── Scanning ─────────────────────────────────────────────────────────────────


def scan(content: str, language: str, max_matches: int = 200) -> tuple[list[dict], list[dict]]:
    """Scan with the active rules; returns ``(matches, suppressed)``."""
    return scan_content_detailed(content, language, snapshot().rules, max_matches)


def describe_rules(language: str | None = None, include_disabled: bool = False) -> list[dict]:
    """List the active rules (or every rule) with their origin and state."""
    current = snapshot()
    rows = []
    for rule in current.catalog if include_disabled else current.rules:
        if language and "*" not in rule.languages and language.lower() not in rule.languages:
            continue
        rows.append(
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity.value,
                "cwe": rule.cwe,
                "languages": sorted(rule.languages),
                "origin": "custom" if rule.id in current.custom_rule_ids else "builtin",
                "enabled": rule.id not in current.disabled_rule_ids,
            }
        )
    return rows


# ── Checklists ───────────────────────────────────────────────────────────────


def domains() -> tuple[str, ...]:
    """Return every checklist domain (built-in and custom)."""
    return tuple(snapshot().checklists)


def get_checklist(domain: str) -> tuple[CheckItem, ...]:
    """Return the checklist of a domain.

    Raises:
        ValueError: If the domain is unknown.
    """
    key = domain.strip().lower()
    available = snapshot().checklists
    if key not in available:
        raise ValueError(f"Unknown domain '{domain}'. Available: {', '.join(available)}")
    return available[key]


def render_checklist_markdown(domain: str) -> str:
    """Render a checklist as Markdown (embedded in prompts and returned by tools)."""
    lines = [f"### Checklist: {domain.strip().lower()}"]
    for item in get_checklist(domain):
        cwe = f" ({item.cwe})" if item.cwe else ""
        lines.append(f"- **{item.id} - {item.title}**{cwe}: {item.what_to_look_for}")
    return "\n".join(lines)


def company_checklist_markdown() -> str:
    """Return the company-wide checklist, or an empty string when none is defined."""
    if COMPANY_DOMAIN in snapshot().checklists:
        return render_checklist_markdown(COMPANY_DOMAIN)
    return ""
