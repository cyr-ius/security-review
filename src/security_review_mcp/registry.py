"""Active rules and checklists, read from the database (seeded from default_rules.toml)."""

import logging
import threading
import time
from dataclasses import dataclass

from sqlalchemy.exc import SQLAlchemyError

from . import rule_store
from .checklists import CheckItem
from .rules_loader import LoadResult, default_content, rule_entry
from .scanner import Rule, scan_content_detailed

logger = logging.getLogger(__name__)

# Checklist domain appended to every review prompt (company-wide requirements)
COMPANY_DOMAIN = "company"
# How often a cached snapshot checks the database revision (changes made by another process)
REFRESH_SECONDS = 5.0


@dataclass(frozen=True)
class Snapshot:
    """An immutable view of the merged content (swapped atomically on reload)."""

    rules: tuple[Rule, ...]
    catalog: tuple[Rule, ...]
    custom_rule_ids: frozenset[str]
    modified_rule_ids: frozenset[str]
    disabled_rule_ids: frozenset[str]
    checklists: dict[str, tuple[CheckItem, ...]]
    errors: tuple[str, ...]
    revision: int | None


_lock = threading.Lock()
_snapshot: Snapshot | None = None
_checked_at = 0.0


def _build(loaded: LoadResult, revision: int | None) -> Snapshot:
    """Build the snapshot of the loaded content; disabled rules stay in the catalog only."""
    defaults = rule_store.default_rules()
    catalog = tuple(loaded.rules)
    return Snapshot(
        rules=tuple(r for r in catalog if r.id not in loaded.disabled_rules),
        catalog=catalog,
        custom_rule_ids=frozenset(r.id for r in catalog if r.id not in defaults),
        modified_rule_ids=frozenset(
            r.id for r in catalog if rule_store.is_modified_default(rule_entry(r))
        ),
        disabled_rule_ids=frozenset(loaded.disabled_rules),
        checklists={domain: tuple(items) for domain, items in loaded.checklist.items()},
        errors=tuple(loaded.errors),
        revision=revision,
    )


def _defaults(message: str, disabled: set[str] | None = None) -> LoadResult:
    """Return the default content of default_rules.toml, with the reason for using it."""
    defaults = default_content()
    checklist = {domain: list(items) for domain, items in defaults.checklist.items()}
    return LoadResult(list(defaults.rules), checklist, disabled or set(), [message])


def _load() -> tuple[LoadResult, int | None]:
    """Read the stored rules; fall back to the default content rather than scan without rules.

    The fallback applies when the database is unavailable, and when it holds no rule at all:
    default rules cannot be deleted, so an empty table means the database was never seeded.
    """
    try:
        loaded, revision = rule_store.load()
    except SQLAlchemyError as exc:
        # The message may contain the database URL: only the error type is reported
        message = (
            f"stored rules unavailable: database error ({type(exc).__name__}); "
            "using the default rules"
        )
        loaded, revision = _defaults(message), None
    else:
        if not loaded.rules and not loaded.errors:
            message = "no rule stored in the database (not initialized); using the default rules"
            loaded = _defaults(message, loaded.disabled_rules)
    for message in loaded.errors:
        logger.warning("Internal rules problem: %s", message)
    return loaded, revision


def reload() -> Snapshot:
    """(Re)read the rules from the database and publish a new snapshot."""
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
                "modified": rule.id in current.modified_rule_ids,
                "enabled": rule.id not in current.disabled_rule_ids,
            }
        )
    return rows


# ── Checklists ───────────────────────────────────────────────────────────────


def domains() -> tuple[str, ...]:
    """Return every checklist domain (default and custom)."""
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
