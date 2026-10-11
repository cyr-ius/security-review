"""Active rules and checklists: built-in content merged with the internal rule packs."""

import threading
from dataclasses import dataclass

from .checklists import CHECKLISTS, CheckItem
from .config import get_settings
from .rules_loader import LoadResult, load_rules_dir
from .rules_platform import PLATFORM_RULES
from .scanner import RULES, Rule, scan_content_detailed

# Checklist domain appended to every review prompt (company-wide requirements)
COMPANY_DOMAIN = "company"

BUILTIN_RULES: tuple[Rule, ...] = RULES + PLATFORM_RULES


@dataclass(frozen=True)
class Snapshot:
    """An immutable view of the merged content (swapped atomically on reload)."""

    rules: tuple[Rule, ...]
    custom_rule_ids: frozenset[str]
    disabled_rule_ids: frozenset[str]
    checklists: dict[str, tuple[CheckItem, ...]]
    sources: tuple[str, ...]
    errors: tuple[str, ...]


_lock = threading.Lock()
_snapshot: Snapshot | None = None


def _build(loaded: LoadResult) -> Snapshot:
    """Merge built-in and custom content: a custom id replaces a built-in one."""
    custom_ids = {rule.id for rule in loaded.rules}
    merged = [r for r in BUILTIN_RULES if r.id not in custom_ids] + loaded.rules
    active = tuple(r for r in merged if r.id not in loaded.disabled_rules)

    checklists = {domain: list(items) for domain, items in CHECKLISTS.items()}
    for domain, items in loaded.checklist.items():
        existing = checklists.setdefault(domain, [])
        replaced = {item.id for item in items}
        existing[:] = [item for item in existing if item.id not in replaced] + items

    return Snapshot(
        rules=active,
        custom_rule_ids=frozenset(custom_ids),
        disabled_rule_ids=frozenset(loaded.disabled_rules),
        checklists={domain: tuple(items) for domain, items in checklists.items()},
        sources=tuple(loaded.sources),
        errors=tuple(loaded.errors),
    )


def reload() -> Snapshot:
    """(Re)read the rules directory and publish a new snapshot."""
    global _snapshot
    snapshot = _build(load_rules_dir(get_settings().rules_dir))
    with _lock:
        _snapshot = snapshot
    return snapshot


def snapshot() -> Snapshot:
    """Return the current snapshot, loading it on first use."""
    current = _snapshot
    return current if current is not None else reload()


def reset() -> None:
    """Forget the loaded content (used by tests)."""
    global _snapshot
    with _lock:
        _snapshot = None


# ── Scanning ─────────────────────────────────────────────────────────────────


def scan(content: str, language: str, max_matches: int = 200) -> tuple[list[dict], list[dict]]:
    """Scan with the active rules; returns ``(matches, suppressed)``."""
    return scan_content_detailed(content, language, snapshot().rules, max_matches)


def describe_rules(language: str | None = None) -> list[dict]:
    """List the active rules with their origin (builtin or custom)."""
    current = snapshot()
    rows = []
    for rule in current.rules:
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
