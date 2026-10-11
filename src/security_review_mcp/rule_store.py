"""Internal rules stored in the database: custom rules, checklist items and disabled rule ids.

The database is the only source of internal content. Administrators manage it with
``security-review-mcp rules import|export|enable|disable|delete`` and the web interface. Every
change bumps ``RuleSetRevision`` so that each server instance sharing the database reloads its
registry (see ``registry.snapshot``).
"""

import functools
import json
from collections.abc import Callable
from typing import Any

import tomlkit
from sqlalchemy import delete as sql_delete
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, select

from .database import session_scope
from .models import CustomCheckItem, CustomRule, DisabledRule, RuleSetRevision, utcnow
from .rules_loader import (
    LoadResult,
    parse_check_item,
    parse_pack,
    parse_rule,
    rule_entry,
    validate_id,
)
from .rules_platform import PLATFORM_RULES
from .scanner import RULES

MAX_CUSTOM_RULES = 1000
MAX_CHECK_ITEMS = 1000
MAX_IDS_PER_CALL = 200

BUILTIN_RULE_IDS = frozenset(rule.id for rule in RULES + PLATFORM_RULES)


def _conflicts_as_errors(func: Callable[..., Any]) -> Callable[..., Any]:
    """Report a concurrent change (unique key conflict) as a ValueError, like other errors."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except IntegrityError as exc:
            raise ValueError("The rules were changed concurrently; retry the operation") from exc

    return wrapper


# ── Revision ─────────────────────────────────────────────────────────────────


def _bump(session: Session) -> None:
    """Increment the rule set revision inside the caller's transaction."""
    result = session.exec(
        update(RuleSetRevision)
        .where(col(RuleSetRevision.id) == 1)
        .values(revision=col(RuleSetRevision.revision) + 1)
    )
    if result.rowcount == 0:
        session.add(RuleSetRevision(id=1, revision=1))


def revision() -> int:
    """Return the current rule set revision (0 when nothing was ever changed)."""
    with session_scope() as session:
        row = session.get(RuleSetRevision, 1)
        return row.revision if row else 0


# ── Reading ──────────────────────────────────────────────────────────────────


def _row_entry(row: CustomRule) -> dict:
    """Return the pack fields of a stored rule."""
    return {
        "id": row.id,
        "title": row.title,
        "severity": row.severity,
        "cwe": row.cwe,
        "languages": json.loads(row.languages),
        "pattern": row.pattern,
        "advice": row.advice,
        "ignore_case": row.ignore_case,
    }


def load() -> tuple[LoadResult, int]:
    """Read and re-validate the stored content; return it with its revision.

    A stored row that no longer passes validation is skipped and reported in ``errors``.
    """
    result = LoadResult()
    with session_scope() as session:
        current = session.get(RuleSetRevision, 1)
        for row in session.exec(select(CustomRule).order_by(col(CustomRule.id))).all():
            try:
                result.rules.append(parse_rule(_row_entry(row)))
            except (ValueError, TypeError) as exc:
                result.errors.append(f"rule {row.id}: {exc}")
        items = session.exec(
            select(CustomCheckItem).order_by(col(CustomCheckItem.domain), col(CustomCheckItem.id))
        ).all()
        for item in items:
            try:
                domain, check = parse_check_item(item.model_dump())
            except ValueError as exc:
                result.errors.append(f"checklist item {item.id}: {exc}")
                continue
            result.checklist.setdefault(domain, []).append(check)
        result.disabled_rules = set(session.exec(select(DisabledRule.rule_id)).all())
        return result, current.revision if current else 0


def list_custom_rules() -> list[dict]:
    """Return the stored rules with their state, for the web interface and the CLI."""
    with session_scope() as session:
        disabled = set(session.exec(select(DisabledRule.rule_id)).all())
        rows = session.exec(select(CustomRule).order_by(col(CustomRule.id))).all()
        return [
            _row_entry(row)
            | {"enabled": row.id not in disabled, "updated_at": row.updated_at.isoformat()}
            for row in rows
        ]


# ── Rules ────────────────────────────────────────────────────────────────────


def _store_rule(session: Session, entry: dict, row: CustomRule | None = None) -> None:
    """Validate a rule and insert it, or update ``row`` in place."""
    fields = rule_entry(parse_rule(entry))
    fields["languages"] = json.dumps(fields["languages"])
    if row is None:
        session.add(CustomRule(**fields))
        return
    for key, value in fields.items():
        setattr(row, key, value)
    row.updated_at = utcnow()
    session.add(row)


def _check_limits(session: Session) -> None:
    """Refuse a change that would exceed the number of stored rules or checklist items."""
    session.flush()
    rules = session.exec(select(func.count()).select_from(CustomRule)).one()
    items = session.exec(select(func.count()).select_from(CustomCheckItem)).one()
    if rules > MAX_CUSTOM_RULES:
        raise ValueError(f"The limit of {MAX_CUSTOM_RULES} custom rules has been reached")
    if items > MAX_CHECK_ITEMS:
        raise ValueError(f"The limit of {MAX_CHECK_ITEMS} checklist items has been reached")


@_conflicts_as_errors
def create_rule(entry: dict) -> None:
    """Add a new custom rule; an existing id is refused."""
    with session_scope() as session:
        rule_id = str(entry.get("id", ""))
        if session.get(CustomRule, rule_id) is not None:
            raise ValueError(f"Rule {rule_id} already exists")
        _store_rule(session, entry)
        _check_limits(session)
        _bump(session)


@_conflicts_as_errors
def update_rule(rule_id: str, entry: dict) -> None:
    """Replace the fields of a custom rule without changing its id."""
    if str(entry.get("id", "")) != rule_id:
        raise ValueError("A rule id cannot be changed")
    with session_scope() as session:
        row = session.get(CustomRule, rule_id)
        if row is None:
            raise ValueError(f"Custom rule {rule_id} was not found")
        _store_rule(session, entry, row)
        _bump(session)


def _bounded_ids(rule_ids: list[str]) -> list[str]:
    """Validate a list of ids given on the command line or to the API."""
    if not rule_ids:
        raise ValueError("At least one id is required")
    if len(rule_ids) > MAX_IDS_PER_CALL:
        raise ValueError(f"At most {MAX_IDS_PER_CALL} ids can be given at once")
    return list(dict.fromkeys(validate_id(item.strip()) for item in rule_ids))


@_conflicts_as_errors
def delete_entries(ids: list[str], checklist: bool = True) -> dict[str, list[str]]:
    """Delete custom rules (and checklist items) by id; built-in rules can only be disabled.

    Every id must match something, otherwise nothing is deleted.
    """
    ids = _bounded_ids(ids)
    with session_scope() as session:
        rules = session.exec(select(CustomRule).where(col(CustomRule.id).in_(ids))).all()
        items = (
            session.exec(select(CustomCheckItem).where(col(CustomCheckItem.id).in_(ids))).all()
            if checklist
            else []
        )
        found = {row.id for row in rules} | {item.id for item in items}
        missing = [item for item in ids if item not in found]
        if missing:
            builtin = set(missing) & BUILTIN_RULE_IDS
            hint = " (built-in rules can only be disabled)" if builtin else ""
            raise ValueError(f"Not found: {', '.join(missing)}{hint}")
        for row in [*rules, *items]:
            session.delete(row)
        # The state of a deleted custom rule goes with it, unless it also names a built-in rule
        orphans = [row.id for row in rules if row.id not in BUILTIN_RULE_IDS]
        if orphans:
            session.exec(sql_delete(DisabledRule).where(col(DisabledRule.rule_id).in_(orphans)))
        _bump(session)
    return {
        "deleted_rules": sorted(row.id for row in rules),
        "deleted_checklist_items": sorted({item.id for item in items}),
    }


@_conflicts_as_errors
def set_enabled(ids: list[str], enabled: bool) -> list[str]:
    """Enable or disable built-in or custom rules; an unknown id changes nothing."""
    ids = _bounded_ids(ids)
    with session_scope() as session:
        custom = set(session.exec(select(CustomRule.id).where(col(CustomRule.id).in_(ids))).all())
        missing = [item for item in ids if item not in custom and item not in BUILTIN_RULE_IDS]
        if missing:
            raise ValueError(f"Unknown rule: {', '.join(missing)}")
        disabled = set(
            session.exec(select(DisabledRule.rule_id).where(col(DisabledRule.rule_id).in_(ids)))
        )
        if enabled:
            session.exec(sql_delete(DisabledRule).where(col(DisabledRule.rule_id).in_(ids)))
        else:
            for rule_id in ids:
                if rule_id not in disabled:
                    session.add(DisabledRule(rule_id=rule_id))
        _bump(session)
    return ids


# ── Import / export ──────────────────────────────────────────────────────────


@_conflicts_as_errors
def import_packs(packs: list[tuple[str, str]], replace: bool = False) -> dict:
    """Import TOML packs given as ``(name, text)``, all or nothing.

    Rules and checklist items are added or replaced by id, and ``disabled_rules`` are added.
    With ``replace``, the stored content is first cleared so that the database matches the packs.

    Raises:
        ValueError: Listing every invalid entry; nothing is imported then.
    """
    if not packs:
        raise ValueError("No rule pack to import")
    parsed = [parse_pack(text, name) for name, text in packs]
    errors = [message for result in parsed for message in result.errors]
    if errors:
        raise ValueError("Invalid rule pack, nothing imported: " + "; ".join(errors[:20]))

    rules = {rule.id: rule for result in parsed for rule in result.rules}
    items = {
        (domain, item.id): item
        for result in parsed
        for domain, domain_items in result.checklist.items()
        for item in domain_items
    }
    disabled = {rule_id for result in parsed for rule_id in result.disabled_rules}
    with session_scope() as session:
        if replace:
            for model in (CustomRule, CustomCheckItem, DisabledRule):
                session.exec(sql_delete(model))
        for rule in rules.values():
            _store_rule(session, rule_entry(rule), session.get(CustomRule, rule.id))
        for (domain, _), item in items.items():
            row = session.get(CustomCheckItem, (domain, item.id))
            row = row or CustomCheckItem(domain=domain, id=item.id, title="", what_to_look_for="")
            row.title, row.what_to_look_for, row.cwe = item.title, item.what_to_look_for, item.cwe
            session.add(row)
        session.flush()
        known = set(session.exec(select(DisabledRule.rule_id)).all())
        for rule_id in sorted(disabled - known):
            session.add(DisabledRule(rule_id=rule_id))
        _check_limits(session)
        _bump(session)
    return {
        "files": [name for name, _ in packs],
        "rules": len(rules),
        "checklist_items": len(items),
        "disabled_rules": len(disabled),
        "replaced": replace,
    }


def export_pack() -> str:
    """Return the stored content as a TOML pack accepted by ``import_packs``."""
    with session_scope() as session:
        rules = [
            _row_entry(row)
            for row in session.exec(select(CustomRule).order_by(col(CustomRule.id))).all()
        ]
        items = session.exec(
            select(CustomCheckItem).order_by(col(CustomCheckItem.domain), col(CustomCheckItem.id))
        ).all()
        checklist = [item.model_dump() for item in items]
        disabled = sorted(session.exec(select(DisabledRule.rule_id)).all())

    document = tomlkit.document()
    document.add(tomlkit.comment("Internal rules exported by `security-review-mcp rules export`."))
    document.add(tomlkit.comment("Import with `security-review-mcp rules import FILE`."))
    document["disabled_rules"] = disabled
    for key, entries in (("rules", rules), ("checklist", checklist)):
        tables = tomlkit.aot()
        for entry in entries:
            table = tomlkit.table()
            for name, value in entry.items():
                if value != "":  # omit empty optional fields (cwe, advice)
                    table[name] = value
            tables.append(table)
        if entries:
            document[key] = tables
    return tomlkit.dumps(document)
