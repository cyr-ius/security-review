"""Rules stored in the database: scan rules, checklist items and disabled rule ids.

The database is the source of the active content. On the first run, ``seed_defaults`` copies
the default rules and checklists of ``default_rules.toml`` into it; later runs add the new
defaults and update the ones an administrator has not modified (see ``DefaultSeed``).
Administrators manage the content with ``security-review-controller rules
import|export|enable|disable|delete`` and the web interface. Every change bumps
``RuleSetRevision`` so that each server instance sharing the database reloads its registry
(see ``registry.snapshot``).
"""

import functools
import hashlib
import json
from collections.abc import Callable
from typing import Any

import tomlkit
from sqlalchemy import delete as sql_delete
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, select

from .database import session_scope
from .models import (
    CustomCheckItem,
    CustomRule,
    DefaultSeed,
    DisabledRule,
    RuleSetRevision,
    utcnow,
)
from .rules_loader import (
    LoadResult,
    default_content,
    parse_check_item,
    parse_pack,
    parse_rule,
    rule_entry,
    validate_id,
)

MAX_CUSTOM_RULES = 1000
MAX_CHECK_ITEMS = 1000
MAX_IDS_PER_CALL = 200


# ── Default content ──────────────────────────────────────────────────────────


def digest(entry: dict) -> str:
    """Fingerprint the pack fields of a rule or checklist item (to detect modifications)."""
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode("utf-8")).hexdigest()


@functools.cache
def default_rules() -> dict[str, dict]:
    """Return the pack fields of the default rules, by id."""
    return {rule.id: rule_entry(rule) for rule in default_content().rules}


@functools.cache
def default_check_items() -> dict[tuple[str, str], dict]:
    """Return the fields of the default checklist items, by ``(domain, id)``."""
    return {
        (domain, item.id): _item_entry(domain, item.id, item.title, item.what_to_look_for, item.cwe)
        for domain, items in default_content().checklist.items()
        for item in items
    }


def is_modified_default(entry: dict) -> bool:
    """Tell whether a stored rule is a default rule changed by an administrator."""
    default = default_rules().get(entry["id"])
    return default is not None and digest(default) != digest(entry)


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


def _item_entry(domain: str, item_id: str, title: str, what: str, cwe: str) -> dict:
    """Return the pack fields of a checklist item."""
    return {"domain": domain, "id": item_id, "title": title, "what_to_look_for": what, "cwe": cwe}


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


def list_rules() -> list[dict]:
    """Return the stored rules with their origin and state, for the web interface."""
    with session_scope() as session:
        disabled = set(session.exec(select(DisabledRule.rule_id)).all())
        rows = session.exec(select(CustomRule).order_by(col(CustomRule.id))).all()
        result = []
        for row in rows:
            entry = _row_entry(row)
            result.append(
                entry
                | {
                    "origin": "builtin" if row.id in default_rules() else "custom",
                    "modified": is_modified_default(entry),
                    "enabled": row.id not in disabled,
                    "updated_at": row.updated_at.isoformat(),
                }
            )
        return result


def list_checklist_items() -> list[dict]:
    """Return the stored checklist items with their origin and modification state."""
    defaults = default_check_items()
    with session_scope() as session:
        rows = session.exec(
            select(CustomCheckItem).order_by(col(CustomCheckItem.domain), col(CustomCheckItem.id))
        ).all()
        result = []
        for row in rows:
            entry = row.model_dump()
            default = defaults.get((row.domain, row.id))
            result.append(
                entry
                | {
                    "origin": "builtin" if default is not None else "custom",
                    "modified": default is not None and digest(entry) != digest(default),
                }
            )
        return result


# ── Seeding ──────────────────────────────────────────────────────────────────


def _seed_entry(
    session: Session,
    seeds: dict[tuple[str, str], DefaultSeed],
    kind: str,
    key: str,
    default: dict,
    stored: dict | None,
    write: Callable[[], None],
) -> bool:
    """Seed or upgrade one default entry; return True when the stored entry was written.

    ``stored`` holds the fields of the stored entry (None when absent) and ``write`` stores
    the default. An entry modified or deleted by an administrator is left untouched.
    """
    new_digest = digest(default)
    seed = seeds.get((kind, key))
    if seed is not None and seed.digest == new_digest:
        return False
    if seed is None:
        # First seeding: add the entry unless one with that id already exists (kept as is)
        replace = stored is None
        session.add(DefaultSeed(kind=kind, key=key, digest=new_digest))
    else:
        # Newer default: replace the entry only if it still is the previously seeded default
        replace = stored is not None and digest(stored) == seed.digest
        seed.digest, seed.seeded_at = new_digest, utcnow()
        session.add(seed)
    if replace and stored != default:
        write()
        return True
    return False


def _seed(session: Session) -> int:
    """Copy the missing or updated default content; return the number of entries written."""
    seeds = {(seed.kind, seed.key): seed for seed in session.exec(select(DefaultSeed)).all()}
    written = 0
    for rule_id, default in default_rules().items():
        row = session.get(CustomRule, rule_id)
        written += _seed_entry(
            session,
            seeds,
            "rule",
            rule_id,
            default,
            _row_entry(row) if row else None,
            functools.partial(_store_rule, session, default, row),
        )
    for (domain, item_id), default in default_check_items().items():
        item = session.get(CustomCheckItem, (domain, item_id))
        written += _seed_entry(
            session,
            seeds,
            "checklist",
            f"{domain}/{item_id}",
            default,
            item.model_dump() if item else None,
            functools.partial(_store_item, session, default, item),
        )
    return written


def seed_defaults() -> int:
    """Copy the default rules and checklists into the database (first run and upgrades).

    Idempotent; returns the number of entries written. Several instances may start at the
    same time: the loser of a concurrent insert retries once and finds the work done.
    """
    for attempt in range(2):
        try:
            with session_scope() as session:
                written = _seed(session)
                if written:
                    _bump(session)
            return written
        except IntegrityError:
            if attempt:
                raise
    return 0


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


def _store_item(session: Session, entry: dict, row: CustomCheckItem | None = None) -> None:
    """Insert a validated checklist item, or update ``row`` in place."""
    row = row or CustomCheckItem(
        domain=entry["domain"], id=entry["id"], title="", what_to_look_for=""
    )
    row.title, row.what_to_look_for, row.cwe = (
        entry["title"],
        entry["what_to_look_for"],
        entry["cwe"],
    )
    session.add(row)


def _check_limits(session: Session) -> None:
    """Refuse a change that would exceed the number of stored rules or checklist items."""
    session.flush()
    rules = session.exec(select(func.count()).select_from(CustomRule)).one()
    items = session.exec(select(func.count()).select_from(CustomCheckItem)).one()
    if rules > MAX_CUSTOM_RULES:
        raise ValueError(f"The limit of {MAX_CUSTOM_RULES} stored rules has been reached")
    if items > MAX_CHECK_ITEMS:
        raise ValueError(f"The limit of {MAX_CHECK_ITEMS} checklist items has been reached")


@_conflicts_as_errors
def create_rule(entry: dict) -> None:
    """Add a new custom rule; an existing id (default or custom) is refused."""
    with session_scope() as session:
        rule_id = str(entry.get("id", ""))
        if session.get(CustomRule, rule_id) is not None:
            raise ValueError(f"Rule {rule_id} already exists")
        _store_rule(session, entry)
        _check_limits(session)
        _bump(session)


@_conflicts_as_errors
def update_rule(rule_id: str, entry: dict) -> None:
    """Replace the fields of a stored rule (default or custom) without changing its id."""
    if str(entry.get("id", "")) != rule_id:
        raise ValueError("A rule id cannot be changed")
    with session_scope() as session:
        row = session.get(CustomRule, rule_id)
        if row is None:
            raise ValueError(f"Rule {rule_id} was not found")
        _store_rule(session, entry, row)
        _bump(session)


@_conflicts_as_errors
def create_check_item(entry: dict) -> None:
    """Add a checklist item; an existing ``(domain, id)`` pair is refused."""
    domain, item = parse_check_item(entry)
    normalized = _item_entry(domain, item.id, item.title, item.what_to_look_for, item.cwe)
    with session_scope() as session:
        if session.get(CustomCheckItem, (domain, item.id)) is not None:
            raise ValueError(f"Checklist item {domain}/{item.id} already exists")
        _store_item(session, normalized)
        _check_limits(session)
        _bump(session)


@_conflicts_as_errors
def update_check_item(domain: str, item_id: str, entry: dict) -> None:
    """Replace a checklist item's fields without changing its domain or id."""
    stored_domain, item = parse_check_item(entry)
    if (stored_domain, item.id) != (domain, item_id):
        raise ValueError("A checklist item domain and id cannot be changed")
    with session_scope() as session:
        row = session.get(CustomCheckItem, (domain, item_id))
        if row is None:
            raise ValueError(f"Checklist item {domain}/{item_id} was not found")
        _store_item(
            session,
            _item_entry(domain, item.id, item.title, item.what_to_look_for, item.cwe),
            row,
        )
        _bump(session)


@_conflicts_as_errors
def delete_check_item(domain: str, item_id: str) -> None:
    """Delete one custom checklist item; default items cannot be deleted."""
    with session_scope() as session:
        row = session.get(CustomCheckItem, (domain, item_id))
        if row is None:
            raise ValueError(f"Checklist item {domain}/{item_id} was not found")
        if (domain, item_id) in default_check_items():
            raise ValueError(f"Default checklist item {domain}/{item_id} cannot be deleted")
        session.delete(row)
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
    """Delete custom rules (and checklist items) by id; default content cannot be deleted.

    Every id must match a custom entry, otherwise nothing is deleted.
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
            raise ValueError(f"Not found: {', '.join(missing)}")
        defaults = sorted(
            {row.id for row in rules if row.id in default_rules()}
            | {item.id for item in items if (item.domain, item.id) in default_check_items()}
        )
        if defaults:
            raise ValueError(
                f"Default content cannot be deleted: {', '.join(defaults)} "
                "(disable or edit it instead)"
            )
        for row in [*rules, *items]:
            session.delete(row)
        # The state of a deleted rule goes with it
        if rules:
            deleted = [row.id for row in rules]
            session.exec(sql_delete(DisabledRule).where(col(DisabledRule.rule_id).in_(deleted)))
        _bump(session)
    return {
        "deleted_rules": sorted(row.id for row in rules),
        "deleted_checklist_items": sorted({item.id for item in items}),
    }


@_conflicts_as_errors
def set_enabled(ids: list[str], enabled: bool) -> list[str]:
    """Enable or disable stored rules (default or custom); an unknown id changes nothing."""
    ids = _bounded_ids(ids)
    with session_scope() as session:
        stored = set(session.exec(select(CustomRule.id).where(col(CustomRule.id).in_(ids))).all())
        missing = [item for item in ids if item not in stored]
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
    With ``replace``, the stored content is first reset to the default content, so that the
    database matches the defaults plus the packs.

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
            for model in (CustomRule, CustomCheckItem, DisabledRule, DefaultSeed):
                session.exec(sql_delete(model))
            session.flush()
            _seed(session)
            session.flush()
        for rule in rules.values():
            _store_rule(session, rule_entry(rule), session.get(CustomRule, rule.id))
        for (domain, _), item in items.items():
            entry = _item_entry(domain, item.id, item.title, item.what_to_look_for, item.cwe)
            _store_item(session, entry, session.get(CustomCheckItem, (domain, item.id)))
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


PACK_SECTIONS = frozenset({"rules", "checklist"})


def export_pack(sections: frozenset[str] = PACK_SECTIONS) -> str:
    """Return the stored content as a TOML pack accepted by ``import_packs``.

    Unmodified default rules and checklist items are left out: the pack holds what differs
    from the defaults (custom and modified entries, disabled rules). ``sections`` limits the
    pack to the rules (with the disabled rule ids) or to the checklist items.

    Raises:
        ValueError: If ``sections`` names an unknown section or none.
    """
    if not sections or not sections <= PACK_SECTIONS:
        raise ValueError(f"sections must be a non-empty subset of {sorted(PACK_SECTIONS)}")
    defaults = {digest(entry) for entry in default_rules().values()}
    defaults |= {digest(entry) for entry in default_check_items().values()}
    with session_scope() as session:
        rules = [
            entry
            for row in session.exec(select(CustomRule).order_by(col(CustomRule.id))).all()
            if digest(entry := _row_entry(row)) not in defaults
        ]
        items = session.exec(
            select(CustomCheckItem).order_by(col(CustomCheckItem.domain), col(CustomCheckItem.id))
        ).all()
        checklist = [entry for item in items if digest(entry := item.model_dump()) not in defaults]
        disabled = sorted(session.exec(select(DisabledRule.rule_id)).all())

    document = tomlkit.document()
    document.add(tomlkit.comment("Internal rules exported by security-review-controller."))
    document.add(
        tomlkit.comment(
            "Import with `security-review-controller rules import FILE` or the web interface."
        )
    )
    if "rules" in sections:
        document["disabled_rules"] = disabled
    for key, entries in (("rules", rules), ("checklist", checklist)):
        if key not in sections:
            continue
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
