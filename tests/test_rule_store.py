"""Tests for the rules stored in the database (seeding, import, export, state, limits)."""

import tomllib

import pytest

from security_review_mcp.rules import registry, rule_store
from security_review_mcp.rules.rules_loader import default_content

PACK = """
disabled_rules = ["PY-008"]

[[rules]]
id = "ACME-001"
title = "Legacy crypto helper"
severity = "high"
cwe = "CWE-327"
languages = ["python"]
pattern = '''LegacyCrypto\\.encrypt\\('''
advice = "Use CryptoService."

[[rules]]
id = "ACME-002"
title = "Case sensitive marker"
severity = "low"
pattern = "DANGER"
ignore_case = false

[[checklist]]
domain = "company"
id = "ACME-CL-01"
title = "Tenant isolation"
what_to_look_for = "Queries are scoped by tenant."
cwe = "CWE-639"
"""

RULE = {
    "id": "ACME-010",
    "title": "Unsafe eval",
    "severity": "high",
    "languages": ["python"],
    "pattern": "eval\\(",
}


def custom_rules() -> list[dict]:
    """Return the stored custom rules (the default rules are stored too)."""
    return [row for row in rule_store.list_rules() if row["origin"] == "custom"]


def active_ids(language: str = "python") -> set[str]:
    """Return the ids of the active rules after a reload."""
    registry.reload()
    return {row["id"] for row in registry.describe_rules(language)}


# ── Seeding of the default content ───────────────────────────────────────────


def stored_rule(rule_id: str) -> dict | None:
    """Return a stored rule by id (default or custom)."""
    return next((row for row in rule_store.list_rules() if row["id"] == rule_id), None)


def test_first_run_seeds_every_default_rule_and_checklist_item():
    defaults = default_content()
    rows = rule_store.list_rules()
    assert [row["id"] for row in rows] == sorted(rule.id for rule in defaults.rules)
    assert all(row["origin"] == "builtin" and not row["modified"] for row in rows)
    snapshot = registry.reload()
    assert {domain: len(items) for domain, items in snapshot.checklists.items()} == {
        domain: len(items) for domain, items in defaults.checklist.items()
    }
    assert snapshot.custom_rule_ids == frozenset()


def test_seeding_is_idempotent():
    revision = rule_store.revision()
    assert rule_store.seed_defaults() == 0
    assert rule_store.revision() == revision


def test_init_db_seeds_an_empty_database(tmp_path, monkeypatch):
    from security_review_mcp import config
    from security_review_mcp.storage import database

    monkeypatch.setenv("SECREVIEW_DATABASE_URL", f"sqlite:///{tmp_path / 'fresh.db'}")
    config.get_settings.cache_clear()
    database.set_engine(None)
    try:
        database.init_db()
        assert len(rule_store.list_rules()) == len(default_content().rules)
        database.init_db()  # a second start writes nothing
        assert rule_store.revision() == 1
    finally:
        database.get_engine().dispose()
        database.set_engine(None)
        config.get_settings.cache_clear()


def _upgraded_defaults(monkeypatch, **changes: dict) -> None:
    """Simulate a newer default_rules.toml where the given rules changed."""
    upgraded = {rule_id: dict(entry) for rule_id, entry in rule_store.default_rules().items()}
    for rule_id, fields in changes.items():
        upgraded[rule_id.replace("_", "-")] = upgraded.get(rule_id.replace("_", "-"), {}) | fields
    monkeypatch.setattr(rule_store, "default_rules", lambda: upgraded)


def test_upgrade_updates_unmodified_defaults_and_adds_new_ones(monkeypatch):
    new_rule = RULE | {"id": "PY-999", "cwe": "", "advice": "", "ignore_case": True}
    _upgraded_defaults(monkeypatch, PY_002={"title": "Better title"}, PY_999=new_rule)
    revision = rule_store.revision()
    assert rule_store.seed_defaults() == 2
    assert stored_rule("PY-002")["title"] == "Better title"
    assert stored_rule("PY-999")["origin"] == "builtin"
    assert rule_store.revision() == revision + 1
    assert rule_store.seed_defaults() == 0


def test_upgrade_keeps_modified_and_deleted_defaults(monkeypatch, database):
    from sqlmodel import Session

    from security_review_mcp.storage.models import CustomRule

    rule_store.update_rule("PY-001", rule_store.default_rules()["PY-001"] | {"title": "Mine"})
    with Session(database) as session:  # removed by hand from the database
        session.delete(session.get(CustomRule, "PY-003"))
        session.commit()
    _upgraded_defaults(monkeypatch, PY_001={"title": "New"}, PY_003={"title": "New"})
    assert rule_store.seed_defaults() == 0
    assert stored_rule("PY-001")["title"] == "Mine"
    assert stored_rule("PY-003") is None


def test_first_seeding_keeps_an_existing_rule_with_a_default_id(database):
    from sqlmodel import Session, delete

    from security_review_mcp.storage.models import DefaultSeed

    # A database of the previous version: PY-001 overridden, nothing seeded yet
    rule_store.update_rule("PY-001", rule_store.default_rules()["PY-001"] | {"title": "Override"})
    with Session(database) as session:
        session.exec(delete(DefaultSeed))
        session.commit()
    assert rule_store.seed_defaults() == 0
    assert stored_rule("PY-001")["title"] == "Override"
    assert stored_rule("PY-001")["modified"] is True


def test_concurrent_seeding_retries_once(monkeypatch):
    from sqlalchemy.exc import IntegrityError

    calls = []
    original = rule_store._seed

    def racing(session):
        calls.append(1)
        if len(calls) == 1:
            raise IntegrityError("INSERT", {}, Exception("duplicate key"))
        return original(session)

    monkeypatch.setattr(rule_store, "_seed", racing)
    assert rule_store.seed_defaults() == 0
    assert len(calls) == 2


def test_import_replace_restores_the_defaults():
    rule_store.update_rule("PY-001", rule_store.default_rules()["PY-001"] | {"title": "Mine"})
    rule_store.set_enabled(["PY-002"], False)
    rule_store.import_packs([("a.toml", PACK)], replace=True)
    assert stored_rule("PY-001")["modified"] is False
    assert stored_rule("PY-002")["enabled"] is True
    assert stored_rule("ACME-001")["origin"] == "custom"
    assert stored_rule("PY-008")["enabled"] is False  # from the pack


# ── Import / export ──────────────────────────────────────────────────────────


def test_import_stores_rules_checklist_and_disabled_ids():
    stats = rule_store.import_packs([("company.toml", PACK)])
    assert stats == {
        "files": ["company.toml"],
        "rules": 2,
        "checklist_items": 1,
        "disabled_rules": 1,
        "replaced": False,
    }
    assert {"ACME-001", "ACME-002"} <= active_ids()
    assert "PY-008" not in active_ids()
    assert "ACME-CL-01" in registry.render_checklist_markdown("company")


def test_import_is_all_or_nothing():
    broken = PACK + '\n[[rules]]\nid = "ACME-003"\ntitle = "t"\nseverity = "low"\npattern = "(a+)+"'
    with pytest.raises(ValueError, match=r"nothing imported.*rules\[3\].*backtracking"):
        rule_store.import_packs([("company.toml", broken)])
    assert custom_rules() == []


def test_import_updates_existing_entries_by_id():
    rule_store.import_packs([("a.toml", PACK)])
    changed = PACK.replace('title = "Legacy crypto helper"', 'title = "Renamed"')
    rule_store.import_packs([("b.toml", changed.replace('"PY-008"', '"PY-001"'))])
    rules = {row["id"]: row for row in custom_rules()}
    assert rules["ACME-001"]["title"] == "Renamed"
    assert len(rules) == 2
    assert registry.reload().disabled_rule_ids == {"PY-008", "PY-001"}  # disabled ids add up


def test_import_replace_clears_the_previous_content():
    rule_store.import_packs([("a.toml", PACK)])
    stats = rule_store.import_packs(
        [("b.toml", '[[rules]]\nid = "ACME-020"\ntitle = "t"\nseverity = "low"\npattern = "x"')],
        replace=True,
    )
    assert stats["replaced"] is True
    snapshot = registry.reload()
    assert snapshot.custom_rule_ids == {"ACME-020"}
    assert snapshot.disabled_rule_ids == frozenset()
    assert "company" not in registry.domains()


def test_export_round_trips_through_import():
    rule_store.import_packs([("company.toml", PACK)])
    exported = rule_store.export_pack()
    data = tomllib.loads(exported)
    assert data["disabled_rules"] == ["PY-008"]
    assert [rule["id"] for rule in data["rules"]] == ["ACME-001", "ACME-002"]
    assert data["rules"][1]["ignore_case"] is False
    assert "cwe" not in data["rules"][1]  # empty optional fields are omitted

    rule_store.import_packs([("export.toml", exported)], replace=True)
    assert rule_store.export_pack() == exported
    matches, _ = registry.scan("danger DANGER", "python")
    assert [m["line"] for m in matches if m["rule_id"] == "ACME-002"] == [1]


def test_export_of_an_empty_database_is_a_valid_pack():
    assert tomllib.loads(rule_store.export_pack()) == {"disabled_rules": []}


def test_export_can_be_limited_to_one_section():
    rule_store.import_packs([("company.toml", PACK)])
    rules_only = tomllib.loads(rule_store.export_pack(frozenset({"rules"})))
    assert set(rules_only) == {"disabled_rules", "rules"}
    checklist_only = tomllib.loads(rule_store.export_pack(frozenset({"checklist"})))
    assert set(checklist_only) == {"checklist"}
    assert checklist_only["checklist"][0]["id"] == "ACME-CL-01"
    for sections in (frozenset(), frozenset({"standards"})):
        with pytest.raises(ValueError, match="sections"):
            rule_store.export_pack(sections)


def test_import_limits(monkeypatch):
    monkeypatch.setattr(rule_store, "MAX_CUSTOM_RULES", 1)
    with pytest.raises(ValueError, match="limit of 1 stored rules"):
        rule_store.import_packs([("company.toml", PACK)])
    assert custom_rules() == []
    with pytest.raises(ValueError, match="No rule pack"):
        rule_store.import_packs([])


# ── Enable / disable / delete ────────────────────────────────────────────────


def test_disable_and_enable_builtin_and_custom_rules():
    rule_store.create_rule(RULE)
    assert rule_store.set_enabled(["PY-001", "ACME-010"], False) == ["PY-001", "ACME-010"]
    assert not {"PY-001", "ACME-010"} & active_ids()
    assert custom_rules()[0]["enabled"] is False
    rule_store.set_enabled(["PY-001", "ACME-010"], False)  # idempotent
    rule_store.set_enabled(["PY-001", "ACME-010"], True)
    assert {"PY-001", "ACME-010"} <= active_ids()


def test_unknown_or_malformed_ids_change_nothing():
    with pytest.raises(ValueError, match="Unknown rule: ACME-404"):
        rule_store.set_enabled(["PY-001", "ACME-404"], False)
    assert "PY-001" in active_ids()
    with pytest.raises(ValueError, match="invalid id"):
        rule_store.set_enabled(["drop table"], False)
    with pytest.raises(ValueError, match="At most"):
        rule_store.set_enabled(["PY-001"] * (rule_store.MAX_IDS_PER_CALL + 1), False)


def test_delete_rules_and_checklist_items():
    rule_store.import_packs([("company.toml", PACK)])
    rule_store.set_enabled(["ACME-001"], False)
    deleted = rule_store.delete_entries(["ACME-001", "ACME-CL-01"])
    assert deleted == {"deleted_rules": ["ACME-001"], "deleted_checklist_items": ["ACME-CL-01"]}
    snapshot = registry.reload()
    assert "ACME-001" not in snapshot.custom_rule_ids
    assert "ACME-001" not in snapshot.disabled_rule_ids  # its state went with it
    assert "company" not in registry.domains()


def test_default_content_cannot_be_deleted():
    rule_store.create_rule(RULE)
    with pytest.raises(ValueError, match="Default content cannot be deleted: PY-001"):
        rule_store.delete_entries(["ACME-010", "PY-001"])
    with pytest.raises(ValueError, match="Default content cannot be deleted: PY-01"):
        rule_store.delete_entries(["PY-01"])
    with pytest.raises(ValueError, match="Not found: ACME-404"):
        rule_store.delete_entries(["ACME-404"])
    assert {"ACME-010", "PY-001"} <= active_ids()  # all or nothing


def test_default_rule_can_be_edited_and_is_marked_modified():
    with pytest.raises(ValueError, match="already exists"):
        rule_store.create_rule(RULE | {"id": "PY-001"})
    rule_store.update_rule("PY-001", RULE | {"id": "PY-001", "title": "Edited default"})
    rows = {row["id"]: row for row in registry.describe_rules("python")}
    assert (rows["PY-001"]["title"], rows["PY-001"]["origin"]) == ("Edited default", "builtin")
    assert rows["PY-001"]["modified"] is True
    assert rows["PY-002"]["modified"] is False
    # Only what differs from the defaults is exported
    assert [rule["id"] for rule in tomllib.loads(rule_store.export_pack())["rules"]] == ["PY-001"]


# ── Single rule changes ──────────────────────────────────────────────────────


def test_create_update_and_revision():
    rule_store.create_rule(RULE)
    first = rule_store.revision()
    with pytest.raises(ValueError, match="already exists"):
        rule_store.create_rule(RULE)
    rule_store.update_rule("ACME-010", RULE | {"title": "Unsafe eval call"})
    assert rule_store.revision() == first + 1
    assert custom_rules()[0]["title"] == "Unsafe eval call"
    with pytest.raises(ValueError, match="cannot be changed"):
        rule_store.update_rule("ACME-010", RULE | {"id": "ACME-011"})
    with pytest.raises(ValueError, match="not found"):
        rule_store.update_rule("ACME-011", RULE | {"id": "ACME-011"})
    with pytest.raises(ValueError, match="backtracking"):
        rule_store.update_rule("ACME-010", RULE | {"pattern": "(a*)*"})


def test_invalid_stored_row_is_reported_not_fatal(database):
    from sqlmodel import Session

    from security_review_mcp.storage.models import CustomRule

    with Session(database) as session:
        session.add(CustomRule(id="ACME-099", title="t", severity="bogus", pattern="x"))
        session.commit()
    snapshot = registry.reload()
    assert any("rule ACME-099" in error for error in snapshot.errors)
    assert "ACME-099" not in snapshot.custom_rule_ids


def test_concurrent_conflict_is_reported_as_value_error(monkeypatch):
    from sqlalchemy.exc import IntegrityError

    def conflict(session):
        raise IntegrityError("INSERT", {}, Exception("duplicate key"))

    monkeypatch.setattr(rule_store, "_bump", conflict)
    with pytest.raises(ValueError, match="changed concurrently"):
        rule_store.create_rule(RULE)
    assert custom_rules() == []


def test_deeply_nested_pack_is_refused():
    with pytest.raises(ValueError, match="nothing imported.*nested.toml"):
        rule_store.import_packs([("nested.toml", "a = " + "[" * 50_000 + "]" * 50_000)])
