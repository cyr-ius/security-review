"""Tests for the internal rules stored in the database (import, export, state, limits)."""

import tomllib

import pytest

from security_review_mcp import registry, rule_store

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


def active_ids(language: str = "python") -> set[str]:
    """Return the ids of the active rules after a reload."""
    registry.reload()
    return {row["id"] for row in registry.describe_rules(language)}


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
    assert rule_store.list_custom_rules() == []
    assert rule_store.revision() == 0


def test_import_updates_existing_entries_by_id():
    rule_store.import_packs([("a.toml", PACK)])
    changed = PACK.replace('title = "Legacy crypto helper"', 'title = "Renamed"')
    rule_store.import_packs([("b.toml", changed.replace('"PY-008"', '"PY-001"'))])
    rules = {row["id"]: row for row in rule_store.list_custom_rules()}
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


def test_import_limits(monkeypatch):
    monkeypatch.setattr(rule_store, "MAX_CUSTOM_RULES", 1)
    with pytest.raises(ValueError, match="limit of 1 custom rules"):
        rule_store.import_packs([("company.toml", PACK)])
    assert rule_store.list_custom_rules() == []
    with pytest.raises(ValueError, match="No rule pack"):
        rule_store.import_packs([])


# ── Enable / disable / delete ────────────────────────────────────────────────


def test_disable_and_enable_builtin_and_custom_rules():
    rule_store.create_rule(RULE)
    assert rule_store.set_enabled(["PY-001", "ACME-010"], False) == ["PY-001", "ACME-010"]
    assert not {"PY-001", "ACME-010"} & active_ids()
    assert rule_store.list_custom_rules()[0]["enabled"] is False
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


def test_builtin_rules_cannot_be_deleted():
    with pytest.raises(ValueError, match="built-in rules can only be disabled"):
        rule_store.delete_entries(["PY-001"])
    with pytest.raises(ValueError, match="Not found: ACME-404"):
        rule_store.delete_entries(["ACME-404"])


def test_deleting_an_override_restores_the_builtin_rule_and_keeps_its_state():
    rule_store.create_rule(RULE | {"id": "PY-001", "title": "Override"})
    rule_store.set_enabled(["PY-001"], False)
    rule_store.delete_entries(["PY-001"])
    snapshot = registry.reload()
    assert "PY-001" not in snapshot.custom_rule_ids
    assert "PY-001" in snapshot.disabled_rule_ids


# ── Single rule changes ──────────────────────────────────────────────────────


def test_create_update_and_revision():
    rule_store.create_rule(RULE)
    first = rule_store.revision()
    with pytest.raises(ValueError, match="already exists"):
        rule_store.create_rule(RULE)
    rule_store.update_rule("ACME-010", RULE | {"title": "Unsafe eval call"})
    assert rule_store.revision() == first + 1
    assert rule_store.list_custom_rules()[0]["title"] == "Unsafe eval call"
    with pytest.raises(ValueError, match="cannot be changed"):
        rule_store.update_rule("ACME-010", RULE | {"id": "ACME-011"})
    with pytest.raises(ValueError, match="not found"):
        rule_store.update_rule("ACME-011", RULE | {"id": "ACME-011"})
    with pytest.raises(ValueError, match="backtracking"):
        rule_store.update_rule("ACME-010", RULE | {"pattern": "(a*)*"})


def test_invalid_stored_row_is_reported_not_fatal(database):
    from sqlmodel import Session

    from security_review_mcp.models import CustomRule

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
    assert rule_store.list_custom_rules() == []
