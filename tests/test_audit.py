"""Audit log: events of the triage decisions, proposals, tokens and enrollments."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlmodel import Session, select

from security_review_mcp import audit, cli, token_store
from security_review_mcp.audit import AuditAction
from security_review_mcp.config import get_settings
from security_review_mcp.http_server import Role
from security_review_mcp.reports import services
from security_review_mcp.storage.database import session_scope
from security_review_mcp.storage.models import AuditEvent, FindingCreate, FindingStatus, Severity

# Fake secret, only used to check that it is masked
FAKE_SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def stored_events(database) -> list[AuditEvent]:
    with Session(database) as session:
        return list(session.exec(select(AuditEvent).order_by(AuditEvent.id)).all())


def actions(database) -> list[str]:
    return [event.action for event in stored_events(database)]


@pytest.fixture
def finding_id() -> int:
    finding = FindingCreate(title="SQL injection", severity=Severity.HIGH, description="Query")
    report = services.save_report("shop-api", "Review", [finding])
    return services.get_report(report["report_id"]).findings[0].id


# ── Recording ────────────────────────────────────────────────────────────────


def test_a_triage_decision_is_audited_with_its_actor_and_previous_status(database, finding_id):
    services.propose_finding_status(finding_id, FindingStatus.ACCEPTED, "Internal tool only", "bot")
    expires_at = datetime.now(UTC) + timedelta(days=30)
    services.update_finding_status(
        finding_id,
        FindingStatus.ACCEPTED,
        "alice",
        "Accepted by the security team",
        expires_at,
        actor="user:alice",
    )

    proposed, decided = stored_events(database)
    assert (proposed.action, proposed.actor) == ("finding.status_proposed", "token:bot")
    assert (decided.action, decided.actor) == ("finding.status_changed", "user:alice")
    assert (decided.target_type, decided.target_id, decided.project) == (
        "finding",
        str(finding_id),
        "shop-api",
    )
    details = json.loads(decided.details)
    assert details["previous_status"] == "open"
    assert details["status"] == "accepted"
    assert details["proposal"] == "accepted"
    assert details["reason"] == "Accepted by the security team"


def test_the_approver_is_the_default_actor(database, finding_id):
    services.update_finding_status(finding_id, FindingStatus.FIXED, "alice")

    (event,) = stored_events(database)
    assert event.actor == "alice"


def test_a_failed_decision_writes_no_event(database, finding_id):
    with pytest.raises(ValueError):
        services.update_finding_status(finding_id, FindingStatus.ACCEPTED, "alice", "Too short")
    with pytest.raises(services.NotFoundError):
        services.update_finding_status(999, FindingStatus.FIXED, "alice")

    assert stored_events(database) == []


def test_rejecting_a_proposal_is_audited_only_when_one_exists(database, finding_id):
    services.clear_finding_proposal(finding_id, "user:tess")
    assert stored_events(database) == []

    services.propose_finding_status(finding_id, FindingStatus.FIXED, "Query is now bound", "bot")
    services.clear_finding_proposal(finding_id, "user:tess")

    event = stored_events(database)[-1]
    assert (event.action, event.actor) == ("finding.proposal_rejected", "user:tess")
    assert json.loads(event.details) == {"proposed_by": "bot", "status": "fixed"}


def test_token_lifecycle_is_audited_without_any_secret(database):
    created = token_store.create_token("ci", Role.MCP, ["shop-api"], actor="user:root")
    rotated = token_store.rotate_token("ci", grace_hours=1, actor="cli")
    token_store.revoke_token("ci", actor="token:ops")

    assert actions(database) == ["token.created", "token.rotated", "token.revoked"]
    events = stored_events(database)
    assert [event.actor for event in events] == ["user:root", "cli", "token:ops"]
    assert all(event.project == "shop-api" for event in events)
    assert json.loads(events[1].details)["grace_hours"] == 1
    dumped = " ".join(event.model_dump_json() for event in events)
    for secret in (created["token"], rotated["token"]):
        assert secret not in dumped


def test_details_are_masked_and_bounded(database):
    with session_scope() as session:
        audit.record(
            session,
            AuditAction.TOKEN_CREATED,
            "token:ops",
            "token",
            "x" * 500,
            details={"reason": f"key {FAKE_SECRET}", "long": "y" * 10_000},
        )

    (event,) = stored_events(database)
    assert FAKE_SECRET not in event.model_dump_json()
    assert len(event.target_id) == audit.MAX_TARGET_CHARS
    assert len(event.details) <= audit.MAX_DETAILS_CHARS


# ── Reading and purge ────────────────────────────────────────────────────────


def test_events_are_listed_newest_first_with_filters(database, finding_id):
    token_store.create_token("ci", Role.MCP, ["shop-api"], actor="cli")
    token_store.create_token("ops", Role.ADMIN, actor="user:root")
    services.update_finding_status(finding_id, FindingStatus.FIXED, "alice", actor="user:alice")

    listed = audit.list_events()
    assert listed["total"] == 3
    assert [event["action"] for event in listed["events"]] == [
        "finding.status_changed",
        "token.created",
        "token.created",
    ]
    assert audit.list_events(action="token.created")["total"] == 2
    assert audit.list_events(project="shop-api")["total"] == 2
    assert audit.list_events(actor="user:root")["events"][0]["details"]["label"] == "ops"
    future = datetime.now(UTC) + timedelta(days=1)
    assert audit.list_events(since=future)["total"] == 0
    page = audit.list_events(limit=1, offset=1)
    assert (page["total"], len(page["events"])) == (3, 1)


def test_listing_is_bounded_and_validated(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_list_limit", 2)
    for index in range(3):
        token_store.create_token(f"t{index}", Role.MCP)

    assert len(audit.list_events(limit=50)["events"]) == 2
    with pytest.raises(ValueError, match="Unknown audit action"):
        audit.list_events(action="token.deleted")
    with pytest.raises(ValueError):
        audit.list_events(limit=0)


def test_old_events_are_purged(database):
    token_store.create_token("old", Role.MCP)
    token_store.create_token("new", Role.MCP)
    with Session(database) as session:
        old = session.exec(select(AuditEvent)).first()
        old.created_at = datetime.now(UTC) - timedelta(days=400)
        session.add(old)
        session.commit()

    assert audit.prune_events(0) == {"retention_days": 0, "max_events": 0, "deleted": 0}
    assert audit.prune_events() == {"retention_days": 365, "max_events": 0, "deleted": 1}
    assert [event["details"]["label"] for event in audit.list_events()["events"]] == ["new"]
    with pytest.raises(ValueError):
        audit.prune_events(-1)


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_audit_cli_lists_and_purges(capsys):
    assert cli.run(["token", "create", "--label", "ci", "--role", "mcp"]) == cli.EXIT_PASSED
    capsys.readouterr()

    assert cli.run(["audit", "list", "--action", "token.created", "--actor", "cli"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["total"] == 1
    assert listed["events"][0]["details"]["label"] == "ci"

    assert cli.run(["audit", "list", "--since", "2999-01-01"]) == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out)["total"] == 0

    assert cli.run(["audit", "prune", "--days", "30"]) == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out) == {
        "retention_days": 30,
        "max_events": 0,
        "deleted": 0,
    }
    assert cli.run(["audit", "prune", "--days", "0", "--max-events", "1"]) == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out)["deleted"] == 0  # a single event


def test_audit_cli_refuses_bad_values(capsys):
    assert cli.run(["audit", "list", "--limit", "0"]) == cli.EXIT_ERROR
    assert "limit" in json.loads(capsys.readouterr().err)["error"]
    assert cli.run(["audit", "prune", "--days", "-1"]) == cli.EXIT_ERROR
    assert cli.run(["audit", "prune", "--max-events", "-1"]) == cli.EXIT_ERROR
    with pytest.raises(SystemExit) as exc:
        cli.run(["audit", "list", "--since", "yesterday"])
    assert exc.value.code == cli.EXIT_ERROR


def test_the_web_interface_knows_every_kind_of_event():
    # The audit screen filters and labels the events: a new kind must be added there too
    web = Path(__file__).parents[1] / "web" / "src" / "app" / "core"
    models = (web / "models" / "api.models.ts").read_text(encoding="utf-8")
    listed = models.split("export const AUDIT_ACTIONS", 1)[1].split("];", 1)[0]
    typed = models.split("export type AuditAction =", 1)[1].split(";", 1)[0]
    labels = (web / "i18n" / "messages" / "audit.ts").read_text(encoding="utf-8")

    for action in audit.AuditAction:
        assert f"'{action.value}'" in listed and f"'{action.value}'" in typed, action
        # en, fr and es
        assert labels.count(f"'audit.action.{action.value}'") == 3, action


def test_the_oldest_events_beyond_the_limit_are_purged():
    for label in ("first", "second", "third", "fourth"):
        token_store.create_token(label, Role.MCP)

    assert audit.prune_events(0, 2) == {"retention_days": 0, "max_events": 2, "deleted": 2}
    labels = [event["details"]["label"] for event in audit.list_events()["events"]]
    assert labels == ["fourth", "third"]
    # Under the limit: nothing more is deleted
    assert audit.prune_events(0, 5)["deleted"] == 0
    with pytest.raises(ValueError, match="max_events"):
        audit.prune_events(0, -1)
