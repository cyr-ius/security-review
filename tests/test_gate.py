"""Tests for the security gate (service and MCP tool) and the shipped example pack."""

from pathlib import Path

import pytest
from mcp.client import Client

from security_review_mcp import registry, rule_store
from security_review_mcp.reports import services
from security_review_mcp.server import mcp
from security_review_mcp.storage.models import FindingCreate, FindingStatus, Severity


def finding(severity: Severity) -> FindingCreate:
    """Build a minimal valid finding."""
    return FindingCreate(title="Issue", severity=severity, description="Something is wrong")


def test_gate_blocks_on_open_high_finding():
    services.save_report("shop", "summary", [finding(Severity.HIGH), finding(Severity.LOW)])
    result = services.evaluate_gate("shop")
    assert result["passed"] is False
    assert result["blocking_findings"] == 1


def test_gate_threshold_is_configurable():
    services.save_report("shop", "summary", [finding(Severity.MEDIUM)])
    assert services.evaluate_gate("shop", Severity.HIGH)["passed"] is True
    assert services.evaluate_gate("shop", Severity.MEDIUM)["passed"] is False


def test_gate_unblocks_when_findings_are_triaged(triage):
    saved = services.save_report("shop", "summary", [finding(Severity.CRITICAL)])
    report = services.get_report(saved["report_id"])
    for status in (FindingStatus.FIXED, FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED):
        triage(report.findings[0].id, FindingStatus.OPEN)
        assert services.evaluate_gate("shop")["passed"] is False
        triage(report.findings[0].id, status)
        assert services.evaluate_gate("shop")["passed"] is True


def test_gate_can_target_one_report():
    first = services.save_report("shop", "summary", [finding(Severity.CRITICAL)])
    second = services.save_report("shop", "summary", [finding(Severity.LOW)])
    assert services.evaluate_gate("shop", report_id=second["report_id"])["passed"] is True
    assert services.evaluate_gate("shop", report_id=first["report_id"])["passed"] is False


def test_gate_rejects_unknown_or_foreign_report():
    other = services.save_report("other", "summary", [])
    with pytest.raises(services.NotFoundError):
        services.evaluate_gate("shop", report_id=999)
    with pytest.raises(ValueError):
        services.evaluate_gate("shop", report_id=other["report_id"])


def test_gate_on_unknown_project_passes():
    assert services.evaluate_gate("ghost")["passed"] is True


def test_shipped_example_pack_is_valid(import_pack):
    example = Path(__file__).resolve().parent.parent / "examples" / "rules" / "company.toml"
    import_pack(example.read_text(encoding="utf-8"), example.name)
    snapshot = registry.snapshot()
    assert snapshot.errors == ()
    assert {"ACME-001", "ACME-002", "ACME-003", "ACME-004"} <= snapshot.custom_rule_ids
    assert "payments" in registry.domains()
    matches, _ = registry.scan("npm config set registry https://registry.npmjs.org/", "config")
    assert "ACME-002" in {m["rule_id"] for m in matches}


@pytest.mark.anyio
async def test_new_tools_over_mcp():
    rule_store.import_packs(
        [
            (
                "p.toml",
                '[[rules]]\nid = "ACME-9"\ntitle = "t"\nseverity = "low"\n'
                'languages = ["python"]\npattern = "foo_bar"\n',
            )
        ]
    )
    async with Client(mcp) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {"list_rules", "reload_rules", "check_project_gate"} <= names

        reloaded = await client.call_tool("reload_rules", {})
        assert "ACME-9" not in reloaded.content[0].text  # only counts are returned
        listed = await client.call_tool("list_rules", {"language": "python"})
        assert "ACME-9" in listed.content[0].text

        scan = await client.call_tool(
            "scan_code",
            {"content": "x = foo_bar  # secreview:ignore", "language": "python"},
        )
        assert '"suppressed_count": 1' in scan.content[0].text

        services.save_report("demo", "summary", [finding(Severity.HIGH)])
        gate = await client.call_tool("check_project_gate", {"project": "demo"})
        assert '"passed": false' in gate.content[0].text


def test_gate_blocks_again_when_a_dismissal_expires(triage):
    from security_review_mcp.storage.database import session_scope
    from security_review_mcp.storage.models import Finding, utcnow

    saved = services.save_report("shop", "summary", [finding(Severity.CRITICAL)])
    finding_id = services.get_report(saved["report_id"]).findings[0].id
    triage(finding_id, FindingStatus.ACCEPTED)
    assert services.evaluate_gate("shop")["passed"] is True

    with session_scope() as session:
        stored = session.get(Finding, finding_id)
        stored.status_expires_at = utcnow()
        session.add(stored)

    assert services.evaluate_gate("shop")["passed"] is False
    assert services.project_posture("shop")["open_findings_total"] == 1
    assert services.list_reports("shop")[0]["findings_open"] == 1
    assert services.get_report(saved["report_id"]).findings[0].status == FindingStatus.OPEN


def test_an_agent_proposal_never_unblocks_the_gate():
    saved = services.save_report("shop", "summary", [finding(Severity.CRITICAL)])
    finding_id = services.get_report(saved["report_id"]).findings[0].id
    for status in (FindingStatus.FIXED, FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE):
        services.propose_finding_status(finding_id, status, "The comment says it is safe", "bot")
        assert services.evaluate_gate("shop")["passed"] is False
