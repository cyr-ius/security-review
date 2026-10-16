"""Tests for the report persistence service."""

from datetime import timedelta

import pytest
from sqlmodel import select

from security_review_mcp import services
from security_review_mcp.config import Settings
from security_review_mcp.database import session_scope
from security_review_mcp.models import (
    FindingCreate,
    FindingStatus,
    SecurityReport,
    Severity,
    utcnow,
)


def make_finding(severity: Severity = Severity.HIGH, **kwargs) -> FindingCreate:
    """Build a valid finding with sensible defaults."""
    data = {
        "title": "SQL injection",
        "severity": severity,
        "description": "User input concatenated in a query",
        "cwe": "89",
        "file_path": "app/db.py",
        "line_start": 10,
        "line_end": 12,
    }
    data.update(kwargs)
    return FindingCreate(**data)


def test_save_and_get_report():
    saved = services.save_report(
        project="shop-api",
        summary="Review of the checkout module",
        findings=[make_finding(Severity.HIGH), make_finding(Severity.LOW, title="Weak hash")],
        branch="main",
        commit_sha="abc123",
    )
    assert saved["risk_level"] == "high"
    assert saved["findings_count"] == 2
    assert saved["findings_by_severity"] == {"high": 1, "low": 1}

    report = services.get_report(saved["report_id"])
    assert report.project == "shop-api"
    assert report.risk_level == Severity.HIGH
    assert len(report.findings) == 2
    assert report.findings[0].cwe == "CWE-89"  # normalized
    assert all(f.status == FindingStatus.OPEN for f in report.findings)


def test_empty_report_is_info_risk():
    saved = services.save_report("clean", "Nothing found", [])
    assert saved["risk_level"] == "info"


def test_risk_override_can_only_raise():
    raised = services.save_report(
        "p", "summary", [make_finding(Severity.LOW)], risk_level=Severity.HIGH
    )
    assert raised["risk_level"] == "high"
    kept = services.save_report(
        "p", "summary", [make_finding(Severity.HIGH)], risk_level=Severity.LOW
    )
    assert kept["risk_level"] == "high"


def test_secrets_are_masked_before_storage():
    finding = make_finding(
        evidence='password = "SuperSecret123"',
        description="Leaked token Bearer abcdefghijklmnop12345 in code",
    )
    saved = services.save_report("p", 'api_key="AKIAABCDEFGHIJKLMNOP"', [finding])
    report = services.get_report(saved["report_id"])
    stored = report.findings[0]
    assert "SuperSecret123" not in (stored.evidence or "")
    assert "abcdefghijklmnop12345" not in stored.description
    assert "AKIAABCDEFGHIJKLMNOP" not in report.summary


def test_too_many_findings_rejected(monkeypatch):
    monkeypatch.setattr(services.get_settings(), "max_findings_per_report", 2)
    with pytest.raises(ValueError):
        services.save_report("p", "summary", [make_finding() for _ in range(3)])


def test_invalid_finding_is_rejected():
    with pytest.raises(ValueError):
        make_finding(cwe="not-a-cwe")
    with pytest.raises(ValueError):
        make_finding(line_start=0)


def test_line_end_is_never_before_line_start():
    saved = services.save_report("p", "summary", [make_finding(line_start=20, line_end=5)])
    finding = services.get_report(saved["report_id"]).findings[0]
    assert finding.line_end == 20


def test_list_reports_filters_and_counts():
    services.save_report("a", "report a", [make_finding(Severity.CRITICAL)])
    services.save_report("b", "report b", [make_finding(Severity.LOW), make_finding(Severity.LOW)])

    everything = services.list_reports()
    assert [r["project"] for r in everything] == ["b", "a"]  # newest first
    assert everything[0]["findings_total"] == 2
    assert everything[0]["findings_open"] == 2

    assert [r["project"] for r in services.list_reports(project="a")] == ["a"]
    assert [r["project"] for r in services.list_reports(risk_level=Severity.CRITICAL)] == ["a"]
    assert len(services.list_reports(limit=1)) == 1
    assert len(services.list_reports(limit=1, offset=1)) == 1


def test_update_finding_status_and_posture():
    saved = services.save_report(
        "shop", "summary", [make_finding(Severity.CRITICAL), make_finding(Severity.LOW)]
    )
    report = services.get_report(saved["report_id"])
    critical = next(f for f in report.findings if f.severity == Severity.CRITICAL)

    before = services.project_posture("shop")
    assert before["open_findings_total"] == 2
    assert before["worst_open_severity"] == "critical"

    updated = services.update_finding_status(critical.id, FindingStatus.FIXED)
    assert updated.status == FindingStatus.FIXED

    after = services.project_posture("shop")
    assert after["open_findings_total"] == 1
    assert after["worst_open_severity"] == "low"
    assert services.list_reports(project="shop")[0]["findings_open"] == 1


def test_list_project_findings_across_reports(monkeypatch):
    first = services.save_report(
        "shop",
        "first",
        [make_finding(Severity.LOW, title="Weak hash"), make_finding(Severity.HIGH)],
        branch="main",
    )
    services.save_report(
        "shop",
        "second",
        [make_finding(Severity.CRITICAL, title="RCE", evidence="token = 'ghp_" + "a" * 36 + "'")],
        commit_sha="abc123",
    )
    services.save_report("other", "other project", [make_finding(Severity.CRITICAL)])
    low = next(
        f for f in services.get_report(first["report_id"]).findings if f.title == "Weak hash"
    )
    services.update_finding_status(low.id, FindingStatus.ACCEPTED)

    page = services.list_project_findings("shop")
    assert page["total"] == 2
    assert [f["severity"] for f in page["findings"]] == [Severity.CRITICAL, Severity.HIGH]
    critical, high = page["findings"]
    assert critical["commit_sha"] == "abc123"
    assert high["branch"] == "main"
    assert high["report_id"] == first["report_id"]
    assert "ghp_" + "a" * 36 not in critical["evidence"]  # stored masked

    accepted = services.list_project_findings("shop", status=FindingStatus.ACCEPTED)
    assert [f["id"] for f in accepted["findings"]] == [low.id]
    assert services.list_project_findings("shop", severity=Severity.HIGH)["total"] == 1
    assert services.list_project_findings("unknown") == {
        "project": "unknown",
        "total": 0,
        "findings": [],
    }

    # Paging, and the limit is capped by SECREVIEW_MAX_LIST_LIMIT
    second_page = services.list_project_findings("shop", limit=1, offset=1)
    assert second_page["total"] == 2
    assert [f["severity"] for f in second_page["findings"]] == [Severity.HIGH]
    monkeypatch.setattr(services.get_settings(), "max_list_limit", 1)
    assert len(services.list_project_findings("shop", limit=50)["findings"]) == 1


def test_posture_of_unknown_project_is_empty():
    posture = services.project_posture("ghost")
    assert posture["reports_total"] == 0
    assert posture["worst_open_severity"] is None


def test_not_found_errors():
    with pytest.raises(services.NotFoundError):
        services.get_report(999)
    with pytest.raises(services.NotFoundError):
        services.update_finding_status(999, FindingStatus.FIXED)


def test_markdown_rendering_orders_by_severity():
    saved = services.save_report(
        "shop",
        "Summary text",
        [
            make_finding(Severity.LOW, title="Minor issue"),
            make_finding(Severity.CRITICAL, title="Major issue", evidence="exec(x)"),
        ],
    )
    markdown = services.render_report_markdown(services.get_report(saved["report_id"]))
    assert "# Security report" in markdown
    assert markdown.index("Major issue") < markdown.index("Minor issue")
    assert "`app/db.py:10-12`" in markdown
    assert "exec(x)" in markdown


def test_blank_project_or_summary_is_rejected():
    with pytest.raises(ValueError):
        services.save_report("  ", "A valid summary", [])
    with pytest.raises(ValueError):
        services.save_report("project", "ab", [])


def test_list_projects():
    assert services.list_projects() == []
    services.save_report("shop", "First", [make_finding(Severity.HIGH), make_finding(Severity.LOW)])
    clean = services.save_report("billing", "Clean", [])
    report = services.get_report(services.list_reports(project="shop")[0]["report_id"])
    services.update_finding_status(report.findings[0].id, FindingStatus.FIXED)

    projects = {p["project"]: p for p in services.list_projects()}
    assert list(projects) == ["billing", "shop"]  # latest report first
    shop = projects["shop"]
    assert shop["reports_total"] == 1
    assert shop["open_findings_total"] == 1
    assert shop["open_findings_by_severity"]["low"] == 1
    assert shop["worst_open_severity"] == "low"
    billing = projects["billing"]
    assert billing["open_findings_total"] == 0
    assert billing["worst_open_severity"] is None
    assert (
        billing["last_report_at"] == services.get_report(clean["report_id"]).created_at.isoformat()
    )


def age_report(report_id: int, days: int) -> None:
    """Move the creation date of a report ``days`` days back."""
    with session_scope() as session:
        report = session.get(SecurityReport, report_id)
        report.created_at = utcnow() - timedelta(days=days)
        session.add(report)


def stored_report_ids() -> set[int]:
    """Return the ids of the stored reports."""
    with session_scope() as session:
        return set(session.exec(select(SecurityReport.id)).all())


def test_prune_deletes_only_old_reports_without_findings():
    old_empty = services.save_report("shop", "Old clean review", [])["report_id"]
    old_with_finding = services.save_report("shop", "Old review", [make_finding()])["report_id"]
    old_fixed = services.save_report("shop", "Old fixed review", [make_finding()])["report_id"]
    services.update_finding_status(services.get_report(old_fixed).findings[0].id, "fixed")
    recent_empty = services.save_report("shop", "Recent clean review", [])["report_id"]
    latest = services.save_report("shop", "Latest clean review", [])["report_id"]
    for report_id in (old_empty, old_with_finding, old_fixed, latest):
        age_report(report_id, 100)
    age_report(recent_empty, 10)

    assert services.prune_empty_reports(90) == {"retention_days": 90, "deleted": 1}

    # A report with findings (even fixed), a recent one and the latest of the project stay
    assert stored_report_ids() == {old_with_finding, old_fixed, recent_empty, latest}


def test_prune_keeps_the_latest_report_of_each_project():
    first = services.save_report("shop", "Clean review", [])["report_id"]
    other = services.save_report("billing", "Clean review", [])["report_id"]
    age_report(first, 365)
    age_report(other, 365)

    assert services.prune_empty_reports(90)["deleted"] == 0
    assert stored_report_ids() == {first, other}


def test_prune_uses_the_setting_and_zero_disables_it(monkeypatch):
    old = services.save_report("shop", "Old clean review", [])["report_id"]
    services.save_report("shop", "Latest clean review", [])
    age_report(old, 40)

    monkeypatch.setattr(
        services, "get_settings", lambda: Settings(_env_file=None, empty_report_retention_days=0)
    )
    assert services.prune_empty_reports() == {"retention_days": 0, "deleted": 0}
    monkeypatch.setattr(
        services, "get_settings", lambda: Settings(_env_file=None, empty_report_retention_days=30)
    )
    assert services.prune_empty_reports() == {"retention_days": 30, "deleted": 1}
    assert old not in stored_report_ids()


@pytest.mark.parametrize("days", [-1, 36_501, 10**9])
def test_prune_refuses_an_out_of_range_retention(days):
    with pytest.raises(ValueError, match="retention_days"):
        services.prune_empty_reports(days)


def test_retention_setting_defaults_to_90_days_and_rejects_negative_values():
    assert Settings(_env_file=None).empty_report_retention_days == 90
    with pytest.raises(ValueError):
        Settings(_env_file=None, empty_report_retention_days=-1)
