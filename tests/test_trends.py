"""Tests for the trend report."""

from datetime import UTC, datetime, timedelta

import pytest

from security_review_mcp import services, trends
from security_review_mcp.database import session_scope
from security_review_mcp.models import (
    Finding,
    FindingCreate,
    FindingStatus,
    SecurityReport,
    Severity,
)
from security_review_mcp.trends import TrendFinding, TrendReport

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)  # a Sunday


def at(month: int, day: int) -> datetime:
    """Return a UTC date in 2026."""
    return datetime(2026, month, day, tzinfo=UTC)


def sample() -> tuple[list[TrendFinding], list[TrendReport]]:
    """Four findings with known histories (see the expected values in the tests)."""
    findings = [
        TrendFinding(Severity.CRITICAL, FindingStatus.FIXED, "CWE-89", at(9, 15), at(10, 1)),
        TrendFinding(Severity.HIGH, FindingStatus.OPEN, "CWE-79", at(9, 22), None),
        TrendFinding(Severity.LOW, FindingStatus.OPEN, "CWE-79", at(10, 6), None),
        TrendFinding(Severity.MEDIUM, FindingStatus.ACCEPTED, None, at(9, 8), at(9, 20)),
    ]
    reports = [TrendReport(at(9, 8), Severity.MEDIUM), TrendReport(at(10, 6), Severity.LOW)]
    return findings, reports


def test_weekly_periods_and_backlog():
    findings, reports = sample()
    trend = trends.compute_trend(findings, reports, "shop", days=28, granularity="week", now=NOW)
    periods = trend["periods"]
    assert [p["period"] for p in periods] == [
        "2026-09-07",
        "2026-09-14",
        "2026-09-21",
        "2026-09-28",
        "2026-10-05",
    ]
    assert [p["risk_score"] for p in periods] == [2, 10, 15, 5, 6]
    assert [p["new_total"] for p in periods] == [1, 1, 1, 0, 1]
    assert periods[3]["fixed_total"] == 1  # the critical finding fixed on 1 October
    assert periods[1]["dismissed_total"] == 1  # the accepted one
    assert periods[0]["reports"] == 1 and periods[0]["worst_report_risk"] == "medium"
    assert trend["direction"] == "worsening"  # 5 -> 6 is +20%


def test_summary_mttr_and_oldest():
    findings, reports = sample()
    summary = trends.compute_trend(findings, reports, "shop", 28, "week", NOW)["summary"]
    assert summary["open_now"]["high"] == 1 and summary["open_now"]["low"] == 1
    assert summary["risk_score_now"] == 6
    assert summary["mttr_days"]["critical"] == {"count": 1, "mean_days": 16.0, "median_days": 16.0}
    assert summary["oldest_open_days"]["high"] == pytest.approx(19.5)
    assert summary["top_open_cwes"] == [{"cwe": "CWE-79", "count": 2}]
    assert summary["fixed_findings"] == 1 and summary["dismissed_findings"] == 1


@pytest.mark.parametrize(
    "scores, expected",
    [
        ([10], "insufficient_data"),
        ([10, 5], "improving"),
        ([10, 20], "worsening"),
        ([10, 10], "stable"),
        ([10, 10 + 1], "stable"),  # +10% is inside the tolerance
        ([0, 0], "stable"),
        ([0, 3], "worsening"),
    ],
)
def test_direction(scores, expected):
    assert trends._direction(scores) == expected


def test_naive_datetimes_from_sqlite_are_accepted():
    naive = datetime(2026, 10, 1)
    finding = TrendFinding(Severity.HIGH, FindingStatus.OPEN, None, naive, None)
    trend = trends.compute_trend([finding], [], "p", 14, "week", NOW)
    assert trend["summary"]["open_now_total"] == 1


def test_closed_findings_without_a_date_are_noted_and_excluded():
    old = TrendFinding(Severity.HIGH, FindingStatus.FIXED, None, at(9, 1), None)
    trend = trends.compute_trend([old], [], "p", 30, "week", NOW)
    assert trend["summary"]["open_now_total"] == 0
    assert trend["summary"]["mttr_days"] == {}
    assert any("predate" in note for note in trend["notes"])


def test_month_and_day_granularity():
    month = trends.compute_trend([], [], "p", 90, "month", NOW)
    assert month["periods"][-1]["period"] == "2026-10"
    day = trends.compute_trend([], [], "p", 3, "day", NOW)
    assert len(day["periods"]) == 4


def test_invalid_parameters():
    with pytest.raises(ValueError):
        trends.compute_trend([], [], "p", 0, "week", NOW)
    with pytest.raises(ValueError):
        trends.compute_trend([], [], "p", 30, "year", NOW)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Too many periods"):
        trends.compute_trend([], [], "p", 400, "day", NOW)


def test_unknown_project_has_a_note():
    trend = trends.get_trend("ghost")
    assert trend["summary"]["reports_total"] == 0
    assert any("No report" in note for note in trend["notes"])


def test_database_round_trip_and_markdown(triage):
    finding = FindingCreate(title="Issue", severity=Severity.HIGH, description="Something wrong")
    saved = services.save_report("shop", "summary", [finding])
    fixed_id = services.get_report(saved["report_id"]).findings[0].id

    # Move the history into the past to get a measurable time to fix
    with session_scope() as session:
        report = session.get(SecurityReport, saved["report_id"])
        report.created_at = datetime.now(UTC) - timedelta(days=10)
        session.add(report)
    triage(fixed_id, FindingStatus.FIXED)
    with session_scope() as session:
        row = session.get(Finding, fixed_id)
        assert row.status_changed_at is not None  # stamped by update_finding_status

    trend = trends.get_trend("shop", days=30, granularity="week")
    assert trend["summary"]["fixed_findings"] == 1
    assert trend["summary"]["mttr_days"]["high"]["mean_days"] == pytest.approx(10, abs=0.1)
    assert trend["summary"]["open_now_total"] == 0

    markdown = trends.render_trend_markdown(trend)
    assert "# Security trend - shop" in markdown
    assert "| Period |" in markdown and "Time to remediate" in markdown


def test_reopening_does_not_restamp_without_a_change(triage):
    saved = services.save_report(
        "shop", "summary", [FindingCreate(title="Issue", severity=Severity.LOW, description="Text")]
    )
    finding_id = services.get_report(saved["report_id"]).findings[0].id
    first = triage(finding_id, FindingStatus.OPEN)
    assert first.status_changed_at is None  # no change, no stamp
    changed = triage(finding_id, FindingStatus.FIXED)
    assert changed.status_changed_at is not None


def test_an_expired_acceptance_counts_as_open():
    expired = TrendFinding(
        Severity.HIGH, FindingStatus.ACCEPTED, None, at(9, 1), at(9, 2), at(10, 1)
    )
    valid = TrendFinding(
        Severity.HIGH, FindingStatus.FALSE_POSITIVE, None, at(9, 1), at(9, 2), at(12, 1)
    )
    trend = trends.compute_trend([expired, valid], [], "shop", now=NOW)
    assert trend["summary"]["open_now_total"] == 1
