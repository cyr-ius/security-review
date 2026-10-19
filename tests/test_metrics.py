"""Prometheus metrics of the controller: values, format and escaping."""

import re
from datetime import UTC, datetime, timedelta

from conftest import make_user

from security_review_mcp import access_control, http_server, metrics, services, token_store
from security_review_mcp.database import session_scope
from security_review_mcp.http_server import Role
from security_review_mcp.models import AdvisoryUpdate, FindingCreate, FindingStatus, Severity

# A sample line: name, optional labels, value
SAMPLE = re.compile(r'^[a-z_]+(\{([a-z_]+="([^"\\\n]|\\.)*",?)*\})? -?[0-9.e+]+$')


def finding(severity: Severity, title: str = "SQL injection") -> FindingCreate:
    return FindingCreate(title=title, severity=severity, description="Concatenated query")


def test_metrics_count_findings_tokens_and_users(triage):
    report = services.save_report(
        "shop-api", "Review", [finding(Severity.HIGH), finding(Severity.LOW, "Weak hash")]
    )
    high, low = services.get_report(report["report_id"]).findings
    triage(low.id, "accepted")
    services.propose_finding_status(high.id, FindingStatus.FIXED, "Query is now bound", "bot")
    services.save_report("billing", "Clean review", [])
    token_store.create_token("dev", Role.MCP)
    token_store.create_token("soon", Role.MCP, expires_in_days=3)
    access_control.enroll_project("crm")
    make_user("alice", "Correct horse battery 9", "reader")

    text = metrics.render()

    for line in (
        "secreview_projects 2",
        "secreview_reports 2",
        'secreview_findings{status="open"} 1',
        'secreview_findings{status="accepted"} 1',
        'secreview_open_findings{severity="high"} 1',
        'secreview_open_findings{severity="low"} 0',
        'secreview_project_open_findings{project="shop-api",severity="high"} 1',
        'secreview_project_open_findings{project="billing",severity="high"} 0',
        "secreview_finding_proposals_pending 1",
        'secreview_tokens{role="mcp",state="active"} 2',
        "secreview_tokens_expiring_soon 1",
        "secreview_project_enrollments_pending 1",
        'secreview_web_users{auth_source="local"} 1',
        "secreview_advisories 0",
        'secreview_auth_rejections_total{reason="token_expired"} '
        f"{http_server.AUTH_REJECTIONS['token_expired']}",
    ):
        assert line in text.splitlines(), line
    # No OSV download yet: no timestamp
    assert "secreview_advisory_last_update_timestamp_seconds" not in text


def test_every_line_follows_the_exposition_format():
    services.save_report('evil"} 1\nsecreview_fake 9', "Review", [finding(Severity.HIGH)])

    text = metrics.render()

    assert text.endswith("\n")
    for line in text.splitlines():
        assert line.startswith("# HELP ") or line.startswith("# TYPE ") or SAMPLE.match(line), line
    assert "\nsecreview_fake" not in text
    # The project name is normalized before storage: no quote or newline reaches the label
    assert 'project="evil-1-secreview-fake-9"' in text


def test_escape_label():
    assert metrics.escape_label('a\\b"c\nd') == 'a\\\\b\\"c\\nd'


def test_latest_successful_advisory_update_is_exposed():
    finished = datetime.now(UTC) - timedelta(hours=1)
    with session_scope() as session:
        session.add(AdvisoryUpdate(trigger="cli", status="success", finished_at=finished))
        session.add(AdvisoryUpdate(trigger="cli", status="failed", finished_at=datetime.now(UTC)))

    text = metrics.render()

    line = next(
        line
        for line in text.splitlines()
        if line.startswith("secreview_advisory_last_update_timestamp_seconds ")
    )
    assert abs(float(line.split()[1]) - finished.timestamp()) < 1


def test_metrics_never_expose_a_secret():
    created = token_store.create_token("dev", Role.MCP)

    assert created["token"] not in metrics.render()
    assert "dev" not in metrics.render()
