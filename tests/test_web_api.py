"""Web interface: REST API, permissions and static files."""

import pytest
from starlette.testclient import TestClient

from security_review_mcp import http_server, server, services, web_api
from security_review_mcp.http_server import parse_tokens
from security_review_mcp.models import FindingCreate, Severity

TOKENS = {
    "reader": "r" * 32,
    "triager": "t" * 32,
    "mcp": "m" * 32,
}


def make_finding(severity: Severity = Severity.HIGH, **kwargs) -> FindingCreate:
    data = {"title": "SQL injection", "severity": severity, "description": "Concatenated query"}
    data.update(kwargs)
    return FindingCreate(**data)


@pytest.fixture
def ui_dir(tmp_path):
    """A fake Angular build."""
    (tmp_path / "index.html").write_text("<html>app</html>", encoding="utf-8")
    (tmp_path / "main.js").write_text("console.log(1)", encoding="utf-8")
    return tmp_path


@pytest.fixture
def client(ui_dir) -> TestClient:
    """The web app without authentication (everyone is admin)."""
    return TestClient(web_api.create_app(ui_dir=str(ui_dir)), base_url="http://127.0.0.1")


@pytest.fixture
def secured(ui_dir) -> TestClient:
    """The full HTTP app (MCP + web) protected by role tokens."""
    tokens = parse_tokens(f"{role}:{role}:{token}" for role, token in TOKENS.items())
    app = http_server.build_app(
        server.mcp, "127.0.0.1", tokens, web_api.create_app(ui_dir=str(ui_dir))
    )
    return TestClient(app, base_url="http://127.0.0.1")


def auth(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


@pytest.fixture
def reports() -> tuple[int, int]:
    first = services.save_report(
        "shop-api",
        "First review",
        [make_finding(Severity.HIGH), make_finding(Severity.LOW, title="Weak hash")],
    )
    second = services.save_report("billing", "Clean review", [])
    return first["report_id"], second["report_id"]


# ── Read endpoints ───────────────────────────────────────────────────────────


def test_me_without_authentication(client):
    body = client.get("/api/v1/me").json()
    assert body["client"] == "anonymous"
    assert body["role"] == "admin"
    assert body["can_triage"] is True
    assert body["auth_enabled"] is False


def test_projects(client, reports):
    projects = client.get("/api/v1/projects").json()
    assert [p["project"] for p in projects] == ["billing", "shop-api"]
    shop = projects[1]
    assert shop["open_findings_total"] == 2
    assert shop["open_findings_by_severity"]["high"] == 1
    assert shop["worst_open_severity"] == "high"
    assert projects[0]["worst_open_severity"] is None


def test_reports_list_and_detail(client, reports):
    shop_id, _ = reports
    listed = client.get("/api/v1/reports", params={"project": "shop-api"}).json()
    assert [r["report_id"] for r in listed] == [shop_id]
    assert listed[0]["findings_open"] == 2

    detail = client.get(f"/api/v1/reports/{shop_id}").json()
    assert detail["risk_level"] == "high"
    assert len(detail["findings"]) == 2

    markdown = client.get(f"/api/v1/reports/{shop_id}/markdown")
    assert markdown.headers["content-type"].startswith("text/markdown")
    assert "# Security report" in markdown.text


def test_unknown_report_is_404(client):
    response = client.get("/api/v1/reports/999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_posture_trend_and_sarif(client, reports):
    posture = client.get("/api/v1/posture", params={"project": "shop-api"}).json()
    assert posture["open_findings_total"] == 2

    trend = client.get("/api/v1/trend", params={"project": "shop-api", "days": 30}).json()
    assert trend["summary"]["open_now_total"] == 2
    assert client.get("/api/v1/trend", params={"project": "x", "days": 0}).status_code == 422

    sarif = client.get("/api/v1/sarif", params={"project": "shop-api"})
    assert sarif.headers["content-type"] == "application/sarif+json"
    assert len(sarif.json()["runs"][0]["results"]) == 2
    assert client.get("/api/v1/sarif").status_code == 422


def test_update_finding_status(client, reports):
    finding = client.get(f"/api/v1/reports/{reports[0]}").json()["findings"][0]
    response = client.patch(f"/api/v1/findings/{finding['id']}", json={"status": "accepted"})
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert client.patch("/api/v1/findings/1", json={"status": "bogus"}).status_code == 422
    assert client.patch("/api/v1/findings/999", json={"status": "fixed"}).status_code == 404


# ── Permissions ──────────────────────────────────────────────────────────────


def test_reader_can_read_but_not_triage(secured, reports):
    me = secured.get("/api/v1/me", headers=auth("reader")).json()
    assert (me["client"], me["role"], me["can_triage"]) == ("reader", "reader", False)
    assert secured.get("/api/v1/projects", headers=auth("reader")).status_code == 200

    response = secured.patch("/api/v1/findings/1", json={"status": "fixed"}, headers=auth("reader"))
    assert response.status_code == 403


def test_triager_can_change_status(secured, reports):
    response = secured.patch(
        "/api/v1/findings/1", json={"status": "false_positive"}, headers=auth("triager")
    )
    assert response.status_code == 200
    assert response.json()["status"] == "false_positive"


def test_mcp_token_cannot_use_the_api(secured):
    assert secured.get("/api/v1/projects", headers=auth("mcp")).status_code == 403
    assert secured.get("/api/v1/projects").status_code == 401


# ── Static files ─────────────────────────────────────────────────────────────


def test_ui_is_served_with_security_headers(secured):
    assert secured.get("/", follow_redirects=False).headers["location"] == "/ui/"
    index = secured.get("/ui/")
    assert index.text == "<html>app</html>"
    assert "frame-ancestors 'none'" in index.headers["content-security-policy"]
    assert index.headers["cache-control"] == "no-cache"
    assert secured.get("/ui/main.js").text == "console.log(1)"


def test_ui_client_side_routes_fall_back_to_index(client):
    assert client.get("/ui/reports/12").text == "<html>app</html>"


def test_missing_ui_build(tmp_path):
    with pytest.raises(ValueError, match="no index.html"):
        web_api.create_app(ui_dir=str(tmp_path))
    assert web_api.resolve_ui_dir(None) in (None, web_api.BUNDLED_UI_DIR)


def test_loopback_server_rejects_foreign_host(ui_dir):
    app = web_api.create_app(host="127.0.0.1", ui_dir=str(ui_dir))
    for base_url, expected in (("http://evil.example", 400), ("http://localhost:8000", 200)):
        assert TestClient(app, base_url=base_url).get("/api/v1/health").status_code == expected
