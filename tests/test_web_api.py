"""Web interface: REST API, permissions and static files."""

import pytest
from starlette.testclient import TestClient

from security_review_mcp import http_server, registry, server, services, web_api
from security_review_mcp.config import Settings
from security_review_mcp.http_server import parse_tokens
from security_review_mcp.models import FindingCreate, Severity

TOKENS = {
    "reader": "r" * 32,
    "triager": "t" * 32,
    "mcp": "m" * 32,
    "admin": "a" * 32,
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


def test_custom_rule_lifecycle(client, rules_dir):
    pack = rules_dir / "company.toml"
    pack.write_text(
        '# Preserve this note\n\n[[rules]]\nid = "ACME-001"\ntitle = "Unsafe eval"\n'
        'severity = "high"\nlanguages = ["python"]\npattern = "eval\\\\("\n',
        encoding="utf-8",
    )

    listed = client.get("/api/v1/rules").json()
    assert listed["rules"][0]["source"] == "company.toml"
    assert listed["rules"][0]["enabled"] is True

    changed = {
        "id": "ACME-001",
        "title": "Unsafe eval call",
        "severity": "critical",
        "languages": ["python"],
        "pattern": "eval\\(",
        "advice": "Use a safe parser.",
    }
    response = client.put("/api/v1/rules/ACME-001", json=changed)
    assert response.status_code == 200
    assert "Preserve this note" in pack.read_text(encoding="utf-8")
    assert "Unsafe eval call" in pack.read_text(encoding="utf-8")
    assert any(hit["rule_id"] == "ACME-001" for hit in registry.scan("eval(x)", "python")[0])

    response = client.patch("/api/v1/rules/ACME-001/enabled", json={"enabled": False})
    assert response.status_code == 200
    assert client.get("/api/v1/rules").json()["rules"][0]["enabled"] is False
    assert not any(hit["rule_id"] == "ACME-001" for hit in registry.scan("eval(x)", "python")[0])

    assert client.patch("/api/v1/rules/ACME-001/enabled", json={"enabled": True}).status_code == 200
    assert any(hit["rule_id"] == "ACME-001" for hit in registry.scan("eval(x)", "python")[0])

    assert (
        client.patch("/api/v1/rules/ACME-001/enabled", json={"enabled": False}).status_code == 200
    )
    assert client.delete("/api/v1/rules/ACME-001").status_code == 204
    assert client.get("/api/v1/rules").json()["rules"] == []
    assert not any(hit["rule_id"] == "ACME-001" for hit in registry.scan("eval(x)", "python")[0])
    assert "ACME-001" not in registry.snapshot().disabled_rule_ids


def test_rule_creation_and_reload(client, rules_dir):
    response = client.post(
        "/api/v1/rules",
        json={
            "id": "ACME-002",
            "title": "Unsafe dynamic execution",
            "severity": "high",
            "languages": ["python"],
            "pattern": "exec\\(",
            "advice": "Avoid dynamic execution.",
        },
    )
    assert response.status_code == 201
    assert (rules_dir / "web-managed.toml").is_file()
    assert any(hit["rule_id"] == "ACME-002" for hit in registry.scan("exec(x)", "python")[0])

    (rules_dir / "external.toml").write_text(
        '[[rules]]\nid = "ACME-003"\ntitle = "External"\nseverity = "low"\n'
        'languages = ["python"]\npattern = "compile"\n',
        encoding="utf-8",
    )
    response = client.post("/api/v1/rules/reload")
    assert response.status_code == 200
    assert any(hit["rule_id"] == "ACME-003" for hit in registry.scan("compile(x)", "python")[0])


def test_rule_validation_and_admin_permissions(client, secured, rules_dir):
    invalid = client.post(
        "/api/v1/rules",
        json={
            "id": "ACME-004",
            "title": "Backtracking",
            "severity": "high",
            "languages": ["python"],
            "pattern": "(a+)+$",
        },
    )
    assert invalid.status_code == 422
    assert not (rules_dir / "web-managed.toml").exists()

    payload = {
        "id": "ACME-004",
        "title": "Safe pattern",
        "severity": "high",
        "languages": ["python"],
        "pattern": "safe_call\\(",
    }
    assert secured.post("/api/v1/rules", json=payload, headers=auth("triager")).status_code == 403
    assert secured.get("/api/v1/rules", headers=auth("reader")).status_code == 403
    assert secured.post("/api/v1/rules", json=payload, headers=auth("admin")).status_code == 201


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


def test_openapi_marks_api_operations_as_bearer_protected(secured):
    response = secured.get("/api/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert schema["components"]["securitySchemes"]["HTTPBearer"] == {
        "type": "http",
        "scheme": "bearer",
    }
    operations = [
        operation
        for path, methods in schema["paths"].items()
        if path.startswith("/api/v1/")
        for method, operation in methods.items()
        if method in {"get", "post", "put", "patch", "delete"}
    ]
    assert operations
    assert all({"HTTPBearer": []} in operation.get("security", []) for operation in operations)
    assert secured.get("/api/v1/projects").status_code == 401


def test_admin_creates_project_token_scoped_to_one_project(secured, reports, tmp_path, monkeypatch):
    token_file = tmp_path / "project-tokens.json"
    monkeypatch.setattr(
        web_api,
        "get_settings",
        lambda: Settings(_env_file=None, auth_managed_tokens_file=str(token_file)),
    )
    shop_report_id, billing_report_id = reports
    created_response = secured.post(
        "/api/v1/project-tokens",
        json={"label": "shop-ci", "project": "shop-api"},
        headers=auth("admin"),
    )

    assert created_response.status_code == 201
    created = created_response.json()
    token = created["token"]
    stored = token_file.read_text(encoding="utf-8")
    assert token not in stored
    assert http_server.hash_token(token).removeprefix("sha256:") in stored

    listed = secured.get("/api/v1/project-tokens", headers=auth("admin"))
    assert listed.status_code == 200
    assert listed.json() == [
        {key: created[key] for key in ("id", "label", "project", "created_at")}
    ]
    assert token not in listed.text
    assert "sha256" not in listed.text
    assert (
        secured.post(
            "/api/v1/project-tokens",
            json={"label": "denied", "project": "shop-api"},
            headers=auth("reader"),
        ).status_code
        == 403
    )

    project_headers = {"Authorization": f"Bearer {token}"}
    identity = secured.get("/api/v1/me", headers=project_headers).json()
    assert (identity["role"], identity["project"], identity["can_triage"]) == (
        "reader",
        "shop-api",
        False,
    )
    assert [
        item["project"] for item in secured.get("/api/v1/projects", headers=project_headers).json()
    ] == ["shop-api"]
    assert all(
        report["project"] == "shop-api"
        for report in secured.get("/api/v1/reports", headers=project_headers).json()
    )
    assert (
        secured.get(f"/api/v1/reports/{shop_report_id}", headers=project_headers).status_code == 200
    )
    assert (
        secured.get(
            f"/api/v1/reports/{shop_report_id}/markdown", headers=project_headers
        ).status_code
        == 200
    )
    assert (
        secured.get(
            "/api/v1/posture", params={"project": "shop-api"}, headers=project_headers
        ).status_code
        == 200
    )
    assert (
        secured.get(
            "/api/v1/trend", params={"project": "shop-api"}, headers=project_headers
        ).status_code
        == 200
    )
    assert secured.get("/api/v1/sarif", headers=project_headers).status_code == 200
    assert (
        secured.get(f"/api/v1/reports/{billing_report_id}", headers=project_headers).status_code
        == 404
    )
    assert (
        secured.get(
            "/api/v1/reports", params={"project": "billing"}, headers=project_headers
        ).status_code
        == 404
    )
    assert (
        secured.get(
            "/api/v1/posture", params={"project": "billing"}, headers=project_headers
        ).status_code
        == 404
    )
    assert (
        secured.get(
            "/api/v1/trend", params={"project": "billing"}, headers=project_headers
        ).status_code
        == 404
    )
    assert (
        secured.get(
            "/api/v1/sarif", params={"report_id": billing_report_id}, headers=project_headers
        ).status_code
        == 404
    )
    assert (
        secured.get(
            "/api/v1/sarif", params={"project": "billing"}, headers=project_headers
        ).status_code
        == 404
    )
    assert secured.get("/mcp", headers=project_headers).status_code == 403
    assert (
        secured.patch(
            "/api/v1/findings/1",
            json={"status": "fixed"},
            headers=project_headers,
        ).status_code
        == 403
    )

    revoked = secured.delete(f"/api/v1/project-tokens/{created['id']}", headers=auth("admin"))
    assert revoked.status_code == 204
    assert secured.get("/api/v1/me", headers=project_headers).status_code == 401
    assert token not in token_file.read_text(encoding="utf-8")


def test_project_token_management_requires_a_configured_file(secured, reports, monkeypatch):
    monkeypatch.setattr(web_api, "get_settings", lambda: Settings(_env_file=None))

    assert secured.get("/api/v1/project-tokens", headers=auth("admin")).status_code == 503
    response = secured.post(
        "/api/v1/project-tokens",
        json={"label": "ci", "project": "shop-api"},
        headers=auth("admin"),
    )
    assert response.status_code == 503


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
