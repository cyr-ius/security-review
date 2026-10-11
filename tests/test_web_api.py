"""Web interface: REST API, permissions and static files."""

import pytest
from sqlmodel import Session, select
from starlette.testclient import TestClient

from security_review_mcp import (
    http_server,
    registry,
    rule_store,
    server,
    services,
    token_store,
    web_api,
)
from security_review_mcp.database import session_scope
from security_review_mcp.http_server import Role
from security_review_mcp.models import ApiToken, FindingCreate, Severity

# Raw secret of one token per role, created in the database by the ``secured`` fixture
TOKENS: dict[str, str] = {}


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
    """The full HTTP app (MCP + web) protected by one token per role."""
    TOKENS.clear()
    for role in Role:
        TOKENS[role.value] = token_store.create_token(role.value, role)["token"]
    app = http_server.build_app(
        server.mcp,
        "127.0.0.1",
        token_store.DatabaseTokenStore(),
        web_api.create_app(ui_dir=str(ui_dir)),
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


def custom_rules(client) -> list[dict]:
    """Return the custom rules listed by the API (the default rules are listed too)."""
    return [row for row in client.get("/api/v1/rules").json()["rules"] if row["origin"] == "custom"]


def test_custom_rule_lifecycle(client, import_pack):
    import_pack(
        '[[rules]]\nid = "ACME-001"\ntitle = "Unsafe eval"\n'
        'severity = "high"\nlanguages = ["python"]\npattern = "eval\\\\("\n'
    )

    listed = client.get("/api/v1/rules").json()
    assert custom_rules(client)[0]["id"] == "ACME-001"
    assert custom_rules(client)[0]["enabled"] is True
    assert listed["load_errors"] == []

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
    assert custom_rules(client)[0]["title"] == "Unsafe eval call"
    assert any(hit["rule_id"] == "ACME-001" for hit in registry.scan("eval(x)", "python")[0])

    response = client.patch("/api/v1/rules/ACME-001/enabled", json={"enabled": False})
    assert response.status_code == 200
    assert custom_rules(client)[0]["enabled"] is False
    assert not any(hit["rule_id"] == "ACME-001" for hit in registry.scan("eval(x)", "python")[0])

    assert client.patch("/api/v1/rules/ACME-001/enabled", json={"enabled": True}).status_code == 200
    assert any(hit["rule_id"] == "ACME-001" for hit in registry.scan("eval(x)", "python")[0])

    assert (
        client.patch("/api/v1/rules/ACME-001/enabled", json={"enabled": False}).status_code == 200
    )
    assert client.delete("/api/v1/rules/ACME-001").status_code == 204
    assert custom_rules(client) == []
    assert not any(hit["rule_id"] == "ACME-001" for hit in registry.scan("eval(x)", "python")[0])
    assert "ACME-001" not in registry.snapshot().disabled_rule_ids
    assert client.delete("/api/v1/rules/ACME-001").status_code == 422
    assert client.delete("/api/v1/rules/PY-001").status_code == 422


def test_builtin_rule_can_be_disabled(client):
    response = client.patch("/api/v1/rules/PY-001/enabled", json={"enabled": False})
    assert response.status_code == 200
    assert "PY-001" in registry.snapshot().disabled_rule_ids
    unknown = client.patch("/api/v1/rules/ACME-404/enabled", json={"enabled": False})
    assert unknown.status_code == 422


def test_rule_creation_and_reload(client):
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
    assert response.json() == {"loaded_rules": 1, "load_errors": []}
    assert any(hit["rule_id"] == "ACME-002" for hit in registry.scan("exec(x)", "python")[0])

    # A change made by the CLI in another process is applied by the reload button
    rule_store.import_packs(
        [
            (
                "external.toml",
                '[[rules]]\nid = "ACME-003"\ntitle = "External"\nseverity = "low"\n'
                'languages = ["python"]\npattern = "compile"\n',
            )
        ]
    )
    response = client.post("/api/v1/rules/reload")
    assert response.status_code == 200
    assert any(hit["rule_id"] == "ACME-003" for hit in registry.scan("compile(x)", "python")[0])


def test_rule_validation_and_admin_permissions(client, secured):
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
    assert "ACME-004" not in {row["id"] for row in rule_store.list_rules()}

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


def test_admin_creates_project_token_scoped_to_one_project(secured, reports, database):
    shop_report_id, billing_report_id = reports
    created_response = secured.post(
        "/api/v1/project-tokens",
        json={"label": "shop-ci", "projects": ["shop-api"]},
        headers=auth("admin"),
    )

    assert created_response.status_code == 201
    created = created_response.json()
    token = created["token"]
    with Session(database) as session:
        row = session.exec(select(ApiToken).where(ApiToken.label == "shop-ci")).one()
    assert (row.label, row.role, row.project) == ("shop-ci", "reader", "shop-api")
    assert row.token_hash == http_server.hash_token(token).hex()
    assert token not in row.model_dump_json()

    listed = secured.get("/api/v1/project-tokens", headers=auth("admin"))
    assert listed.status_code == 200
    assert listed.json() == [{key: value for key, value in created.items() if key != "token"}]
    assert token not in listed.text
    assert "sha256" not in listed.text
    assert (
        secured.post(
            "/api/v1/project-tokens",
            json={"label": "denied", "projects": ["shop-api"]},
            headers=auth("reader"),
        ).status_code
        == 403
    )

    project_headers = {"Authorization": f"Bearer {token}"}
    identity = secured.get("/api/v1/me", headers=project_headers).json()
    assert (identity["role"], identity["projects"], identity["can_triage"]) == (
        "reader",
        ["shop-api"],
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
    assert secured.get("/api/v1/project-tokens", headers=auth("admin")).json() == []


def test_project_token_errors(secured, reports):
    def create(label: str, *projects: str):
        return secured.post(
            "/api/v1/project-tokens",
            json={"label": label, "projects": list(projects or ["shop-api"])},
            headers=auth("admin"),
        )

    assert create("ci").status_code == 201
    # Labels are unique among all the tokens
    assert create("ci").status_code == 422
    assert create("triager").status_code == 422
    assert create("other", "unknown-project").status_code == 404
    assert create("other", "shop-api", "unknown-project").status_code == 404
    assert (
        secured.post(
            "/api/v1/project-tokens", json={"label": "other", "projects": []}, headers=auth("admin")
        ).status_code
        == 422
    )
    assert create("x" * 65).status_code == 422
    deleted = secured.delete("/api/v1/project-tokens/unknown", headers=auth("admin"))
    assert deleted.status_code == 404
    assert secured.get("/api/v1/project-tokens", headers=auth("triager")).status_code == 403


@pytest.mark.parametrize("role", ["mcp", "reader", "triager"])
def test_admin_creates_project_token_with_selected_role(secured, reports, role):
    response = secured.post(
        "/api/v1/project-tokens",
        json={"label": f"{role}-client", "role": role, "projects": ["shop-api"]},
        headers=auth("admin"),
    )

    assert response.status_code == 201
    assert response.json()["role"] == role


def test_project_token_creation_rejects_admin_role(secured, reports):
    response = secured.post(
        "/api/v1/project-tokens",
        json={"label": "admin-client", "role": "admin", "projects": ["shop-api"]},
        headers=auth("admin"),
    )

    assert response.status_code == 422


def test_bootstrap_admin_cannot_be_revoked_as_a_project_token(secured):
    token_store.ensure_bootstrap_admin()
    (row_id,) = [row.id for row in _stored_tokens() if row.label == "bootstrap-admin"]

    response = secured.delete(f"/api/v1/project-tokens/{row_id}", headers=auth("admin"))

    assert response.status_code == 404
    assert "bootstrap-admin" in {row.label for row in _stored_tokens()}


# ── Enrollment ───────────────────────────────────────────────────────────────


def test_public_enrollment_then_admin_approval(secured):
    response = secured.post(
        "/api/v1/enroll", json={"project": "new-service", "requested_by": "alice@example.com"}
    )

    assert response.status_code == 201
    created = response.json()
    assert (created["project"], created["role"], created["status"]) == (
        "new-service",
        "mcp",
        "pending",
    )
    assert created["requested_from"] == "testclient"
    pending_headers = {"Authorization": f"Bearer {created['token']}"}
    refused = secured.get("/api/v1/me", headers=pending_headers)
    assert refused.status_code == 403 and refused.json()["error"] == "enrollment_pending"

    listed = secured.get("/api/v1/enrollments", headers=auth("admin"))
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [created["request_id"]]
    assert (listed.json()[0]["token_id"], listed.json()[0]["kind"]) == (created["id"], "new")
    assert listed.json()[0]["requested_by"] == "alice@example.com"
    assert created["token"] not in listed.text
    # Pending requests are not listed with the active project tokens
    assert secured.get("/api/v1/project-tokens", headers=auth("admin")).json() == []
    for role in ("reader", "triager", "mcp"):
        assert secured.get("/api/v1/enrollments", headers=auth(role)).status_code == 403
        assert (
            secured.post(
                f"/api/v1/enrollments/{created['id']}/approve", headers=auth(role)
            ).status_code
            == 403
        )

    approved = secured.post(f"/api/v1/enrollments/{created['id']}/approve", headers=auth("admin"))

    assert approved.status_code == 200 and approved.json()["status"] == "active"
    assert secured.get("/api/v1/enrollments", headers=auth("admin")).json() == []
    assert [
        item["id"] for item in secured.get("/api/v1/project-tokens", headers=auth("admin")).json()
    ] == [created["id"]]
    # The approved token is an MCP token: it reaches /mcp, not the REST API
    assert secured.get("/api/v1/me", headers=pending_headers).status_code == 403
    assert secured.get("/api/v1/me", headers=pending_headers).json()["error"] == (
        "insufficient_scope"
    )
    assert (
        secured.post(f"/api/v1/enrollments/{created['id']}/approve", headers=auth("admin"))
    ).status_code == 404


def test_admin_rejects_enrollment(secured):
    created = secured.post("/api/v1/enroll", json={"project": "new-service"}).json()

    assert secured.delete("/api/v1/enrollments/unknown", headers=auth("admin")).status_code == 404
    assert (
        secured.delete(f"/api/v1/enrollments/{created['id']}", headers=auth("reader")).status_code
        == 403
    )
    rejected = secured.delete(f"/api/v1/enrollments/{created['id']}", headers=auth("admin"))

    assert rejected.status_code == 204
    pending_headers = {"Authorization": f"Bearer {created['token']}"}
    assert secured.get("/api/v1/me", headers=pending_headers).status_code == 401
    # Active tokens cannot be deleted as enrollment requests
    (admin_id,) = [row.id for row in _stored_tokens() if row.label == "admin"]
    response = secured.delete(f"/api/v1/enrollments/{admin_id}", headers=auth("admin"))
    assert response.status_code == 404


def test_enrollment_endpoint_errors(secured, client, monkeypatch):
    assert secured.post("/api/v1/enroll", json={"project": ""}).status_code == 422
    assert secured.post("/api/v1/enroll", json={"project": "p" * 201}).status_code == 422
    assert (
        secured.post("/api/v1/enroll", json={"project": "p", "label": "x" * 65}).status_code == 422
    )
    # An existing label is not revealed: the requested one gets a random suffix
    taken = secured.post("/api/v1/enroll", json={"project": "p", "label": "admin"})
    assert taken.status_code == 201 and taken.json()["label"].startswith("admin-")
    monkeypatch.setattr(token_store, "MAX_PENDING_ENROLLMENTS", 2)
    assert secured.post("/api/v1/enroll", json={"project": "p"}).status_code == 201
    too_many = secured.post("/api/v1/enroll", json={"project": "q"})
    assert too_many.status_code == 422 and "Too many" in too_many.json()["detail"]
    monkeypatch.setattr(web_api.get_settings(), "enrollment", False)
    assert secured.post("/api/v1/enroll", json={"project": "p"}).status_code == 404


def test_token_with_several_projects_in_the_web_interface(secured, reports, database):
    shop_report_id, billing_report_id = reports
    services.save_report("crm", "Hidden review", [])
    created = secured.post(
        "/api/v1/project-tokens",
        json={"label": "multi", "projects": ["shop-api", "billing"]},
        headers=auth("admin"),
    ).json()
    headers = {"Authorization": f"Bearer {created['token']}"}

    assert created["projects"] == ["shop-api", "billing"]
    assert secured.get("/api/v1/me", headers=headers).json()["projects"] == [
        "billing",
        "shop-api",
    ]
    listed = secured.get("/api/v1/projects", headers=headers).json()
    assert sorted(item["project"] for item in listed) == ["billing", "shop-api"]
    reports_listed = secured.get("/api/v1/reports", headers=headers).json()
    assert {item["project"] for item in reports_listed} == {"billing", "shop-api"}
    for project in ("shop-api", "billing"):
        assert (
            secured.get("/api/v1/posture", params={"project": project}, headers=headers).status_code
            == 200
        )
    for report_id in (shop_report_id, billing_report_id):
        assert secured.get(f"/api/v1/reports/{report_id}", headers=headers).status_code == 200
    assert (
        secured.get("/api/v1/posture", params={"project": "crm"}, headers=headers).status_code
        == 404
    )
    # Several projects: the SARIF export needs to know which one
    assert secured.get("/api/v1/sarif", headers=headers).status_code == 422
    assert (
        secured.get("/api/v1/sarif", params={"project": "billing"}, headers=headers).status_code
        == 200
    )


def test_complementary_enrollment_over_rest(secured):
    created = token_store.create_token("shop-ci", Role.MCP, "shop-api")
    headers = {"Authorization": f"Bearer {created['token']}"}

    response = secured.post(
        "/api/v1/enroll",
        json={"project": "billing", "label": "ignored", "requested_by": "bob"},
        headers=headers,
    )

    assert response.status_code == 201
    request = response.json()
    assert (request["kind"], request["token_id"], request["label"]) == (
        "additional",
        created["id"],
        "shop-ci",
    )
    assert "token" not in request
    duplicate = secured.post("/api/v1/enroll", json={"project": "billing"}, headers=headers)
    assert duplicate.status_code == 422 and "already waiting" in duplicate.json()["detail"]
    (listed,) = secured.get("/api/v1/enrollments", headers=auth("admin")).json()
    assert (listed["id"], listed["kind"], listed["project"]) == (
        request["id"],
        "additional",
        "billing",
    )

    approved = secured.post(f"/api/v1/enrollments/{request['id']}/approve", headers=auth("admin"))

    assert approved.status_code == 200
    assert approved.json()["projects"] == ["shop-api", "billing"]
    info = token_store.DatabaseTokenStore().lookup(http_server.hash_token(created["token"]))
    assert info.projects == {"shop-api", "billing"}

    # A rejected complementary request leaves the token as it was
    other = secured.post("/api/v1/enroll", json={"project": "crm"}, headers=headers).json()
    assert (
        secured.delete(f"/api/v1/enrollments/{other['id']}", headers=auth("admin")).status_code
        == 204
    )
    info = token_store.DatabaseTokenStore().lookup(http_server.hash_token(created["token"]))
    assert info.projects == {"shop-api", "billing"}


def test_complementary_enrollment_needs_a_valid_restricted_token(secured, monkeypatch):
    def enroll(token: str):
        return secured.post(
            "/api/v1/enroll",
            json={"project": "billing"},
            headers={"Authorization": f"Bearer {token}"},
        )

    unknown = enroll("not-a-token")
    assert unknown.status_code == 401 and "WWW-Authenticate" in unknown.headers
    assert (
        secured.post(
            "/api/v1/enroll", json={"project": "p"}, headers={"Authorization": "Basic abc"}
        ).status_code
        == 401
    )
    pending = token_store.request_enrollment("shop-api")
    assert enroll(pending["token"]).status_code == 403
    unrestricted = enroll(TOKENS["admin"])
    assert unrestricted.status_code == 422
    assert "every project" in unrestricted.json()["detail"]
    # Nothing was created by the refused requests
    assert [item["id"] for item in token_store.list_enrollments()] == [pending["request_id"]]
    monkeypatch.setattr(web_api.get_settings(), "enrollment", False)
    restricted = token_store.create_token("shop-ci", Role.MCP, "shop-api")
    assert enroll(restricted["token"]).status_code == 404


def test_enrollment_is_pointless_without_authentication(client):
    response = client.post("/api/v1/enroll", json={"project": "p"})

    assert response.status_code == 409
    assert token_store.list_tokens() == []


def _stored_tokens() -> list[ApiToken]:
    with session_scope() as session:
        rows = session.exec(select(ApiToken)).all()
        for row in rows:
            session.expunge(row)
        return list(rows)


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


def test_project_triager_only_changes_findings_of_its_project(secured, reports):
    shop_report_id, _ = reports
    billing = services.save_report("billing", "Billing review", [make_finding()])
    billing_finding = services.get_report(billing["report_id"]).findings[0].id
    shop_finding = services.get_report(shop_report_id).findings[0].id
    token = token_store.create_token("shop-triage", Role.TRIAGER, "shop-api")["token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = secured.patch(
        f"/api/v1/findings/{billing_finding}", json={"status": "accepted"}, headers=headers
    )
    assert response.status_code == 404
    assert services.get_report(billing["report_id"]).findings[0].status == "open"
    response = secured.patch(
        f"/api/v1/findings/{shop_finding}", json={"status": "fixed"}, headers=headers
    )
    assert response.status_code == 200
    assert secured.get("/mcp", headers=headers).status_code == 403
