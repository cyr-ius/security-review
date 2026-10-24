"""Public enrollment endpoint of the MCP server (POST /api/v1/enroll)."""

import pytest
from starlette.testclient import TestClient

from security_review_mcp import audit, http_server, server
from security_review_mcp.auth import access_control, enrollment_api, token_store
from security_review_mcp.http_server import Role


@pytest.fixture
def admin_token() -> str:
    """An administrator token: authentication is configured, so enrollment is possible."""
    return token_store.create_token("admin", Role.ADMIN)["token"]


@pytest.fixture
def public(admin_token) -> TestClient:
    """The MCP server app, as served by `security-review-mcp --transport streamable-http`."""
    app = http_server.build_mcp_app(
        server.mcp,
        "127.0.0.1",
        token_store.DatabaseTokenStore(),
        server.enrollment_mcp,
        enrollment_api.create_app(),
    )
    return TestClient(app, base_url="http://127.0.0.1")


def pending(project: str) -> bool:
    """True when the project waits for an approval."""
    return project in [item["project"] for item in access_control.list_enrollments()]


def test_enrollment_requests_the_project_and_no_token(public, monkeypatch):
    monkeypatch.setattr(enrollment_api.get_settings(), "web_url", "https://secreview.example/ui")
    response = public.post(
        "/api/v1/enroll",
        json={"project": "git@github.com:acme/Shop_API.git", "requested_by": "bob"},
    )

    assert response.status_code == 202
    enrolled = response.json()
    assert set(enrolled) == {"project", "web_url", "next_steps"}
    assert (enrolled["project"], enrolled["web_url"]) == (
        "shop-api",
        "https://secreview.example/ui",
    )
    assert "personal MCP token" in enrolled["next_steps"]
    assert pending("shop-api")
    assert [token["label"] for token in token_store.list_tokens()] == ["admin"]
    (event,) = audit.list_events(action="enrollment.requested")["events"]
    assert (event["details"]["requested_by"], event["details"]["requested_from"]) == (
        "bob",
        "testclient",
    )


def test_enrollment_endpoint_errors(public, monkeypatch):
    assert public.post("/api/v1/enroll", json={"project": ""}).status_code == 422
    assert public.post("/api/v1/enroll", json={"project": "p" * 201}).status_code == 422
    assert public.post("/api/v1/enroll", json={"project": "-/-"}).status_code == 422
    too_long = {"project": "p", "requested_by": "x" * 201}
    assert public.post("/api/v1/enroll", json=too_long).status_code == 422
    invalid = public.post("/api/v1/enroll", content=b"not json")
    assert invalid.status_code == 422 and isinstance(invalid.json()["detail"], list)
    assert public.get("/api/v1/enroll").status_code == 405
    oversized = b'{"project": "' + b"p" * enrollment_api.MAX_BODY_BYTES + b'"}'
    assert public.post("/api/v1/enroll", content=oversized).status_code == 413
    monkeypatch.setattr(access_control, "MAX_PENDING_PROJECTS", 1)
    assert public.post("/api/v1/enroll", json={"project": "p"}).status_code == 202
    too_many = public.post("/api/v1/enroll", json={"project": "q"})
    assert too_many.status_code == 422 and "Too many" in too_many.json()["detail"]
    monkeypatch.setattr(access_control, "MAX_ENROLLMENTS_PER_ADDRESS", 2)
    throttled = public.post("/api/v1/enroll", json={"project": "p"})
    assert throttled.status_code == 429 and "retry later" in throttled.json()["detail"]
    monkeypatch.setattr(enrollment_api.get_settings(), "enrollment", False)
    assert public.post("/api/v1/enroll", json={"project": "p"}).status_code == 404
    assert not pending("q")


def test_enrollment_is_pointless_on_an_open_server_without_token():
    client = TestClient(enrollment_api.create_app(allow_open=True), base_url="http://127.0.0.1")

    response = client.post("/api/v1/enroll", json={"project": "p"})

    assert response.status_code == 409
    assert not pending("p")


def test_closed_server_accepts_enrollment_before_its_first_token():
    client = TestClient(enrollment_api.create_app("0.0.0.0"), base_url="http://10.0.0.5")

    response = client.post("/api/v1/enroll", json={"project": "p"})

    assert response.status_code == 202
    assert pending("p")


def test_loopback_server_refuses_other_hosts(admin_token):
    client = TestClient(enrollment_api.create_app("127.0.0.1"), base_url="http://evil.example")

    assert client.post("/api/v1/enroll", json={"project": "p"}).status_code == 400
    assert not pending("p")
