"""Public enrollment endpoint of the MCP server (POST /api/v1/enroll)."""

import pytest
from starlette.testclient import TestClient

from security_review_mcp import enrollment_api, http_server, server, token_store
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


def test_enrollment_creates_a_pending_token(public):
    response = public.post("/api/v1/enroll", json={"project": "shop-api", "requested_by": "bob"})

    assert response.status_code == 201
    created = response.json()
    assert (created["project"], created["role"]) == ("shop-api", "mcp")
    assert created["status"] == "pending"
    assert created["requested_from"] == "testclient"
    assert [item["id"] for item in token_store.list_enrollments()] == [created["request_id"]]


def test_enrollment_normalizes_the_project(public):
    response = public.post("/api/v1/enroll", json={"project": "git@github.com:acme/Shop_API.git"})

    assert response.status_code == 201 and response.json()["project"] == "shop-api"


def test_enrollment_endpoint_errors(public, monkeypatch):
    assert public.post("/api/v1/enroll", json={"project": ""}).status_code == 422
    assert public.post("/api/v1/enroll", json={"project": "p" * 201}).status_code == 422
    assert public.post("/api/v1/enroll", json={"project": "-/-"}).status_code == 422
    assert public.post("/api/v1/enroll", json={"project": "p", "label": "x" * 65}).status_code == (
        422
    )
    invalid = public.post("/api/v1/enroll", content=b"not json")
    assert invalid.status_code == 422 and isinstance(invalid.json()["detail"], list)
    assert public.get("/api/v1/enroll").status_code == 405
    # An existing label is not revealed: the requested one gets a random suffix
    taken = public.post("/api/v1/enroll", json={"project": "p", "label": "admin"})
    assert taken.status_code == 201 and taken.json()["label"].startswith("admin-")
    monkeypatch.setattr(token_store, "MAX_PENDING_ENROLLMENTS", 2)
    assert public.post("/api/v1/enroll", json={"project": "p"}).status_code == 201
    too_many = public.post("/api/v1/enroll", json={"project": "q"})
    assert too_many.status_code == 422 and "Too many" in too_many.json()["detail"]
    monkeypatch.setattr(enrollment_api.get_settings(), "enrollment", False)
    assert public.post("/api/v1/enroll", json={"project": "p"}).status_code == 404


def test_enrollment_endpoint_bounds_the_requests_of_one_address(public, monkeypatch):
    monkeypatch.setattr(token_store, "MAX_PENDING_PER_ADDRESS", 2)
    for project in ("a", "b"):
        assert public.post("/api/v1/enroll", json={"project": project}).status_code == 201

    refused = public.post("/api/v1/enroll", json={"project": "c"})

    assert refused.status_code == 422 and "from this address" in refused.json()["detail"]
    assert len(token_store.list_enrollments()) == 2


def test_enrollment_body_is_bounded(public):
    oversized = b'{"project": "' + b"p" * enrollment_api.MAX_BODY_BYTES + b'"}'

    response = public.post("/api/v1/enroll", content=oversized)

    assert response.status_code == 413
    assert token_store.list_enrollments() == []


def test_complementary_enrollment_needs_a_valid_restricted_token(public, admin_token, monkeypatch):
    def enroll(token: str):
        return public.post(
            "/api/v1/enroll",
            json={"project": "billing"},
            headers={"Authorization": f"Bearer {token}"},
        )

    unknown = enroll("not-a-token")
    assert unknown.status_code == 401 and "WWW-Authenticate" in unknown.headers
    basic = public.post(
        "/api/v1/enroll", json={"project": "p"}, headers={"Authorization": "Basic abc"}
    )
    assert basic.status_code == 401
    pending = token_store.request_enrollment("shop-api")
    assert enroll(pending["token"]).status_code == 403
    unrestricted = enroll(admin_token)
    assert unrestricted.status_code == 422
    assert "every project" in unrestricted.json()["detail"]
    # Nothing was created by the refused requests
    assert [item["id"] for item in token_store.list_enrollments()] == [pending["request_id"]]
    restricted = token_store.create_token("shop-ci", Role.MCP, "shop-api")
    accepted = enroll(restricted["token"])
    assert accepted.status_code == 201 and accepted.json()["kind"] == "additional"
    monkeypatch.setattr(enrollment_api.get_settings(), "enrollment", False)
    assert enroll(restricted["token"]).status_code == 404


def test_enrollment_is_pointless_on_an_open_server_without_token():
    client = TestClient(enrollment_api.create_app(allow_open=True), base_url="http://127.0.0.1")

    response = client.post("/api/v1/enroll", json={"project": "p"})

    assert response.status_code == 409
    assert token_store.list_tokens() == []


def test_closed_server_accepts_enrollment_before_its_first_token():
    client = TestClient(enrollment_api.create_app("0.0.0.0"), base_url="http://10.0.0.5")

    response = client.post("/api/v1/enroll", json={"project": "p"})

    assert response.status_code == 201
    assert [item["project"] for item in token_store.list_enrollments()] == ["p"]


def test_loopback_server_refuses_other_hosts(admin_token):
    client = TestClient(enrollment_api.create_app("127.0.0.1"), base_url="http://evil.example")

    assert client.post("/api/v1/enroll", json={"project": "p"}).status_code == 400
    assert token_store.list_enrollments() == []
