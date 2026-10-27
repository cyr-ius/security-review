"""OAuth login of the MCP clients: authorization server of the controller (oauth_server)."""

import base64
import hashlib
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import group_for, make_user
from sqlmodel import select
from starlette.testclient import TestClient

from security_review_mcp import app_settings, http_server, web_api
from security_review_mcp.auth import oauth_server, oidc, token_store, web_users
from security_review_mcp.config import check_mcp_url, get_settings
from security_review_mcp.http_server import Role, hash_token
from security_review_mcp.observability import audit
from security_review_mcp.storage.database import session_scope
from security_review_mcp.storage.models import OAuthGrant, as_utc

CONTROLLER = "http://127.0.0.1"
MCP_URL = "http://127.0.0.1:8000/mcp"
REDIRECT = "http://127.0.0.1:33418/callback"
PASSWORD = "Correct horse battery 9"
VERIFIER = "v" * 64
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
)


@pytest.fixture
def controller(monkeypatch, tmp_path) -> TestClient:
    """The controller with the OAuth login of the MCP clients, and a developer ``dev`` who may
    create MCP tokens on ``shop``."""
    settings = get_settings()
    monkeypatch.setattr(settings, "mcp_oauth_enabled", True)
    monkeypatch.setattr(settings, "mcp_url", MCP_URL)
    app_settings.set_controller_url(CONTROLLER, "test")
    app_settings.sync_mcp_oauth(settings)
    make_user("dev", PASSWORD, group_ids=[group_for("mcp-user"), group_for("reader", ["shop"])])
    signer = oidc.SessionSigner("s" * 40)
    app = http_server.build_controller_app(
        web_api.create_app(ui=False, signer=signer),
        token_store.DatabaseTokenStore(include_users=True),
        web_users.SessionVerifier(signer),
    )
    return TestClient(app, base_url=CONTROLLER)


def session(client: TestClient) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"username": "dev", "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['session']}"}


def register(client: TestClient, redirect: str = REDIRECT):
    return client.post(
        "/register",
        json={
            "redirect_uris": [redirect],
            "client_name": "Claude Code",
            # Asked for, but replaced: every client is public
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["authorization_code", "refresh_token"],
        },
    )


def authorize(client: TestClient, client_id: str, resource: str = MCP_URL):
    return client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "state": "st4te",
            "resource": resource,
        },
        follow_redirects=False,
    )


def token(client: TestClient, **data: str):
    return client.post("/token", data=data)


def log_in(client: TestClient, client_id: str, headers: dict[str, str]) -> str:
    """Approve a new request of the client as dev and return its access token."""
    handle = parse_qs(urlsplit(authorize(client, client_id).headers["location"]).query)
    approved = client.post(
        "/api/v1/oauth/approve", json={"request": handle["request"][0]}, headers=headers
    )
    code = parse_qs(urlsplit(approved.json()["redirect_url"]).query)["code"][0]
    return token(
        client,
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
        client_id=client_id,
        code_verifier=VERIFIER,
    ).json()["access_token"]


def test_an_mcp_client_logs_in_and_acts_as_a_personal_mcp_token(controller):
    metadata = controller.get("/.well-known/oauth-authorization-server").json()
    # RFC 8414 §3.3: the issuer is the URL named by the MCP server, character for character
    assert metadata["issuer"] == CONTROLLER
    assert metadata["token_endpoint_auth_methods_supported"] == ["none"]
    registered = register(controller)
    assert registered.status_code == 201, registered.text
    client_id = registered.json()["client_id"]
    assert registered.json()["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in registered.json()

    # The browser goes to the consent screen, behind the login of the web interface
    location = authorize(controller, client_id).headers["location"]
    assert location.startswith(f"{CONTROLLER}/ui/oauth/authorize?request=")
    handle = parse_qs(urlsplit(location).query)["request"][0]
    headers = session(controller)
    pending = controller.post("/api/v1/oauth/request", json={"request": handle}, headers=headers)
    assert pending.json()["client_name"] == "Claude Code"
    assert pending.json()["redirect_host"] == "127.0.0.1"
    # A bearer token never approves a client
    admin = token_store.create_token("admin", Role.ADMIN)["token"]
    refused = controller.post(
        "/api/v1/oauth/approve",
        json={"request": handle},
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert refused.status_code == 403
    approved = controller.post("/api/v1/oauth/approve", json={"request": handle}, headers=headers)
    assert approved.status_code == 200, approved.text
    back = urlsplit(approved.json()["redirect_url"])
    assert f"{back.scheme}://{back.netloc}{back.path}" == REDIRECT
    query = parse_qs(back.query)
    assert query["state"] == ["st4te"]
    code = query["code"][0]

    exchange = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "client_id": client_id,
    }
    assert token(controller, **exchange, code_verifier="w" * 64).json()["error"] == "invalid_grant"
    tokens = token(controller, **exchange, code_verifier=VERIFIER)
    assert tokens.status_code == 200, tokens.text
    access, refresh = tokens.json()["access_token"], tokens.json()["refresh_token"]
    # A code is used once
    assert token(controller, **exchange, code_verifier=VERIFIER).status_code == 400

    # The access token acts as a personal mcp token of dev: its projects, the MCP server only
    info = token_store.DatabaseTokenStore().lookup(hash_token(access))
    assert (info.role, info.owner, info.projects) == (Role.MCP, "dev", frozenset({"shop"}))
    assert (
        controller.get("/api/v1/me", headers={"Authorization": f"Bearer {access}"}).status_code
        == 403
    )
    assert controller.get("/api/v1/me/oauth-grants", headers=headers).json()[0]["client_name"] == (
        "Claude Code"
    )

    # A refresh replaces both tokens
    renewed = token(
        controller, grant_type="refresh_token", refresh_token=refresh, client_id=client_id
    )
    assert renewed.status_code == 200, renewed.text
    new_access = renewed.json()["access_token"]
    assert token_store.DatabaseTokenStore().lookup(hash_token(access)) is None
    assert token_store.DatabaseTokenStore().lookup(hash_token(new_access)) is not None
    # The replaced refresh token presented again (stolen?) revokes the grant
    reused = token(
        controller, grant_type="refresh_token", refresh_token=refresh, client_id=client_id
    )
    assert reused.status_code == 400
    assert token_store.DatabaseTokenStore().lookup(hash_token(new_access)) is None
    actions = [event["action"] for event in audit.list_events()["events"]]
    assert {"oauth.client_registered", "oauth.grant_approved", "oauth.refresh_reused"} <= set(
        actions
    )


@pytest.mark.parametrize(
    "redirect",
    [
        # A site of an attacker would receive the code of the user who follows its link
        "https://evil.example/callback",
        "http://vscode.dev/redirect",
        "cursor://anysphere/callback",
        "https://localhost/cb#x",
    ],
)
def test_registration_only_accepts_a_loopback_redirect_by_default(controller, redirect):
    response = register(controller, redirect)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_redirect_uri"


def test_listed_redirect_hosts_and_schemes_are_accepted(controller, monkeypatch):
    monkeypatch.setattr(get_settings(), "mcp_oauth_redirect_hosts", "vscode.dev")
    monkeypatch.setattr(get_settings(), "mcp_oauth_redirect_schemes", "cursor")

    assert register(controller, "https://vscode.dev/redirect").status_code == 201
    assert register(controller, "cursor://anysphere/callback").status_code == 201
    assert register(controller, "https://evil.example/callback").status_code == 400


def test_a_token_for_another_resource_is_refused(controller):
    client_id = register(controller).json()["client_id"]

    location = authorize(controller, client_id, "https://other.example/mcp").headers["location"]

    assert location.startswith(REDIRECT)
    assert parse_qs(urlsplit(location).query)["error"] == ["invalid_target"]


def test_a_denied_client_gets_access_denied_and_a_deleted_user_loses_its_clients(controller):
    client_id = register(controller).json()["client_id"]
    headers = session(controller)
    handle = parse_qs(urlsplit(authorize(controller, client_id).headers["location"]).query)
    denied = controller.post(
        "/api/v1/oauth/deny", json={"request": handle["request"][0]}, headers=headers
    )
    assert parse_qs(urlsplit(denied.json()["redirect_url"]).query)["error"] == ["access_denied"]
    # Decided: the request is gone
    again = controller.post(
        "/api/v1/oauth/approve", json={"request": handle["request"][0]}, headers=headers
    )
    assert again.status_code == 404

    access = log_in(controller, client_id, headers)
    user_id = next(user["id"] for user in web_users.list_users() if user["username"] == "dev")

    web_users.delete_user(user_id, "admin")

    assert token_store.DatabaseTokenStore().lookup(hash_token(access)) is None


def test_a_controller_started_with_the_oauth_login_off_revokes_every_grant(controller):
    access = log_in(controller, register(controller).json()["client_id"], session(controller))

    assert oauth_server.revoke_all_grants("environment") == 1

    assert token_store.DatabaseTokenStore().lookup(hash_token(access)) is None


def test_secreview_token_max_days_bounds_the_whole_grant_not_each_refresh(controller, monkeypatch):
    client_id = register(controller).json()["client_id"]
    log_in(controller, client_id, session(controller))
    monkeypatch.setattr(get_settings(), "token_max_days", 7)
    refresh = "r" * 43
    with session_scope() as db:
        grant = db.exec(select(OAuthGrant)).one()
        grant.created_at = as_utc(grant.created_at) - timedelta(days=6)
        grant.refresh_token_hash = oauth_server.digest(refresh)
        db.add(grant)
        created = as_utc(grant.created_at)

    renewed = token(
        controller, grant_type="refresh_token", refresh_token=refresh, client_id=client_id
    )

    assert renewed.status_code == 200, renewed.text
    with session_scope() as db:
        grant = db.exec(select(OAuthGrant)).one()
        assert as_utc(grant.refresh_expires_at) <= created + timedelta(days=7)


@pytest.mark.parametrize("url", ['https://mcp.example/m"cp', "https://mcp.ex\u00e4mple/mcp"])
def test_the_mcp_url_fits_in_the_www_authenticate_challenge(url):
    with pytest.raises(ValueError, match="ASCII"):
        check_mcp_url(url)


def test_a_tokens_manager_lists_revokes_and_deletes_every_client(controller):
    client_id = register(controller).json()["client_id"]
    access = log_in(controller, client_id, session(controller))
    admin = {"Authorization": f"Bearer {token_store.create_token('ops', Role.ADMIN)['token']}"}
    # dev may approve clients, not manage those of the others
    assert controller.get("/api/v1/oauth/clients", headers=session(controller)).status_code == 403

    overview = controller.get("/api/v1/oauth/clients", headers=admin).json()
    assert overview["enabled"] is True
    assert overview["clients"][0]["grants"] == 1
    assert overview["grants"][0]["username"] == "dev"
    assert "access_token_hash" not in overview["grants"][0]
    grant_id = overview["grants"][0]["id"]
    assert controller.delete(f"/api/v1/oauth/grants/{grant_id}", headers=admin).status_code == 204
    assert token_store.DatabaseTokenStore().lookup(hash_token(access)) is None

    access = log_in(controller, client_id, session(controller))
    assert controller.delete(f"/api/v1/oauth/clients/{client_id}", headers=admin).status_code == 204
    assert token_store.DatabaseTokenStore().lookup(hash_token(access)) is None
    assert controller.get("/api/v1/oauth/clients", headers=admin).json()["clients"] == []
