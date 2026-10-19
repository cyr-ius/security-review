"""OpenID Connect login to the web interface: settings, ID token checks, sessions and routes."""

import logging
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from conftest import group_for, make_user
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from security_review_mcp import (
    access_control,
    audit,
    http_server,
    oidc,
    server,
    services,
    token_store,
    web_api,
    web_users,
)
from security_review_mcp.access_control import Permission
from security_review_mcp.config import Settings
from security_review_mcp.http_server import Role

ISSUER = "https://idp.example.com/realms/acme"
CLIENT_ID = "secreview"
REDIRECT_URI = "https://secreview.example.com/api/v1/auth/oidc/callback"
SECRET = "s" * 40


def make_settings(**values) -> Settings:
    """OIDC settings that ignore the developer's .env file."""
    defaults = {
        "oidc_enabled": True,
        "oidc_issuer": ISSUER,
        "oidc_client_id": CLIENT_ID,
        "oidc_client_secret": "client-secret",
        "oidc_redirect_uri": REDIRECT_URI,
        "oidc_admin_groups": "secreview-admins",
        "oidc_auto_create_users": True,
        "secret_key": SECRET,
    }
    return Settings(_env_file=None, **{**defaults, **values})


class FakeProvider(oidc.OidcLogin):
    """An OIDC login whose identity provider answers from memory (no network)."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "key-1"
        self.claims: dict[str, Any] = {"preferred_username": "alice", "groups": ["qa"]}
        self.userinfo_claims: dict[str, Any] = {}
        self.token_overrides: dict[str, Any] = {}
        self.header_overrides: dict[str, Any] = {}
        self.requests: list[tuple[str, dict | None, dict | None]] = []
        self.last_nonce = ""

    def jwks(self) -> dict:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        return {"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]}

    def id_token(self, nonce: str) -> str:
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "user-123",
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            **self.claims,
            **self.token_overrides,
        }
        headers = {"kid": self.kid, **self.header_overrides}
        return jwt.encode(payload, self.key, algorithm="RS256", headers=headers)

    def fetch_json(self, url, data=None, headers=None):  # noqa: ANN001, ANN201
        self.requests.append((url, data, headers))
        if url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
                "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
                "userinfo_endpoint": f"{ISSUER}/protocol/openid-connect/userinfo",
                "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
                "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            }
        if url.endswith("/certs"):
            return self.jwks()
        if url.endswith("/token"):
            return {"access_token": "access-abc", "id_token": self.id_token(self.last_nonce)}
        if url.endswith("/userinfo"):
            return {"sub": "user-123", **self.userinfo_claims}
        raise AssertionError(url)


@pytest.fixture
def provider() -> FakeProvider:
    # The groups claim of the fake provider names "qa": a group of readers open to OIDC
    group_for("reader", name="qa", sso=True)
    return FakeProvider(make_settings())


@pytest.fixture
def controller(provider, tmp_path) -> TestClient:
    """The controller app with OIDC, no token in the database."""
    (tmp_path / "index.html").write_text("<html>app</html>", encoding="utf-8")
    app = web_api.create_app("0.0.0.0", ui_dir=str(tmp_path), oidc_login=provider)
    secured = http_server.build_controller_app(
        app,
        token_store.DatabaseTokenStore(include_users=True),
        web_users.SessionVerifier(provider.signer),
        require_auth=True,
    )
    return TestClient(secured, base_url="https://secreview.example.com", follow_redirects=False)


def start_login(client: TestClient, provider: FakeProvider, return_url: str = "/reports") -> str:
    """Call the login route and return the state sent to the provider."""
    response = client.get("/api/v1/auth/oidc/login", params={"return_url": return_url})
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["location"]).query)
    provider.last_nonce = query["nonce"][0]
    return query["state"][0]


def session_of(response) -> str:
    """Session token handed to the web application in the URL fragment."""
    location = urlsplit(response.headers["location"])
    assert location.path == "/ui/login"
    return parse_qs(location.fragment)["session"][0]


def error_of(response) -> str:
    location = urlsplit(response.headers["location"])
    assert location.path == "/ui/login" and not location.fragment
    return parse_qs(location.query)["oidcError"][0]


# ── Settings and role mapping ────────────────────────────────────────────────


def test_from_settings_is_none_when_disabled():
    assert oidc.from_settings(Settings(_env_file=None)) is None


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"oidc_issuer": ""}, "SECREVIEW_OIDC_ISSUER is required"),
        ({"oidc_issuer": "http://idp.example.com"}, "SECREVIEW_OIDC_ISSUER must be an https"),
        ({"oidc_issuer": "https://u:p@idp.example.com"}, "must not contain credentials"),
        ({"oidc_client_id": ""}, "SECREVIEW_OIDC_CLIENT_ID"),
        ({"oidc_redirect_uri": ""}, "SECREVIEW_OIDC_REDIRECT_URI is required"),
        ({"oidc_redirect_uri": "javascript:alert(1)"}, "SECREVIEW_OIDC_REDIRECT_URI must be"),
        ({"oidc_scope": "profile email"}, "must include openid"),
        ({"oidc_default_group": "x" * 201}, "SECREVIEW_OIDC_DEFAULT_GROUP"),
        ({"oidc_cafile": "/nonexistent/ca.pem"}, "SECREVIEW_OIDC_CAFILE"),
        ({"oidc_display_name": " "}, "SECREVIEW_OIDC_DISPLAY_NAME"),
    ],
)
def test_invalid_settings_are_refused(values, message):
    with pytest.raises(ValueError, match=message):
        oidc.from_settings(make_settings(**values))


def test_plain_http_issuer_is_accepted_on_localhost_only():
    login = oidc.from_settings(make_settings(oidc_issuer="http://localhost:8080/realms/dev"))
    assert login is not None and login.issuer == "http://localhost:8080/realms/dev"


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"session_hours": 0}, "SECREVIEW_SESSION_HOURS"),
        ({"session_hours": 25}, "SECREVIEW_SESSION_HOURS"),
        ({"secret_key": "short"}, "at least 32"),
    ],
)
def test_invalid_session_settings_are_refused(values, message):
    with pytest.raises(ValueError, match=message):
        oidc.session_signer(make_settings(**values))


def test_without_a_secret_key_a_random_secret_is_drawn_at_each_start(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    settings = make_settings(secret_key=None)
    with caplog.at_level(logging.WARNING, logger="security_review_mcp.oidc"):
        token = oidc.session_signer(settings).issue_session("alice", None, 1, 1)
    # Another start (or replica) does not accept the session, and nothing is written to disk
    assert oidc.session_signer(settings).decode_session(token) is None
    assert "SECREVIEW_SECRET_KEY is not set" in caplog.text
    assert list(tmp_path.iterdir()) == []


def test_secrets_are_never_shown_by_the_settings():
    settings = make_settings(
        secret_key="s3cr3t" * 6,
        oidc_client_secret="client-s3cr3t",
        tls_keyfile_password="key-s3cr3t",
        database_url="postgresql+psycopg2://app:db-s3cr3t@db/app",
    )
    shown = repr(settings) + str(settings.model_dump())
    for secret in ("s3cr3t" * 6, "client-s3cr3t", "key-s3cr3t", "db-s3cr3t"):
        assert secret not in shown


def test_the_oidc_login_uses_the_shared_signer():
    signer = oidc.session_signer(make_settings())
    login = oidc.from_settings(make_settings(), signer)
    assert login is not None and login.signer is signer


@pytest.mark.parametrize(
    ("claims", "path", "values"),
    [
        ({"groups": ["qa", "dev"]}, "groups", {"qa", "dev"}),
        ({"groups": "qa, dev"}, "groups", {"qa", "dev"}),
        ({"groups": [{"name": "x"}, "qa"]}, "groups", {"qa"}),
        ({"realm_access": {"roles": ["admin"]}}, "groups", set()),
        ({}, "groups", set()),
        ({"realm_access": {"roles": ["admin"]}}, "realm_access.roles", {"admin"}),
        ({"realm_access": "x"}, "realm_access.roles", set()),
    ],
)
def test_claim_values(claims, path, values):
    assert oidc.claim_values(claims, path) == values


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/reports/3?x=1", "/reports/3?x=1"),
        (None, "/"),
        ("https://evil.example.com", "/"),
        ("//evil.example.com", "/"),
        ("/\\evil.example.com", "/"),
        ("/a\nb", "/"),
        ("/" + "a" * 600, "/"),
    ],
)
def test_return_url_stays_local(value, expected):
    assert oidc.safe_return_url(value) == expected


# ── Session tokens ───────────────────────────────────────────────────────────


def test_session_token_round_trip_and_rejections():
    signer = oidc.SessionSigner(SECRET, session_hours=1)
    token = signer.issue_session("oidc:alice", None, 7, 42)
    assert signer.owns(token)
    payload = signer.decode_session(token)
    # No role: the permissions of the user are read from the database at each request
    assert (payload["sub"], payload["uid"], payload["uver"]) == ("oidc:alice", 7, 42)
    assert "role" not in payload

    # Another secret, a state cookie or a database token are refused
    assert oidc.SessionSigner("x" * 40).decode_session(token) is None
    assert signer.decode_session(signer.sign_state({"state": "s"})) is None
    assert not signer.owns(token_store.create_token("api", Role.ADMIN)["token"])


@pytest.mark.parametrize(
    "extra",
    [
        {"uid": 1, "uver": 0, "iat": int(time.time()) - 7200, "exp": int(time.time()) - 3600},
        # Every session token names a web user and its version, with the right types
        {},
        {"uid": 1},
        {"uid": "1", "uver": 0},
        {"uid": 1, "uver": True},
    ],
)
def test_forged_or_expired_session_tokens_are_refused(extra):
    signer = oidc.SessionSigner(SECRET)
    now = int(time.time())
    claims = {
        "iss": oidc.SESSION_ISSUER,
        "aud": oidc.SESSION_AUDIENCE,
        "sub": "x",
        "role": "admin",
        "iat": now,
        "exp": now + 60,
    }
    forged = jwt.encode({**claims, **extra}, signer._session_key, algorithm="HS256")
    assert signer.decode_session(forged) is None


# ── Login flow ───────────────────────────────────────────────────────────────


def test_auth_config_is_public(controller):
    response = controller.get("/api/v1/auth/config")
    assert response.json() == {"password": True, "oidc": True, "oidc_display_name": "OIDC"}


def test_oidc_only_refuses_the_local_logins_while_oidc_works(controller, tmp_path, monkeypatch):
    password = "Local-admin-pa55word"  # secreview:ignore GEN-004 test value
    make_user("alice", password, "reader")
    only = Settings(_env_file=None, oidc_only=True)
    monkeypatch.setattr(web_api.auth_routes, "get_settings", lambda: only)
    body = {"username": "alice", "password": password}

    assert controller.get("/api/v1/auth/config").json()["password"] is False
    refused = controller.post("/api/v1/auth/login", json=body)
    assert refused.status_code == 403
    assert controller.get("/api/v1/auth/oidc/login").status_code == 302

    # Without a working OIDC login, the local accounts stay usable (no lock-out)
    disabled = TestClient(web_api.create_app(ui_dir=str(tmp_path)), base_url="http://127.0.0.1")
    assert disabled.get("/api/v1/auth/config").json()["password"] is True
    assert disabled.post("/api/v1/auth/login", json=body).status_code == 200


def test_login_redirects_to_the_provider_with_pkce_and_a_state_cookie(controller, provider):
    response = controller.get("/api/v1/auth/oidc/login", params={"return_url": "/reports"})

    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}".startswith(ISSUER)
    query = {key: values[0] for key, values in parse_qs(location.query).items()}
    assert query["response_type"] == "code"
    assert query["client_id"] == CLIENT_ID
    assert query["redirect_uri"] == REDIRECT_URI
    assert query["code_challenge_method"] == "S256"
    assert len(query["state"]) >= 32 and len(query["nonce"]) >= 32
    cookie = response.headers["set-cookie"]
    for attribute in ("HttpOnly", "Secure", "SameSite=lax", "Path=/api/v1/auth/oidc/callback"):
        assert attribute in cookie
    assert response.headers["cache-control"] == "no-store"
    # The cookie holds the PKCE verifier matching the challenge
    saved = provider.signer.read_state(controller.cookies.get(oidc.STATE_COOKIE))
    assert oidc.pkce_challenge(saved["verifier"]) == query["code_challenge"]


def test_full_login_gives_a_session_accepted_by_the_api(controller, provider, caplog):
    state = start_login(controller, provider)
    with caplog.at_level(logging.INFO):
        response = controller.get(
            "/api/v1/auth/oidc/callback", params={"code": "code-xyz", "state": state}
        )

    assert response.status_code == 303
    assert parse_qs(urlsplit(response.headers["location"]).query)["returnUrl"] == ["/reports"]
    session = session_of(response)
    # The code went to the token endpoint with the PKCE verifier and the client secret
    url, data, headers = next(r for r in provider.requests if r[0].endswith("/token"))
    assert data["code"] == "code-xyz" and data["code_verifier"]
    assert headers["Authorization"].startswith("Basic ")
    # The state cookie is dropped
    assert oidc.STATE_COOKIE not in controller.cookies

    me = controller.get("/api/v1/me", headers={"Authorization": f"Bearer {session}"})
    assert me.status_code == 200
    assert (me.json()["client"], me.json()["role"]) == ("oidc:alice", "user")
    assert me.json()["permissions"] == {"reports.read": None}
    # Nothing secret in the logs of the controller
    logs = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("security_review_mcp")
    )
    (event,) = audit.list_events(action="user.login")["events"]
    assert (event["actor"], event["details"]["method"]) == ("user:oidc:alice", "oidc")
    for secret in ("code-xyz", session, "access-abc", "client-secret"):
        assert secret not in logs


def test_session_is_refused_by_the_mcp_server(controller, provider):
    state = start_login(controller, provider)
    session = session_of(
        controller.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": state})
    )
    token_store.create_token("ci", Role.MCP)  # the MCP server is protected
    mcp = TestClient(
        http_server.build_mcp_app(server.mcp, "127.0.0.1", token_store.DatabaseTokenStore()),
        base_url="http://127.0.0.1",
    )
    response = mcp.post("/mcp", headers={"Authorization": f"Bearer {session}"}, json={})
    assert response.status_code == 401


def test_api_needs_a_token_even_without_database_tokens(controller):
    # With OIDC the API is configured: 401 instead of 503
    assert controller.get("/api/v1/me").status_code == 401
    forged = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
    response = controller.get("/api/v1/me", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_admin_group_and_userinfo_groups(controller, provider):
    # Groups missing from the ID token are read from the userinfo endpoint
    provider.claims = {"preferred_username": "bob"}
    provider.userinfo_claims = {"groups": ["secreview-admins"]}
    state = start_login(controller, provider)
    session = session_of(
        controller.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": state})
    )
    me = controller.get("/api/v1/me", headers={"Authorization": f"Bearer {session}"}).json()
    assert (me["client"], me["role"], me["permissions"]) == (
        "oidc:bob",
        "user",
        {permission.value: None for permission in Permission},
    )


def test_sso_group_restricts_the_session_to_its_projects(controller, provider):
    for project in ("shop-api", "billing"):
        services.save_report(project, "Review", [])
    group_for("triager", ["billing"], name="payments-team", sso=True)
    provider.claims = {"preferred_username": "carol", "groups": ["payments-team"]}
    state = start_login(controller, provider)
    session = session_of(
        controller.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": state})
    )
    headers = {"Authorization": f"Bearer {session}"}

    me = controller.get("/api/v1/me", headers=headers).json()
    assert (me["role"], me["projects"]) == ("user", ["billing"])
    assert me["permissions"] == {"findings.triage": ["billing"], "reports.read": ["billing"]}
    projects = controller.get("/api/v1/projects", headers=headers).json()
    assert [item["project"] for item in projects] == ["billing"]
    assert controller.get("/api/v1/posture?project=shop-api", headers=headers).status_code == 404


def test_sso_user_created_by_an_administrator_reads_its_projects(controller, provider):
    for project in ("shop-api", "billing"):
        services.save_report(project, "Review", [])
    make_user("dave", None, "reader", ["shop-api"], auth_source="oidc")
    # No group of the claim of dave exists: only the groups given by an administrator apply
    provider.claims = {"preferred_username": "dave", "groups": ["unmapped"]}
    state = start_login(controller, provider)
    session = session_of(
        controller.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": state})
    )
    headers = {"Authorization": f"Bearer {session}"}

    me = controller.get("/api/v1/me", headers=headers).json()
    assert (me["client"], me["role"], me["projects"]) == ("oidc:dave", "user", ["shop-api"])
    assert (me["auth_source"], me["local_account"]) == ("oidc", False)
    projects = controller.get("/api/v1/projects", headers=headers).json()
    assert [item["project"] for item in projects] == ["shop-api"]
    # An OIDC user has no password to change
    response = controller.put(
        "/api/v1/me/password",
        headers=headers,
        json={"current_password": "x", "new_password": "y" * 12},
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("claims", "error"),
    [
        # Another name with the email of dave: a new user without any group
        ({"preferred_username": "mallory", "email": "dave"}, "forbidden"),
        # No fallback to email or sub: only the configured claim names the user
        ({"email": "dave"}, "username"),
        # The subject of the fake provider is "user-123", also a user below
        ({}, "username"),
        # Invisible or control characters are not stripped into another user's name
        ({"preferred_username": "da\u200bve"}, "username"),
        ({"preferred_username": "dave\n"}, "username"),
        ({"preferred_username": ["dave"]}, "username"),
    ],
)
def test_sso_user_of_another_name_does_not_apply(controller, provider, claims, error):
    make_user("dave", None, "reader", ["shop-api"], auth_source="oidc")
    make_user("user-123", None, "reader", ["shop-api"], auth_source="oidc")
    provider.claims = {**claims, "groups": []}
    state = start_login(controller, provider)
    response = controller.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": state})
    assert error_of(response) == error


def test_login_granting_too_many_projects_is_refused(controller, provider, monkeypatch):
    monkeypatch.setattr(access_control, "MAX_SESSION_PROJECTS", 1)
    group_for("reader", ["a"], name="team-a", sso=True)
    group_for("reader", ["b"], name="team-b", sso=True)
    provider.claims = {"preferred_username": "alice", "groups": ["team-a", "team-b"]}
    state = start_login(controller, provider)
    response = controller.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": state})
    assert error_of(response) == "forbidden"


@pytest.mark.parametrize(
    "attributes",
    [
        {"token_overrides": {"aud": "another-client"}},
        {"token_overrides": {"iss": "https://evil.example.com"}},
        {"token_overrides": {"exp": int(time.time()) - 3600}},
        {"token_overrides": {"nonce": "replayed"}},
        {"token_overrides": {"aud": [CLIENT_ID, "other"], "azp": "other"}},
        # Unknown key id: the JWKS is downloaded again, then the token is refused
        {"header_overrides": {"kid": "rotated"}},
        # The userinfo endpoint describes another user
        {"claims": {}, "userinfo_claims": {"sub": "someone-else", "groups": ["secreview-admins"]}},
    ],
)
def test_invalid_id_tokens_are_refused(controller, provider, attributes):
    for name, value in attributes.items():
        setattr(provider, name, value)
    state = start_login(controller, provider)
    response = controller.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": state})
    assert error_of(response) == "token"


def test_a_shared_secret_algorithm_is_never_accepted(provider):
    # Even when the provider announces it
    with pytest.raises(oidc.OidcError, match="algorithm not accepted"):
        provider.validate_id_token(jwt.encode({"sub": "x"}, "k" * 32, algorithm="HS256"), "n")


@pytest.mark.parametrize(
    ("forged_state", "other_browser"),
    [
        ("forged", False),
        # Non-ASCII: refused without a server error
        ("é", False),
        # Another browser (no cookie): login CSRF refused
        (None, True),
    ],
)
def test_callback_needs_the_matching_state_cookie(
    controller, provider, forged_state, other_browser
):
    state = start_login(controller, provider)
    client = controller
    if other_browser:
        client = TestClient(
            controller.app, base_url="https://secreview.example.com", follow_redirects=False
        )
    response = client.get(
        "/api/v1/auth/oidc/callback", params={"code": "c", "state": forged_state or state}
    )
    assert error_of(response) == "state"


def test_provider_error_is_reported_without_echoing_it(controller):
    response = controller.get(
        "/api/v1/auth/oidc/callback",
        params={"error": "access_denied", "error_description": "<script>"},
    )
    assert error_of(response) == "denied"
    assert "script" not in response.headers["location"]


def test_open_redirect_is_impossible(controller, provider):
    state = start_login(controller, provider, return_url="//evil.example.com")
    response = controller.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": state})
    assert parse_qs(urlsplit(response.headers["location"]).query)["returnUrl"] == ["/"]


def test_discovery_of_another_issuer_is_refused(provider):
    original = provider.fetch_json

    def fetch(url, data=None, headers=None):  # noqa: ANN001, ANN202
        document = original(url, data, headers)
        return (
            {**document, "issuer": "https://evil.example.com"} if "well-known" in url else document
        )

    provider.fetch_json = fetch
    with pytest.raises(oidc.OidcError, match="another issuer"):
        provider.start("/")


def test_fetch_json_bounds_the_response(monkeypatch):
    login = oidc.OidcLogin(make_settings())

    class Response:
        def __init__(self, body: bytes) -> None:
            self.body = body

        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *args) -> None:
            pass

        def read(self, size: int) -> bytes:
            return self.body[:size]

    body = b'{"a": "' + b"x" * oidc.MAX_RESPONSE_BYTES + b'"}'
    monkeypatch.setattr(login._opener, "open", lambda request, timeout: Response(body))
    with pytest.raises(oidc.OidcError, match="too large"):
        login.fetch_json(f"{ISSUER}/x")
    monkeypatch.setattr(login._opener, "open", lambda request, timeout: Response(b"[1]"))
    with pytest.raises(oidc.OidcError, match="unexpected document"):
        login.fetch_json(f"{ISSUER}/x")


def test_the_provider_is_reached_through_the_proxy_of_the_controller():
    login = oidc.OidcLogin(make_settings(https_proxy="http://proxy.internal:3128"))
    (handler,) = [h for h in login._opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert handler.proxies["https"] == "http://proxy.internal:3128"


def test_an_unreachable_provider_never_logs_the_proxy_password(monkeypatch, caplog):
    proxy_url = "http://alice:s3cr3t@proxy.internal:3128"
    login = oidc.OidcLogin(make_settings(https_proxy=proxy_url))

    def fail(request, timeout):  # noqa: ANN001, ANN202
        raise urllib.error.URLError(f"cannot reach {proxy_url}")

    monkeypatch.setattr(login._opener, "open", fail)
    with pytest.raises(oidc.OidcError, match="unreachable"):
        login.fetch_json("https://sso.example.com/realms/acme/.well-known/openid-configuration")
    assert "s3cr3t" not in caplog.text and "alice:***@proxy.internal" in caplog.text
