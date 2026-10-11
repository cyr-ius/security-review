"""Streamable HTTP transport: bearer authentication, TLS options and start-up wiring."""

import json
import ssl

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from security_review_mcp import cli, http_server, server, token_store
from security_review_mcp.config import Settings
from security_review_mcp.http_server import BearerAuthMiddleware, PathDispatcher, Role, hash_token

STORE = token_store.DatabaseTokenStore()


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def whoami(request: Request) -> PlainTextResponse:
    """Echo the label and role stored by the middleware."""
    state = request.scope.get("state", {})
    return PlainTextResponse(f"{state.get('auth_client')}/{state.get('auth_role')}")


def enrollment_echo(request: Request) -> PlainTextResponse:
    """Stand-in for the enrollment server: echo the pending token id it receives."""
    return PlainTextResponse(f"enroll/{request.scope['state']['enrollment_token_id']}")


def protected_client(web: bool = False, enrollment: bool = False) -> TestClient:
    app = Starlette(
        routes=[
            Route("/mcp", whoami),
            Route("/api/v1/me", whoami),
            Route("/api/v1/enroll", whoami, methods=["POST"]),
            Route("/api/docs", whoami),
            Route("/api/openapi.json", whoami),
            Route("/ui/", whoami),
        ]
    )
    enrollment_app = Starlette(routes=[Route("/mcp", enrollment_echo)]) if enrollment else None
    return TestClient(BearerAuthMiddleware(app, STORE, web=web, enrollment_app=enrollment_app))


# ── Middleware ───────────────────────────────────────────────────────────────


def test_valid_token_is_accepted_and_labelled():
    dev = token_store.create_token("dev", Role.MCP)["token"]
    client = protected_client()
    assert client.get("/mcp", headers=bearer(dev)).text == "dev/mcp"
    assert client.get("/mcp", headers={"Authorization": f"bearer {dev}"}).text == "dev/mcp"


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer "},
        {"Authorization": f"Bearer {'x' * 40}"},
    ],
)
def test_missing_or_wrong_token_is_rejected(headers):
    token_store.create_token("dev", Role.MCP)
    response = protected_client().get("/mcp", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")
    assert response.json()["error"] == "invalid_token"


@pytest.mark.parametrize(
    "role, mcp_status, api_status",
    [
        ("mcp", 200, 403),
        ("reader", 403, 200),
        ("triager", 403, 200),
        ("admin", 200, 200),
    ],
)
def test_roles_select_the_endpoints(role, mcp_status, api_status):
    token = token_store.create_token("user", role)["token"]
    client = protected_client(web=True)
    assert client.get("/mcp", headers=bearer(token)).status_code == mcp_status
    response = client.get("/api/v1/me", headers=bearer(token))
    assert response.status_code == api_status
    if api_status == 403:
        assert response.json()["error"] == "insufficient_scope"
    else:
        assert response.text == f"user/{role}"


def test_web_ui_files_are_public_but_not_the_api():
    token_store.create_token("dev", Role.MCP)
    client = protected_client(web=True)
    assert client.get("/ui/").status_code == 200
    assert client.get("/api/v1/me").status_code == 401
    assert client.get("/api/docs").status_code == 200
    assert client.get("/api/openapi.json").status_code == 200
    # Without the web interface, every path needs a token
    assert protected_client().get("/ui/").status_code == 401


def test_without_any_token_mcp_is_open_and_the_web_api_not_configured():
    client = protected_client(web=True)

    assert client.get("/ui/").status_code == 200
    response = client.get("/api/v1/me")
    assert response.status_code == 503
    assert response.json()["error"] == "authentication_not_configured"
    assert client.get("/mcp").status_code == 200
    assert protected_client().get("/mcp").status_code == 200


def test_enrollment_app_receives_mcp_clients_without_an_approved_token():
    token_store.create_token("ops", Role.ADMIN)
    request = token_store.request_enrollment("shop-api")
    client = protected_client(web=True, enrollment=True)

    assert client.get("/mcp").text == "enroll/None"
    # Hosts send an empty bearer value when the token input or variable is left empty
    for empty in ("Bearer ", "Bearer    ", "bearer"):
        assert client.get("/mcp", headers={"Authorization": empty}).text == "enroll/None"
    assert client.get("/mcp", headers=bearer(request["token"])).text == f"enroll/{request['id']}"
    # A wrong token is still an error, and the REST API never falls back to enrollment
    assert client.get("/mcp", headers=bearer("x" * 40)).status_code == 401
    assert client.get("/api/v1/me").status_code == 401
    response = client.get("/api/v1/me", headers=bearer(request["token"]))
    assert response.status_code == 403
    assert response.json()["error"] == "enrollment_pending"
    # The enrollment endpoint itself is public
    assert client.post("/api/v1/enroll").status_code == 200

    token_store.approve_enrollment(request["id"])
    assert client.get("/mcp", headers=bearer(request["token"])).text == f"{request['label']}/mcp"


def test_pending_token_is_refused_without_enrollment_app():
    token_store.create_token("ops", Role.ADMIN)
    request = token_store.request_enrollment("shop-api")
    client = protected_client()

    assert client.get("/mcp").status_code == 401
    response = client.get("/mcp", headers=bearer(request["token"]))
    assert response.status_code == 403
    assert response.json()["error"] == "enrollment_pending"


def test_pending_requests_do_not_close_an_open_server():
    token_store.request_enrollment("shop-api")

    client = protected_client(web=True, enrollment=True)

    assert client.get("/mcp").text == "None/None"
    assert client.get("/api/v1/me").status_code == 503


def test_tokens_are_checked_in_the_database_on_each_request():
    client = protected_client(web=True)
    password = token_store.ensure_bootstrap_admin()
    created = token_store.create_project_token("ci", "shop-api")
    reader = bearer(created["token"])
    assert client.get("/api/v1/me", headers=bearer(password)).text == "bootstrap-admin/admin"
    assert client.get("/mcp", headers=bearer(password)).status_code == 200
    assert client.get("/api/v1/me", headers=reader).text == "ci/reader"
    assert client.get("/mcp", headers=reader).status_code == 403
    assert client.get("/mcp").status_code == 401

    # A revocation (from this or another instance) applies to the next request
    token_store.revoke_token("ci")
    assert client.get("/api/v1/me", headers=reader).status_code == 401


def test_path_dispatcher_routes_web_paths():
    def app_named(name: str) -> Starlette:
        return Starlette(routes=[Route("/{path:path}", lambda _: PlainTextResponse(name))])

    client = TestClient(PathDispatcher(app_named("mcp"), app_named("web")))
    assert [client.get(path).text for path in ("/mcp", "/api/v1/me", "/ui", "/ui/x", "/")] == [
        "mcp",
        "web",
        "web",
        "web",
        "web",
    ]
    assert client.get("/uix").text == "mcp"


def test_build_app_is_always_protected_by_the_store():
    app = http_server.build_app(server.mcp, "127.0.0.1", STORE)
    assert isinstance(app, BearerAuthMiddleware) and not app.web
    web_app = http_server.build_app(server.mcp, "127.0.0.1", STORE, web_app=Starlette())
    assert isinstance(web_app, BearerAuthMiddleware) and web_app.web


# ── TLS ──────────────────────────────────────────────────────────────────────


def test_tls_disabled_by_default():
    assert http_server.tls_options(make_settings()) is None


def test_tls_options(tmp_path):
    cert, key, ca = (tmp_path / name for name in ("cert.pem", "key.pem", "ca.pem"))
    for path in (cert, key, ca):
        path.write_text("x", encoding="utf-8")

    tls = http_server.tls_options(make_settings(tls_certfile=str(cert), tls_keyfile=str(key)))
    assert tls.uvicorn_kwargs() == {
        "ssl_certfile": str(cert),
        "ssl_keyfile": str(key),
        "ssl_keyfile_password": None,
    }

    mutual = http_server.tls_options(make_settings(tls_certfile=str(cert), tls_client_ca=str(ca)))
    kwargs = mutual.uvicorn_kwargs()
    assert kwargs["ssl_ca_certs"] == str(ca)
    assert kwargs["ssl_cert_reqs"] == ssl.CERT_REQUIRED


def test_tls_options_errors(tmp_path):
    with pytest.raises(ValueError, match="need SECREVIEW_TLS_CERTFILE"):
        http_server.tls_options(make_settings(tls_keyfile="key.pem"))
    with pytest.raises(ValueError, match="file not found"):
        http_server.tls_options(make_settings(tls_certfile=str(tmp_path / "missing.pem")))


# ── Start-up ─────────────────────────────────────────────────────────────────


@pytest.fixture
def captured_run(monkeypatch):
    """Capture the uvicorn.run call instead of starting a server."""
    calls: list[dict] = []
    monkeypatch.setattr(server, "init_db", lambda: None)
    monkeypatch.setattr(
        http_server.uvicorn, "run", lambda app, **kwargs: calls.append({"app": app, **kwargs})
    )
    return calls


def test_main_serves_http_with_auth_and_tls(tmp_path, monkeypatch, captured_run):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text("x", encoding="utf-8")
    key.write_text("x", encoding="utf-8")
    token_store.create_token("ci", Role.MCP)
    monkeypatch.setattr(
        server, "get_settings", lambda: make_settings(web_ui=False, enrollment=False)
    )

    server.main(
        [
            "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8443",
            "--tls-certfile", str(cert), "--tls-keyfile", str(key),
        ]
    )  # fmt: skip

    (call,) = captured_run
    assert isinstance(call["app"], BearerAuthMiddleware)
    assert (call["host"], call["port"]) == ("0.0.0.0", 8443)
    assert (call["ssl_certfile"], call["ssl_keyfile"]) == (str(cert), str(key))
    assert TestClient(call["app"]).get("/mcp").status_code == 401


@pytest.mark.parametrize("enabled", [True, False])
def test_main_serves_the_enrollment_server_when_enabled(monkeypatch, captured_run, enabled):
    token_store.create_token("ops", Role.ADMIN)
    monkeypatch.setattr(server, "get_settings", lambda: make_settings(enrollment=enabled))

    server.main(["--transport", "streamable-http"])

    (call,) = captured_run
    assert (call["app"].enrollment_app is not None) is enabled
    with TestClient(call["app"], base_url="http://127.0.0.1:8000") as client:
        response = client.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    if enabled:
        tools = {tool["name"] for tool in response.json()["result"]["tools"]}
        assert tools == {"request_enrollment", "get_enrollment_status"}
    else:
        assert response.status_code == 401


def test_main_logs_bootstrap_password_only_when_created(monkeypatch, caplog, captured_run):
    monkeypatch.setattr(server, "get_settings", lambda: make_settings(auth_bootstrap_admin=True))

    with caplog.at_level("WARNING", logger="security_review_mcp"):
        server.main(["--transport", "streamable-http"])
        messages = [record.message for record in caplog.records]
        assert sum("Initial Web UI administrator password" in message for message in messages) == 1
        caplog.clear()
        server.main(["--transport", "streamable-http"])

    assert not any(
        "Initial Web UI administrator password" in record.message for record in caplog.records
    )
    (password,) = [
        message.rsplit(" ", 1)[1] for message in messages if "administrator password" in message
    ]
    client = TestClient(captured_run[-1]["app"], base_url="http://127.0.0.1")
    identity = client.get("/api/v1/me", headers=bearer(password)).json()
    assert identity["role"] == "admin"


def test_main_without_bootstrap_setting_creates_no_admin(monkeypatch, captured_run):
    monkeypatch.setattr(server, "get_settings", lambda: make_settings())

    server.main(["--transport", "streamable-http"])

    assert STORE.has_tokens() is False


@pytest.mark.parametrize("web", [True, False])
@pytest.mark.parametrize(
    ("host", "with_tls", "warned"),
    [("0.0.0.0", False, True), ("0.0.0.0", True, False), ("127.0.0.1", False, False)],
)
def test_run_warns_without_tls_only_when_exposed(
    tmp_path, caplog, captured_run, host, with_tls, warned, web
):
    """The missing-TLS warning depends on the host and TLS, not on the web interface."""
    tls = http_server.TLSOptions(certfile=str(tmp_path / "cert.pem")) if with_tls else None
    web_app = Starlette() if web else None

    with caplog.at_level("WARNING", logger="security_review_mcp"):
        http_server.run(server.mcp, host, 8000, STORE, tls, web_app=web_app)

    assert len(captured_run) == 1
    assert any("without TLS" in record.message for record in caplog.records) is warned


@pytest.mark.parametrize("has_token", [True, False])
def test_run_warns_without_authentication_only_when_no_token(caplog, captured_run, has_token):
    if has_token:
        token_store.create_token("ci", Role.MCP)

    with caplog.at_level("WARNING", logger="security_review_mcp"):
        http_server.run(server.mcp, "0.0.0.0", 8000, STORE, None)

    warned = any("without authentication" in record.message for record in caplog.records)
    assert warned is not has_token


# ── CLI ──────────────────────────────────────────────────────────────────────


def run_cli(capsys, *argv: str) -> tuple[int, object]:
    """Run ``security-review-mcp token ...`` and decode its JSON output (None on error)."""
    code = cli.run(["token", *argv])
    out = capsys.readouterr().out
    return code, json.loads(out) if out else None


def test_token_create_list_revoke(capsys):
    code, created = run_cli(capsys, "create", "--label", "ci")
    assert code == cli.EXIT_PASSED
    assert (created["label"], created["role"], created["project"]) == ("ci", "mcp", None)
    assert STORE.lookup(hash_token(created["token"])).label == "ci"

    code, reader = run_cli(
        capsys, "create", "--label", "shop", "--role", "reader", "--project", "shop-api"
    )
    assert code == cli.EXIT_PASSED and reader["project"] == "shop-api"

    code, listed = run_cli(capsys, "list")
    assert [token["label"] for token in listed] == ["ci", "shop"]
    assert created["token"] not in json.dumps(listed) and "hash" not in json.dumps(listed)
    _, scoped = run_cli(capsys, "list", "--project", "shop-api")
    assert [token["label"] for token in scoped] == ["shop"]

    code, multi = run_cli(
        capsys, "create", "--label", "multi", "--project", "shop-api", "--project", "billing"
    )
    assert code == cli.EXIT_PASSED and multi["projects"] == ["shop-api", "billing"]
    assert STORE.lookup(hash_token(multi["token"])).projects == {"shop-api", "billing"}
    _, scoped = run_cli(capsys, "list", "--project", "billing")
    assert [token["label"] for token in scoped] == ["multi"]
    assert cli.run(["token", "revoke", "multi"]) == cli.EXIT_PASSED

    assert cli.run(["token", "revoke", "ci"]) == cli.EXIT_PASSED
    assert capsys.readouterr().err == ""
    assert cli.run(["token", "revoke", reader["id"]]) == cli.EXIT_PASSED
    assert "No token left" in capsys.readouterr().err
    assert STORE.has_tokens() is False


@pytest.mark.parametrize(
    "argv, message",
    [
        (["create", "--label", "x", "--role", "admin", "--project", "p"], "cannot be restricted"),
        (["create", "--label", " "], "between 1 and 64"),
        (["revoke", "unknown"], "not found"),
    ],
)
def test_token_command_errors(capsys, argv, message):
    assert cli.run(["token", *argv]) == cli.EXIT_ERROR
    assert message in json.loads(capsys.readouterr().err)["error"]


def test_token_approve_and_reject_enrollment_requests(capsys):
    first = token_store.request_enrollment("shop-api", label="shop-dev")
    second = token_store.request_enrollment("billing")

    code, pending = run_cli(capsys, "list", "--pending")
    assert code == cli.EXIT_PASSED
    assert [item["label"] for item in pending] == [first["label"], second["label"]]
    assert first["token"] not in json.dumps(pending)

    code, approved = run_cli(capsys, "approve", first["label"])
    assert code == cli.EXIT_PASSED and approved["status"] == "active"
    assert STORE.lookup(hash_token(first["token"])).pending is False

    code, rejected = run_cli(capsys, "reject", second["id"])
    assert code == cli.EXIT_PASSED and rejected["label"] == second["label"]
    assert STORE.lookup(hash_token(second["token"])) is None
    assert run_cli(capsys, "list", "--pending")[1] == []

    assert cli.run(["token", "approve", first["label"]]) == cli.EXIT_ERROR
    assert "not found" in json.loads(capsys.readouterr().err)["error"]


def test_token_approve_complementary_enrollment_requests(capsys):
    created = token_store.create_token("ci", Role.MCP, "shop-api")
    billing = token_store.request_additional_project(created["id"], "billing")
    token_store.request_additional_project(created["id"], "crm")

    code, pending = run_cli(capsys, "list", "--pending")
    assert [(item["kind"], item["project"]) for item in pending] == [
        ("additional", "billing"),
        ("additional", "crm"),
    ]
    # Two requests for the same token: the label is ambiguous, the request id is not
    assert cli.run(["token", "approve", "ci"]) == cli.EXIT_ERROR
    assert "several pending requests" in json.loads(capsys.readouterr().err)["error"]
    code, approved = run_cli(capsys, "approve", billing["id"])
    assert code == cli.EXIT_PASSED and approved["projects"] == ["shop-api", "billing"]
    code, rejected = run_cli(capsys, "reject", "ci")
    assert code == cli.EXIT_PASSED and rejected["project"] == "crm"
    assert STORE.lookup(hash_token(created["token"])).projects == {"shop-api", "billing"}


def test_revoking_the_last_active_token_warns_despite_pending_requests(capsys):
    token_store.request_enrollment("shop-api")
    token_store.create_token("ci", Role.MCP)

    assert cli.run(["token", "revoke", "ci"]) == cli.EXIT_PASSED
    assert "No token left" in capsys.readouterr().err


def test_token_create_rejects_duplicate_labels(capsys):
    assert run_cli(capsys, "create", "--label", "ci")[0] == cli.EXIT_PASSED
    assert run_cli(capsys, "create", "--label", "ci")[0] == cli.EXIT_ERROR


def test_token_reset_admin(capsys):
    first = token_store.ensure_bootstrap_admin()

    code, output = run_cli(capsys, "reset-admin")

    assert code == cli.EXIT_PASSED
    assert output["label"] == "bootstrap-admin"
    assert STORE.lookup(hash_token(first)) is None
    info = STORE.lookup(hash_token(output["token"]))
    assert (info.label, info.role) == ("bootstrap-admin", Role.ADMIN)
