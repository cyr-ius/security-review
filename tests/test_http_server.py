"""HTTP serving: bearer authentication, TLS options and start-up of the MCP server."""

import argparse
import json
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from conftest import make_user
from sqlmodel import select
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from security_review_mcp import (
    cli,
    config,
    database,
    http_server,
    server,
    token_store,
    web_users,
)
from security_review_mcp.config import Settings
from security_review_mcp.http_server import BearerAuthMiddleware, PathDispatcher, Role, hash_token
from security_review_mcp.models import ApiToken

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
    """Stand-in for the enrollment server: echo the pending token id it receives, and why a
    token was rejected if one was."""
    state = request.scope["state"]
    rejected = state["enrollment_rejected_token"]
    suffix = f"/{rejected}" if rejected else ""
    return PlainTextResponse(f"enroll/{state['enrollment_token_id']}{suffix}")


def expire(label: str) -> None:
    """Move the expiry date of a token into the past."""
    with database.session_scope() as session:
        row = session.exec(select(ApiToken).where(ApiToken.label == label)).one()
        row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        session.add(row)


def protected_client(
    web: bool = False, enrollment: bool = False, allow_open: bool = False
) -> TestClient:
    """The middleware of the MCP server (``web=False``) or of the controller (``web=True``)."""
    app = Starlette(
        routes=[
            Route("/mcp", whoami),
            Route("/api/v1/me", whoami),
            Route("/api/v1/enroll", whoami, methods=["POST"]),
            Route("/api/v1/auth/config", whoami),
            Route("/api/docs", whoami),
            Route("/api/openapi.json", whoami),
            Route("/api/health", whoami),
            Route("/api/swagger/swagger-ui.css", whoami),
            Route("/api/favicon.svg", whoami),
            Route("/ui/", whoami),
            Route("/healthz", whoami),
        ]
    )
    enrollment_app = Starlette(routes=[Route("/mcp", enrollment_echo)]) if enrollment else None
    public = frozenset({"/api/v1/enroll", "/healthz"})
    return TestClient(
        BearerAuthMiddleware(
            app,
            STORE,
            web=web,
            enrollment_app=enrollment_app,
            public_paths=public,
            allow_open=allow_open,
        )
    )


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
        ("admin", 200, 200),
        ("ci", 403, 403),
        ("metrics", 403, 403),
    ],
)
def test_roles_select_the_process(role, mcp_status, api_status):
    projects = ["shop-api"] if role == "ci" else None
    token = token_store.create_token("user", role, projects)["token"]
    assert protected_client().get("/mcp", headers=bearer(token)).status_code == mcp_status
    response = protected_client(web=True).get("/api/v1/me", headers=bearer(token))
    assert response.status_code == api_status
    if api_status == 403:
        assert response.json()["error"] == "insufficient_scope"
    else:
        assert response.text == f"user/{role}"
    # Without a web role, the controller refuses every private path, even an unknown one
    response = protected_client(web=True).get("/mcp", headers=bearer(token))
    assert response.status_code == api_status


def test_web_ui_files_are_public_but_not_the_api():
    token_store.create_token("dev", Role.MCP)
    client = protected_client(web=True)
    assert client.get("/ui/").status_code == 200
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/v1/me").status_code == 401
    assert client.get("/api/docs").status_code == 200
    assert client.get("/api/openapi.json").status_code == 200
    assert client.get("/api/swagger/swagger-ui.css").status_code == 200
    assert client.get("/api/favicon.svg").status_code == 200
    # The controller does not serve the public enrollment endpoint
    assert client.post("/api/v1/enroll").status_code == 401
    # On the MCP server, only the public paths it declares are open
    mcp_client = protected_client()
    assert mcp_client.get("/ui/").status_code == 401
    assert mcp_client.get("/api/docs").status_code == 401
    assert mcp_client.get("/api/swagger/swagger-ui.css").status_code == 401
    assert mcp_client.get("/api/favicon.svg").status_code == 401
    assert mcp_client.get("/healthz").status_code == 200
    assert mcp_client.post("/api/v1/enroll").status_code == 200
    # The login routes are public on the controller only
    assert client.get("/api/v1/auth/config").status_code == 200
    assert mcp_client.get("/api/v1/auth/config").status_code == 401


def test_without_any_token_the_web_api_is_not_configured():
    client = protected_client(web=True)

    assert client.get("/ui/").status_code == 200
    response = client.get("/api/v1/me")
    assert response.status_code == 503
    assert response.json()["error"] == "authentication_not_configured"
    # allow_open only concerns the MCP server
    assert protected_client(web=True, allow_open=True).get("/api/v1/me").status_code == 503


def test_without_any_token_mcp_is_closed_unless_allowed():
    closed = protected_client()
    assert closed.get("/mcp").status_code == 401
    # Any bearer value used to be accepted while no token existed
    assert closed.get("/mcp", headers=bearer("anything")).status_code == 401
    assert closed.get("/healthz").status_code == 200
    # Without a token, a client of a closed server reaches enrollment
    assert protected_client(enrollment=True).get("/mcp").text == "enroll/None"

    assert protected_client(allow_open=True).get("/mcp").status_code == 200
    # Once a token exists, an open server requires it too
    token_store.create_token("ops", Role.ADMIN)
    assert protected_client(allow_open=True).get("/mcp").status_code == 401


@pytest.mark.parametrize(
    ("host", "allow_unauthenticated", "expected"),
    [
        ("127.0.0.1", False, True),
        ("::1", False, True),
        ("0.0.0.0", False, False),
        ("192.168.1.1", False, False),
        ("0.0.0.0", True, True),
    ],
)
def test_only_loopback_or_explicit_setting_opens_mcp(host, allow_unauthenticated, expected):
    assert http_server.allows_open_mcp(host, allow_unauthenticated) is expected


def test_enrollment_app_receives_mcp_clients_without_an_approved_token():
    token_store.create_token("ops", Role.ADMIN)
    request = token_store.request_enrollment("shop-api")
    client = protected_client(enrollment=True)

    assert client.get("/mcp").text == "enroll/None"
    # Hosts send an empty bearer value when the token input or variable is left empty
    assert client.get("/mcp", headers={"Authorization": "Bearer "}).text == "enroll/None"
    assert client.get("/mcp", headers=bearer(request["token"])).text == f"enroll/{request['id']}"

    token_store.approve_enrollment(request["id"])
    assert client.get("/mcp", headers=bearer(request["token"])).text == f"{request['label']}/mcp"


def test_rejected_tokens_fall_back_to_enrollment_on_the_mcp_server_only():
    token_store.create_token("ops", Role.ADMIN)
    old = token_store.create_token("old", Role.MCP, expires_in_days=1)["token"]
    expire("old")
    before = dict(http_server.AUTH_REJECTIONS)
    client = protected_client(enrollment=True)

    assert client.get("/mcp", headers=bearer(old)).text == "enroll/None/token_expired"
    assert client.get("/mcp", headers=bearer("x" * 40)).text == "enroll/None/invalid_token"
    # Still counted as rejections, and never a way into the review server
    assert http_server.AUTH_REJECTIONS["token_expired"] == before.get("token_expired", 0) + 1
    assert http_server.AUTH_REJECTIONS["invalid_token"] == before.get("invalid_token", 0) + 1
    # Without enrollment the MCP server answers 401, and the controller always does
    for rejected in (old, "x" * 40):
        assert protected_client().get("/mcp", headers=bearer(rejected)).status_code == 401
        response = protected_client(web=True, enrollment=True).get(
            "/api/v1/me", headers=bearer(rejected)
        )
        assert response.status_code == 401


@pytest.mark.parametrize(
    ("web", "enrollment", "path"),
    [(True, True, "/api/v1/me"), (False, False, "/mcp")],
    ids=["controller", "mcp-without-enrollment"],
)
def test_pending_token_is_refused_without_enrollment_fallback(web, enrollment, path):
    token_store.create_token("ops", Role.ADMIN)
    request = token_store.request_enrollment("shop-api")
    client = protected_client(web=web, enrollment=enrollment)

    assert client.get(path).status_code == 401
    response = client.get(path, headers=bearer(request["token"]))
    assert response.status_code == 403
    assert response.json()["error"] == "enrollment_pending"


def test_pending_requests_do_not_close_an_open_server():
    token_store.request_enrollment("shop-api")

    assert protected_client(enrollment=True, allow_open=True).get("/mcp").text == "None/None"
    assert protected_client(web=True).get("/api/v1/me").status_code == 503


def test_tokens_are_checked_in_the_database_on_each_request():
    mcp_client = protected_client()
    created = token_store.create_project_token("agent", "shop-api")
    agent = bearer(created["token"])
    assert mcp_client.get("/mcp", headers=agent).text == "agent/mcp"

    # A revocation (from the controller or another instance) applies to the next request
    token_store.revoke_token("agent")
    assert mcp_client.get("/mcp", headers=agent).status_code == 401


def test_path_dispatcher_routes_exact_paths():
    def app_named(name: str) -> Starlette:
        return Starlette(routes=[Route("/{path:path}", lambda _: PlainTextResponse(name))])

    client = TestClient(PathDispatcher(app_named("mcp"), {"/healthz": app_named("health")}))
    assert [client.get(path).text for path in ("/mcp", "/healthz", "/healthz/x", "/")] == [
        "mcp",
        "health",
        "mcp",
        "mcp",
    ]


@pytest.mark.parametrize(("enrollment", "enroll_status"), [(True, 200), (False, 401)])
def test_mcp_app_serves_health_and_enrollment_but_not_the_web_interface(enrollment, enroll_status):
    token_store.create_token("ops", Role.ADMIN)
    endpoint = Starlette(routes=[Route("/api/v1/enroll", whoami, methods=["POST"])])
    app = http_server.build_mcp_app(
        server.mcp, "127.0.0.1", STORE, enroll_endpoint=endpoint if enrollment else None
    )
    client = TestClient(app, base_url="http://127.0.0.1")

    health = client.get("/healthz")
    assert (health.status_code, health.json()) == (200, {"status": "ok"})
    assert client.post("/api/v1/enroll").status_code == enroll_status
    assert client.get("/ui/").status_code == 401
    assert client.get("/api/v1/me").status_code == 401


def json_answer(_request):
    return JSONResponse({"ok": True})


def html_answer(_request):
    return HTMLResponse("<p>ok</p>", headers={"Content-Security-Policy": "default-src 'self'"})


def headers_client(scheme: str = "http") -> TestClient:
    token_store.create_token("dev", Role.ADMIN)
    web = Starlette(routes=[Route("/api/v1/me", json_answer), Route("/ui/", html_answer)])
    app = http_server.build_controller_app(web, token_store.DatabaseTokenStore())
    return TestClient(app, base_url=f"{scheme}://127.0.0.1")


@pytest.mark.parametrize(("scheme", "hsts"), [("http", None), ("https", "max-age=31536000")])
def test_every_controller_answer_has_the_security_headers(scheme, hsts):
    client = headers_client(scheme)
    token = token_store.create_token("ops", Role.ADMIN)["token"]

    for response in (
        client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}),
        client.get("/api/v1/me"),  # refused (401): headers too
    ):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["content-security-policy"].startswith("default-src 'none'")
        # Plain HTTP: no HSTS (the browser would ignore it, and it must not stick to http://)
        assert response.headers.get("strict-transport-security") == hsts
    # The CSP of a page (web interface, Swagger) is kept
    assert client.get("/ui/").headers["content-security-policy"] == "default-src 'self'"


# ── TLS ──────────────────────────────────────────────────────────────────────


def test_tls_options(tmp_path):
    assert http_server.tls_options(make_settings()) is None  # disabled by default

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
    with pytest.raises(ValueError, match="CLIENT_CA needs SECREVIEW_TLS_CERTFILE"):
        http_server.tls_options(make_settings(tls_client_ca="ca.pem"))
    with pytest.raises(ValueError, match="file not found"):
        http_server.tls_options(make_settings(tls_certfile=str(tmp_path / "missing.pem")))


# ── Start-up ─────────────────────────────────────────────────────────────────


@pytest.fixture
def captured_run(monkeypatch):
    """Capture the uvicorn.run call instead of starting a server (schema migrated)."""
    database.upgrade_db()
    calls: list[dict] = []
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
        server,
        "get_settings",
        lambda: make_settings(enrollment=False, forwarded_allow_ips="10.0.0.0/8"),
    )

    server.main(
        [
            "serve", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8443",
            "--tls-certfile", str(cert), "--tls-keyfile", str(key),
        ]
    )  # fmt: skip

    (call,) = captured_run
    assert (call["host"], call["port"]) == ("0.0.0.0", 8443)
    assert (call["ssl_certfile"], call["ssl_keyfile"]) == (str(cert), str(key))
    # The client address comes from X-Forwarded-For of the trusted reverse proxies only
    assert (call["proxy_headers"], call["forwarded_allow_ips"]) == (True, "10.0.0.0/8")
    client = TestClient(call["app"])
    assert client.get("/mcp").status_code == 401
    # The web interface is served by the controller only
    assert client.get("/ui/").status_code == 401


@pytest.mark.parametrize("enabled", [True, False])
def test_main_serves_the_enrollment_server_when_enabled(monkeypatch, captured_run, enabled):
    token_store.create_token("ops", Role.ADMIN)
    monkeypatch.setattr(server, "get_settings", lambda: make_settings(enrollment=enabled))

    server.main(["serve", "--transport", "streamable-http"])

    (call,) = captured_run
    with TestClient(call["app"], base_url="http://127.0.0.1:8000") as client:
        response = client.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        enroll = client.post("/api/v1/enroll", json={"project": "shop-api"})
    if enabled:
        # The enrollment server answers (its tools are checked in test_server.py)
        assert response.status_code == 200
        assert enroll.status_code == 201
    else:
        assert response.status_code == 401
        assert enroll.status_code == 401


@pytest.mark.parametrize(
    ("host", "allow_unauthenticated", "status"),
    [("0.0.0.0", False, 401), ("0.0.0.0", True, 200), ("127.0.0.1", False, 200)],
)
def test_main_closes_an_exposed_server_without_token(
    monkeypatch, captured_run, host, allow_unauthenticated, status
):
    monkeypatch.setattr(
        server,
        "get_settings",
        lambda: make_settings(enrollment=False, allow_unauthenticated=allow_unauthenticated),
    )

    server.main(["serve", "--transport", "streamable-http", "--host", host])

    (call,) = captured_run
    with TestClient(call["app"], base_url="http://127.0.0.1:8000") as client:
        response = client.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream", **bearer("anything")},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                },
            },
        )
    assert response.status_code == status


def test_http_mcp_server_refuses_a_database_that_was_not_migrated(monkeypatch, capsys):
    monkeypatch.setattr(server, "get_settings", lambda: make_settings())
    started = []
    monkeypatch.setattr(http_server.uvicorn, "run", lambda app, **kwargs: started.append(app))

    with pytest.raises(SystemExit) as exc:
        server.main(["serve", "--transport", "streamable-http"])

    assert exc.value.code == 2 and not started
    assert database.current_revision() is None  # the MCP server never migrates


def test_http_mcp_server_creates_no_bootstrap_admin(monkeypatch, captured_run):
    monkeypatch.setattr(server, "get_settings", lambda: make_settings())

    server.main(["serve", "--transport", "streamable-http"])

    assert STORE.has_tokens() is False
    assert web_users.has_users() is False


def test_stdio_server_migrates_its_own_database(monkeypatch):
    monkeypatch.setattr(server, "get_settings", lambda: make_settings())
    started = []
    monkeypatch.setattr(server.mcp, "run", lambda transport: started.append(transport))

    server.main(["serve"])

    assert started == ["stdio"]
    assert database.current_revision() == database.head_revision()


def test_moved_commands_still_run_from_the_mcp_cli_with_a_warning(capsys):
    with pytest.raises(SystemExit) as exc:
        server.main(["db", "status"])

    assert exc.value.code == cli.EXIT_BLOCKED  # not migrated yet
    captured = capsys.readouterr()
    assert "use `security-review-controller db`" in captured.err
    assert json.loads(captured.out)["up_to_date"] is False


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--help"], ["serve", *cli.MCP_COMMANDS]),
        (["serve", "--help"], ["--transport", "--host", "--port"]),
    ],
)
def test_mcp_help_lists_every_command_and_option(capsys, argv, expected):
    try:
        server.main(argv)
    except SystemExit as exc:  # argparse exits after the help of a command
        assert exc.code == 0

    out = capsys.readouterr().out
    assert all(item in out for item in expected)


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        ([], "usage: security-review-mcp COMMAND"),
        (["--transport", "streamable-http"], "use `security-review-mcp serve --transport ...`"),
        (["start"], "unknown command 'start'"),
    ],
)
def test_mcp_without_a_valid_command_serves_nothing(monkeypatch, capsys, argv, message):
    started = []
    monkeypatch.setattr(server.mcp, "run", lambda transport: started.append(transport))

    with pytest.raises(SystemExit) as exc:
        server.main(argv)

    assert exc.value.code == cli.EXIT_ERROR and not started
    captured = capsys.readouterr()
    # stdout is the MCP protocol of a stdio host: errors and usage go to stderr
    assert captured.out == ""
    assert message in captured.err


@pytest.mark.parametrize("argv", [["serve"], *([command] for command in cli.MCP_COMMANDS)])
def test_mcp_options_all_have_a_help_text(monkeypatch, argv):
    parsers: list[argparse.ArgumentParser] = []

    def record(self, args=None, namespace=None):
        """Remember the parser, then stop before the command runs."""
        parsers.append(self)
        raise SystemExit(0)

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", record)
    with pytest.raises(SystemExit):
        server.main([*argv, "--help"])

    undocumented = [a.dest for a in parsers[0]._actions if not a.help]
    assert undocumented == []


@pytest.mark.parametrize(
    ("host", "with_tls", "has_token", "allow_open", "expected", "absent"),
    [
        ("0.0.0.0", False, True, True, "without TLS", None),
        ("0.0.0.0", True, True, True, None, "without TLS"),
        ("127.0.0.1", False, True, True, None, "without TLS"),
        ("0.0.0.0", True, False, True, "without authentication", None),
        ("0.0.0.0", True, True, True, None, "without authentication"),
        (
            "0.0.0.0",
            True,
            False,
            False,
            "every MCP client is refused",
            "without authentication",
        ),
    ],
)
def test_serve_warns_about_an_unsafe_exposure(
    tmp_path, caplog, captured_run, host, with_tls, has_token, allow_open, expected, absent
):
    tls = http_server.TLSOptions(certfile=str(tmp_path / "cert.pem")) if with_tls else None
    if has_token:
        token_store.create_token("ci", Role.MCP)

    with caplog.at_level("WARNING", logger="security_review_mcp"):
        http_server.serve(Starlette(), host, 8000, STORE, tls, allow_open=allow_open)

    assert len(captured_run) == 1
    messages = " ".join(record.message for record in caplog.records)
    assert expected is None or expected in messages
    assert absent is None or absent not in messages


@pytest.mark.parametrize("forwarded_allow_ips", [None, "*"])
def test_serve_trusted_proxies(caplog, captured_run, forwarded_allow_ips):
    with caplog.at_level("WARNING", logger="security_review_mcp"):
        http_server.serve(
            Starlette(), "0.0.0.0", 8000, STORE, None, forwarded_allow_ips=forwarded_allow_ips
        )

    (call,) = captured_run
    warned = any("X-Forwarded-For" in record.message for record in caplog.records)
    if forwarded_allow_ips is None:
        # Unset: the uvicorn default is kept
        assert "forwarded_allow_ips" not in call and "proxy_headers" not in call
        assert not warned
    else:
        # Every client is a trusted proxy: warned
        assert call["forwarded_allow_ips"] == "*" and warned


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("  ", None),
        ("*", "*"),
        (" 10.0.0.0/8, 192.168.1.10 ,fd00::/8", "10.0.0.0/8,192.168.1.10,fd00::/8"),
    ],
)
def test_forwarded_allow_ips_setting(value, expected):
    assert make_settings(forwarded_allow_ips=value).forwarded_allow_ips == expected


@pytest.mark.parametrize("value", ["proxy.local", "10.0.0.0/8,*", "10.0.0.300"])
def test_forwarded_allow_ips_refuses_what_is_not_an_address(value):
    with pytest.raises(ValueError, match="forwarded_allow_ips"):
        make_settings(forwarded_allow_ips=value)


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

    code, reader = run_cli(capsys, "create", "--label", "shop", "--project", "shop-api")
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
        (["create", "--label", "dup"], "already"),
    ],
)
def test_token_command_errors(capsys, argv, message):
    token_store.create_token("dup", Role.MCP)
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


@pytest.mark.parametrize(
    ("oidc", "auth_source", "projects"),
    [(False, "local", ["billing", "shop-api"]), (True, "oidc", ["shop-api"])],
)
def test_token_approve_can_give_web_read_access(capsys, monkeypatch, oidc, auth_source, projects):
    if oidc:
        monkeypatch.setenv("SECREVIEW_OIDC_ENABLED", "true")
    config.get_settings.cache_clear()
    first = token_store.request_enrollment("shop-api", label="shop-dev")
    try:
        if not oidc:
            # Without OIDC, an unknown user name is refused before the approval
            args = ["token", "approve", first["label"], "--portal-user", "bob"]
            assert cli.run(args) == cli.EXIT_ERROR
            assert "not found" in json.loads(capsys.readouterr().err)["error"]
            assert STORE.lookup(hash_token(first["token"])).pending is True
            make_user("alice", "Correct horse battery 9", "reader", ["billing"])
        code, approved = run_cli(capsys, "approve", first["label"], "--portal-user", "alice")
    finally:
        config.get_settings.cache_clear()

    assert code == cli.EXIT_PASSED and approved["status"] == "active"
    user = approved["portal_user"]
    assert (user["username"], user["auth_source"], user["permissions"]) == (
        "alice",
        auth_source,
        {"reports.read": projects},
    )
    # With OIDC, the SSO user is created on the fly
    assert (user["created_by"] == "cli") is oidc


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
    capsys.readouterr()
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


def test_token_reset_admin_is_replaced_by_the_user_command(capsys):
    with pytest.raises(SystemExit) as exc:
        run_cli(capsys, "reset-admin")

    assert exc.value.code == cli.EXIT_ERROR
