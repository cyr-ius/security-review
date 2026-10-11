"""Streamable HTTP transport: bearer authentication, TLS options and start-up wiring."""

import json
import ssl

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from security_review_mcp import cli, http_server, server
from security_review_mcp.config import Settings
from security_review_mcp.http_server import (
    BearerAuthMiddleware,
    PathDispatcher,
    Role,
    TokenInfo,
    hash_token,
    parse_tokens,
)

TOKEN = "a" * 32
OTHER = "b" * 32


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


def whoami(request: Request) -> PlainTextResponse:
    """Echo the label and role stored by the middleware."""
    state = request.scope.get("state", {})
    return PlainTextResponse(f"{state.get('auth_client')}/{state.get('auth_role')}")


def protected_client(tokens: dict[bytes, TokenInfo], web: bool = False) -> TestClient:
    app = Starlette(
        routes=[Route("/mcp", whoami), Route("/api/v1/me", whoami), Route("/ui/", whoami)]
    )
    return TestClient(BearerAuthMiddleware(app, tokens, web=web))


def labels(tokens: dict[bytes, TokenInfo]) -> list[str]:
    return sorted(info.label for info in tokens.values())


# ── Tokens ───────────────────────────────────────────────────────────────────


def test_parse_tokens_plain_hashed_and_labelled():
    tokens = parse_tokens([TOKEN, f"ci:{hash_token(OTHER)}", "  ", hash_token("c" * 30)])
    assert labels(tokens) == ["ci", "token-1", "token-3"]
    assert {info.role for info in tokens.values()} == {Role.MCP}


def test_parse_tokens_with_roles():
    tokens = parse_tokens(
        [f"alice:triager:{TOKEN}", f"bob:Reader:{hash_token(OTHER)}", f"ops:admin:{'c' * 30}"]
    )
    assert {info.label: info.role for info in tokens.values()} == {
        "alice": Role.TRIAGER,
        "bob": Role.READER,
        "ops": Role.ADMIN,
    }


@pytest.mark.parametrize(
    "entries, message",
    [
        (["short"], "too short"),
        (["sha256:abcd"], "not a valid sha256"),
        ([f":{TOKEN}"], "empty label"),
        ([f"ci:{TOKEN}", f"ci:{OTHER}"], "Duplicate"),
        ([f"ci:boss:{TOKEN}"], "unknown role"),
    ],
)
def test_parse_tokens_rejects_invalid_entries(entries, message):
    with pytest.raises(ValueError, match=message):
        parse_tokens(entries)


def test_load_tokens_from_env_and_file(tmp_path):
    path = tmp_path / "tokens"
    path.write_text(f"# CI runners\nci:{hash_token(OTHER)}\n\n", encoding="utf-8")
    settings = make_settings(auth_tokens=f"dev:{TOKEN}", auth_tokens_file=str(path))
    assert labels(http_server.load_tokens(settings)) == ["ci", "dev"]


def test_load_tokens_missing_file(tmp_path):
    settings = make_settings(auth_tokens_file=str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="Cannot read"):
        http_server.load_tokens(settings)


def test_no_token_means_no_auth():
    assert http_server.load_tokens(make_settings()) == {}


def test_bootstrap_admin_token_is_generated_once_and_persisted_as_hash(tmp_path):
    path = tmp_path / "admin-token"
    tokens, password = http_server.ensure_bootstrap_admin_token(path)

    assert password is not None
    assert tokens == parse_tokens([f"bootstrap-admin:web-admin:{hash_token(password)}"])
    assert password not in path.read_text(encoding="utf-8")
    assert path.stat().st_mode & 0o777 == 0o600
    client = protected_client(tokens, web=True)
    headers = {"Authorization": f"Bearer {password}"}
    assert client.get("/api/v1/me", headers=headers).status_code == 200
    assert client.get("/mcp", headers=headers).status_code == 403

    restarted_tokens, restarted_password = http_server.ensure_bootstrap_admin_token(path)
    assert restarted_tokens == tokens
    assert restarted_password is None


def test_bootstrap_admin_token_rejects_empty_existing_file(tmp_path):
    path = tmp_path / "admin-token"
    path.touch()

    with pytest.raises(ValueError, match="file is empty"):
        http_server.ensure_bootstrap_admin_token(path)


# ── Middleware ───────────────────────────────────────────────────────────────


def test_valid_token_is_accepted_and_labelled():
    client = protected_client(parse_tokens([f"dev:{TOKEN}", f"ci:{hash_token(OTHER)}"]))
    assert client.get("/mcp", headers={"Authorization": f"Bearer {TOKEN}"}).text == "dev/mcp"
    assert client.get("/mcp", headers={"Authorization": f"bearer {OTHER}"}).text == "ci/mcp"


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": f"Basic {TOKEN}"},
        {"Authorization": "Bearer "},
        {"Authorization": f"Bearer {OTHER}"},
    ],
)
def test_missing_or_wrong_token_is_rejected(headers):
    response = protected_client(parse_tokens([TOKEN])).get("/mcp", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")
    assert response.json()["error"] == "invalid_token"


@pytest.mark.parametrize(
    "role, mcp_status, api_status",
    [
        ("mcp", 200, 403),
        ("reader", 403, 200),
        ("triager", 403, 200),
        ("web-admin", 403, 200),
        ("admin", 200, 200),
    ],
)
def test_roles_select_the_endpoints(role, mcp_status, api_status):
    client = protected_client(parse_tokens([f"user:{role}:{TOKEN}"]), web=True)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    assert client.get("/mcp", headers=headers).status_code == mcp_status
    response = client.get("/api/v1/me", headers=headers)
    assert response.status_code == api_status
    if api_status == 403:
        assert response.json()["error"] == "insufficient_scope"
    else:
        assert response.text == f"user/{role}"


def test_web_ui_files_are_public_but_not_the_api():
    client = protected_client(parse_tokens([TOKEN]), web=True)
    assert client.get("/ui/").status_code == 200
    assert client.get("/api/v1/me").status_code == 401
    # Without the web interface, every path needs a token
    assert protected_client(parse_tokens([TOKEN])).get("/ui/").status_code == 401


def test_web_ui_requires_configured_authentication_but_keeps_login_assets_public():
    client = protected_client({}, web=True)

    assert client.get("/ui/").status_code == 200
    response = client.get("/api/v1/me")
    assert response.status_code == 503
    assert response.json()["error"] == "authentication_not_configured"
    assert client.get("/mcp").status_code == 200


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


def test_build_app_without_tokens_protects_web_api_only():
    assert not isinstance(http_server.build_app(server.mcp, "127.0.0.1", {}), BearerAuthMiddleware)
    protected = http_server.build_app(server.mcp, "127.0.0.1", parse_tokens([TOKEN]))
    assert isinstance(protected, BearerAuthMiddleware)
    web_protected = http_server.build_app(server.mcp, "127.0.0.1", {}, web_app=Starlette())
    assert isinstance(web_protected, BearerAuthMiddleware)


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
    monkeypatch.setattr(server, "get_settings", lambda: make_settings(auth_tokens=TOKEN))

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


def test_main_logs_bootstrap_password_only_when_created(
    tmp_path, monkeypatch, caplog, captured_run
):
    path = tmp_path / "admin-token"
    monkeypatch.setattr(
        server, "get_settings", lambda: make_settings(auth_bootstrap_file=str(path))
    )

    with caplog.at_level("WARNING", logger="security_review_mcp"):
        server.main(["--transport", "streamable-http"])
        messages = [record.message for record in caplog.records]
        assert sum("Initial Web UI administrator password" in message for message in messages) == 1
        caplog.clear()
        server.main(["--transport", "streamable-http"])

    assert not any(
        "Initial Web UI administrator password" in record.message for record in caplog.records
    )


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
        http_server.run(server.mcp, host, 8000, {}, tls, web_app=web_app)

    assert len(captured_run) == 1
    assert any("without TLS" in record.message for record in caplog.records) is warned


def test_main_rejects_invalid_auth_configuration(monkeypatch, captured_run):
    monkeypatch.setattr(server, "get_settings", lambda: make_settings(auth_tokens="short"))
    with pytest.raises(SystemExit) as exc:
        server.main(["--transport", "streamable-http"])
    assert exc.value.code == 2
    assert captured_run == []


def test_token_command(capsys):
    assert cli.run(["token", "--label", "ci"]) == cli.EXIT_PASSED
    output = json.loads(capsys.readouterr().out)
    label, entry = output["config_entry"].split(":", 1)
    assert label == "ci"
    assert entry == hash_token(output["token"])
    assert list(parse_tokens([output["config_entry"]]).values()) == [TokenInfo("ci")]


def test_token_command_with_role(capsys):
    assert cli.run(["token", "--label", "alice", "--role", "triager"]) == cli.EXIT_PASSED
    output = json.loads(capsys.readouterr().out)
    assert output["config_entry"].startswith("alice:triager:sha256:")
    (info,) = parse_tokens([output["config_entry"]]).values()
    assert info == TokenInfo("alice", Role.TRIAGER)


def test_token_command_rejects_bad_label():
    assert cli.run(["token", "--label", "a:b"]) == cli.EXIT_ERROR
    assert cli.run(["token", "--role", "reader"]) == cli.EXIT_ERROR
