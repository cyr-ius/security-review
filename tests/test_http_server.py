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
from security_review_mcp.http_server import BearerAuthMiddleware, hash_token, parse_tokens

TOKEN = "a" * 32
OTHER = "b" * 32


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


def whoami(request: Request) -> PlainTextResponse:
    """Echo the label stored by the middleware."""
    return PlainTextResponse(request.scope["state"]["auth_client"])


def protected_client(tokens: dict[bytes, str]) -> TestClient:
    app = Starlette(routes=[Route("/mcp", whoami)])
    return TestClient(BearerAuthMiddleware(app, tokens))


# ── Tokens ───────────────────────────────────────────────────────────────────


def test_parse_tokens_plain_hashed_and_labelled():
    tokens = parse_tokens([TOKEN, f"ci:{hash_token(OTHER)}", "  ", hash_token("c" * 30)])
    assert sorted(tokens.values()) == ["ci", "token-1", "token-3"]


@pytest.mark.parametrize(
    "entries, message",
    [
        (["short"], "too short"),
        (["sha256:abcd"], "not a valid sha256"),
        ([f":{TOKEN}"], "empty label"),
        ([f"ci:{TOKEN}", f"ci:{OTHER}"], "Duplicate"),
    ],
)
def test_parse_tokens_rejects_invalid_entries(entries, message):
    with pytest.raises(ValueError, match=message):
        parse_tokens(entries)


def test_load_tokens_from_env_and_file(tmp_path):
    path = tmp_path / "tokens"
    path.write_text(f"# CI runners\nci:{hash_token(OTHER)}\n\n", encoding="utf-8")
    settings = make_settings(auth_tokens=f"dev:{TOKEN}", auth_tokens_file=str(path))
    assert sorted(http_server.load_tokens(settings).values()) == ["ci", "dev"]


def test_load_tokens_missing_file(tmp_path):
    settings = make_settings(auth_tokens_file=str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="Cannot read"):
        http_server.load_tokens(settings)


def test_no_token_means_no_auth():
    assert http_server.load_tokens(make_settings()) == {}


# ── Middleware ───────────────────────────────────────────────────────────────


def test_valid_token_is_accepted_and_labelled():
    client = protected_client(parse_tokens([f"dev:{TOKEN}", f"ci:{hash_token(OTHER)}"]))
    assert client.get("/mcp", headers={"Authorization": f"Bearer {TOKEN}"}).text == "dev"
    assert client.get("/mcp", headers={"Authorization": f"bearer {OTHER}"}).text == "ci"


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


def test_build_app_without_tokens_is_unprotected():
    assert not isinstance(http_server.build_app(server.mcp, "127.0.0.1", {}), BearerAuthMiddleware)
    protected = http_server.build_app(server.mcp, "127.0.0.1", parse_tokens([TOKEN]))
    assert isinstance(protected, BearerAuthMiddleware)


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
    assert list(parse_tokens([output["config_entry"]]).values()) == ["ci"]


def test_token_command_rejects_bad_label():
    assert cli.run(["token", "--label", "a:b"]) == cli.EXIT_ERROR
