"""Controller entry point (security-review-controller): serve, db and command dispatch."""

import json

import pytest
from starlette.testclient import TestClient

from security_review_mcp import cli, controller, database, http_server, token_store
from security_review_mcp.config import Settings
from security_review_mcp.http_server import BearerAuthMiddleware

STORE = token_store.DatabaseTokenStore()


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


@pytest.fixture
def settings(monkeypatch):
    """Replace the controller settings; returns a function taking the overrides."""

    def _set(**values) -> None:
        current = make_settings(**values)
        monkeypatch.setattr(controller, "get_settings", lambda: current)
        monkeypatch.setattr(database, "get_settings", lambda: current)

    _set()
    return _set


@pytest.fixture
def captured_run(monkeypatch):
    """Capture the uvicorn.run call instead of starting a server."""
    calls: list[dict] = []
    monkeypatch.setattr(
        http_server.uvicorn, "run", lambda app, **kwargs: calls.append({"app": app, **kwargs})
    )
    return calls


@pytest.fixture
def ui_dir(tmp_path, monkeypatch):
    """A fake Angular build used by the controller."""
    (tmp_path / "index.html").write_text("<html>app</html>", encoding="utf-8")
    monkeypatch.setattr(controller.web_api, "BUNDLED_UI_DIR", tmp_path)
    return tmp_path


def test_serve_migrates_and_serves_the_web_interface(settings, captured_run, ui_dir):
    controller.main(["serve", "--host", "0.0.0.0", "--port", "9000"])

    (call,) = captured_run
    assert isinstance(call["app"], BearerAuthMiddleware) and call["app"].web
    assert (call["host"], call["port"]) == ("0.0.0.0", 9000)
    assert database.current_revision() == database.head_revision()
    client = TestClient(call["app"], base_url="http://127.0.0.1")
    assert client.get("/ui/").status_code == 200
    assert client.get("/healthz").json() == {"status": "ok"}


def test_serve_does_not_serve_mcp_nor_the_public_enrollment(settings, captured_run, ui_dir):
    admin = token_store.create_token("ops", "admin")["token"]
    controller.main(["serve"])

    client = TestClient(captured_run[0]["app"], base_url="http://127.0.0.1")
    headers = {"Authorization": f"Bearer {admin}"}
    assert client.post("/mcp", headers=headers).status_code == 404
    # Without a token, nothing but the public files: no unauthenticated write endpoint
    assert client.post("/api/v1/enroll", json={"project": "p"}).status_code == 401
    assert token_store.list_enrollments() == []


def test_serve_logs_bootstrap_password_only_when_created(settings, caplog, captured_run, ui_dir):
    settings(auth_bootstrap_admin=True)

    with caplog.at_level("WARNING", logger="security_review_mcp"):
        controller.main(["serve"])
        messages = [record.message for record in caplog.records]
        assert sum("Initial Web UI administrator password" in message for message in messages) == 1
        caplog.clear()
        controller.main(["serve"])

    assert not any(
        "Initial Web UI administrator password" in record.message for record in caplog.records
    )
    (password,) = [
        message.rsplit(" ", 1)[1] for message in messages if "administrator password" in message
    ]
    client = TestClient(captured_run[-1]["app"], base_url="http://127.0.0.1")
    identity = client.get("/api/v1/me", headers={"Authorization": f"Bearer {password}"}).json()
    assert identity["role"] == "admin"


def test_serve_without_bootstrap_setting_creates_no_admin(settings, captured_run, ui_dir):
    controller.main(["serve"])

    assert STORE.has_tokens() is False


def test_serve_without_web_ui_serves_the_api_only(settings, captured_run, ui_dir):
    settings(web_ui=False)

    controller.main(["serve"])

    client = TestClient(captured_run[0]["app"], base_url="http://127.0.0.1")
    assert client.get("/ui/").status_code == 404
    assert client.get("/healthz").status_code == 200


def test_serve_only_checks_the_schema_without_auto_upgrade(settings, captured_run, capsys):
    settings(db_auto_upgrade=False)

    with pytest.raises(SystemExit) as exc:
        controller.main(["serve"])

    assert exc.value.code == 2 and not captured_run
    assert "security-review-controller db upgrade" in capsys.readouterr().err


def test_db_status_then_upgrade(settings, capsys):
    with pytest.raises(SystemExit) as exc:
        controller.main(["db", "status"])
    assert exc.value.code == cli.EXIT_BLOCKED
    assert json.loads(capsys.readouterr().out)["current"] is None

    with pytest.raises(SystemExit) as exc:
        controller.main(["db", "upgrade"])
    assert exc.value.code == cli.EXIT_PASSED
    status = json.loads(capsys.readouterr().out)
    assert status == {
        "current": database.head_revision(),
        "head": database.head_revision(),
        "up_to_date": True,
    }


def test_commands_report_an_outdated_schema_without_auto_upgrade(settings, capsys):
    settings(db_auto_upgrade=False)

    with pytest.raises(SystemExit) as exc:
        controller.main(["token", "list"])

    assert exc.value.code == cli.EXIT_ERROR
    assert "db upgrade" in json.loads(capsys.readouterr().err)["error"]


def test_administration_commands_run_from_the_controller(settings, capsys):
    with pytest.raises(SystemExit) as exc:
        controller.main(["token", "create", "--label", "ci", "--role", "mcp"])

    assert exc.value.code == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out)["label"] == "ci"


@pytest.mark.parametrize("argv", [[], ["unknown"], ["enroll"]])
def test_unknown_commands_print_the_usage(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        controller.main(argv)

    assert exc.value.code == cli.EXIT_ERROR
    assert "usage: security-review-controller" in capsys.readouterr().err


def test_help(capsys):
    controller.main(["--help"])

    out = capsys.readouterr().out
    assert all(command in out for command in ("serve", *cli.CONTROLLER_COMMANDS))
