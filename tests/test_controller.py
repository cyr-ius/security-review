"""Controller entry point (security-review-controller): serve, db and command dispatch."""

import json
from datetime import timedelta

import pytest
from sqlmodel import select
from starlette.testclient import TestClient

from security_review_mcp import (
    app_settings,
    cli,
    controller,
    database,
    http_server,
    services,
    token_store,
    web_api,
    web_users,
)
from security_review_mcp.config import Settings
from security_review_mcp.database import session_scope
from security_review_mcp.http_server import BearerAuthMiddleware
from security_review_mcp.models import SecurityReport, utcnow

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
        # The SSO settings are read again at each login (see web_api.OidcLogins)
        monkeypatch.setattr(web_api, "get_settings", lambda: current)
        monkeypatch.setattr(app_settings, "get_settings", lambda: current)

    _set()
    return _set


class FakePruner:
    """Records how the controller drives the purge of the reports without findings."""

    instances: list[FakePruner] = []

    def __init__(self, retention_days: int) -> None:
        """Remember the retention."""
        self.retention_days = retention_days
        self.events: list[str] = []
        FakePruner.instances.append(self)

    def start(self) -> None:
        """Record the start."""
        self.events.append("start")

    def stop(self) -> None:
        """Record the stop."""
        self.events.append("stop")


@pytest.fixture(autouse=True)
def fake_pruner(monkeypatch):
    """Replace the report pruner of the controller (no background thread in the tests)."""
    FakePruner.instances = []
    monkeypatch.setattr(controller.retention, "ReportPruner", FakePruner)
    return FakePruner.instances


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
        assert sum("Initial Web UI administrator created" in message for message in messages) == 1
        caplog.clear()
        controller.main(["serve"])

    assert not any(
        "Initial Web UI administrator created" in record.message for record in caplog.records
    )
    (password,) = [
        message.rsplit(" ", 1)[1] for message in messages if "administrator created" in message
    ]
    client = TestClient(captured_run[-1]["app"], base_url="http://127.0.0.1")
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['session']}"}
    identity = client.get("/api/v1/me", headers=headers).json()
    assert (identity["client"], identity["role"], identity["local_account"]) == (
        "admin",
        "admin",
        True,
    )
    # The password is not a bearer token
    assert (
        client.get("/api/v1/me", headers={"Authorization": f"Bearer {password}"}).status_code == 401
    )


def test_serve_without_bootstrap_setting_creates_no_admin(settings, captured_run, ui_dir):
    controller.main(["serve"])

    assert STORE.has_tokens() is False
    assert web_users.has_users() is False


def test_serve_requires_a_login_once_a_web_user_exists(settings, captured_run, ui_dir):
    controller.main(["serve"])
    client = TestClient(captured_run[0]["app"], base_url="http://127.0.0.1")
    assert client.get("/api/v1/me").status_code == 503

    web_users.create_user("alice", "correct horse battery", "reader")

    assert client.get("/api/v1/me").status_code == 401
    assert STORE.has_tokens() is False


def test_serve_refuses_an_invalid_session_secret(settings, captured_run, capsys):
    settings(session_secret="short")

    with pytest.raises(SystemExit) as exc:
        controller.main(["serve"])

    assert exc.value.code == 2 and not captured_run
    assert "SECREVIEW_SESSION_SECRET" in capsys.readouterr().err


def test_serve_without_web_ui_serves_the_api_only(settings, captured_run, ui_dir):
    settings(web_ui=False)

    controller.main(["serve"])

    client = TestClient(captured_run[0]["app"], base_url="http://127.0.0.1")
    assert client.get("/ui/").status_code == 404
    assert client.get("/healthz").status_code == 200


OIDC_SETTINGS = {
    "oidc_enabled": True,
    "oidc_issuer": "https://idp.example.com",
    "oidc_client_id": "secreview",
    "oidc_redirect_uri": "https://secreview.example.com/api/v1/auth/oidc/callback",
    "session_secret": "s" * 40,
}


def test_serve_enables_the_oidc_login(settings, captured_run, ui_dir):
    settings(**OIDC_SETTINGS)

    controller.main(["serve"])

    app = captured_run[0]["app"]
    assert app.sessions is not None
    client = TestClient(app, base_url="http://127.0.0.1")
    assert client.get("/api/v1/auth/config").json()["oidc"] is True
    # No token in the database: the API asks for credentials instead of answering 503
    assert client.get("/api/v1/me").status_code == 401


def test_serve_refuses_invalid_oidc_settings(settings, captured_run, capsys):
    settings(**{**OIDC_SETTINGS, "oidc_redirect_uri": ""})

    with pytest.raises(SystemExit) as exc:
        controller.main(["serve"])

    assert exc.value.code == 2 and not captured_run
    assert "SECREVIEW_OIDC_REDIRECT_URI" in capsys.readouterr().err


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


class FakeUpdater:
    """Records how the controller drives the OSV updater."""

    instances: list[FakeUpdater] = []

    def __init__(self, settings) -> None:
        """Remember the settings."""
        self.settings = settings
        self.events: list[str] = []
        FakeUpdater.instances.append(self)

    def start(self) -> None:
        """Record the start."""
        self.events.append("start")

    def stop(self) -> None:
        """Record the stop."""
        self.events.append("stop")


@pytest.fixture
def fake_updater(monkeypatch):
    """Replace the OSV updater of the controller."""
    FakeUpdater.instances = []
    monkeypatch.setattr(controller.advisory_sync, "AdvisoryUpdater", FakeUpdater)
    return FakeUpdater.instances


def test_serve_runs_the_osv_updater_only_when_enabled(settings, captured_run, ui_dir, fake_updater):
    controller.main(["serve"])
    assert fake_updater == []

    settings(osv_auto_update=True, proxy="http://proxy.internal:3128")
    controller.main(["serve"])

    (updater,) = fake_updater
    assert updater.events == ["start", "stop"]
    assert updater.settings.proxy == "http://proxy.internal:3128"


def test_serve_runs_the_report_pruner_unless_disabled(settings, captured_run, ui_dir, fake_pruner):
    controller.main(["serve"])

    (pruner,) = fake_pruner
    assert pruner.retention_days == 90
    assert pruner.events == ["start", "stop"]

    settings(empty_report_retention_days=0)
    controller.main(["serve"])
    assert len(fake_pruner) == 1


def test_db_prune_deletes_old_reports_without_findings(settings, capsys):
    services.save_report("shop", "Clean review", [])
    services.save_report("shop", "Latest clean review", [])
    with session_scope() as session:
        for report in session.exec(select(SecurityReport)).all():
            report.created_at = utcnow() - timedelta(days=40)
            session.add(report)

    with pytest.raises(SystemExit) as exc:
        controller.main(["db", "prune", "--days", "30"])

    assert exc.value.code == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out) == {"retention_days": 30, "deleted": 1}


@pytest.mark.parametrize("days", ["-1", "1000000000"])
def test_db_prune_refuses_an_out_of_range_retention(settings, capsys, days):
    with pytest.raises(SystemExit) as exc:
        controller.main(["db", "prune", "--days", days])

    assert exc.value.code == cli.EXIT_ERROR
    assert "retention_days" in capsys.readouterr().err


def test_serve_refuses_an_invalid_osv_setting(settings, captured_run, ui_dir, capsys):
    settings(osv_auto_update=True, osv_url="http://osv.example")

    with pytest.raises(SystemExit) as exc:
        controller.main(["serve"])

    assert exc.value.code == 2 and not captured_run
    assert "SECREVIEW_OSV_URL" in capsys.readouterr().err
