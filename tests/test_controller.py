"""Controller entry point (security-review-controller): serve, db and command dispatch."""

import json
from datetime import timedelta

import pytest
from sqlmodel import select
from starlette.testclient import TestClient

from security_review_mcp import app_settings, cli, controller, http_server, web_api
from security_review_mcp.auth import access_control, token_store, web_users
from security_review_mcp.auth.rate_limit import RateLimitMiddleware
from security_review_mcp.clients import commands
from security_review_mcp.config import Settings
from security_review_mcp.http_server import BearerAuthMiddleware, SecurityHeadersMiddleware
from security_review_mcp.observability import audit
from security_review_mcp.reports import services
from security_review_mcp.storage import database
from security_review_mcp.storage.database import session_scope
from security_review_mcp.storage.models import SecurityReport, utcnow

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
        monkeypatch.setattr(web_api, "get_settings", lambda: current)
        # The OIDC settings are read again at each login (see web_api.auth_routes.OidcLogins)
        monkeypatch.setattr(web_api.auth_routes, "get_settings", lambda: current)
        monkeypatch.setattr(web_api.admin_routes, "get_settings", lambda: current)
        monkeypatch.setattr(app_settings, "get_settings", lambda: current)

    _set()
    return _set


class FakePruner:
    """Records how the controller drives the purge of the reports without findings."""

    instances: list[FakePruner] = []

    def __init__(
        self, retention_days: int, audit_retention_days: int = 0, audit_max_events: int = 0
    ) -> None:
        """Remember the retentions."""
        self.retention_days = retention_days
        self.audit_retention_days = audit_retention_days
        self.audit_max_events = audit_max_events
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
    # Requests are limited per address before the token is checked
    # Security headers outermost, then the rate limit before the token is checked
    assert isinstance(call["app"], SecurityHeadersMiddleware)
    assert isinstance(call["app"].app, RateLimitMiddleware)
    bearer = call["app"].app.app
    assert isinstance(bearer, BearerAuthMiddleware) and bearer.web
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
    with session_scope() as session:
        assert not access_control.project_exists(session, "p")


def test_serve_creates_the_admin_once_without_logging_any_password(
    settings, caplog, capsys, captured_run, ui_dir
):
    with caplog.at_level("WARNING", logger="security_review_mcp"):
        controller.main(["serve"])
        (message,) = [r.message for r in caplog.records if "administrator" in r.message]
        caplog.clear()
        controller.main(["serve"])

    assert "user reset-password admin" in message
    assert not any("administrator" in record.message for record in caplog.records)
    (admin,) = web_users.list_users()
    assert (admin["username"], admin["must_change_password"]) == ("admin", True)
    assert [group["name"] for group in admin["groups"]] == ["administrators"]
    # The only way to a password: the CLI, which prints it once
    capsys.readouterr()
    assert cli.run(["user", "reset-password", "admin"]) == cli.EXIT_PASSED
    password = json.loads(capsys.readouterr().out)["password"]
    assert password not in caplog.text and password not in message
    client = TestClient(captured_run[-1]["app"], base_url="http://127.0.0.1")
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['session']}"}
    identity = client.get("/api/v1/me", headers=headers).json()
    assert (identity["client"], identity["role"], identity["local_account"]) == (
        "admin",
        "user",
        True,
    )
    # The password is not a bearer token
    assert (
        client.get("/api/v1/me", headers={"Authorization": f"Bearer {password}"}).status_code == 401
    )
    assert STORE.has_tokens() is False


def test_serve_creates_the_admin_with_the_configured_name(settings, captured_run, ui_dir):
    settings(admin_username="root")

    controller.main(["serve"])

    assert [user["username"] for user in web_users.list_users()] == ["root"]


def test_serve_refuses_an_invalid_admin_username(settings, captured_run, capsys):
    settings(admin_username="bad name!")

    with pytest.raises(SystemExit) as exc:
        controller.main(["serve"])

    assert exc.value.code == 2 and not captured_run
    assert "Username" in capsys.readouterr().err
    assert web_users.has_users() is False


def test_serve_requires_a_login_once_the_admin_exists(settings, captured_run, ui_dir):
    controller.main(["serve"])
    client = TestClient(captured_run[0]["app"], base_url="http://127.0.0.1")

    assert client.get("/api/v1/me").status_code == 401
    assert STORE.has_tokens() is False


def test_serve_refuses_an_invalid_secret_key(settings, captured_run, capsys):
    settings(secret_key="short")

    with pytest.raises(SystemExit) as exc:
        controller.main(["serve"])

    assert exc.value.code == 2 and not captured_run
    assert "SECREVIEW_SECRET_KEY" in capsys.readouterr().err


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
    "secret_key": "s" * 40,
}


def test_serve_enables_the_oidc_login(settings, captured_run, ui_dir):
    settings(**OIDC_SETTINGS)

    controller.main(["serve"])

    app = captured_run[0]["app"]
    assert app.app.app.sessions is not None
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


def test_project_cli_approves_and_rejects_the_pending_projects(capsys):
    for project in ("shop-api", "spam"):
        access_control.enroll_project(project, "alice")

    assert cli.run(["project", "list"]) == cli.EXIT_PASSED
    shop, spam = json.loads(capsys.readouterr().out)
    assert (shop["project"], shop["requested_by"]) == ("shop-api", "alice")
    assert cli.run(["project", "approve", str(shop["id"])]) == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out)["group"] == "project:shop-api"
    assert cli.run(["project", "reject", str(spam["id"])]) == cli.EXIT_PASSED
    capsys.readouterr()

    assert cli.run(["project", "reject", str(spam["id"])]) == cli.EXIT_ERROR
    assert "not found" in json.loads(capsys.readouterr().err)["error"]
    assert access_control.list_enrollments() == []
    with session_scope() as session:
        assert access_control.project_exists(session, "shop-api")
        assert not access_control.project_exists(session, "spam")


def test_token_cli_creates_with_an_expiry_and_rotates(settings, capsys):
    argv = ["token", "create", "--label", "ci", "--role", "mcp", "--expires-in-days", "30"]
    with pytest.raises(SystemExit) as exc:
        controller.main(argv)
    assert exc.value.code == cli.EXIT_PASSED
    created = json.loads(capsys.readouterr().out)
    assert created["expires_at"] is not None

    with pytest.raises(SystemExit) as exc:
        controller.main(["token", "rotate", "ci", "--grace-hours", "4"])
    assert exc.value.code == cli.EXIT_PASSED
    rotated = json.loads(capsys.readouterr().out)
    assert rotated["id"] == created["id"]
    assert rotated["token"] != created["token"]
    assert rotated["grace_until"] is not None
    actors = {event["actor"] for event in audit.list_events()["events"]}
    assert actors == {"cli"}


@pytest.mark.parametrize(
    "argv",
    [
        ["token", "rotate", "missing"],
        ["token", "rotate", "ci", "--grace-hours", "1000"],
        ["token", "create", "--label", "x", "--expires-in-days", "0"],
        ["token", "create", "--label", "m", "--role", "metrics", "--project", "shop"],
    ],
)
def test_token_cli_refuses_bad_rotations_and_expiries(settings, capsys, argv):
    token_store.create_token("ci", "mcp")
    with pytest.raises(SystemExit) as exc:
        controller.main(argv)
    assert exc.value.code == cli.EXIT_ERROR
    assert json.loads(capsys.readouterr().err)["error"]


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["unknown"],
        ["enroll"],
        ["gate"],
        ["sarif", "--project", "shop"],
        ["trend"],
        ["code", "scan", "."],
        ["deps", "scan", "requirements.txt"],
    ],
)
def test_unknown_commands_print_the_usage(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        controller.main(argv)

    assert exc.value.code == cli.EXIT_ERROR
    assert "usage: security-review-controller" in capsys.readouterr().err


def test_pipeline_commands_belong_to_the_ci_client():
    pipeline = {"gate", "sarif", "trend", "code", "deps", "scan-code", "scan-deps"}
    assert not pipeline & cli.CONTROLLER_COMMANDS.keys()
    # security-review-mcp scan-deps is the MCP client of the same name, not the pipeline one
    assert not pipeline & commands.MCP_COMMANDS.keys() - {"scan-deps"}


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

    settings(osv_auto_update=True, https_proxy="http://proxy.internal:3128")
    controller.main(["serve"])

    (updater,) = fake_updater
    assert updater.events == ["start", "stop"]
    assert updater.settings.proxy == "http://proxy.internal:3128"


def test_serve_runs_the_report_pruner_unless_disabled(settings, captured_run, ui_dir, fake_pruner):
    controller.main(["serve"])

    (pruner,) = fake_pruner
    assert pruner.retention_days == 90
    assert pruner.audit_retention_days == 365
    assert pruner.events == ["start", "stop"]

    # The audit purge alone keeps the pruner running
    settings(empty_report_retention_days=0)
    controller.main(["serve"])
    assert len(fake_pruner) == 2
    assert (fake_pruner[1].retention_days, fake_pruner[1].audit_retention_days) == (0, 365)

    # The limit of the audit events alone too
    settings(empty_report_retention_days=0, audit_retention_days=0, audit_max_events=1000)
    controller.main(["serve"])
    assert len(fake_pruner) == 3 and fake_pruner[2].audit_max_events == 1000

    settings(empty_report_retention_days=0, audit_retention_days=0)
    controller.main(["serve"])
    assert len(fake_pruner) == 3


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


def test_serve_always_runs_the_syslog_forwarder_with_the_web_settings(
    settings, captured_run, ui_dir, monkeypatch
):
    started: list[str] = []
    forwarders = []

    class FakeForwarder:
        def __init__(self, settings, current) -> None:
            self.current = current
            forwarders.append(self)

        def start(self) -> None:
            started.append("start")

        def stop(self) -> None:
            started.append("stop")

    monkeypatch.setattr(controller.audit_syslog, "AuditForwarder", FakeForwarder)
    controller.main(["serve"])

    # Started even without a variable: a server may be set in the web interface later
    assert started == ["start", "stop"]
    (forwarder,) = forwarders
    assert forwarder.current().audit_syslog_address is None
    app_settings.set_audit_syslog({"address": "tcp://siem.example.com:601"}, "user:admin")
    assert forwarder.current().audit_syslog_address == "tcp://siem.example.com:601"


def test_serve_refuses_an_invalid_syslog_address(settings, captured_run, capsys):
    settings(audit_syslog_address="syslog.example.com:514")

    with pytest.raises(SystemExit) as exc:
        controller.main(["serve"])

    assert exc.value.code == 2 and not captured_run
    assert "SECREVIEW_AUDIT_SYSLOG_ADDRESS" in capsys.readouterr().err
