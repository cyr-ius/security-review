"""Tests of the connectors: registry, connections, export of the findings."""

import base64
import io
import json
import urllib.error
import urllib.request
from datetime import timedelta
from types import SimpleNamespace

import pytest

from security_review_mcp.config import Settings
from security_review_mcp.connectors import (
    ConnectorError,
    connections,
    core,
    dispatch,
    registry,
    send_finding,
    set_target,
    transport,
)
from security_review_mcp.connectors.api import (
    Connection,
    Connector,
    ConnectorField,
    ExportedFinding,
)
from security_review_mcp.observability import audit
from security_review_mcp.reports import services
from security_review_mcp.storage.models import ExportState, FindingCreate, Severity

JIRA_TOKEN = "jira-test-token-not-real"
SN_PASSWORD = "servicenow-test-password"


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file, with the connectors enabled."""
    defaults = {
        "connectors_enabled": True,
        "secreview_public_url": "https://secreview.acme.example",
    }
    return Settings(_env_file=None, **(defaults | values))


@pytest.fixture(autouse=True)
def fresh_registry():
    """Each test loads the connectors again (allow list of its own settings)."""
    registry.clear_cache()
    yield
    registry.clear_cache()


@pytest.fixture
def jira():
    """The Jira connector, with its connection stored in the web interface, switched on."""
    connector = registry.get("jira")
    values = {"url": "https://acme.atlassian.net", "username": "bot@acme.example"}
    connections.set_connection(connector, values | {"api_token": JIRA_TOKEN}, "user:root")
    connections.set_enabled(connector, True, "user:root", make_settings())
    return connector


@pytest.fixture
def servicenow():
    """The ServiceNow connector, with its connection stored in the web interface, switched on."""
    connector = registry.get("servicenow")
    values = {"url": "https://acme.service-now.com", "username": "secreview"}
    connections.set_connection(connector, values | {"password": SN_PASSWORD}, "user:root")
    connections.set_enabled(connector, True, "user:root", make_settings())
    return connector


class FakeOpener:
    """Opener that answers each request with the next answer (dict, or an exception)."""

    def __init__(self, *answers) -> None:
        self.answers = list(answers)
        self.requests: list[urllib.request.Request] = []

    def open(self, request, timeout):
        self.requests.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return io.BytesIO(json.dumps(answer).encode())


@pytest.fixture
def remote(monkeypatch):
    """Replace the HTTPS opener; returns a function taking the fake answers."""

    def _answers(*answers) -> FakeOpener:
        opener = FakeOpener(*answers)
        monkeypatch.setattr(transport, "_opener", lambda settings: opener)
        return opener

    return _answers


def save_finding(project: str = "shop", severity: Severity = Severity.HIGH, **fields) -> int:
    """Save a report with one finding; return the finding id."""
    data = {
        "title": "SQL injection",
        "severity": severity,
        "description": "Concatenated query",
        "file_path": "app/db.py",
        "line_start": 12,
    } | fields
    saved = services.save_report(project, "Review", [FindingCreate(**data)], branch="main")
    return services.get_report(saved["report_id"]).findings[0].id


def test_a_finding_becomes_a_jira_issue_reused_by_its_next_occurrence(remote, jira):
    set_target("shop", jira, "sec", None, "user:root")
    first = save_finding(
        evidence='password = "Sup3rS3cretValue!"  {noformat} [!https://evil.example/x.png!]'
    )
    opener = remote({"id": "10001", "key": "SEC-7"})

    export = send_finding(first, jira, "user:ann", make_settings())

    assert (export.state, export.external_key) == (ExportState.SENT, "SEC-7")
    assert export.url == "https://acme.atlassian.net/browse/SEC-7"
    (request,) = opener.requests
    assert request.full_url == "https://acme.atlassian.net/rest/api/2/issue"
    expected = base64.b64encode(f"bot@acme.example:{JIRA_TOKEN}".encode()).decode()
    assert request.get_header("Authorization") == f"Basic {expected}"
    fields = json.loads(request.data)["fields"]
    assert fields["project"] == {"key": "SEC"} and fields["issuetype"] == {"name": "Bug"}
    assert fields["summary"] == "[HIGH] shop: SQL injection"
    description = fields["description"]
    assert "Sup3rS3cretValue" not in description
    assert "https://secreview.acme.example/ui/reports/" in description
    # The texts of the report (description, evidence) never leave their {noformat} block
    assert description.count("{noformat}") == 4

    # The same issue in a later report gets the same record, without a new request
    second = save_finding()
    again = send_finding(second, jira, "user:ann", make_settings())
    assert again.external_key == "SEC-7" and len(opener.requests) == 1
    with pytest.raises(ConnectorError) as raised:  # replaced by the later occurrence
        send_finding(first, jira, "user:ann", make_settings())
    assert raised.value.code == "superseded" and len(opener.requests) == 1
    assert [t.external_key for t in services.get_report(1).findings[0].exports] == ["SEC-7"]
    events = audit.list_events(action="finding.exported")["events"]
    assert [(e["actor"], e["details"]["reused"]) for e in events] == [
        ("user:ann", True),
        ("user:ann", False),
    ]


def test_a_refused_export_keeps_a_short_reason_without_secret(remote, jira, caplog):
    set_target("shop", jira, "SEC", None, "user:root")
    finding = save_finding()
    body = json.dumps({"errors": {"project": f"key {JIRA_TOKEN} unknown"}}).encode()
    remote(urllib.error.HTTPError("https://x", 400, "Bad Request", {}, io.BytesIO(body)))

    with pytest.raises(ConnectorError) as raised:
        send_finding(finding, jira, "user:ann", make_settings())

    assert raised.value.code == "refused"
    (export,) = services.get_report(1).findings[0].exports
    assert export.state == ExportState.FAILED
    assert export.error.startswith("refused: Jira refused the request (HTTP 400: project:")
    assert JIRA_TOKEN not in export.error and JIRA_TOKEN not in caplog.text


@pytest.mark.parametrize(
    ("settings", "switched", "configured", "target", "code"),
    [
        ({"connectors_enabled": False}, True, True, True, "disabled"),
        ({}, False, True, True, "disabled"),
        ({}, True, False, True, "not_configured"),
        ({}, True, True, False, "no_target"),
    ],
)
def test_nothing_is_sent_without_its_configuration(
    remote, settings, switched, configured, target, code
):
    connector = registry.get("jira")
    values = {"url": "https://acme.atlassian.net", "api_token": JIRA_TOKEN}
    connections.set_connection(connector, values, "user:root")
    if switched:
        connections.set_enabled(connector, True, "user:root", make_settings())
    if not configured:
        connections.set_connection(connector, {"url": None}, "user:root")
    if target:
        set_target("shop", connector, "SEC", None, "user:root")
    finding = save_finding()
    opener = remote()

    with pytest.raises(ConnectorError) as raised:
        send_finding(finding, connector, "user:ann", make_settings(**settings))

    assert raised.value.code == code and opener.requests == []


def test_a_connector_sends_only_once_switched_on_unless_locked():
    # Allowed by default, every connector off until switched on
    settings = Settings(_env_file=None)
    assert settings.connectors_enabled is True
    jira = registry.get("jira")
    values = {"url": "https://acme.atlassian.net", "api_token": JIRA_TOKEN}
    connections.set_connection(jira, values, "user:root")
    assert connections.enabled(jira, settings) is False
    servicenow = registry.get("servicenow")
    with pytest.raises(ValueError, match="before switching it on"):
        connections.set_enabled(servicenow, True, "user:root", settings)

    connections.set_enabled(jira, True, "user:root", settings)
    assert connections.enabled(jira, settings) is True
    # The lock of the operator wins over the stored switch
    locked = make_settings(connectors_enabled=False)
    assert connections.enabled(jira, locked) is False
    with pytest.raises(ValueError, match="locked off"):
        connections.set_enabled(jira, False, "user:root", locked)


def test_automatic_sending_follows_the_threshold_from_its_setting(remote, servicenow):
    old = save_finding(severity=Severity.CRITICAL, title="Older finding")
    set_target("shop", servicenow, " AppSec Team ", Severity.HIGH, "user:root")
    critical = save_finding(severity=Severity.CRITICAL, title="Remote code execution")
    save_finding(severity=Severity.MEDIUM, title="Verbose errors")
    save_finding(project="crm", severity=Severity.CRITICAL, title="Other project")
    opener = remote({"result": {"sys_id": "a" * 32, "number": "INC0010001"}})

    assert dispatch(make_settings()) == {"sent": 1, "failed": 0}

    (request,) = opener.requests
    assert request.full_url.startswith("https://acme.service-now.com/api/now/table/incident?")
    body = json.loads(request.data)
    assert body["assignment_group"] == "AppSec Team"
    assert (body["urgency"], body["impact"]) == ("1", "1")
    assert body["short_description"] == "[CRITICAL] shop: Remote code execution"
    exports = {f.id: f.exports for f in services.get_report(2).findings}
    assert exports[critical][0].external_key == "INC0010001"
    assert services.get_report(1).findings[0].id == old
    assert services.get_report(1).findings[0].exports == []
    # Nothing left to send
    assert dispatch(make_settings()) == {"sent": 0, "failed": 0}


def test_a_failed_automatic_export_is_retried_later(remote, jira):
    set_target("shop", jira, "SEC", Severity.LOW, "user:root")
    finding = save_finding()
    remote(urllib.error.URLError("connection refused"))
    assert dispatch(make_settings()) == {"sent": 0, "failed": 1}

    assert core.pending_findings("jira") == []
    later = services.utcnow() + core.RETRY_DELAY + timedelta(seconds=1)
    assert core.pending_findings("jira", now=later) == [finding]


# ── Connections ──────────────────────────────────────────────────────────────


def test_a_connection_is_stored_audited_and_never_shows_its_secret(jira):
    state = connections.resolve(jira)
    assert state.configured and state.values["api_token"] == JIRA_TOKEN
    assert state.values["issue_type"] == "Bug"  # default of the connector
    described = connections.describe(jira, builtin=True, settings=make_settings())
    assert JIRA_TOKEN not in str(described)
    token = next(f for f in described["fields"] if f["name"] == "api_token")
    assert (token["value"], token["variable"]) == ("***", "SECREVIEW_JIRA_API_TOKEN")
    # The connection, then the switch of the fixture
    event, _ = audit.list_events(action="connector.changed")["events"][::-1]
    assert JIRA_TOKEN not in str(event) and event["details"]["api_token"] == "***"
    # The mask sent back keeps the stored secret
    connections.set_connection(jira, {"api_token": "***", "issue_type": "Task"}, "user:root")
    assert connections.resolve(jira).values["api_token"] == JIRA_TOKEN


def test_a_secret_never_follows_a_new_url_unless_entered_again(jira, monkeypatch):
    elsewhere = {"url": "https://collector.evil.example", "api_token": "***"}
    with pytest.raises(ValueError, match="enter the API token again"):
        connections.set_connection(jira, elsewhere, "user:mallory")
    # Testing the connection is refused the same way: it would send the token too
    with pytest.raises(ValueError, match="enter the API token again"):
        connections.candidate(jira, elsewhere)
    assert connections.resolve(jira).base_url == "https://acme.atlassian.net"
    # Same host: the token is kept; a new token goes with a new host
    connections.set_connection(jira, {"url": "https://acme.atlassian.net/jira/"}, "user:root")
    moved = {"url": "https://jira.acme.example", "api_token": "new-token"}
    connections.set_connection(jira, moved, "user:root")
    assert connections.resolve(jira).values["api_token"] == "new-token"
    # Deleting the URL first does not unbind the token: a URL set afterwards needs it again
    connections.set_connection(jira, {"url": None}, "user:mallory")
    with pytest.raises(ValueError, match="enter the API token again"):
        connections.set_connection(jira, elsewhere, "user:mallory")

    # A variable takes precedence: its field cannot be stored, and a token set by a variable
    # never goes to a URL chosen in the web interface, even where no URL was set
    monkeypatch.setenv("SECREVIEW_JIRA_API_TOKEN", "env-token")
    with pytest.raises(ValueError, match="SECREVIEW_JIRA_API_TOKEN is set"):
        connections.set_connection(jira, {"api_token": "other"}, "user:root")
    with pytest.raises(ValueError, match="SECREVIEW_JIRA_API_TOKEN is set"):
        connections.set_connection(jira, {"url": "https://other.example"}, "user:root")
    assert connections.resolve(jira).base_url == ""
    assert connections.resolve(jira).values["api_token"] == "env-token"


@pytest.mark.parametrize(
    "url",
    [
        "http://acme.atlassian.net",
        "https://user:pw@acme.atlassian.net",
        "https://acme.atlassian.net/?a=1",
        "ftp://acme.example",
    ],
)
def test_only_plain_https_urls_are_accepted(url):
    with pytest.raises(ValueError):
        connections.check_base_url(url, "Jira URL")
    assert connections.check_base_url("https://jira.acme.example/jira/", "u") == (
        "https://jira.acme.example/jira"
    )


def test_the_client_refuses_every_redirect_and_any_other_host(remote):
    opener = transport._opener(make_settings())
    handler = next(h for h in opener.handlers if isinstance(h, transport._NoRedirect))
    request = urllib.request.Request("https://acme.atlassian.net/rest/api/2/issue")
    with pytest.raises(urllib.error.HTTPError, match="redirect refused"):
        handler.redirect_request(request, None, 307, "", {}, "https://evil.example/")

    sent = remote()
    client = transport.ConnectionClient(make_settings(), "Acme", "https://acme.example/api", {}, [])
    for path in ("/../admin", "/%2E%2e/admin", "/x?y=1", "x", "@evil.example/x", "/a\\b"):
        with pytest.raises(ConnectorError, match="invalid request path|outside"):
            client.request("GET", path)
    assert sent.requests == []


# ── Third-party connectors ───────────────────────────────────────────────────


class AcmeConnector(Connector):
    """A third-party connector, as a package would publish it."""

    kind = "acme"
    name = "Acme Risk"
    fields = (ConnectorField(name="api_key", label="API key", secret=True, required=True),)
    destination = ConnectorField(name="destination", label="Register", required=True)

    def auth_headers(self, values):
        return {"X-Api-Key": values["api_key"]}

    def export_finding(self, connection: Connection, destination, content) -> ExportedFinding:
        if destination == "broken":
            raise RuntimeError(f"crash with {connection.values['api_key']}")
        answer = connection.http.request(
            "POST", "/risks", json_body={"register": destination, "title": content.summary}
        )
        return ExportedFinding(key=answer["id"], url=f"{connection.base_url}/risks/{answer['id']}")

    def test_connection(self, connection: Connection) -> None:
        connection.http.request("GET", "/me")


@pytest.fixture
def plugins(monkeypatch):
    """Installed entry points: ``acme`` (valid) and ``clash`` (kind of a server setting)."""

    class Clash(AcmeConnector):
        kind = "oidc"
        fields = (ConnectorField(name="enabled", label="Enabled"),)

    installed = {"acme": AcmeConnector, "clash": Clash}
    points = [SimpleNamespace(name=n, load=lambda c=c: c) for n, c in installed.items()]
    monkeypatch.setattr(registry.importlib.metadata, "entry_points", lambda group: points)


def test_a_third_party_connector_is_loaded_only_when_allowed(plugins, remote):
    assert set(registry.connectors(make_settings())) == {"jira", "servicenow"}
    settings = make_settings(connectors_plugins="acme")
    acme = registry.get("acme", settings)
    assert not registry.is_builtin(acme)

    values = {"url": "https://risk.acme.example", "api_key": "acme-key-not-real"}
    connections.set_connection(acme, values, "user:root")
    connections.set_enabled(acme, True, "user:root", settings)
    set_target("shop", acme, "AppSec", None, "user:root")
    finding = save_finding()
    opener = remote({"id": "R-1"})

    export = send_finding(finding, acme, "user:ann", settings)

    assert (export.external_key, export.url) == ("R-1", "https://risk.acme.example/risks/R-1")
    assert opener.requests[0].get_header("X-api-key") == "acme-key-not-real"
    # A connector that fails gives a short error, without its message (it may hold a secret)
    other = save_finding(title="Other issue")
    set_target("shop", acme, "broken", None, "user:root")
    with pytest.raises(ConnectorError) as raised:
        send_finding(other, acme, "user:ann", settings)
    assert raised.value.code == "invalid" and "acme-key" not in str(raised.value)


@pytest.mark.parametrize(
    ("plugins_setting", "message"),
    [("clash", "clashes with the setting oidc_enabled"), ("missing", "is not installed")],
)
def test_an_invalid_or_missing_allowed_connector_stops_the_controller(
    plugins, plugins_setting, message
):
    with pytest.raises(ValueError, match=message):
        core.validate_settings(make_settings(connectors_plugins=plugins_setting))


def test_a_former_ticketing_variable_stops_the_controller(monkeypatch):
    # Ignored, SECREVIEW_TICKETING_ENABLED=false would silently unlock the connectors
    monkeypatch.setenv("SECREVIEW_TICKETING_ENABLED", "false")
    with pytest.raises(ValueError, match="SECREVIEW_TICKETING_ENABLED: renamed"):
        core.validate_settings(make_settings())


def test_the_example_connector_follows_the_api():
    # examples/connector is the template of the third-party connectors
    import importlib.util
    from pathlib import Path

    path = Path(__file__).parents[1] / "examples/connector/acme_connector/__init__.py"
    spec = importlib.util.spec_from_file_location("acme_connector", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    registry.check_connector(module.AcmeConnector(), "example")
