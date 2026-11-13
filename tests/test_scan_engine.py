"""Scan engines (engines/worker.py, engines/remote.py, engines/backend.py): the controller sends
the rules and OpenGrep work to security-review-scan-engine, which enrolls with the controller and
reads its rules without any database (engines/enrollment.py, engines/controller_client.py,
engines/rule_sync.py, web_api/engine_routes.py)."""

import io
import json
import subprocess
import sys
import threading
import urllib.error
from urllib.parse import urlsplit

import pytest
from pydantic import SecretStr
from sqlmodel import select
from starlette.testclient import TestClient

from security_review_mcp import cli, http_server, web_api
from security_review_mcp.auth import engine_clients, token_store
from security_review_mcp.config import get_settings
from security_review_mcp.engines import (
    backend,
    controller_client,
    opengrep,
    opengrep_snapshots,
    remote,
    rule_sync,
    worker,
)
from security_review_mcp.engines.protocol import (
    ENGINE_ENROLL_PATH,
    ENGINE_TOKEN_PATH,
    EngineHeartbeat,
)
from security_review_mcp.http_server import Role
from security_review_mcp.observability.audit import AuditAction
from security_review_mcp.rules import codescan, opengrep_rule_store, registry
from security_review_mcp.rules.codescan import SourceFile
from security_review_mcp.storage import server_instances
from security_review_mcp.storage.database import session_scope
from security_review_mcp.storage.models import AuditEvent, ServerKind, utcnow

TOKEN = "engine-secret-for-tests-0123456789abcdef"
URL = "http://10.0.0.5:8000"
FILES = [
    SourceFile("app/views.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n"),
    SourceFile("settings.properties", 'password = "Sup3rSecret99"\n'),
]


class _Answer:
    """Answer of the fake opener, read like the one of urllib."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body = io.BytesIO(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return self.body.read(size)


class _EngineOpener:
    """Send the requests of engines.remote to an engine app in memory (no network)."""

    def __init__(self, app=None, answer=None) -> None:
        self.client = TestClient(app or worker.build_app(TOKEN, get_settings()))
        self.answer = answer
        self.requests: list = []

    def open(self, request, timeout):
        self.requests.append(request)
        if self.answer is not None:
            return _Answer(self.answer)
        response = self.client.post(
            urlsplit(request.full_url).path, content=request.data, headers=request.headers
        )
        if response.status_code >= 400:
            raise urllib.error.HTTPError(
                request.full_url, response.status_code, "", {}, io.BytesIO(response.content)
            )
        return _Answer(response.content)


def _enroll(url: str = URL, free: int = 1) -> str:
    """Enroll an engine reached at ``url`` and record its heartbeat; return its id."""
    engine_id = engine_clients.enroll("engine", "1.0.0", url)["client_id"]
    engine_clients.heartbeat(
        engine_id, EngineHeartbeat(free_codebase_slots=free, free_fragment_slots=free)
    )
    return engine_id


@pytest.fixture
def engines(monkeypatch):
    """Return a function that sends the scans of the controller to an engine enrolled at URL,
    reached through ``opener``."""
    backend.ENGINE_REQUESTS.clear()
    monkeypatch.setattr(worker, "_counters", type(worker._counters)())
    monkeypatch.setattr(worker, "_processing", type(worker._processing)())
    monkeypatch.setattr(worker, "_controller_client", None)

    def use(opener, enroll: bool = True):
        monkeypatch.setattr(get_settings(), "scan_engine_token", SecretStr(TOKEN))
        if enroll:
            _enroll()
        monkeypatch.setattr(remote, "_OPENER", opener)
        return opener

    return use


def test_the_controller_gets_the_same_scan_from_the_engines(engines, monkeypatch):
    local = codescan.scan_files(FILES)
    processing: list[tuple[int, int, int]] = []
    persisted: list[tuple[int, int, int]] = []
    notifications: list[bool] = []
    scan = worker._scan

    class Notifier:
        def notify_activity_change(self, active):
            notifications.append(active)

    monkeypatch.setattr(worker, "_controller_client", Notifier())

    def observe_processing(sources, fragment):
        status = worker._status()
        processing.append(
            (
                status.processing_codebase_scans,
                status.processing_fragment_scans,
                status.processing_files,
            )
        )
        engine_id = engine_clients.active_engines(fragment)[0][0]
        engine_clients.heartbeat(engine_id, status)
        listed = engine_clients.list_engines()[0]
        persisted.append(
            (
                listed["processing_codebase_scans"],
                listed["processing_fragment_scans"],
                listed["processing_files"],
            )
        )
        return scan(sources, fragment)

    monkeypatch.setattr(worker, "_scan", observe_processing)
    opener = engines(_EngineOpener())

    delegated = codescan.scan_files(FILES)
    fragment = codescan.scan_content(FILES[0].content, "python")

    assert delegated == local
    assert {m["rule_id"] for m in fragment["matches"]} >= {"PY-004"}
    assert fragment["engines"] == ["rules"]
    assert "Sup3rSecret99" not in json.dumps(delegated)
    # The secret goes to the engine only, as a bearer token, with no redirect followed
    assert [r.get_header("Authorization") for r in opener.requests] == [f"Bearer {TOKEN}"] * 2
    assert backend.ENGINE_REQUESTS["scanned"] == 2
    # The engine counts what it did, and its heartbeat shows it on the Scan engines page
    beat = worker._status()
    assert (beat.codebase_scans, beat.fragment_scans, beat.scanned_files) == (1, 1, 3)
    assert processing == [(1, 0, 2), (0, 1, 1)]
    assert persisted == processing
    assert notifications == [True, False, True, False]
    assert beat.processing_files == 0
    assert (beat.processing_codebase_scans, beat.processing_fragment_scans) == (0, 0)
    engine_clients.heartbeat(engine_clients.active_engines(False)[0][0], beat)
    [listed] = engine_clients.list_engines()
    assert listed["codebase_scans"] == 1 and listed["scanned_files"] == 3
    assert listed["codebase_slots"] == get_settings().opengrep_max_concurrent_scans
    assert listed["processing_files"] == 0


def test_activity_notification_wakes_the_heartbeat_thread(monkeypatch):
    monkeypatch.setattr(controller_client, "MIN_HEARTBEAT_SECONDS", 0)
    client = controller_client.ControllerClient(URL, TOKEN, URL)
    sent = threading.Event()
    client.beat = sent.set
    client.notify_activity_change(True)
    heartbeat = threading.Thread(target=client._heartbeat)
    heartbeat.start()

    received = sent.wait(timeout=1)
    client.stop()
    heartbeat.join(timeout=1)
    assert received
    assert not heartbeat.is_alive()


def test_the_engine_refuses_a_request_without_its_secret_before_reading_it():
    client = TestClient(worker.build_app(TOKEN, get_settings()))

    assert client.get("/healthz").status_code == 200
    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}):
        # An invalid body is not even parsed: 401, not 422
        response = client.post("/engine/v1/scan", content=b"{", headers=headers)
        assert response.status_code == 401
    # No schema nor documentation served
    assert (
        client.get("/openapi.json", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 404
    )


@pytest.mark.parametrize(
    "answer",
    [
        # Not JSON, a file missing, a match of an unknown severity, too many matches
        b"<html>",
        json.dumps({"files": [], "engines": ["rules"]}).encode(),
        json.dumps(
            {
                "files": [{"matches": [{"severity": "fatal"}], "suppressed": [], "truncated": 0}],
                "engines": ["rules"],
            }
        ).encode(),
        json.dumps(
            {
                "files": [
                    {
                        "matches": [
                            {
                                "rule_id": "PY-004",
                                "title": "t",
                                "severity": "high",
                                "line": 1,
                                "excerpt": "",
                                "advice": "",
                            }
                        ]
                        * 201,
                        "suppressed": [],
                        "truncated": False,
                    }
                ],
                "engines": ["rules"],
            }
        ).encode(),
    ],
)
def test_an_unexpected_answer_of_the_engine_is_refused(engines, answer):
    engines(_EngineOpener(answer=answer))

    with pytest.raises(remote.ScanEngineUnavailableError):
        codescan.scan_content("print(1)\n", "python")


def test_the_excerpts_of_the_engine_are_masked_again(engines):
    match = {
        "rule_id": "GEN-001",
        "title": "Hard-coded secret",
        "severity": "high",
        "line": 1,
        "excerpt": 'password = "Sup3rSecret99"',
        "advice": "Use a vault.",
    }
    answer = {"files": [{"matches": [match], "suppressed": [], "truncated": False}]}
    engines(_EngineOpener(answer=json.dumps(answer | {"engines": ["rules"]}).encode()))

    result = codescan.scan_content("x = 1\n", "python")

    assert "Sup3rSecret99" not in json.dumps(result)


def test_without_engine_the_scan_is_refused_or_run_on_the_controller(engines, monkeypatch):
    class Down:
        def open(self, request, timeout):
            raise urllib.error.URLError("connection refused")

    # No engine enrolled yet: refused by default, like a busy OpenGrep (503 with Retry-After)
    engines(Down(), enroll=False)
    with pytest.raises(opengrep.OpenGrepBusyError):
        codescan.scan_files(FILES)
    backend.ENGINE_REQUESTS.clear()
    # An enrolled engine that does not answer: refused too
    engines(Down())
    with pytest.raises(opengrep.OpenGrepBusyError):
        codescan.scan_files(FILES)

    monkeypatch.setattr(get_settings(), "scan_engine_fallback", "local")
    assert codescan.scan_files(FILES)["matches_count"] > 0
    assert (backend.ENGINE_REQUESTS["unavailable"], backend.ENGINE_REQUESTS["fallback"]) == (1, 1)

    # Busy engines are never replaced by a local scan
    def busy(sources, fragment):
        raise opengrep.OpenGrepBusyError("OpenGrep is busy with other scans; retry later")

    monkeypatch.setattr(worker.local, "scan", busy)
    engines(_EngineOpener(), enroll=False)
    with pytest.raises(remote.ScanEngineBusyError):
        codescan.scan_files(FILES)


def test_the_scans_go_to_the_freest_active_engine_and_skip_a_busy_one(engines, monkeypatch):
    busy, free = "http://10.0.0.6:8000", "http://10.0.0.7:8000"
    stale = engine_clients.enroll("gone", "1.0.0", "http://10.0.0.8:8000")["client_id"]
    _enroll(busy, free=3)
    _enroll(free, free=1)
    opener = engines(_EngineOpener(), enroll=False)
    opened: list[str] = []

    scan = opener.open

    def route(request, timeout):
        opened.append(request.full_url)
        if request.full_url.startswith(busy):
            raise urllib.error.HTTPError(request.full_url, 429, "", {}, io.BytesIO(b"{}"))
        return scan(request, timeout)

    monkeypatch.setattr(opener, "open", route)

    assert codescan.scan_files(FILES)["matches_count"] > 0
    # The freest engine first; the busy one replaced by the next; never the one without heartbeat
    assert [url.rsplit("/engine", 1)[0] for url in opened] == [busy, free]
    assert stale not in json.dumps(opened)


def test_the_engine_loads_none_of_the_controller_modules():
    # A fresh interpreter: the other tests import these modules in this one
    modules = (
        "security_review_mcp.controller",
        "security_review_mcp.web_api",
        "security_review_mcp.connectors",
        "security_review_mcp.auth.oidc",
        "security_review_mcp.deps.advisory_sync",
        "security_review_mcp.engines.remote",
        "security_review_mcp.engines.enrollment",
        "security_review_mcp.auth.engine_clients",
    )
    code = (
        "import sys, security_review_mcp.engines.worker\n"
        f"print([m for m in {modules!r} if m in sys.modules])"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"


CONTROLLER = "http://controller:8000"


def _controller(monkeypatch) -> TestClient:
    """The controller app, with the enrollment of the engines (shared secret TOKEN)."""
    monkeypatch.setattr(get_settings(), "scan_engine_token", SecretStr(TOKEN))
    app = http_server.build_controller_app(
        web_api.create_app(),
        token_store.DatabaseTokenStore(include_users=True),
        engine_routes=backend.engine_routes(get_settings()),
    )
    return TestClient(app, base_url="http://127.0.0.1")


class _ControllerOpener:
    """Send the requests of a scan engine to the controller app in memory (no network)."""

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.requests: list = []

    def open(self, request, timeout):
        self.requests.append(request)
        response = self.client.request(
            request.get_method(),
            request.full_url.removeprefix(CONTROLLER),
            content=request.data,
            headers=request.headers,
        )
        if response.status_code >= 300:
            raise urllib.error.HTTPError(
                request.full_url, response.status_code, "", {}, io.BytesIO(response.content)
            )
        return _Answer(response.content, response.status_code)


def _rule(rule_id: str, pattern: str) -> str:
    return (
        f"rules:\n  - id: {rule_id}\n    languages: [python]\n    severity: ERROR\n"
        f"    message: m\n    pattern: {pattern}\n"
    )


def test_an_engine_enrolls_and_reads_the_rules_of_the_controller_without_a_database(
    tmp_path, monkeypatch
):
    engine_dir = tmp_path / "engine"
    # The OpenGrep rules of the controller are in its database (OpenGrep validation skipped)
    monkeypatch.setattr(opengrep_rule_store, "validate_rule", lambda rule_id, content: "ok")
    for rule_id in ("rule-one", "rule-two"):
        opengrep_rule_store.save_rule(rule_id, _rule(rule_id, "eval(...)"), create=True)
    controller = _controller(monkeypatch)
    admin = {"Authorization": f"Bearer {token_store.create_token('admin', Role.ADMIN)['token']}"}
    opener = _ControllerOpener(controller)
    monkeypatch.setattr(controller_client, "_OPENER", opener)
    published: list = []
    engine = controller_client.ControllerClient(
        CONTROLLER, TOKEN, "http://10.0.0.7:8000", name="engine-1"
    )
    cache = rule_sync.RuleCache(engine, engine_dir, lambda rules, errors: published.append(rules))

    def posted() -> list[str]:
        """OpenGrep rules asked for by the engine since the last call."""
        ids = [
            rule_id
            for request in opener.requests
            if request.get_method() == "POST" and request.full_url.endswith("opengrep-rules")
            for rule_id in json.loads(request.data)["ids"]
        ]
        opener.requests.clear()
        return sorted(ids)

    with cache.use() as first:
        assert sorted(p.name for p in first.iterdir()) == ["rule-one.yaml", "rule-two.yaml"]
    # The shared secret only goes to the enrollment; the rules need the token of the engine
    assert {
        r.full_url.removeprefix(CONTROLLER)
        for r in opener.requests
        if r.get_header("Authorization") == f"Bearer {TOKEN}"
    } == {ENGINE_ENROLL_PATH}
    # The active internal rules of the controller, validated again by the engine
    assert {rule.id for rule in published[-1]} == {rule.id for rule in registry.snapshot().rules}
    assert posted() == ["rule-one", "rule-two"]
    # Unchanged: conditional requests answered 304, nothing downloaded nor published again
    with cache.use() as same:
        assert same == first
    assert posted() == [] and len(published) == 1

    # One OpenGrep rule changed, one added, one deleted: only the first two are downloaded
    opengrep_rule_store.save_rule("rule-one", _rule("rule-one", "exec(...)"), create=False)
    opengrep_rule_store.save_rule(
        "rule-three", _rule("rule-three", "pickle.loads(...)"), create=True
    )
    opengrep_rule_store.delete_rule("rule-two")
    with cache.use() as second:
        assert sorted(p.name for p in second.iterdir()) == ["rule-one.yaml", "rule-three.yaml"]
    assert posted() == ["rule-one", "rule-three"]
    assert not first.exists()

    # The access token of the engine reaches its routes only, and nothing else reaches them
    access = {"Authorization": f"Bearer {engine.access_token()}"}
    assert controller.get("/api/v1/engine/rules", headers=access).status_code == 200
    assert controller.get("/api/v1/projects", headers=access).status_code == 403
    assert controller.get("/api/v1/engine/rules", headers=admin).status_code == 403

    # Its heartbeat makes it active: the scans go to the URL it gave
    engine.beat()
    assert engine_clients.active_engines(False) == [(engine.client_id, "http://10.0.0.7:8000")]

    # Listed for the administrators, and revoked: the engine stops scanning at once
    server_instances.register_instance("controller-one", ServerKind.CONTROLLER, utcnow())
    server_instances.register_instance("controller-two", ServerKind.CONTROLLER, utcnow())
    server_instances.register_instance("mcp-one", ServerKind.MCP, utcnow(), "mcp-0", "1.0.0")
    response = controller.get("/api/v1/scan-engines", headers=admin).json()
    listed = response["engines"]
    assert [instance["id"] for instance in response["controllers"]] == [
        "controller-one",
        "controller-two",
    ]
    assert [(m["id"], m["name"], m["version"]) for m in response["mcp_servers"]] == [
        ("mcp-one", "mcp-0", "1.0.0")
    ]
    assert [(e["id"], e["name"], e["active"]) for e in listed] == [
        (engine.client_id, "engine-1", True)
    ]
    assert "secret" not in json.dumps(listed)
    revoked = controller.delete(f"/api/v1/scan-engines/{engine.client_id}", headers=admin)
    assert revoked.status_code == 204
    with pytest.raises(opengrep.OpenGrepError, match="revoked"), cache.use():
        pass
    assert engine.revoked


def test_a_stopping_engine_leaves_the_controller(monkeypatch):
    controller = _controller(monkeypatch)
    token_store.create_token("admin", Role.ADMIN)  # authentication configured
    opener = _ControllerOpener(controller)
    monkeypatch.setattr(controller_client, "_OPENER", opener)
    # Never enrolled: nothing to tell the controller
    controller_client.ControllerClient(CONTROLLER, TOKEN, "http://10.0.0.7:8000").leave()
    assert opener.requests == []

    engine = controller_client.ControllerClient(
        CONTROLLER, TOKEN, "http://10.0.0.7:8000", name="engine-1"
    )
    engine.beat()
    client_id = engine.client_id
    assert engine_clients.active_engines(False) == [(client_id, "http://10.0.0.7:8000")]

    # Restarted on another node, it enrolls as a new engine: the old one is already gone
    engine.leave()
    assert engine_clients.list_engines() == []
    assert engine.revoked and opener.requests[-1].get_method() == "DELETE"
    with session_scope() as session:
        left = session.exec(
            select(AuditEvent).where(AuditEvent.action == AuditAction.SCAN_ENGINE_LEFT)
        ).one()
        assert (left.actor, left.target_id) == ("engine:engine-1", client_id)
    # The client is spent: no new enrollment behind the back of the orchestrator
    sent = len(opener.requests)
    with pytest.raises(controller_client.RevokedError):
        engine.beat()
    assert len(opener.requests) == sent


def test_controller_heartbeat_registers_and_unregisters():
    heartbeat = server_instances.ServerHeartbeat(ServerKind.CONTROLLER)
    heartbeat.start()
    assert [i["id"] for i in server_instances.active_instances(ServerKind.CONTROLLER)] == [
        heartbeat.instance_id
    ]
    assert server_instances.active_instances(ServerKind.MCP) == []

    # A record purged by another replica (long pause, restored database) comes back
    server_instances.unregister_instance(heartbeat.instance_id)
    heartbeat.beat()
    assert [i["id"] for i in server_instances.active_instances(ServerKind.CONTROLLER)] == [
        heartbeat.instance_id
    ]

    heartbeat.stop()

    assert server_instances.active_instances(ServerKind.CONTROLLER) == []


def test_an_mcp_server_reports_its_scan_code_calls_even_shorter_than_its_heartbeat():
    delegated = [True]
    heartbeat = server_instances.ServerHeartbeat(ServerKind.MCP, lambda: delegated[0])
    heartbeat.start()
    try:
        # Two calls ran at once and ended before the heartbeat: it still shows them
        with heartbeat.processing(), heartbeat.processing():
            pass
        heartbeat.beat()
        [mcp] = server_instances.active_instances(ServerKind.MCP)
        assert (mcp["delegated"], mcp["processing_fragments"]) == (True, 2)
        # The next heartbeat shows what runs now: nothing, and scan_code no longer delegated
        delegated[0] = False
        heartbeat.beat()
        [mcp] = server_instances.active_instances(ServerKind.MCP)
        assert (mcp["delegated"], mcp["processing_fragments"]) == (False, 0)
    finally:
        heartbeat.stop()
    assert server_instances.active_instances(ServerKind.MCP) == []


def test_the_agents_of_an_mcp_server_are_opaque_and_bounded(monkeypatch):
    heartbeat = server_instances.ServerHeartbeat(ServerKind.MCP)
    # The same token and client give the same key here, another one in another process
    key = heartbeat.seen(42, "claude-code\x1b[31m", "2.1")
    assert heartbeat.seen(42, "claude-code\x1b[31m", None) == key
    assert server_instances.ServerHeartbeat(ServerKind.MCP).agent_key(42, "claude-code[31m") != key
    for token in range(server_instances.MAX_AGENTS + 10):
        heartbeat.seen(token, "cursor", "1.0")
    heartbeat.beat()
    [instance] = server_instances.active_instances(ServerKind.MCP)
    agents = instance["agents"]
    assert len(agents) == server_instances.MAX_AGENTS
    assert {agent["client"] for agent in agents} == {"cursor"}
    # A malformed row shows no agent rather than failing the page
    assert server_instances._decode_agents("{not json") == []
    assert server_instances._decode_agents('[{"id": 1}, "x"]') == []
    heartbeat.stop()


def test_only_the_holders_of_the_shared_secret_enroll_and_get_tokens(monkeypatch, capsys):
    assert backend.engine_routes(get_settings()) == {}
    controller = _controller(monkeypatch)
    enroll = {"name": "engine", "version": "1.0.0", "url": "http://10.1.2.3:8000"}

    for headers in ({}, {"Authorization": "Bearer wrong"}):
        # An invalid body is not even parsed: 401, not 422
        assert controller.post(ENGINE_ENROLL_PATH, content=b"{", headers=headers).status_code == 401
    secret = {"Authorization": f"Bearer {TOKEN}"}
    # The files never go to a host name nor to an address outside SECREVIEW_SCAN_ENGINE_NETWORKS
    for url in ("http://scan-engine:8000", "http://203.0.113.9:8000"):
        refused = controller.post(ENGINE_ENROLL_PATH, json=enroll | {"url": url}, headers=secret)
        assert refused.status_code == 422
    credentials = controller.post(ENGINE_ENROLL_PATH, json=enroll, headers=secret).json()
    assert credentials["client_id"].startswith(engine_clients.CLIENT_ID_PREFIX)

    def token(grant: str, client_secret: str):
        return controller.post(
            ENGINE_TOKEN_PATH,
            data={"grant_type": grant},
            auth=(credentials["client_id"], client_secret),
        )

    assert token("password", credentials["client_secret"]).json()["error"] == (
        "unsupported_grant_type"
    )
    refused = token("client_credentials", "wrong")
    assert refused.status_code == 401 and refused.json()["error"] == "invalid_client"
    issued = token("client_credentials", credentials["client_secret"])
    assert issued.status_code == 200 and issued.json()["token_type"] == "Bearer"
    assert issued.headers["cache-control"] == "no-store"

    # Listed by the CLI, never with a secret
    assert cli.run(["engine", "list"]) == cli.EXIT_PASSED
    listed = json.loads(capsys.readouterr().out)
    assert [entry["id"] for entry in listed] == [credentials["client_id"]]
    assert credentials["client_secret"] not in json.dumps(listed)


def test_a_snapshot_never_writes_a_rule_id_as_a_path(tmp_path):
    snapshots = opengrep_snapshots.RuleSnapshots(tmp_path / "rules")
    with pytest.raises(opengrep.OpenGrepError, match="identifier"):
        snapshots.update({"../outside": "0" * 64}, lambda ids: {})
    assert not (tmp_path / "outside.yaml").exists() and not snapshots.ready
