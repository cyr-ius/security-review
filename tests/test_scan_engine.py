"""Scan engines (engines/worker.py, engines/remote.py, engines/backend.py): the controller sends
the rules and OpenGrep work to security-review-scan-engine."""

import io
import json
import subprocess
import sys
import urllib.error

import pytest
from pydantic import SecretStr
from starlette.testclient import TestClient

from security_review_mcp.config import get_settings
from security_review_mcp.engines import backend, opengrep, remote, worker
from security_review_mcp.rules import codescan
from security_review_mcp.rules.codescan import SourceFile

TOKEN = "engine-secret-for-tests-0123456789abcdef"
URL = "http://scan-engine:8000"
FILES = [
    SourceFile("app/views.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n"),
    SourceFile("settings.properties", 'password = "Sup3rSecret99"\n'),
]


class _Answer:
    """Answer of the fake opener, read like the one of urllib."""

    def __init__(self, body: bytes) -> None:
        self.body = io.BytesIO(body)

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
            request.full_url.removeprefix(URL), content=request.data, headers=request.headers
        )
        if response.status_code >= 400:
            raise urllib.error.HTTPError(
                request.full_url, response.status_code, "", {}, io.BytesIO(response.content)
            )
        return _Answer(response.content)


@pytest.fixture
def engines(monkeypatch):
    """Return a function that sends the scans of the controller to the scan engines at URL,
    reached through ``opener``."""
    backend.ENGINE_REQUESTS.clear()

    def use(opener):
        monkeypatch.setattr(get_settings(), "scan_engine_url", URL)
        monkeypatch.setattr(get_settings(), "scan_engine_token", SecretStr(TOKEN))
        monkeypatch.setattr(remote, "_OPENER", opener)
        return opener

    return use


def test_the_controller_gets_the_same_scan_from_the_engines(engines):
    local = codescan.scan_files(FILES)
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

    engines(Down())
    # Refused by default: answered like a busy OpenGrep (503 with Retry-After)
    with pytest.raises(opengrep.OpenGrepBusyError):
        codescan.scan_files(FILES)

    monkeypatch.setattr(get_settings(), "scan_engine_fallback", "local")
    assert codescan.scan_files(FILES)["matches_count"] > 0
    assert (backend.ENGINE_REQUESTS["unavailable"], backend.ENGINE_REQUESTS["fallback"]) == (1, 1)

    # A busy engine is never replaced by a local scan
    def busy(sources, fragment):
        raise opengrep.OpenGrepBusyError("OpenGrep is busy with other scans; retry later")

    monkeypatch.setattr(worker.local, "scan", busy)
    engines(_EngineOpener())
    with pytest.raises(remote.ScanEngineBusyError):
        codescan.scan_files(FILES)


def test_the_engine_loads_none_of_the_controller_modules():
    # A fresh interpreter: the other tests import these modules in this one
    modules = (
        "security_review_mcp.controller",
        "security_review_mcp.web_api",
        "security_review_mcp.connectors",
        "security_review_mcp.auth.oidc",
        "security_review_mcp.deps.advisory_sync",
        "security_review_mcp.engines.remote",
    )
    code = (
        "import sys, security_review_mcp.engines.worker\n"
        f"print([m for m in {modules!r} if m in sys.modules])"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"
