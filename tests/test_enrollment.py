"""Client side of the enrollment (``security-review-mcp enroll``), without any network."""

import io
import json
import urllib.error

import pytest
from starlette.testclient import TestClient

from security_review_mcp import (
    access_control,
    cli,
    enrollment,
    enrollment_api,
    http_server,
    server,
    token_store,
)
from security_review_mcp.http_server import Role


class FakeOpener:
    """Stand-in for the urllib opener: forwards the request to the web app in memory."""

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.requests: list = []

    def open(self, request, timeout: float):
        self.requests.append(request)
        path = request.full_url.split("://", 1)[1].split("/", 1)[1]
        response = self.client.post(f"/{path}", content=request.data, headers=request.headers)
        if response.status_code >= 400:
            raise urllib.error.HTTPError(
                request.full_url, response.status_code, "error", {}, io.BytesIO(response.content)
            )
        return io.BytesIO(response.content)


@pytest.fixture
def opener(monkeypatch, tmp_path) -> FakeOpener:
    """The MCP server app (public enrollment endpoint), reached through a fake urllib opener."""
    token_store.create_token("ops", Role.ADMIN)
    app = http_server.build_mcp_app(
        server.mcp,
        "127.0.0.1",
        token_store.DatabaseTokenStore(),
        server.enrollment_mcp,
        enrollment_api.create_app(),
    )
    fake = FakeOpener(TestClient(app, base_url="http://127.0.0.1"))
    monkeypatch.setattr(enrollment.urllib.request, "build_opener", lambda *handlers: fake)
    return fake


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://secreview.example.com", "https://secreview.example.com/api/v1/enroll"),
        ("https://secreview.example.com/mcp/", "https://secreview.example.com/api/v1/enroll"),
        ("https://example.com:8443/secreview", "https://example.com:8443/secreview/api/v1/enroll"),
        ("http://127.0.0.1:8000/mcp", "http://127.0.0.1:8000/api/v1/enroll"),
    ],
)
def test_enrollment_url(url, expected):
    assert enrollment.enrollment_url(url) == expected


@pytest.mark.parametrize(
    "url, message",
    [
        ("ftp://example.com", "Invalid server URL"),
        ("example.com", "Invalid server URL"),
        ("https://user:pass@example.com", "must not contain credentials"),
        ("http://secreview.example.com", "plain HTTP"),
    ],
)
def test_enrollment_url_is_refused(url, message):
    with pytest.raises(ValueError, match=message):
        enrollment.enrollment_url(url)


def test_plain_http_needs_an_explicit_flag():
    url = enrollment.enrollment_url("http://secreview.internal", allow_http=True)
    assert url == "http://secreview.internal/api/v1/enroll"


def test_request_enrollment_requests_the_project_and_no_token(opener):
    answer = enrollment.request_enrollment("http://127.0.0.1/mcp", "shop-api", requested_by="alice")

    assert set(answer) == {"project", "web_url", "next_steps"}
    assert answer["project"] == "shop-api"
    assert json.loads(opener.requests[0].data) == {"project": "shop-api", "requested_by": "alice"}
    assert "Authorization" not in opener.requests[0].headers
    assert [token["label"] for token in token_store.list_tokens()] == ["ops"]
    assert [item["project"] for item in access_control.list_enrollments()] == ["shop-api"]


def test_request_enrollment_reports_the_server_error(opener):
    with pytest.raises(ValueError, match=r"refused the request \(422\).*between 1 and 200"):
        enrollment.request_enrollment("http://127.0.0.1", "")


def test_unreachable_server(monkeypatch):
    class Unreachable:
        def open(self, request, timeout):
            raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(enrollment.urllib.request, "build_opener", lambda *h: Unreachable())

    with pytest.raises(ValueError, match="Cannot reach .*connection refused"):
        enrollment.request_enrollment("https://secreview.example.com", "shop-api")


def test_redirects_are_not_followed():
    handler = enrollment._NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "http://evil.example") is None


@pytest.mark.parametrize("login, requested_by", [("alice", "alice"), (None, None)])
def test_enroll_command_names_the_developer(opener, capsys, monkeypatch, login, requested_by):
    def getuser() -> str:
        if login is None:
            raise OSError("No username set in the environment")
        return login

    monkeypatch.setattr(enrollment.getpass, "getuser", getuser)

    code = cli.run(["enroll", "--url", "http://127.0.0.1", "--project", "shop-api"])

    assert code == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out)["project"] == "shop-api"
    assert json.loads(opener.requests[0].data)["requested_by"] == requested_by
    args = ["enroll", "--url", "http://127.0.0.1", "--project", "crm", "--requested-by", "bob"]
    assert cli.run(args) == cli.EXIT_PASSED
    assert json.loads(opener.requests[1].data)["requested_by"] == "bob"


def test_enroll_command_errors(capsys):
    code = cli.run(["enroll", "--url", "http://secreview.example.com", "--project", "p"])

    assert code == cli.EXIT_ERROR
    assert "plain HTTP" in json.loads(capsys.readouterr().err)["error"]
