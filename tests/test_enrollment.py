"""Client side of the enrollment (``security-review-mcp enroll``), without any network."""

import io
import json
import urllib.error

import pytest
from starlette.testclient import TestClient

from security_review_mcp import cli, enrollment, http_server, server, token_store, web_api
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
    """The full HTTP app, reached through a fake urllib opener."""
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    token_store.create_token("ops", Role.ADMIN)
    app = http_server.build_app(
        server.mcp,
        "127.0.0.1",
        token_store.DatabaseTokenStore(),
        web_api.create_app(ui_dir=str(tmp_path)),
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


def test_request_enrollment_creates_a_pending_token(opener):
    answer = enrollment.request_enrollment(
        "http://127.0.0.1/mcp", "shop-api", label="shop-dev", requested_by="alice"
    )

    assert answer["label"].startswith("shop-dev-")
    assert (answer["project"], answer["status"]) == ("shop-api", "pending")
    (pending,) = token_store.list_enrollments()
    assert pending["requested_by"] == "alice"
    assert json.loads(opener.requests[0].data) == {
        "project": "shop-api",
        "label": "shop-dev",
        "requested_by": "alice",
    }


def test_request_enrollment_reports_the_server_error(opener):
    with pytest.raises(ValueError, match=r"refused the request \(422\).*at least 1 character"):
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


def test_enroll_command(opener, capsys):
    code = cli.run(
        ["enroll", "--url", "http://127.0.0.1", "--project", "shop-api", "--requested-by", "bob"]
    )

    assert code == cli.EXIT_PASSED
    answer = json.loads(capsys.readouterr().out)
    assert answer["status"] == "pending" and answer["token"]
    assert token_store.DatabaseTokenStore().lookup(http_server.hash_token(answer["token"])).pending


def test_request_enrollment_with_a_token_asks_for_one_more_project(opener):
    created = token_store.create_token("shop-ci", Role.MCP, "shop-api")

    answer = enrollment.request_enrollment(
        "http://127.0.0.1", "billing", requested_by="alice", token=created["token"]
    )

    assert (answer["kind"], answer["token_id"], answer["status"]) == (
        "additional",
        created["id"],
        "pending",
    )
    assert opener.requests[0].headers["Authorization"] == f"Bearer {created['token']}"
    with pytest.raises(ValueError, match=r"refused the request \(401\)"):
        enrollment.request_enrollment("http://127.0.0.1", "billing", token="wrong")


def test_enroll_command_reads_the_token_on_stdin(opener, capsys, monkeypatch):
    created = token_store.create_token("shop-ci", Role.MCP, "shop-api")
    monkeypatch.setattr("sys.stdin", io.StringIO(created["token"] + "\n"))

    code = cli.run(["enroll", "--url", "http://127.0.0.1", "--project", "billing", "--token-stdin"])

    assert code == cli.EXIT_PASSED
    output = capsys.readouterr().out
    answer = json.loads(output)
    assert (answer["kind"], answer["project"]) == ("additional", "billing")
    assert created["token"] not in output
    assert [item["project"] for item in token_store.list_enrollments()] == ["billing"]


def test_enroll_command_needs_a_token_on_stdin(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    code = cli.run(["enroll", "--url", "http://127.0.0.1", "--project", "billing", "--token-stdin"])

    assert code == cli.EXIT_ERROR
    assert "no token read on stdin" in json.loads(capsys.readouterr().err)["error"]


def test_enroll_command_errors(capsys):
    code = cli.run(["enroll", "--url", "http://secreview.example.com", "--project", "p"])

    assert code == cli.EXIT_ERROR
    assert "plain HTTP" in json.loads(capsys.readouterr().err)["error"]
