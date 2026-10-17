"""Pipeline client (security-review-ci): gate, SARIF and trend through the controller REST API."""

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from security_review_mcp import ci_client, http_server, services, token_store, web_api
from security_review_mcp.http_server import Role
from security_review_mcp.models import FindingCreate, Severity

URL = "http://127.0.0.1"
MODULE = Path(ci_client.__file__)


@pytest.fixture
def controller(tmp_path) -> TestClient:
    """The controller app, with a shop-api report holding one high finding."""
    services.save_report(
        "shop-api",
        "First review",
        [
            FindingCreate(
                title="SQL injection\x1b[31m", severity=Severity.HIGH, description="Query"
            ),
            FindingCreate(title="Weak hash", severity=Severity.LOW, description="MD5"),
        ],
    )
    services.save_report("billing", "Clean review", [])
    app = http_server.build_controller_app(
        web_api.create_app(ui=False), token_store.DatabaseTokenStore()
    )
    return TestClient(app, base_url=URL)


@pytest.fixture
def ci_token(controller) -> str:
    """A ci token restricted to shop-api."""
    return token_store.create_token("jenkins", Role.CI, ["shop-api"])["token"]


def fetch_from(client: TestClient) -> ci_client.Fetch:
    """Fetch function that sends the requests to the in-process controller."""

    def fetch(url: str, headers: dict[str, str]) -> tuple[int, str, bytes]:
        response = client.get(url, headers=headers)
        return response.status_code, response.headers.get("content-type", ""), response.content

    return fetch


def run(client: TestClient, monkeypatch, argv: list[str], token: str | None) -> int:
    """Run the client with the token in SECREVIEW_TOKEN and the controller URL in argv."""
    monkeypatch.delenv(ci_client.URL_VARIABLE, raising=False)
    if token is None:
        monkeypatch.delenv(ci_client.TOKEN_VARIABLE, raising=False)
    else:
        monkeypatch.setenv(ci_client.TOKEN_VARIABLE, token)
    return ci_client.main([*argv, "--url", URL], fetch=fetch_from(client))


def test_gate_blocks_then_passes_with_a_higher_threshold(controller, ci_token, monkeypatch, capsys):
    assert run(controller, monkeypatch, ["gate", "--project", "shop-api"], ci_token) == 1
    blocked = json.loads(capsys.readouterr().out)
    assert (blocked["project"], blocked["passed"]) == ("shop-api", False)

    argv = ["gate", "--project", "shop-api", "--fail-on", "critical"]
    assert run(controller, monkeypatch, argv, ci_token) == 0
    assert json.loads(capsys.readouterr().out)["passed"] is True


def test_sarif_is_written_to_a_file(controller, ci_token, monkeypatch, capsys, tmp_path):
    output = tmp_path / "findings.sarif"
    argv = ["sarif", "--project", "shop-api", "-o", str(output)]

    assert run(controller, monkeypatch, argv, ci_token) == 0
    log = json.loads(output.read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0"
    assert len(log["runs"][0]["results"]) == 2
    assert "2 result(s) written" in capsys.readouterr().err


def test_trend_as_markdown_without_control_characters(controller, ci_token, monkeypatch, capsys):
    assert run(controller, monkeypatch, ["trend", "--project", "shop-api"], ci_token) == 0
    markdown = capsys.readouterr().out
    assert "shop-api" in markdown and "\x1b" not in markdown

    argv = ["trend", "--project", "shop-api", "--format", "json", "--days", "30"]
    assert run(controller, monkeypatch, argv, ci_token) == 0
    assert json.loads(capsys.readouterr().out)["project"] == "shop-api"


def test_token_and_url_from_the_environment_or_stdin(controller, ci_token, monkeypatch, capsys):
    monkeypatch.setenv(ci_client.URL_VARIABLE, URL)
    monkeypatch.delenv(ci_client.TOKEN_VARIABLE, raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO(ci_token + "\n"))

    argv = ["gate", "--project", "shop-api", "--fail-on", "critical", "--token-stdin"]
    assert ci_client.main(argv, fetch=fetch_from(controller)) == 0
    assert json.loads(capsys.readouterr().out)["passed"] is True


def test_project_outside_the_token_is_refused(controller, ci_token, monkeypatch, capsys):
    assert run(controller, monkeypatch, ["gate", "--project", "billing"], ci_token) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["passed"] is False and "(404)" in error["error"]


def test_invalid_token_is_refused_and_never_printed(controller, ci_token, monkeypatch, capsys):
    wrong = "not-the-token-" + "x" * 30
    assert run(controller, monkeypatch, ["sarif", "--project", "shop-api"], wrong) == 2
    captured = capsys.readouterr()
    assert "(401)" in json.loads(captured.err)["error"]
    assert wrong not in captured.err + captured.out


def test_mcp_token_cannot_use_the_pipeline_routes(controller, monkeypatch, capsys):
    token = token_store.create_token("agent", Role.MCP, ["shop-api"])["token"]

    assert run(controller, monkeypatch, ["gate", "--project", "shop-api"], token) == 2
    assert "(403)" in json.loads(capsys.readouterr().err)["error"]


def test_missing_url_or_token_is_a_usage_error(controller, ci_token, monkeypatch, capsys):
    monkeypatch.delenv(ci_client.URL_VARIABLE, raising=False)
    monkeypatch.setenv(ci_client.TOKEN_VARIABLE, ci_token)
    assert ci_client.main(["gate", "--project", "shop-api"], fetch=fetch_from(controller)) == 2
    assert "No controller URL" in capsys.readouterr().err

    assert run(controller, monkeypatch, ["gate", "--project", "shop-api"], None) == 2
    assert "No token" in capsys.readouterr().err


def test_oversized_answer_is_refused(controller, ci_token, monkeypatch, capsys):
    monkeypatch.setattr(ci_client, "MAX_RESPONSE_BYTES", 100)

    assert run(controller, monkeypatch, ["sarif", "--project", "shop-api"], ci_token) == 2
    assert "too large" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://ci.example.com", "https://ci.example.com/api/v1/ci/gate"),
        ("https://ci.example.com/ui/", "https://ci.example.com/api/v1/ci/gate"),
        (
            "https://ci.example.com/secreview/api/v1",
            "https://ci.example.com/secreview/api/v1/ci/gate",
        ),
        ("http://localhost:8001", "http://localhost:8001/api/v1/ci/gate"),
    ],
)
def test_controller_endpoint(url, expected):
    assert ci_client.controller_endpoint(url, "gate") == expected


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("http://ci.example.com", "plain HTTP"),
        ("https://user:secret@ci.example.com", "must not contain credentials"),
        ("ftp://ci.example.com", "Invalid controller URL"),
    ],
)
def test_unsafe_controller_url_is_refused(url, message):
    with pytest.raises(ValueError, match=message):
        ci_client.controller_endpoint(url, "gate")
    assert ci_client.controller_endpoint("http://ci.example.com", "gate", allow_http=True)


def test_redirects_are_never_followed():
    handler = ci_client._NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://elsewhere") is None


def test_severities_match_the_server():
    assert sorted(ci_client.SEVERITIES) == sorted(severity.value for severity in Severity)


def test_client_loads_no_database_driver_nor_sqlmodel():
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import security_review_mcp.ci_client; "
        "heavy = {'sqlmodel', 'sqlalchemy', 'psycopg2', 'pydantic', 'mcp', 'fastapi', 'httpx'}; "
        "print(sorted(name for name in sys.modules if name.split('.')[0] in heavy))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(MODULE.parent.parent)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "[]"


def test_client_runs_as_a_standalone_file(tmp_path):
    # Copied alone to a build agent, without the package
    copy = tmp_path / "security_review_ci.py"
    copy.write_text(MODULE.read_text(encoding="utf-8"), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-I", str(copy), "gate", "--project", "shop-api"],
        capture_output=True,
        text=True,
        env={"SECREVIEW_TOKEN": "x"},
    )
    assert result.returncode == 2
    assert "No controller URL" in json.loads(result.stderr)["error"]


def test_printable_removes_terminal_escapes():
    assert ci_client.printable("# shop\x1b[31m-api\x07\n\tok\x7f") == "# shop[31m-api\n\tok"
