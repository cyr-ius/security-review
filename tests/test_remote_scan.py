"""Dependency scan with a shared MCP server (``security-review-mcp scan-deps``), in memory."""

import io
import json

import httpx2
import pytest
from test_advisories import osv

from security_review_mcp import advisories, cli, http_server, remote_scan, server, token_store
from security_review_mcp.config import get_settings
from security_review_mcp.http_server import Role

LOCKFILE = ("requirements.txt", "requests==2.19.0\n")


def import_advisory(tmp_path) -> None:
    """Import one HIGH advisory on requests < 2.20.0 into the test database."""
    path = tmp_path / "adv.json"
    path.write_text(json.dumps(osv(fixed="2.20.0", severity="HIGH")), encoding="utf-8")
    advisories.import_advisories(path)


@pytest.fixture
def settings_env(monkeypatch):
    """Set client settings (SECREVIEW_*) for one test and reload them."""

    def _set(**values: str) -> None:
        # The documented variable names, not the field names
        for name, variable in (("server_url", "SECREVIEW_MCP_URL"), ("token", "SECREVIEW_TOKEN")):
            monkeypatch.setenv(variable, values.get(name, ""))
        get_settings.cache_clear()

    _set()
    yield _set
    get_settings.cache_clear()


@pytest.fixture
async def shared_server():
    """The HTTP app of the MCP server with its session manager running, and an MCP token.

    Returns a factory of HTTP clients that reach the app in memory, as given to
    remote_scan.scan_files_async.
    """
    secret = token_store.create_token("dev", Role.MCP)["token"]
    app = http_server.build_mcp_app(server.mcp, "127.0.0.1", token_store.DatabaseTokenStore())

    def factory(headers: dict[str, str]) -> httpx2.AsyncClient:
        """Build an HTTP client bound to the app."""
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=headers)

    async with server.mcp.session_manager.run():
        yield factory, secret


# ── URL ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://secreview.example.com", "https://secreview.example.com/mcp"),
        ("https://secreview.example.com/mcp/", "https://secreview.example.com/mcp"),
        ("https://example.com/sec/mcp", "https://example.com/sec/mcp"),
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000/mcp"),
    ],
)
def test_mcp_url(url, expected):
    assert remote_scan.mcp_url(url) == expected


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("ftp://example.com", "Invalid server URL"),
        ("https://user:pass@example.com", "must not contain credentials"),
        ("http://secreview.example.com", "a dependency scan over plain HTTP"),
    ],
)
def test_mcp_url_is_refused(url, message):
    with pytest.raises(ValueError, match=message):
        remote_scan.mcp_url(url)


def test_mcp_url_allows_http_on_request():
    assert remote_scan.mcp_url("http://secreview.internal", allow_http=True).startswith("http:")


# ── scan through the MCP endpoint ────────────────────────────────────────────


@pytest.mark.anyio
async def test_scan_uses_the_advisories_of_the_server(tmp_path, shared_server):
    factory, secret = shared_server
    import_advisory(tmp_path)
    (result,) = await remote_scan.scan_files_async(
        "http://127.0.0.1:8000", [LOCKFILE], token=secret, http_client_factory=factory
    )
    assert result["vulnerability_check"] == "performed"
    assert [v["advisory_id"] for v in result["vulnerabilities"]] == ["PYSEC-1"]


@pytest.mark.anyio
async def test_scan_of_a_safe_version_finds_nothing(tmp_path, shared_server):
    factory, secret = shared_server
    import_advisory(tmp_path)
    (result,) = await remote_scan.scan_files_async(
        "http://127.0.0.1:8000",
        [("requirements.txt", "requests==2.20.0\n")],
        token=secret,
        http_client_factory=factory,
    )
    assert result["vulnerability_check"] == "performed"
    assert result["vulnerabilities"] == []


@pytest.mark.anyio
@pytest.mark.parametrize("token", [None, "not-a-valid-token"])
async def test_scan_without_a_valid_token_is_refused(shared_server, token):
    factory, _ = shared_server
    with pytest.raises(ValueError, match=r"refused the request \(401\)") as error:
        await remote_scan.scan_files_async(
            "http://127.0.0.1:8000", [LOCKFILE], token=token, http_client_factory=factory
        )
    assert "not-a-valid-token" not in str(error.value)


@pytest.mark.anyio
async def test_scan_with_a_rejected_token_suggests_a_new_personal_token(shared_server):
    factory, _ = shared_server
    with pytest.raises(ValueError, match="create a new personal MCP token"):
        await remote_scan.scan_files_async(
            "http://127.0.0.1:8000", [LOCKFILE], token="nope", http_client_factory=factory
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("token", "message"),
    [(None, "received no token"), ("not-a-valid-token", "create a new personal MCP token")],
)
async def test_scan_without_a_valid_token_on_a_server_with_enrollment(token, message):
    token_store.create_token("ops", Role.ADMIN)
    app = http_server.build_mcp_app(
        server.mcp,
        "127.0.0.1",
        token_store.DatabaseTokenStore(),
        enrollment_server=server.enrollment_mcp,
    )

    def factory(headers: dict[str, str]) -> httpx2.AsyncClient:
        """Build an HTTP client bound to the app."""
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=headers)

    async with server.mcp.session_manager.run(), server.enrollment_mcp.session_manager.run():
        with pytest.raises(ValueError, match=message) as error:
            await remote_scan.scan_files_async(
                "http://127.0.0.1:8000", [LOCKFILE], token=token, http_client_factory=factory
            )
    assert "not-a-valid-token" not in str(error.value)


@pytest.mark.anyio
async def test_scan_with_a_token_without_mcp_is_forbidden(shared_server):
    factory, _ = shared_server
    reader = token_store.create_token("viewer", Role.METRICS)["token"]
    with pytest.raises(ValueError, match=r"refused the request \(403\)"):
        await remote_scan.scan_files_async(
            "http://127.0.0.1:8000", [LOCKFILE], token=reader, http_client_factory=factory
        )


@pytest.mark.anyio
async def test_tool_error_names_the_file(shared_server):
    factory, secret = shared_server
    with pytest.raises(ValueError, match="The server refused notes.txt"):
        await remote_scan.scan_files_async(
            "http://127.0.0.1:8000",
            [("notes.txt", "hello")],
            token=secret,
            http_client_factory=factory,
        )


# ── CLI ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_scan(monkeypatch):
    """Replace the network call of scan-deps and record its arguments."""
    calls: list[dict] = []

    def scan(server_url, files, **kwargs):
        calls.append({"url": server_url, "files": files, **kwargs})
        return [_result(name) for name, _ in files]

    monkeypatch.setattr(remote_scan, "scan_files", scan)
    return calls


def _result(filename: str, check: str = "performed", severity: str | None = None) -> dict:
    """A scan result as returned by the scan_dependencies tool."""
    vulnerabilities = []
    if severity:
        vulnerabilities = [
            {
                "advisory_id": "PYSEC-1",
                "package": "requests",
                "version": "2.19.0",
                "severity": severity,
                "summary": "Advisory",
                "fixed_versions": ["2.20.0"],
                "recommended_upgrade": "2.20.0",
            }
        ]
    return {
        "file": filename,
        "file_type": "requirements",
        "ecosystem": "PyPI",
        "is_lockfile": False,
        "components_total": 1,
        "components": [],
        "vulnerability_check": check,
        "vulnerabilities_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "hygiene_count": 0,
        "hygiene": [],
        "notes": [],
    }


def _lockfile(tmp_path):
    path = tmp_path / LOCKFILE[0]
    path.write_text(LOCKFILE[1], encoding="utf-8")
    return path


def test_cli_sends_the_files_and_the_token_of_the_settings(
    tmp_path, settings_env, fake_scan, capsys
):
    settings_env(server_url="https://secreview.example.com", token="tok-123")
    assert cli.run(["scan-deps", str(_lockfile(tmp_path))]) == cli.EXIT_PASSED
    (call,) = fake_scan
    assert call["url"] == "https://secreview.example.com"
    assert call["files"] == [LOCKFILE]
    assert call["token"] == "tok-123"
    assert "RESULT: OK" in capsys.readouterr().out


def test_cli_url_option_and_token_on_stdin(tmp_path, settings_env, fake_scan, monkeypatch):
    settings_env(server_url="https://ignored.example.com", token="from-env")
    monkeypatch.setattr("sys.stdin", io.StringIO("from-stdin\n"))
    args = ["scan-deps", str(_lockfile(tmp_path)), "--url", "https://s.example.com"]
    assert cli.run([*args, "--token-stdin"]) == cli.EXIT_PASSED
    assert fake_scan[0]["url"] == "https://s.example.com"
    assert fake_scan[0]["token"] == "from-stdin"


def test_cli_blocks_on_a_vulnerability(tmp_path, settings_env, monkeypatch, capsys):
    settings_env(server_url="https://secreview.example.com")
    monkeypatch.setattr(
        remote_scan, "scan_files", lambda url, files, **kw: [_result(files[0][0], severity="high")]
    )
    path = str(_lockfile(tmp_path))
    assert cli.run(["scan-deps", path]) == cli.EXIT_BLOCKED
    assert "PYSEC-1" in capsys.readouterr().out
    assert cli.run(["scan-deps", path, "--fail-on", "critical"]) == cli.EXIT_PASSED


def test_cli_require_database(tmp_path, settings_env, monkeypatch, capsys):
    settings_env(server_url="https://secreview.example.com")
    monkeypatch.setattr(
        remote_scan,
        "scan_files",
        lambda url, files, **kw: [_result(files[0][0], check="skipped_no_advisory_database")],
    )
    path = str(_lockfile(tmp_path))
    assert cli.run(["scan-deps", path]) == cli.EXIT_PASSED
    assert cli.run(["scan-deps", path, "--require-database"]) == cli.EXIT_ERROR
    assert "--require-database" in capsys.readouterr().err


def test_cli_without_server_url(tmp_path, settings_env, fake_scan, capsys):
    path = str(_lockfile(tmp_path))
    assert cli.run(["scan-deps", path]) == cli.EXIT_ERROR
    assert "SECREVIEW_MCP_URL" in json.loads(capsys.readouterr().err)["error"]
    assert cli.run(["scan-deps", path, "--skip-unconfigured"]) == cli.EXIT_PASSED
    assert "skipped" in capsys.readouterr().err
    assert fake_scan == []


def test_cli_refuses_a_symbolic_link(tmp_path, settings_env, fake_scan, capsys):
    settings_env(server_url="https://secreview.example.com")
    link = tmp_path / "uv.lock"
    link.symlink_to(_lockfile(tmp_path))
    assert cli.run(["scan-deps", str(link)]) == cli.EXIT_ERROR
    assert "symbolic link" in json.loads(capsys.readouterr().err)["error"]
    assert fake_scan == []


def test_cli_empty_token_on_stdin(tmp_path, settings_env, fake_scan, monkeypatch):
    settings_env(server_url="https://secreview.example.com")
    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))
    assert cli.run(["scan-deps", str(_lockfile(tmp_path)), "--token-stdin"]) == cli.EXIT_ERROR
    assert fake_scan == []


def test_cli_refuses_plain_http_before_reading_the_token(tmp_path, settings_env, capsys):
    settings_env(server_url="http://secreview.example.com", token="tok-123")
    assert cli.run(["scan-deps", str(_lockfile(tmp_path))]) == cli.EXIT_ERROR
    assert "plain HTTP" in json.loads(capsys.readouterr().err)["error"]


def test_scan_deps_is_a_command_of_the_mcp_entry_point(tmp_path, settings_env, fake_scan):
    settings_env(server_url="https://secreview.example.com")
    with pytest.raises(SystemExit) as exit_info:
        server.main(["scan-deps", str(_lockfile(tmp_path))])
    assert exit_info.value.code == cli.EXIT_PASSED


def test_cli_text_output_drops_terminal_escapes(tmp_path, settings_env, monkeypatch, capsys):
    settings_env(server_url="https://secreview.example.com")
    result = _result("requirements.txt", severity="high")
    result["vulnerabilities"][0]["package"] = "requests\x1b[2J\x1b]0;pwned\x07"
    result["notes"] = ["note\x1b[31m"]
    monkeypatch.setattr(remote_scan, "scan_files", lambda url, files, **kw: [result])
    assert cli.run(["scan-deps", str(_lockfile(tmp_path))]) == cli.EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "requests?[2J?]0;pwned?" in out
