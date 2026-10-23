"""Pipeline client (security-review-ci): gate, SARIF, trend and scans through the controller REST
API, and the listing of the files of a code scan."""

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient
from test_advisories import osv

from security_review_mcp import advisories, ci_client, http_server, services, token_store, web_api
from security_review_mcp.config import get_settings
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

    def fetch(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, str, bytes]:
        response = client.request(method, url, headers=headers, content=body)
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


def test_no_argument_prints_the_help(capsys):
    assert ci_client.main([]) == 2
    out = capsys.readouterr().out
    assert out.startswith("usage: security-review-ci")
    for command in ("gate", "sarif", "trend", "scan-code", "scan-deps"):
        assert command in out


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


# ── File listing ─────────────────────────────────────────────────────────────


def make_tree(root):
    """Create a small project with issues in several languages."""
    root.mkdir(exist_ok=True)
    (root / "app").mkdir()
    (root / "app" / "views.py").write_text(
        "import subprocess\nsubprocess.run(cmd, shell=True)\n", encoding="utf-8"
    )
    (root / "app" / "ok.py").write_text("print('hello')\n", encoding="utf-8")
    (root / "Dockerfile").write_text("FROM python:latest\nUSER root\n", encoding="utf-8")
    (root / "settings.properties").write_text('password = "Sup3rSecret99"\n', encoding="utf-8")
    (root / "README.md").write_text("subprocess.run(x, shell=True)\n", encoding="utf-8")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "lib.js").write_text("eval(userInput)\n", encoding="utf-8")
    return root


def git_init(root):
    """Turn root into a git work tree."""
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)


@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("src/app.py", "python"),
        ("Main.java", "java"),
        ("src/app/app.component.ts", "typescript"),
        ("src/app/app.component.html", "angular"),
        ("web/index.mjs", "javascript"),
        ("Dockerfile", "docker"),
        ("docker/Dockerfile.prod", "docker"),
        ("Jenkinsfile", "jenkins"),
        (".gitlab-ci.yml", "gitlab-ci"),
        (".gitlab-ci/build.yml", "gitlab-ci"),
        ("k8s/deploy.yaml", "yaml"),
        (".env.production", "config"),
        ("application.properties", "config"),
        ("README.md", None),
        ("AGENTS.md", "agent-instructions"),
        (".github/copilot-instructions.md", "agent-instructions"),
        (".cursor/rules/style.mdc", "agent-instructions"),
        (".claude/commands/deploy.md", "agent-instructions"),
        ("docs/guide.md", None),
        ("dist/app.min.js", None),
        ("types/index.d.ts", None),
        ("package-lock.json", None),
        ("logo.png", None),
    ],
)
def test_detect_language(path, language):
    assert ci_client.detect_language(path) == language


def test_collect_sources_walks_and_skips_dependency_folders(tmp_path):
    sources = ci_client.collect_sources(make_tree(tmp_path), use_git=False)
    files = {entry["path"] for entry in sources["files"]}
    assert sources["listing"] == "walk"
    assert files == {"app/views.py", "app/ok.py", "Dockerfile", "settings.properties"}
    assert sources["unsupported"] >= 1


def test_collect_sources_uses_git_and_honours_gitignore(tmp_path):
    make_tree(tmp_path)
    (tmp_path / ".gitignore").write_text("app/ok.py\n", encoding="utf-8")
    git_init(tmp_path)
    sources = ci_client.collect_sources(tmp_path)
    files = {entry["path"] for entry in sources["files"]}
    assert sources["listing"] == "git"
    assert "app/views.py" in files and "app/ok.py" not in files


def test_collect_sources_ignores_repository_fsmonitor_command(tmp_path):
    repo = make_tree(tmp_path / "repo")
    git_init(repo)
    marker = tmp_path / "executed"
    hook = tmp_path / "hook.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o755)
    subprocess.run(["git", "config", "core.fsmonitor", str(hook)], cwd=repo, check=True)
    sources = ci_client.collect_sources(repo)
    assert sources["listing"] == "git" and sources["files"]
    assert not marker.exists()


def test_collect_sources_excludes_large_binary_and_symlinks(tmp_path):
    make_tree(tmp_path)
    (tmp_path / "big.py").write_text("x = 1\n" * 100, encoding="utf-8")
    (tmp_path / "blob.py").write_bytes(b"\0\1\2eval(x)")
    (tmp_path / "link.py").symlink_to(tmp_path / "app" / "views.py")
    sources = ci_client.collect_sources(
        tmp_path, excludes=["app/", "*.properties"], max_file_bytes=200, use_git=False
    )
    reasons = {entry["file"]: entry["reason"] for entry in sources["skipped"]}
    assert sources["excluded"] == 3
    assert reasons["big.py"].startswith("larger than")
    assert reasons["blob.py"] == "binary file"
    assert reasons["link.py"] == "symbolic link"
    assert {entry["path"] for entry in sources["files"]} == {"Dockerfile"}


def test_collect_sources_rejects_a_file(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="Not a directory"):
        ci_client.collect_sources(target)


# ── scan-code ────────────────────────────────────────────────────────────────


def test_scan_code_blocks_and_prints_the_matches(
    controller, ci_token, monkeypatch, capsys, tmp_path
):
    make_tree(tmp_path / "repo")
    argv = ["scan-code", str(tmp_path / "repo"), "--no-git", "--project", "shop-api"]

    assert run(controller, monkeypatch, argv, ci_token) == 1
    out = capsys.readouterr().out
    assert "app/views.py:2 [HIGH] PY-004" in out and "BLOCKED" in out
    assert "Sup3rSecret99" not in out
    # Nothing is stored without --save
    assert len(services.list_reports(project="shop-api")) == 1


def test_scan_code_passes_below_the_threshold(controller, ci_token, monkeypatch, tmp_path):
    (tmp_path / "a.py").write_text("print('ok')\n", encoding="utf-8")
    argv = ["scan-code", str(tmp_path), "--no-git", "--project", "shop-api"]
    assert run(controller, monkeypatch, argv, ci_token) == 0


def test_scan_code_saves_a_report_of_the_token(controller, ci_token, monkeypatch, capsys, tmp_path):
    make_tree(tmp_path / "repo")
    argv = ["scan-code", str(tmp_path / "repo"), "--no-git", "--project", "shop-api", "--save"]
    argv += ["--format", "json", "--author", "alice", "--branch", "main", "--commit", "abc123"]

    assert run(controller, monkeypatch, argv, ci_token) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["blocked"] is True and "sarif" not in data
    report = services.get_report(data["saved_report"]["report_id"])
    assert (report.project, report.review_type, report.author) == ("shop-api", "code-scan", "alice")
    assert (report.submitted_by, report.branch, report.commit_sha) == ("jenkins", "main", "abc123")
    assert report.reviewer == "security-review-ci scan-code"
    assert {f.file_path for f in report.findings} >= {"app/views.py"}


def test_scan_code_writes_a_sarif_log(controller, ci_token, monkeypatch, capsys, tmp_path):
    make_tree(tmp_path / "repo")
    output = tmp_path / "out.sarif"
    argv = ["scan-code", str(tmp_path / "repo"), "--no-git", "--project", "shop-api"]
    argv += ["--format", "sarif", "-o", str(output)]

    assert run(controller, monkeypatch, argv, ci_token) == 1
    log = json.loads(output.read_text(encoding="utf-8"))
    results = log["runs"][0]["results"]
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert "app/views.py" in uris
    assert "written to" in capsys.readouterr().err


def test_scan_code_of_another_project_is_refused(
    controller, ci_token, monkeypatch, capsys, tmp_path
):
    (tmp_path / "a.py").write_text("eval(x)\n", encoding="utf-8")
    argv = ["scan-code", str(tmp_path), "--no-git", "--project", "billing", "--save"]

    assert run(controller, monkeypatch, argv, ci_token) == 2
    assert "(404)" in json.loads(capsys.readouterr().err)["error"]
    assert len(services.list_reports(project="billing")) == 1


def test_scan_code_too_large_request_is_explained(
    controller, ci_token, monkeypatch, capsys, tmp_path
):
    monkeypatch.setattr(get_settings(), "max_scan_request_mb", 1)
    (tmp_path / "a.py").write_text("x = 1\n" * 300_000, encoding="utf-8")
    argv = ["scan-code", str(tmp_path), "--no-git", "--project", "shop-api"]
    argv += ["--max-file-bytes", str(4 * 1024 * 1024)]

    assert run(controller, monkeypatch, argv, ci_token) == 2
    error = json.loads(capsys.readouterr().err)["error"]
    assert "(413)" in error and "SECREVIEW_MAX_SCAN_REQUEST_MB" in error


def test_scan_code_of_a_missing_directory_is_a_usage_error(
    controller, ci_token, monkeypatch, capsys, tmp_path
):
    argv = ["scan-code", str(tmp_path / "missing"), "--project", "shop-api"]
    assert run(controller, monkeypatch, argv, ci_token) == 2
    assert "Not a directory" in capsys.readouterr().err


# ── scan-deps ────────────────────────────────────────────────────────────────


def import_advisory(tmp_path, severity="HIGH"):
    """Import one OSV record (requests < 2.20.0) into the advisory database."""
    folder = tmp_path / "osv"
    folder.mkdir()
    (folder / "adv.json").write_text(json.dumps(osv(severity=severity, fixed="2.20.0")))
    advisories.import_advisories(folder)


def test_scan_deps_blocks_on_a_vulnerability(controller, ci_token, monkeypatch, capsys, tmp_path):
    import_advisory(tmp_path)
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.19.0\n", encoding="utf-8")
    argv = ["scan-deps", str(manifest), "--project", "shop-api"]

    assert run(controller, monkeypatch, argv, ci_token) == 1
    out = capsys.readouterr().out
    assert "PYSEC-1" in out and "upgrade to 2.20.0" in out and "BLOCKED" in out
    assert run(controller, monkeypatch, [*argv, "--fail-on", "critical"], ci_token) == 0


def test_scan_deps_saves_a_report(controller, ci_token, monkeypatch, capsys, tmp_path):
    import_advisory(tmp_path)
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.19.0\n", encoding="utf-8")
    argv = ["scan-deps", str(manifest), "--project", "shop-api", "--save", "--format", "json"]

    assert run(controller, monkeypatch, [*argv, "--author", "alice"], ci_token) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["blocked"] is True and "components" not in data["files"][0]
    saved = data["saved_report"]
    assert saved["review_type"] == "dependency-scan"
    report = services.get_report(saved["report_id"])
    assert (report.author, report.submitted_by) == ("alice", "jenkins")

    assert run(controller, monkeypatch, [*argv, "--author", "a" * 201], ci_token) == 2
    assert "(422)" in capsys.readouterr().err


def test_scan_deps_require_database(controller, ci_token, monkeypatch, capsys, tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==1.0\n", encoding="utf-8")
    argv = ["scan-deps", str(manifest), "--project", "shop-api"]

    assert run(controller, monkeypatch, argv, ci_token) == 0
    assert "warning: vulnerability check did not run" in capsys.readouterr().err
    assert run(controller, monkeypatch, [*argv, "--require-database", "--save"], ci_token) == 2
    assert "require_database" in capsys.readouterr().err
    assert len(services.list_reports(project="shop-api")) == 1


def test_scan_deps_refuses_symlinks_and_unsupported_files(
    controller, ci_token, monkeypatch, capsys, tmp_path
):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==1.0\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(manifest)
    assert (
        run(controller, monkeypatch, ["scan-deps", str(link), "--project", "shop-api"], ci_token)
        == 2
    )
    assert "symbolic link" in capsys.readouterr().err

    other = tmp_path / "notes.md"
    other.write_text("x", encoding="utf-8")
    argv = ["scan-deps", str(other), "--project", "shop-api"]
    assert run(controller, monkeypatch, argv, ci_token) == 2
    assert "(422)" in capsys.readouterr().err
    argv = ["scan-deps", str(tmp_path / "missing.txt"), "--project", "shop-api"]
    assert run(controller, monkeypatch, argv, ci_token) == 2


def test_scans_need_a_ci_or_admin_token(controller, monkeypatch, capsys, tmp_path):
    reader = token_store.create_token("viewer", Role.MCP)["token"]
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==1.0\n", encoding="utf-8")

    argv = ["scan-deps", str(manifest), "--project", "shop-api"]
    assert run(controller, monkeypatch, argv, reader) == 2
    assert "(403)" in json.loads(capsys.readouterr().err)["error"]
    admin = token_store.create_token("root", Role.ADMIN)["token"]
    assert run(controller, monkeypatch, argv, admin) == 0
