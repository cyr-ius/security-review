"""Tests for the CLI commands, the new MCP tools and the schema upgrade."""

import json

import pytest
from mcp.client import Client
from sqlalchemy import inspect, text
from test_advisories import osv

from security_review_mcp import cli, server, services
from security_review_mcp.config import get_settings
from security_review_mcp.database import get_engine, init_db
from security_review_mcp.models import FindingCreate, Severity


def seed(project="demo", severity=Severity.HIGH):
    """Store one report with one finding."""
    return services.save_report(
        project=project,
        summary="Seeded report",
        findings=[
            FindingCreate(
                title="Seeded finding",
                severity=severity,
                description="Something wrong",
                file_path="app.py",
                line_start=3,
                cwe="CWE-79",
            )
        ],
    )


def import_osv(tmp_path, **kwargs):
    """Write one OSV record and return its path."""
    path = tmp_path / "adv.json"
    path.write_text(json.dumps(osv(fixed="2.20.0", **kwargs)), encoding="utf-8")
    return path


def text_of(result) -> str:
    """Concatenate the text blocks of a tool result."""
    return "".join(block.text for block in result.content if hasattr(block, "text"))


# ── deps scan ────────────────────────────────────────────────────────────────


def test_deps_scan_blocks_on_vulnerability(tmp_path, capsys):
    assert cli.run(["advisories", "import", str(import_osv(tmp_path, severity="HIGH"))]) == 0
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.19.0\n", encoding="utf-8")
    capsys.readouterr()
    assert cli.run(["deps", "scan", str(manifest)]) == cli.EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "PYSEC-1" in out and "upgrade to 2.20.0" in out and "BLOCKED" in out


def test_deps_scan_fail_on_threshold(tmp_path):
    cli.run(["advisories", "import", str(import_osv(tmp_path, severity="HIGH"))])
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.19.0\n", encoding="utf-8")
    assert cli.run(["deps", "scan", str(manifest), "--fail-on", "critical"]) == cli.EXIT_PASSED


def test_deps_scan_json_and_save(tmp_path, capsys):
    cli.run(["advisories", "import", str(import_osv(tmp_path, severity="HIGH"))])
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.19.0\n", encoding="utf-8")
    capsys.readouterr()
    code = cli.run(
        ["deps", "scan", str(manifest), "--format", "json", "--save", "--project", "demo"]
    )
    data = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_BLOCKED and data["blocked"] is True
    assert data["saved_report"]["report_id"] >= 1
    assert services.list_reports(project="demo")


def test_deps_scan_save_needs_a_project(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==1.0\n", encoding="utf-8")
    assert cli.run(["deps", "scan", str(manifest), "--save"]) == cli.EXIT_ERROR


def test_deps_scan_require_database(tmp_path, capsys):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==1.0\n", encoding="utf-8")
    assert cli.run(["deps", "scan", str(manifest)]) == cli.EXIT_PASSED
    assert "warning" in capsys.readouterr().err
    assert cli.run(["deps", "scan", str(manifest), "--require-database"]) == cli.EXIT_ERROR


def test_deps_scan_errors(tmp_path):
    assert cli.run(["deps", "scan", str(tmp_path / "missing.txt")]) == cli.EXIT_ERROR
    other = tmp_path / "notes.md"
    other.write_text("x", encoding="utf-8")
    assert cli.run(["deps", "scan", str(other)]) == cli.EXIT_ERROR


# ── advisories / sarif / trend ───────────────────────────────────────────────


def test_advisories_import_and_status(tmp_path, capsys):
    assert cli.run(["advisories", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["loaded"] is False
    assert cli.run(["advisories", "import", str(import_osv(tmp_path))]) == 0
    capsys.readouterr()
    assert cli.run(["advisories", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["advisories"] == 1
    assert cli.run(["advisories", "import", str(tmp_path / "nope.json")]) == cli.EXIT_ERROR


def test_sarif_command_stdout_and_file(tmp_path, capsys):
    seed()
    capsys.readouterr()
    assert cli.run(["sarif", "--project", "demo"]) == 0
    log = json.loads(capsys.readouterr().out)
    assert log["version"] == "2.1.0" and len(log["runs"][0]["results"]) == 1
    target = tmp_path / "out.sarif"
    assert cli.run(["sarif", "--project", "demo", "-o", str(target)]) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"
    capsys.readouterr()
    assert cli.run(["sarif", "--project", "unknown"]) == 0  # nothing to report is not an error
    assert json.loads(capsys.readouterr().out)["runs"][0]["results"] == []


def test_trend_command(capsys):
    seed()
    capsys.readouterr()
    assert cli.run(["trend", "--project", "demo", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["project"] == "demo"
    assert cli.run(["trend", "--project", "demo"]) == 0
    assert "demo" in capsys.readouterr().out


def test_main_dispatches_cli_commands():
    with pytest.raises(SystemExit) as stop:
        server.main(["advisories", "status"])
    assert stop.value.code == 0


# ── MCP tools and prompt ─────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_scan_dependencies_tool(tmp_path):
    cli.run(["advisories", "import", str(import_osv(tmp_path, severity="HIGH"))])
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "scan_dependencies",
            {"content": "requests==2.19.0\n", "filename": "requirements.txt"},
        )
        data = json.loads(text_of(result))
        assert data["vulnerabilities_count"] == 1
        status = json.loads(text_of(await client.call_tool("get_advisory_status", {})))
        assert status["loaded"] is True


@pytest.mark.anyio
async def test_scan_dependencies_tool_limits_and_errors(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_dependency_chars", 20)
    async with Client(server.mcp) as client:
        big = await client.call_tool(
            "scan_dependencies", {"content": "flask==1.0\n" * 10, "filename": "requirements.txt"}
        )
        assert big.is_error and "deps scan" in text_of(big)
        bad = await client.call_tool("scan_dependencies", {"content": "x", "filename": "notes.md"})
        assert bad.is_error and "Unsupported" in text_of(bad)


@pytest.mark.anyio
async def test_export_sarif_and_trend_tools():
    seed()
    async with Client(server.mcp) as client:
        sarif = await client.call_tool("export_sarif", {"project": "demo"})
        assert json.loads(text_of(sarif))["version"] == "2.1.0"
        both = await client.call_tool("export_sarif", {"project": "demo", "report_id": 1})
        assert both.is_error
        trend = await client.call_tool("get_trend_report", {"project": "demo"})
        assert "demo" in text_of(trend)
        as_json = await client.call_tool(
            "get_trend_report", {"project": "demo", "format": "json", "granularity": "day"}
        )
        assert json.loads(text_of(as_json))["project"] == "demo"


@pytest.mark.anyio
async def test_dependency_review_prompt():
    async with Client(server.mcp) as client:
        prompt = await client.get_prompt("dependency-review", {"ecosystem": "npm"})
    body = "".join(m.content.text for m in prompt.messages)
    assert "scan_dependencies" in body and "SC-01" in body


# ── schema upgrade ───────────────────────────────────────────────────────────


def test_init_db_adds_missing_columns_and_keeps_data():
    seed()
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE finding DROP COLUMN rule_id"))
        conn.execute(text("ALTER TABLE finding DROP COLUMN status_changed_at"))
    names = {c["name"] for c in inspect(engine).get_columns("finding")}
    assert "rule_id" not in names

    init_db()

    names = {c["name"] for c in inspect(engine).get_columns("finding")}
    assert {"rule_id", "status_changed_at"} <= names
    report = services.list_reports(project="demo")
    assert len(report) == 1
