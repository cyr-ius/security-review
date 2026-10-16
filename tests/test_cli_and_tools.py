"""Tests for the CLI commands, the new MCP tools and the schema upgrade."""

import json

import pytest
from mcp.client import Client
from sqlalchemy import inspect, text
from test_advisories import osv

from security_review_mcp import cli, rule_store, rules_loader, server, services, token_store
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
    assert data["saved_report"]["review_type"] == "dependency-scan"
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


# ── rules ────────────────────────────────────────────────────────────────────

RULE_PACK = """
disabled_rules = ["PY-008"]

[[rules]]
id = "ACME-001"
title = "Legacy crypto helper"
severity = "high"
languages = ["python"]
pattern = "LegacyCrypto"

[[checklist]]
domain = "company"
id = "ACME-CL-01"
title = "Tenant isolation"
what_to_look_for = "Queries are scoped by tenant."
"""


def test_rules_import_export_round_trip(tmp_path, capsys):
    packs = tmp_path / "rules.d"
    packs.mkdir()
    (packs / "company.toml").write_text(RULE_PACK, encoding="utf-8")
    (packs / "notes.txt").write_text("ignored", encoding="utf-8")
    assert cli.run(["rules", "import", str(packs)]) == cli.EXIT_PASSED
    stats = json.loads(capsys.readouterr().out)
    assert (stats["files"], stats["rules"], stats["checklist_items"]) == (["company.toml"], 1, 1)

    exported = tmp_path / "export.toml"
    assert cli.run(["rules", "export", "-o", str(exported)]) == cli.EXIT_PASSED
    assert "ACME-001" in exported.read_text(encoding="utf-8")
    assert cli.run(["rules", "export"]) == cli.EXIT_PASSED
    assert capsys.readouterr().out == exported.read_text(encoding="utf-8")

    assert cli.run(["rules", "import", "--replace", str(exported)]) == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out)["replaced"] is True


def test_rules_list_shows_modified_default_rules(capsys):
    rule_store.update_rule("PY-001", rule_store.default_rules()["PY-001"] | {"title": "Edited"})
    assert cli.run(["rules", "list", "--language", "python"]) == cli.EXIT_PASSED
    lines = capsys.readouterr().out.splitlines()
    assert any(line.startswith("PY-001") and " modified " in line for line in lines)
    assert any(line.startswith("PY-002") and " builtin " in line for line in lines)


def test_rules_list_enable_disable_delete(capsys):
    assert cli.run(["rules", "disable", "PY-001", "PY-004"]) == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out) == {"disabled": ["PY-001", "PY-004"]}

    assert cli.run(["rules", "list", "--language", "python", "--format", "json"]) == 0
    rows = {row["id"]: row for row in json.loads(capsys.readouterr().out)}
    assert rows["PY-001"]["enabled"] is False
    assert rows["PY-002"]["enabled"] is True

    assert cli.run(["rules", "list", "--language", "python"]) == cli.EXIT_PASSED
    out = capsys.readouterr().out
    assert any(line.startswith("PY-001") and "disabled" in line for line in out.splitlines())
    assert "2 disabled" in out

    assert cli.run(["rules", "enable", "PY-001"]) == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out) == {"enabled": ["PY-001"]}

    rule_store.import_packs([("p.toml", RULE_PACK)])  # changed by another process
    assert cli.run(["rules", "list", "--custom", "--format", "json"]) == cli.EXIT_PASSED
    assert [row["id"] for row in json.loads(capsys.readouterr().out)] == ["ACME-001"]
    assert cli.run(["rules", "delete", "ACME-001", "ACME-CL-01"]) == cli.EXIT_PASSED
    assert json.loads(capsys.readouterr().out)["deleted_rules"] == ["ACME-001"]


def test_rules_errors(tmp_path, capsys):
    assert cli.run(["rules", "disable", "ACME-404"]) == cli.EXIT_ERROR
    assert "Unknown rule" in json.loads(capsys.readouterr().err)["error"]
    assert cli.run(["rules", "delete", "PY-001"]) == cli.EXIT_ERROR
    assert "cannot be deleted" in capsys.readouterr().err

    bad = tmp_path / "bad.toml"
    bad.write_text('[[rules]]\nid = "ACME-1"\ntitle = "t"\nseverity = "low"\npattern = "a*"')
    assert cli.run(["rules", "import", str(bad)]) == cli.EXIT_ERROR
    assert "empty string" in capsys.readouterr().err
    assert cli.run(["rules", "import", str(tmp_path / "missing.toml")]) == cli.EXIT_ERROR
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.run(["rules", "import", str(empty)]) == cli.EXIT_ERROR
    with pytest.raises(SystemExit):
        cli.run(["rules", "bogus"])


def test_rules_import_does_not_follow_symlinks(tmp_path, capsys):
    target = tmp_path / "outside.toml"
    target.write_text(RULE_PACK, encoding="utf-8")
    packs = tmp_path / "rules.d"
    packs.mkdir()
    (packs / "link.toml").symlink_to(target)
    (packs / "real.toml").write_text(
        '[[rules]]\nid = "ACME-002"\ntitle = "t"\nseverity = "low"\npattern = "x"',
        encoding="utf-8",
    )
    assert cli.run(["rules", "import", str(packs / "link.toml")]) == cli.EXIT_ERROR
    assert "symbolic link" in capsys.readouterr().err
    assert cli.run(["rules", "import", str(packs)]) == cli.EXIT_PASSED
    captured = capsys.readouterr()
    assert json.loads(captured.out)["files"] == ["real.toml"]
    assert "skipped" in captured.err


def test_rules_import_rejects_oversized_pack(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(rules_loader, "MAX_PACK_BYTES", 10)
    pack = tmp_path / "big.toml"
    pack.write_text(RULE_PACK, encoding="utf-8")
    assert cli.run(["rules", "import", str(pack)]) == cli.EXIT_ERROR
    assert "larger than" in capsys.readouterr().err


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


def test_init_db_moves_legacy_project_tokens():
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO apitoken (id, label, role, project, token_hash, created_at) "
                "VALUES ('t1', 'old', 'reader', 'shop-api', :digest, CURRENT_TIMESTAMP)"
            ),
            {"digest": "ab" * 32},
        )

    init_db()

    (token,) = token_store.list_tokens("shop-api")
    assert (token["label"], token["projects"]) == ("old", ["shop-api"])
