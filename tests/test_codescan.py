"""Tests for the whole-codebase scan (module, CLI command and codebase-review prompt)."""

import json
import subprocess

import pytest
from mcp.client import Client

from security_review_mcp import cli, codescan, rule_store, services
from security_review_mcp.config import get_settings
from security_review_mcp.models import Severity
from security_review_mcp.server import mcp


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


# ── language detection ───────────────────────────────────────────────────────


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
        ("dist/app.min.js", None),
        ("types/index.d.ts", None),
        ("package-lock.json", None),
        ("logo.png", None),
    ],
)
def test_detect_language(path, language):
    assert codescan.detect_language(path) == language


# ── scan_tree ────────────────────────────────────────────────────────────────


def test_scan_tree_walks_and_skips_dependency_folders(tmp_path):
    result = codescan.scan_tree(make_tree(tmp_path), use_git=False)
    files = {entry["file"] for entry in result["files"]}
    assert result["listing"] == "walk"
    assert {"app/views.py", "app/ok.py", "Dockerfile", "settings.properties"} <= files
    assert "node_modules/lib.js" not in files
    assert "README.md" not in files and result["files_unsupported"] >= 1
    rules = {m["rule_id"] for entry in result["files"] for m in entry["matches"]}
    assert {"PY-004", "GEN-001"} <= rules
    assert "Sup3rSecret99" not in json.dumps(result)


def test_scan_tree_uses_git_and_honours_gitignore(tmp_path):
    make_tree(tmp_path)
    (tmp_path / ".gitignore").write_text("app/ok.py\n", encoding="utf-8")
    git_init(tmp_path)
    result = codescan.scan_tree(tmp_path)
    files = {entry["file"] for entry in result["files"]}
    assert result["listing"] == "git"
    assert "app/views.py" in files and "app/ok.py" not in files


def test_scan_tree_ignores_repository_fsmonitor_command(tmp_path):
    repo = make_tree(tmp_path / "repo")
    git_init(repo)
    marker = tmp_path / "executed"
    hook = tmp_path / "hook.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o755)
    subprocess.run(["git", "config", "core.fsmonitor", str(hook)], cwd=repo, check=True)
    result = codescan.scan_tree(repo)
    assert result["listing"] == "git" and result["files_scanned"] >= 1
    assert not marker.exists()


def test_scan_tree_excludes_large_binary_and_symlinks(tmp_path):
    make_tree(tmp_path)
    (tmp_path / "big.py").write_text("x = 1\n" * 100, encoding="utf-8")
    (tmp_path / "blob.py").write_bytes(b"\0\1\2eval(x)")
    (tmp_path / "link.py").symlink_to(tmp_path / "app" / "views.py")
    result = codescan.scan_tree(
        tmp_path, excludes=["app/", "*.properties"], max_file_bytes=200, use_git=False
    )
    reasons = {entry["file"]: entry["reason"] for entry in result["skipped"]}
    assert reasons["app/views.py"] == "excluded"
    assert reasons["settings.properties"] == "excluded"
    assert reasons["big.py"].startswith("larger than")
    assert reasons["blob.py"] == "binary file"
    assert reasons["link.py"] == "symbolic link"


def test_scan_tree_reports_suppressed_matches(tmp_path):
    (tmp_path / "a.py").write_text(
        "subprocess.run(c, shell=True)  # secreview:ignore PY-004\n", encoding="utf-8"
    )
    result = codescan.scan_tree(tmp_path, use_git=False)
    assert result["matches_count"] == 0 and result["suppressed_count"] == 1


def test_scan_tree_rejects_a_file(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        codescan.scan_tree(target)


def test_to_findings_sorted_with_categories(tmp_path):
    result = codescan.scan_tree(make_tree(tmp_path), use_git=False)
    findings = codescan.to_findings(result)
    ranks = [f.severity for f in findings]
    assert ranks[0] in (Severity.CRITICAL, Severity.HIGH)
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["GEN-001"].category == "secret"
    assert by_rule["PY-004"].category == "code" and by_rule["PY-004"].file_path == "app/views.py"
    assert codescan.blocking_count(result, Severity.CRITICAL) <= len(findings)


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_code_scan_text_blocks(tmp_path, capsys):
    make_tree(tmp_path)
    assert cli.run(["code", "scan", str(tmp_path), "--no-git"]) == cli.EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "app/views.py:2 [HIGH] PY-004" in out and "BLOCKED" in out


def test_code_scan_passes_below_threshold(tmp_path):
    (tmp_path / "a.py").write_text("print('ok')\n", encoding="utf-8")
    assert cli.run(["code", "scan", str(tmp_path), "--no-git"]) == cli.EXIT_PASSED


def test_code_scan_json_and_save(tmp_path, capsys):
    make_tree(tmp_path)
    code = cli.run(
        ["code", "scan", str(tmp_path), "--no-git", "--format", "json", "--save"]
        + ["--project", "demo"]
    )
    data = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_BLOCKED and data["blocked"] is True
    report = services.get_report(data["saved_report"]["report_id"])
    assert report.reviewer == "security-review-mcp code scan"
    assert {f.file_path for f in report.findings} >= {"app/views.py"}


def test_code_scan_save_keeps_most_severe_within_limit(tmp_path, monkeypatch):
    make_tree(tmp_path)
    monkeypatch.setattr(get_settings(), "max_findings_per_report", 1)
    cli.run(["code", "scan", str(tmp_path), "--no-git", "--save", "--project", "demo"])
    report = services.list_reports(project="demo")[0]
    stored = services.get_report(report["report_id"])
    assert len(stored.findings) == 1 and "Only the 1 most severe" in stored.summary


def test_code_scan_sarif_without_save(tmp_path):
    make_tree(tmp_path)
    output = tmp_path / "out.sarif"
    cli.run(["code", "scan", str(tmp_path), "--no-git", "--format", "sarif", "-o", str(output)])
    log = json.loads(output.read_text(encoding="utf-8"))
    results = log["runs"][0]["results"]
    assert results and results[0]["level"] in ("error", "warning", "note")
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert "app/views.py" in uris


def test_code_scan_applies_internal_rules(tmp_path, capsys):
    rule_store.import_packs(
        [
            (
                "p.toml",
                'disabled_rules = ["PY-001"]\n[[rules]]\nid = "ACME-001"\ntitle = "Legacy"\n'
                'severity = "high"\nlanguages = ["python"]\npattern = "LegacyCrypto"\n',
            )
        ]
    )
    (tmp_path / "app.py").write_text("LegacyCrypto.encrypt(x)\neval(y)\n", encoding="utf-8")
    assert cli.run(["code", "scan", str(tmp_path), "--no-git", "--format", "json"]) == 1
    result = json.loads(capsys.readouterr().out)
    found = {match["rule_id"] for entry in result["files"] for match in entry["matches"]}
    assert "ACME-001" in found
    assert "PY-001" not in found


def test_code_scan_errors(tmp_path):
    assert cli.run(["code", "scan", str(tmp_path), "--save"]) == cli.EXIT_ERROR
    assert cli.run(["code", "scan", str(tmp_path / "missing")]) == cli.EXIT_ERROR


# ── codebase-review prompt ───────────────────────────────────────────────────


@pytest.mark.anyio
async def test_codebase_review_prompt():
    async with Client(mcp) as client:
        prompts = {p.name for p in (await client.list_prompts()).prompts}
        assert "codebase-review" in prompts
        result = await client.get_prompt(
            "codebase-review",
            {"languages": "python, angular", "scan_results": '{"matches_count": 3}'},
        )
    text = result.messages[0].content.text
    assert "whole codebase" in text and "(python, angular)" in text
    assert '"matches_count": 3' in text
    assert "Coverage" in text and "save_security_report" in text


@pytest.mark.anyio
async def test_codebase_review_prompt_rejects_huge_scan_results(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_content_chars", 10)
    async with Client(mcp) as client:
        with pytest.raises(Exception, match="too large"):
            await client.get_prompt("codebase-review", {"scan_results": "x" * 11})
