"""Tests for the whole-codebase scan run by the controller (module and codebase-review prompt).

The listing of the files is done by the pipeline client: see test_ci_client.
"""

import json

import pytest
from mcp.client import Client

from security_review_mcp import codescan, rule_store
from security_review_mcp.codescan import SourceFile
from security_review_mcp.config import get_settings
from security_review_mcp.reports import services
from security_review_mcp.server import mcp
from security_review_mcp.storage.models import Severity

FILES = [
    SourceFile("app/views.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n"),
    SourceFile("app/ok.py", "print('hello')\n"),
    SourceFile("Dockerfile", "FROM python:latest\nUSER root\n"),
    SourceFile("settings.properties", 'password = "Sup3rSecret99"\n'),
]


# ── scan_files ───────────────────────────────────────────────────────────────


def test_scan_files_matches_and_masks_secrets():
    result = codescan.scan_files(FILES, listing="walk", root="shop")
    files = {entry["file"] for entry in result["files"]}
    assert files == {"app/views.py", "app/ok.py", "Dockerfile", "settings.properties"}
    assert (result["root"], result["listing"], result["files_scanned"]) == ("shop", "walk", 4)
    rules = {m["rule_id"] for entry in result["files"] for m in entry["matches"]}
    assert {"PY-004", "GEN-001"} <= rules
    assert "Sup3rSecret99" not in json.dumps(result)


def test_scan_files_detects_the_language_from_the_path_again():
    # A path whose type is not scanned is counted, whatever the client claims
    result = codescan.scan_files([SourceFile("README.md", "eval(x)\n")], unsupported=2)
    assert result["files_scanned"] == 0 and result["files_unsupported"] == 3


def test_scan_files_reports_skipped_and_oversized_files(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_scan_file_chars", 20)
    big = SourceFile("big.py", "x = 1\n" * 10)
    result = codescan.scan_files([big, FILES[1]], [("blob.py", "binary file")], excluded=3)
    reasons = {entry["file"]: entry["reason"] for entry in result["skipped"]}
    assert reasons["blob.py"] == "binary file"
    assert reasons["big.py"].startswith("larger than 20 characters")
    assert result["files_skipped"] == 5 and result["files_scanned"] == 1


def test_scan_files_refuses_too_many_files(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_scan_files", 3)
    with pytest.raises(ValueError, match="SECREVIEW_MAX_SCAN_FILES"):
        codescan.scan_files(FILES)


def test_scan_files_reports_suppressed_matches():
    source = SourceFile("a.py", "subprocess.run(c, shell=True)  # secreview:ignore PY-004\n")
    result = codescan.scan_files([source])
    assert result["matches_count"] == 0 and result["suppressed_count"] == 1


def test_scan_files_applies_internal_rules():
    rule_store.import_packs(
        [
            (
                "p.toml",
                'disabled_rules = ["PY-001"]\n[[rules]]\nid = "ACME-001"\ntitle = "Legacy"\n'
                'severity = "high"\nlanguages = ["python"]\npattern = "LegacyCrypto"\n',
            )
        ]
    )
    result = codescan.scan_files([SourceFile("app.py", "LegacyCrypto.encrypt(x)\neval(y)\n")])
    found = {match["rule_id"] for entry in result["files"] for match in entry["matches"]}
    assert "ACME-001" in found
    assert "PY-001" not in found


def test_to_findings_sorted_with_categories():
    result = codescan.scan_files(FILES)
    findings = codescan.to_findings(result)
    assert findings[0].severity in (Severity.CRITICAL, Severity.HIGH)
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["GEN-001"].category == "secret"
    assert by_rule["PY-004"].category == "code" and by_rule["PY-004"].file_path == "app/views.py"
    assert codescan.blocking_count(result, Severity.CRITICAL) <= len(findings)


# ── save and SARIF ───────────────────────────────────────────────────────────


def test_save_stores_a_code_scan_report():
    result = codescan.scan_files(FILES, [("blob.py", "binary file")], root="shop")
    saved = codescan.save(result, "demo", branch="main", author="alice", submitted_by="jenkins")
    report = services.get_report(saved["report_id"])
    assert report.reviewer == "security-review-ci scan-code"
    assert (report.author, report.submitted_by, report.branch) == ("alice", "jenkins", "main")
    assert report.review_type == "code-scan"
    assert "Codebase shop" in report.scope and "not scanned: blob.py" in report.scope
    assert {f.file_path for f in report.findings} >= {"app/views.py"}
    assert "Sup3rSecret99" not in json.dumps(report.model_dump(mode="json"))


def test_save_keeps_most_severe_within_limit(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_findings_per_report", 1)
    saved = codescan.save(codescan.scan_files(FILES), "demo")
    stored = services.get_report(saved["report_id"])
    assert len(stored.findings) == 1 and "Only the 1 most severe" in stored.summary


def test_to_sarif_with_and_without_a_saved_report():
    result = codescan.scan_files(FILES)
    log = codescan.to_sarif(result, "demo", commit_sha="abc123")
    results = log["runs"][0]["results"]
    assert results and results[0]["level"] in ("error", "warning", "note")
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert "app/views.py" in uris

    saved = codescan.save(result, "demo")
    stored = codescan.to_sarif(result, "demo", saved)
    assert len(stored["runs"][0]["results"]) == len(results)


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
