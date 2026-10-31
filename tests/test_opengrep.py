"""Tests for the optional OpenGrep whole-codebase engine."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_review_mcp.engines import opengrep


def test_disabled_engine_does_not_require_binary_or_rules(monkeypatch):
    monkeypatch.setattr(opengrep, "get_settings", lambda: SimpleNamespace(opengrep_enabled=False))
    assert opengrep.scan_files([("app.py", "print('hello')")]) == {}


def test_safe_relative_path_rejects_traversal():
    with pytest.raises(ValueError, match="Invalid source path"):
        opengrep._safe_relative_path("../outside.py")
    with pytest.raises(ValueError, match="Invalid source path"):
        opengrep._safe_relative_path("/etc/passwd")


def test_normalize_result_maps_severity_cwe_and_redacts_secrets():
    path, finding = opengrep._normalize_result(
        {
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "app.py",
            "start": {"line": 8},
            "end": {"line": 9},
            "extra": {
                "message": "Hardcoded password",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-798"]},
                "lines": 'password = "SuperSecret123"',
            },
        }
    )
    assert path == "app.py"
    assert finding["severity"] == "high"
    assert finding["cwe"] == "CWE-798"
    assert finding["line"] == 8 and finding["line_end"] == 9
    assert "SuperSecret123" not in finding["excerpt"]


def test_scan_files_executes_with_private_workspace_and_parses_json(tmp_path, monkeypatch):
    binary = tmp_path / "opengrep"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "security.yml").write_text("rules: []\n", encoding="utf-8")
    settings = SimpleNamespace(
        opengrep_enabled=True,
        opengrep_binary=str(binary),
        opengrep_rules_dir=str(rules),
        opengrep_timeout_seconds=15,
        max_scan_file_chars=1000,
    )
    monkeypatch.setattr(opengrep, "get_settings", lambda: settings)
    monkeypatch.setattr(opengrep.shutil, "which", lambda _: str(binary))

    def fake_run(command, **kwargs):
        workspace = Path(kwargs["cwd"])
        assert (workspace / "app.py").is_file()
        assert command[1:4] == ["scan", "--json", "--config"]
        payload = {
            "results": [
                {
                    "check_id": "python.security.demo",
                    "path": "app.py",
                    "start": {"line": 2},
                    "end": {"line": 2},
                    "extra": {
                        "message": "Unsafe call",
                        "severity": "WARNING",
                        "metadata": {"cwe": "CWE-78"},
                        "lines": "run(command)",
                    },
                }
            ]
        }
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(opengrep.subprocess, "run", fake_run)
    result = opengrep.scan_files([("app.py", "print('ok')\nrun(command)\n")])
    assert result["app.py"][0]["rule_id"] == "OPENGREP:python.security.demo"
    assert result["app.py"][0]["severity"] == "medium"


def test_scan_files_rejects_nonzero_exit(tmp_path, monkeypatch):
    binary = tmp_path / "opengrep"
    binary.touch()
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rules.yaml").write_text("rules: []\n", encoding="utf-8")
    settings = SimpleNamespace(
        opengrep_enabled=True,
        opengrep_binary=str(binary),
        opengrep_rules_dir=str(rules),
        opengrep_timeout_seconds=1,
    )
    monkeypatch.setattr(opengrep, "get_settings", lambda: settings)
    monkeypatch.setattr(opengrep.shutil, "which", lambda _: str(binary))
    monkeypatch.setattr(
        opengrep.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout="", stderr="secret details"),
    )
    with pytest.raises(opengrep.OpenGrepError, match="scan failed"):
        opengrep.scan_files([("app.py", "print('ok')")])
