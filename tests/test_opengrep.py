"""Tests for the optional OpenGrep whole-codebase engine."""

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_review_mcp.config import Settings, get_settings
from security_review_mcp.engines import opengrep
from security_review_mcp.rules import codescan, opengrep_rule_store
from security_review_mcp.rules.codescan import SourceFile


def test_engine_disabled_by_default_runs_only_once_rules_are_installed(tmp_path, monkeypatch):
    # Disabled by default (a PyPI installation has no executable); once enabled, skipped
    # without any rule: scan-code works out of the box
    assert Settings().opengrep_enabled is False
    rules = tmp_path / "rules"
    settings = SimpleNamespace(
        opengrep_enabled=True,
        opengrep_binary=str(tmp_path / "missing-opengrep"),
        opengrep_rules_dir=str(rules),
    )
    monkeypatch.setattr(opengrep, "get_settings", lambda: settings)
    assert opengrep.scan_files([("app.py", "print('hello')")]) == {}

    # Installed rules without the executable are a misconfiguration, never a silent skip
    rules.mkdir()
    (rules / "demo.yaml").write_text("rules: []\n", encoding="utf-8")
    with pytest.raises(opengrep.OpenGrepError, match="executable is unavailable"):
        opengrep.scan_files([("app.py", "print('hello')")])


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
        opengrep_max_concurrent_scans=1,
        opengrep_jobs=2,
        opengrep_max_memory_mb=512,
        opengrep_taint_intrafile=True,
        max_scan_file_chars=1000,
    )
    monkeypatch.setattr(opengrep, "get_settings", lambda: settings)
    monkeypatch.setattr(opengrep.shutil, "which", lambda _: str(binary))
    monkeypatch.setenv("XDG_CACHE_HOME", "/opt/opengrep/cache")
    monkeypatch.setenv("SECREVIEW_DATABASE_URL", "postgresql://user:secret@db/secreview")

    def fake_run(command, **kwargs):
        workspace = Path(kwargs["cwd"])
        assert (workspace / "app.py").is_file()
        # Private HOME and the bundle cache of the image; nothing else of the controller
        assert set(kwargs["env"]) == {"PATH", "HOME", "NO_COLOR", "XDG_CACHE_HOME"}
        assert kwargs["env"]["XDG_CACHE_HOME"] == "/opt/opengrep/cache"
        assert command[1:4] == ["scan", "--json", "--config"]
        assert command[5:9] == ["--jobs", "2", "--max-memory", "512"]
        # Inter-procedural taint within a file, unless disabled (older executables lack it)
        intrafile = ["--taint-intrafile"] if settings.opengrep_taint_intrafile else []
        assert command[9:] == [*intrafile, str(workspace)]
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

    monkeypatch.setattr(opengrep, "_run", fake_run)
    result = opengrep.scan_files([("app.py", "print('ok')\nrun(command)\n")])
    assert result["app.py"][0]["rule_id"] == "OPENGREP:python.security.demo"
    assert result["app.py"][0]["severity"] == "medium"
    settings.opengrep_taint_intrafile = False
    assert opengrep.scan_files([("app.py", "run(command)\n")])["app.py"]


def test_scan_files_rejects_nonzero_exit_and_busy_engine(tmp_path, monkeypatch):
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
        opengrep_max_concurrent_scans=1,
        opengrep_max_concurrent_fragment_scans=1,
        opengrep_jobs=1,
        opengrep_max_memory_mb=0,
        opengrep_taint_intrafile=False,
    )
    monkeypatch.setattr(opengrep, "get_settings", lambda: settings)
    monkeypatch.setattr(opengrep.shutil, "which", lambda _: str(binary))
    monkeypatch.setattr(
        opengrep,
        "_run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout="", stderr="secret details"),
    )
    with pytest.raises(opengrep.OpenGrepError, match="scan failed"):
        opengrep.scan_files([("app.py", "print('ok')")])

    # Every slot taken: the scan is refused before writing the sources, and the slot is free again
    # once the running scan ends
    with opengrep._scan_slot(1), pytest.raises(opengrep.OpenGrepBusyError, match="busy"):
        opengrep.scan_files([("app.py", "print('ok')")])
    with pytest.raises(opengrep.OpenGrepError, match="scan failed"):
        opengrep.scan_files([("app.py", "print('ok')")])
    # The fragments of scan_code have their own slots: they never take those of the pipelines
    with opengrep._scan_slot(1), pytest.raises(opengrep.OpenGrepError, match="scan failed"):
        opengrep.scan_files([("app.py", "print('ok')")], fragment=True)
    with opengrep._scan_slot(1, "fragment"):
        with pytest.raises(opengrep.OpenGrepBusyError, match="busy"):
            opengrep.scan_files([("app.py", "print('ok')")], fragment=True)
        with pytest.raises(opengrep.OpenGrepError, match="scan failed"):
            opengrep.scan_files([("app.py", "print('ok')")])


def test_codebase_scan_merges_opengrep_findings(monkeypatch):
    monkeypatch.setattr(get_settings(), "opengrep_enabled", True)
    monkeypatch.setattr(
        opengrep,
        "scan_files",
        lambda files, fragment=False, rules_dir=None: {
            "app.py": [
                {
                    "title": "Unsafe subprocess",
                    "description": "Command injection risk",
                    "severity": "high",
                    "rule_id": "OPENGREP:python.security.demo",
                    "cwe": "CWE-78",
                    "line": 3,
                    "line_end": 4,
                    "excerpt": "subprocess.run(command)",
                    "advice": "Use a safe argument list.",
                }
            ]
        },
    )
    result = codescan.scan_files(
        [SourceFile("app.py", "import subprocess\n\nsubprocess.run(command)\n")]
    )
    findings = codescan.to_findings(result)
    assert result["matches_count"] == 1
    assert findings[0].rule_id == "OPENGREP:python.security.demo"
    assert findings[0].description == "Command injection risk"
    assert findings[0].line_start == 3 and findings[0].line_end == 4


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="OpenGrep is not installed")
def test_scan_files_reports_the_rule_id_without_the_rules_directory(tmp_path, monkeypatch):
    # Regression: OpenGrep prefixes rule ids with the dotted path of the --config directory
    # (var.lib.secreview.rules.opengrep.x), which hid the rule id once truncated
    rules = tmp_path / "var" / "lib" / "secreview" / "rules" / "opengrep"
    rules.mkdir(parents=True)
    bundled = opengrep_rule_store.BUNDLED_DIR / "python" / "secreview.python.taint-sql.yaml"
    (rules / bundled.name).write_text(bundled.read_text(encoding="utf-8"), encoding="utf-8")
    settings = SimpleNamespace(
        opengrep_enabled=True,
        opengrep_binary="opengrep",
        opengrep_rules_dir=str(rules),
        opengrep_timeout_seconds=120,
        opengrep_max_concurrent_scans=1,
        opengrep_jobs=1,
        opengrep_max_memory_mb=0,
        opengrep_taint_intrafile=True,
    )
    monkeypatch.setattr(opengrep, "get_settings", lambda: settings)
    source = (
        "from flask import request\n"
        "def users(cursor):\n"
        "    cursor.execute(\"SELECT * FROM users WHERE name = '\" + request.args['n'] + \"'\")\n"
    )
    result = opengrep.scan_files([("app.py", source)])
    assert [finding["rule_id"] for finding in result["app.py"]] == [
        "OPENGREP:secreview.python.taint-sql"
    ]
    assert result["app.py"][0]["cwe"] == "CWE-89"
