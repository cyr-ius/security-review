"""Tests for the dependency scan (parsing + advisory matching + findings)."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import select
from test_advisories import osv

from security_review_mcp.config import get_settings
from security_review_mcp.deps import advisories, depscan
from security_review_mcp.reports import services
from security_review_mcp.storage.database import session_scope
from security_review_mcp.storage.models import Advisory, Severity

REQUIREMENTS = "flask==1.0\nrequests==2.19.0\n"


def load(*records, tmp_path):
    """Import OSV records through a temporary directory."""
    for index, record in enumerate(records):
        (tmp_path / f"{index}.json").write_text(json.dumps(record), encoding="utf-8")
    return advisories.import_advisories(tmp_path)


def test_without_database_the_check_is_skipped_and_explained():
    result = depscan.scan_dependencies(REQUIREMENTS, "requirements.txt")
    assert result["vulnerability_check"] == "skipped_no_advisory_database"
    assert result["vulnerabilities"] == []
    assert any("CANNOT" in note for note in result["notes"])


def test_vulnerable_component_is_found_with_line_and_upgrade(tmp_path):
    load(osv(severity="HIGH", fixed="2.20.0"), tmp_path=tmp_path)
    result = depscan.scan_dependencies(REQUIREMENTS, "requirements.txt")
    assert result["vulnerability_check"] == "performed"
    (vuln,) = result["vulnerabilities"]
    assert (vuln["package"], vuln["version"], vuln["line"]) == ("requests", "2.19.0", 2)
    assert vuln["severity"] == "high" and vuln["severity_known"] is True
    assert vuln["recommended_upgrade"] == "2.20.0"


def test_vulnerable_component_is_found_in_uv_lock(tmp_path):
    load(osv(severity="HIGH", fixed="2.20.0"), tmp_path=tmp_path)
    lock = (
        'version = 1\n\n[[package]]\nname = "requests"\nversion = "2.19.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    result = depscan.scan_dependencies(lock, "uv.lock")
    assert result["vulnerability_check"] == "performed"
    (vuln,) = result["vulnerabilities"]
    assert (vuln["package"], vuln["version"]) == ("requests", "2.19.0")
    assert vuln["recommended_upgrade"] == "2.20.0"


def test_fixed_version_is_not_reported(tmp_path):
    load(osv(fixed="2.0.0"), tmp_path=tmp_path)
    assert depscan.scan_dependencies(REQUIREMENTS, "requirements.txt")["vulnerabilities"] == []


def test_ecosystem_without_advisory_is_reported(tmp_path):
    load(osv(), tmp_path=tmp_path)
    result = depscan.scan_dependencies(
        '{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0"}}}',
        "package-lock.json",
    )
    assert result["vulnerability_check"] == "skipped_no_advisories_for_ecosystem"


SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "components": [
            {"purl": "pkg:maven/org.springframework/spring-web@5.3.0"},
            {"purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8"},
            {"purl": "pkg:npm/lodash@4.17.0"},
        ],
    }
)


def test_transitive_maven_dependency_is_found_in_a_cyclonedx_sbom(tmp_path):
    load(
        osv(
            "GHSA-1",
            package="com.fasterxml.jackson.core:jackson-databind",
            ecosystem="Maven",
            fixed="2.9.10",
            severity="CRITICAL",
        ),
        tmp_path=tmp_path,
    )
    result = depscan.scan_dependencies(SBOM, "bom.json")
    assert result["vulnerability_check"] == "performed"
    assert result["is_lockfile"] and result["components_resolved"] == 3
    (vuln,) = result["vulnerabilities"]
    assert (vuln["package"], vuln["version"]) == (
        "com.fasterxml.jackson.core:jackson-databind",
        "2.9.8",
    )
    assert vuln["recommended_upgrade"] == "2.9.10"
    # npm has no advisory: the check still ran for Maven, and the gap is reported
    assert any("no npm advisory" in note for note in result["notes"])
    (finding,) = [f for f in depscan.to_findings(result) if f.rule_id == "GHSA-1"]
    assert finding.file_path == "bom.json" and finding.severity.value == "critical"


GO_MOD = """module example.com/app

go 1.22

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect
)
"""
CARGO_LOCK = """version = 3

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "time"
version = "0.1.43"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
PACKAGES_LOCK = json.dumps(
    {
        "version": 1,
        "dependencies": {
            "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"}},
        },
    }
)


@pytest.mark.parametrize(
    ("content", "filename", "record", "expected"),
    [
        (
            GO_MOD,
            "go.mod",
            osv("GO-1", "golang.org/x/net", "Go", fixed="0.7.0"),
            ("golang.org/x/net", "v0.0.0-20220127200216-cd36cc0744dd", 7, "0.7.0"),
        ),
        (
            CARGO_LOCK,
            "Cargo.lock",
            osv("RUSTSEC-1", "time", "crates.io", introduced="0.1.0", fixed="0.2.23"),
            ("time", "0.1.43", None, "0.2.23"),
        ),
        (
            PACKAGES_LOCK,
            "packages.lock.json",
            osv("GHSA-n", "newtonsoft.json", "NuGet", fixed="13.0.1"),
            ("Newtonsoft.Json", "12.0.1", None, "13.0.1"),
        ),
    ],
)
def test_go_rust_and_nuget_components_are_matched(tmp_path, content, filename, record, expected):
    load(record, tmp_path=tmp_path)
    result = depscan.scan_dependencies(content, filename)
    assert result["vulnerability_check"] == "performed" and result["is_lockfile"]
    (vuln,) = result["vulnerabilities"]
    found = (vuln["package"], vuln["version"], vuln["line"], vuln["recommended_upgrade"])
    assert found == expected


def test_sbom_without_advisories_for_any_of_its_ecosystems_is_skipped(tmp_path):
    load(osv(), tmp_path=tmp_path)
    result = depscan.scan_dependencies(SBOM, "bom.json")
    assert result["vulnerability_check"] == "skipped_no_advisories_for_ecosystem"
    assert any("Maven, npm" in note for note in result["notes"])


def test_unknown_severity_defaults_to_medium(tmp_path):
    load(osv(fixed="2.20.0"), tmp_path=tmp_path)
    (vuln,) = depscan.scan_dependencies(REQUIREMENTS, "requirements.txt")["vulnerabilities"]
    assert vuln["severity"] == "medium" and vuln["severity_known"] is False
    (finding,) = [
        f
        for f in depscan.to_findings(depscan.scan_dependencies(REQUIREMENTS, "requirements.txt"))
        if f.rule_id == "PYSEC-1"
    ]
    assert "medium is assumed" in finding.description


def test_stale_database_adds_a_note(tmp_path):
    load(osv(fixed="2.20.0"), tmp_path=tmp_path)
    with session_scope() as session:
        for row in session.exec(select(Advisory)):
            row.imported_at = datetime.now(UTC) - timedelta(days=90)
            session.add(row)
    result = depscan.scan_dependencies(REQUIREMENTS, "requirements.txt")
    assert any("days ago" in note for note in result["notes"])


def test_findings_can_be_saved_as_a_report(tmp_path):
    load(osv(severity="CRITICAL", fixed="2.20.0"), tmp_path=tmp_path)
    result = depscan.scan_dependencies("requests==2.19.0\nflask\n", "requirements.txt")
    findings = depscan.to_findings(result)
    assert {f.rule_id for f in findings} == {"PYSEC-1", "DEP-001"}
    assert all(f.category == "dependency" for f in findings)
    saved = services.save_report(project="demo", summary="Dependency scan", findings=findings)
    assert saved["findings_count"] == 2
    assert saved["risk_level"] == "critical"


# ── Scans sent by security-review-ci scan-deps ───────────────────────────────


def test_scan_files_uses_the_file_name_and_counts_blocking_entries(tmp_path):
    load(osv(severity="HIGH", fixed="2.20.0"), tmp_path=tmp_path)
    results = depscan.scan_files([("backend/requirements.txt", "requests==2.19.0\nflask\n")])
    assert results[0]["file"] == "requirements.txt"
    assert depscan.blocking_count(results, Severity.HIGH) == 1
    assert depscan.blocking_count(results, Severity.LOW) == 2
    assert depscan.blocking_count(results, Severity.CRITICAL) == 0


def test_scan_files_limits_and_errors(monkeypatch):
    with pytest.raises(ValueError, match="No dependency file"):
        depscan.scan_files([])
    with pytest.raises(ValueError, match="Unsupported"):
        depscan.scan_files([("notes.md", "x")])
    monkeypatch.setattr(get_settings(), "max_scan_files", 1)
    with pytest.raises(ValueError, match="SECREVIEW_MAX_SCAN_FILES"):
        depscan.scan_files([("requirements.txt", "flask==1.0\n")] * 2)
    monkeypatch.setattr(get_settings(), "max_dependency_chars", 5)
    with pytest.raises(ValueError, match="SECREVIEW_MAX_DEPENDENCY_CHARS"):
        depscan.scan_files([("requirements.txt", "flask==1.0\n")])


def test_scan_files_require_database():
    assert depscan.scan_files([("requirements.txt", "flask==1.0\n")])
    with pytest.raises(ValueError, match="require_database"):
        depscan.scan_files([("requirements.txt", "flask==1.0\n")], require_database=True)


def test_save_stores_a_dependency_scan_report(tmp_path):
    load(osv(severity="CRITICAL", fixed="2.20.0"), tmp_path=tmp_path)
    results = depscan.scan_files([("requirements.txt", "requests==2.19.0\n")])
    saved = depscan.save(results, "demo", commit_sha="abc123", author="alice", submitted_by="ci")
    report = services.get_report(saved["report_id"])
    assert (saved["review_type"], saved["risk_level"]) == ("dependency-scan", "critical")
    assert report.reviewer == "security-review-ci scan-deps"
    assert (report.author, report.submitted_by, report.scope) == ("alice", "ci", "requirements.txt")
