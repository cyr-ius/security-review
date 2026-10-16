"""Tests for the dependency scan (parsing + advisory matching + findings)."""

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import select
from test_advisories import osv

from security_review_mcp import advisories, depscan, services
from security_review_mcp.database import session_scope
from security_review_mcp.models import Advisory

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
