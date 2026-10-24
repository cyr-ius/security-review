"""Tests for the SARIF export."""

import pytest

from security_review_mcp import sarif, services
from security_review_mcp.storage.models import FindingCreate, FindingStatus, Severity


def make(severity=Severity.HIGH, **kwargs) -> FindingCreate:
    """Build a valid finding."""
    data = {
        "title": "SQL injection",
        "severity": severity,
        "description": "User input is concatenated in a query",
        "cwe": "CWE-89",
        "file_path": "app\\db.py",
        "line_start": 10,
        "line_end": 12,
        "evidence": "cur.execute(q + x)",
        "recommendation": "Use bound parameters",
    }
    data.update(kwargs)
    return FindingCreate(**data)


def export(project="shop", **kwargs) -> dict:
    """Export a project as SARIF."""
    name, items = services.collect_sarif_items(None, project)
    return sarif.build_sarif(items, name, **kwargs)


def test_structure_and_mapping():
    services.save_report(
        "shop",
        "summary",
        [
            make(Severity.CRITICAL),
            make(Severity.MEDIUM, title="Weak hash", cwe="CWE-327"),
            make(
                Severity.LOW,
                title="Debug",
                cwe=None,
                file_path=None,
                line_start=None,
                line_end=None,
            ),
        ],
        repository="https://git.example/shop",
        branch="main",
        commit_sha="abc123",
    )
    log = export()
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "security-review-mcp"
    levels = {r["properties"]["severity"]: r["level"] for r in run["results"]}
    assert levels == {"critical": "error", "medium": "warning", "low": "note"}

    sql = next(r for r in run["results"] if r["properties"]["severity"] == "critical")
    location = sql["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app/db.py"  # backslashes normalized
    assert location["region"] == {
        "startLine": 10,
        "endLine": 12,
        "snippet": {"text": "cur.execute(q + x)"},
    }
    assert sql["properties"]["security-severity"] == "9.5"
    assert sql["partialFingerprints"]["secreview/v1"]

    no_file = next(r for r in run["results"] if r["properties"]["severity"] == "low")
    assert "physicalLocation" not in no_file["locations"][0]
    assert no_file["locations"][0]["logicalLocations"][0]["name"] == "shop"

    assert run["versionControlProvenance"] == [
        {"revisionId": "abc123", "repositoryUri": "https://git.example/shop", "branch": "main"}
    ]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "CWE-89")
    assert rule["helpUri"].endswith("/89.html")
    assert rule["help"]["text"] == "Use bound parameters"
    assert all(
        r["ruleIndex"] == [x["id"] for x in run["tool"]["driver"]["rules"]].index(r["ruleId"])
        for r in run["results"]
    )


def test_rule_id_is_preferred_and_advisories_get_an_osv_link():
    services.save_report("shop", "summary", [make(rule_id="GHSA-aaaa-bbbb-cccc", cwe="CWE-1395")])
    rule = export()["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "GHSA-aaaa-bbbb-cccc"
    assert rule["helpUri"] == "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"


def test_only_open_findings_by_default_and_resolved_on_request(triage):
    saved = services.save_report(
        "shop",
        "summary",
        [
            make(title="Alpha issue"),
            make(title="Beta issue"),
            make(title="Gamma issue"),
            make(title="Delta issue"),
        ],
    )
    findings = services.get_report(saved["report_id"]).findings
    statuses = [FindingStatus.FIXED, FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE]
    for finding, status in zip(findings[:3], statuses, strict=True):
        triage(finding.id, status)

    assert len(export()["runs"][0]["results"]) == 1

    results = {
        r["message"]["text"].split(".")[0]: r
        for r in export(include_resolved=True)["runs"][0]["results"]
    }
    assert results["Alpha issue"]["baselineState"] == "absent"
    assert results["Beta issue"]["suppressions"][0]["justification"] == "Risk accepted"
    assert results["Gamma issue"]["suppressions"][0]["justification"] == "False positive"
    assert "suppressions" not in results["Delta issue"]


def test_project_export_keeps_the_latest_occurrence_of_a_finding():
    services.save_report("shop", "first", [make()])
    second = services.save_report("shop", "second", [make(line_start=40, line_end=41)])
    results = export()["runs"][0]["results"]
    assert len(results) == 1  # same rule, file and title: reported once
    assert results[0]["properties"]["reportId"] == second["report_id"]
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 40


def test_fingerprint_is_stable_when_lines_move():
    services.save_report("shop", "first", [make(line_start=10)])
    first = export()["runs"][0]["results"][0]["partialFingerprints"]
    services.save_report("shop", "second", [make(line_start=99, line_end=100)])
    second = export()["runs"][0]["results"][0]["partialFingerprints"]
    assert first == second


def test_target_arguments_are_validated():
    with pytest.raises(ValueError):
        services.collect_sarif_items(None, None)
    with pytest.raises(ValueError):
        services.collect_sarif_items(1, "shop")
    with pytest.raises(services.NotFoundError):
        services.collect_sarif_items(999, None)


def test_single_report_export_and_empty_project():
    saved = services.save_report("shop", "summary", [make()])
    name, items = services.collect_sarif_items(saved["report_id"], None)
    assert name == "shop"
    assert len(sarif.build_sarif(items, name)["runs"][0]["results"]) == 1
    assert export("ghost")["runs"][0]["results"] == []
