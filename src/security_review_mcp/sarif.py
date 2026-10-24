"""SARIF 2.1.0 export of stored findings.

SARIF is the interchange format read by code-scanning dashboards (GitHub code scanning, the
VS Code SARIF viewer, DefectDojo...). Results without a ``file_path`` only carry a logical
location (the project): some consumers ignore or reject those.
"""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from . import __version__
from .storage.models import FindingPublic, FindingStatus, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub reads "security-severity" as a CVSS-like score: >9 critical, 7-8.9 high, 4-6.9 medium
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.1",
}
_ADVISORY_PREFIXES = ("GHSA-", "PYSEC-", "CVE-", "OSV-", "RUSTSEC-", "GO-", "MAL-")


@dataclass(frozen=True)
class SarifItem:
    """A finding with the context of the report it belongs to."""

    finding: FindingPublic
    report_id: int
    project: str
    repository: str | None
    branch: str | None
    commit_sha: str | None
    created_at: datetime


def rule_key(finding: FindingPublic) -> str:
    """Return the SARIF rule id of a finding: its rule id, else its CWE, else its category."""
    return finding.rule_id or finding.cwe or f"secreview/{finding.category}"


def fingerprint(item: SarifItem) -> str:
    """Return a stable id for deduplication; it ignores line numbers so edits don't reset it."""
    finding = item.finding
    raw = "|".join(
        [item.project, rule_key(finding), finding.file_path or "", finding.title.strip().lower()]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def dedupe_latest(items: list[SarifItem]) -> list[SarifItem]:
    """Keep the most recent occurrence of every fingerprint (items sorted oldest first)."""
    latest: dict[str, SarifItem] = {}
    for item in items:
        latest[fingerprint(item)] = item
    return list(latest.values())


def _help_uri(key: str) -> str | None:
    """Return a documentation link for a CWE or an advisory id."""
    if key.startswith("CWE-") and key[4:].isdigit():
        return f"https://cwe.mitre.org/data/definitions/{key[4:]}.html"
    if key.startswith(_ADVISORY_PREFIXES):
        return f"https://osv.dev/vulnerability/{key}"
    return None


def _uri(path: str) -> str:
    """Normalize a file path into a relative SARIF uri."""
    uri = path.strip().replace("\\", "/")
    while uri.startswith("./"):
        uri = uri[2:]
    return uri


def _result(item: SarifItem, rule_index: int) -> dict:
    """Build the SARIF result of one finding."""
    finding = item.finding
    message = finding.title
    if finding.description and finding.description != finding.title:
        message = f"{finding.title}. {finding.description}"
    result: dict = {
        "ruleId": rule_key(finding),
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": message[:2000]},
        "partialFingerprints": {"secreview/v1": fingerprint(item)},
        "properties": {
            "severity": finding.severity.value,
            "status": finding.status.value,
            "category": finding.category,
            "findingId": finding.id,
            "reportId": item.report_id,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }
    if finding.cwe:
        result["properties"]["cwe"] = finding.cwe
    if finding.owasp:
        result["properties"]["owasp"] = finding.owasp
    if finding.recommendation:
        result["properties"]["recommendation"] = finding.recommendation

    if finding.file_path:
        physical: dict = {
            "artifactLocation": {"uri": _uri(finding.file_path), "uriBaseId": "%SRCROOT%"}
        }
        if finding.line_start:
            region: dict = {"startLine": finding.line_start}
            if finding.line_end and finding.line_end >= finding.line_start:
                region["endLine"] = finding.line_end
            if finding.evidence:
                region["snippet"] = {"text": finding.evidence[:1000]}
            physical["region"] = region
        result["locations"] = [{"physicalLocation": physical}]
    else:
        result["locations"] = [{"logicalLocations": [{"name": item.project, "kind": "module"}]}]

    if finding.status == FindingStatus.FIXED:
        result["baselineState"] = "absent"
    elif finding.status in (FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE):
        justification = (
            "False positive" if finding.status == FindingStatus.FALSE_POSITIVE else "Risk accepted"
        )
        result["suppressions"] = [
            {"kind": "external", "status": "accepted", "justification": justification}
        ]
    return result


def build_sarif(
    items: list[SarifItem],
    project: str,
    include_resolved: bool = False,
) -> dict:
    """Build a SARIF 2.1.0 log.

    Args:
        items: Findings with their report context.
        project: Project name (used for the automation id).
        include_resolved: Also export fixed, accepted and false-positive findings (as
            ``baselineState: absent`` or ``suppressions``). By default only open findings.
    """
    selected = [i for i in items if include_resolved or i.finding.status == FindingStatus.OPEN]

    rules: list[dict] = []
    index: dict[str, int] = {}
    for item in selected:
        finding = item.finding
        key = rule_key(finding)
        if key in index:
            continue
        index[key] = len(rules)
        rule: dict = {
            "id": key,
            "name": finding.title[:100],
            "shortDescription": {"text": finding.title[:200]},
            "fullDescription": {"text": (finding.description or finding.title)[:1000]},
            "defaultConfiguration": {"level": _LEVEL[finding.severity]},
            "properties": {
                "tags": ["security", *([finding.cwe] if finding.cwe else [])],
                "security-severity": _SECURITY_SEVERITY[finding.severity],
            },
        }
        if finding.recommendation:
            rule["help"] = {"text": finding.recommendation[:1000]}
        uri = _help_uri(key)
        if uri:
            rule["helpUri"] = uri
        rules.append(rule)

    run: dict = {
        "tool": {
            "driver": {
                "name": "security-review-mcp",
                "version": __version__,
                "rules": rules,
            }
        },
        "automationDetails": {"id": f"security-review/{project}/"},
        "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "Repository root"}}},
        "invocations": [
            {
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        ],
        "results": [_result(item, index[rule_key(item.finding)]) for item in selected],
    }

    # Version control provenance, only when every item agrees on repository and commit
    provenance = {(i.repository, i.commit_sha, i.branch) for i in selected if i.commit_sha}
    if len(provenance) == 1:
        repository, commit, branch = next(iter(provenance))
        entry: dict = {"revisionId": commit}
        if repository:
            entry["repositoryUri"] = repository
        if branch:
            entry["branch"] = branch
        run["versionControlProvenance"] = [entry]

    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
