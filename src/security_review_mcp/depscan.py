"""Dependency scan: parse a manifest or lockfile, check it against the advisories, run hygiene.

Used by the ``scan_dependencies`` MCP tool and by the controller for the files sent by
``security-review-ci scan-deps`` (``POST /api/v1/ci/scan/deps``, see scan_files and save).
``security-review-mcp scan-deps --save`` builds its report with report_content.
"""

from collections.abc import Sequence
from pathlib import PurePosixPath

from .advisories import Query, advisory_status, find_vulnerabilities, severity_or_default
from .config import get_settings
from .dependencies import Parsed, parse_dependency_file
from .reports import services
from .storage.models import SEVERITY_RANK, FindingCreate, ReviewType, Severity

MAX_COMPONENTS_LISTED = 200
VULNERABLE_COMPONENT_CWE = "CWE-1395"  # Dependency on Vulnerable Third-Party Component
REVIEWER = "security-review-ci scan-deps"


def _check_state(parsed: Parsed, status: dict) -> tuple[str, list[str]]:
    """Decide whether the vulnerability check really ran, and explain when it did not."""
    notes: list[str] = []
    if not status["loaded"]:
        notes.append(
            "No advisory database is loaded: vulnerable versions CANNOT be detected. Only hygiene "
            "checks ran. Import OSV advisories with `security-review-controller advisories import`."
        )
        return "skipped_no_advisory_database", notes
    # An SBOM may mix ecosystems: the check runs if at least one of them has advisories
    ecosystems = sorted({c.ecosystem for c in parsed.components if c.version is not None}) or [
        parsed.ecosystem
    ]
    missing = [e for e in ecosystems if status["by_ecosystem"].get(e, 0) == 0]
    if len(missing) == len(ecosystems):
        notes.append(
            f"The advisory database has no {', '.join(missing)} advisory: vulnerable versions "
            "cannot be detected for this file."
        )
        return "skipped_no_advisories_for_ecosystem", notes
    if missing:
        notes.append(
            f"The advisory database has no {', '.join(missing)} advisory: vulnerable versions "
            "cannot be detected for the components of this ecosystem."
        )
    if status["stale"]:
        notes.append(
            f"The advisory database was last imported {status['age_days']} days ago: recent "
            "vulnerabilities may be missing."
        )
    return "performed", notes


def scan_dependencies(content: str, filename: str) -> dict:
    """Scan one dependency file.

    Args:
        content: File content.
        filename: File name (it selects the parser, for example ``package-lock.json``).

    Returns:
        The components, the vulnerabilities (with fixed versions), the hygiene issues and the
        state of the advisory database. ``vulnerability_check`` tells whether the check ran.

    Raises:
        ValueError: If the file type is unsupported or its content is invalid.
    """
    parsed = parse_dependency_file(content, filename)
    status = advisory_status()
    check, notes = _check_state(parsed, status)

    lines: dict[tuple[str, str, str], int | None] = {}
    queries: list[Query] = []
    for component in parsed.components:
        if component.version is None:
            continue
        key = (component.ecosystem, component.name, component.version)
        if key not in lines:
            lines[key] = component.line
            queries.append(Query(*key))

    vulnerabilities: list[dict] = []
    if check == "performed":
        for item in find_vulnerabilities(queries):
            severity = severity_or_default(item["severity"])
            vulnerabilities.append(
                {
                    **item,
                    "severity": severity.value,
                    "severity_known": item["severity"] is not None,
                    "file": filename,
                    "line": lines.get((item["ecosystem"], item["package"], item["version"])),
                }
            )
        vulnerabilities.sort(key=lambda v: (-SEVERITY_RANK[Severity(v["severity"])], v["package"]))

    hygiene = [
        {
            "rule_id": issue.rule_id,
            "title": issue.title,
            "severity": issue.severity.value,
            "cwe": issue.cwe,
            "message": issue.message,
            "line": issue.line,
            "file": filename,
        }
        for issue in parsed.issues
    ]
    hygiene.sort(key=lambda h: -SEVERITY_RANK[Severity(h["severity"])])

    resolved = sum(1 for c in parsed.components if c.version is not None)
    return {
        "file": filename,
        "file_type": parsed.file_type,
        "ecosystem": parsed.ecosystem,
        "is_lockfile": parsed.is_lockfile,
        "components_total": len(parsed.components),
        "components_resolved": resolved,
        "components_unresolved": len(parsed.components) - resolved,
        "components": [
            {"name": c.name, "version": c.version, "spec": c.spec, "dev": c.dev, "kind": c.kind}
            for c in parsed.components[:MAX_COMPONENTS_LISTED]
        ],
        "components_truncated": len(parsed.components) > MAX_COMPONENTS_LISTED,
        "vulnerability_check": check,
        "vulnerabilities_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "hygiene_count": len(hygiene),
        "hygiene": hygiene,
        "advisory_database": status,
        "notes": parsed.notes + notes,
    }


def to_findings(result: dict) -> list[FindingCreate]:
    """Convert a scan result to findings, ready for ``save_security_report``."""
    findings: list[FindingCreate] = []
    for vuln in result["vulnerabilities"]:
        parts = [vuln["summary"] or "Known vulnerability."]
        if vuln["also_known_as"]:
            parts.append(f"Also known as: {', '.join(vuln['also_known_as'][:5])}.")
        if not vuln["severity_known"]:
            parts.append("The advisory has no severity: medium is assumed.")
        if vuln["fixed_versions"]:
            parts.append(f"Fixed in: {', '.join(vuln['fixed_versions'][:5])}.")
        upgrade = vuln["recommended_upgrade"]
        findings.append(
            FindingCreate(
                title=f"Vulnerable dependency: {vuln['package']} {vuln['version']}",
                severity=Severity(vuln["severity"]),
                category="dependency",
                rule_id=vuln["advisory_id"],
                cwe=VULNERABLE_COMPONENT_CWE,
                file_path=vuln["file"],
                line_start=vuln["line"],
                description=" ".join(parts),
                evidence=f"{vuln['package']}=={vuln['version']} ({vuln['ecosystem']})",
                recommendation=(
                    f"Upgrade {vuln['package']} to {upgrade} or later."
                    if upgrade
                    else "No fixed version is known: replace the package or apply a mitigation."
                ),
            )
        )
    for issue in result["hygiene"]:
        findings.append(
            FindingCreate(
                title=issue["title"],
                severity=Severity(issue["severity"]),
                category="dependency",
                rule_id=issue["rule_id"],
                cwe=issue["cwe"],
                file_path=issue["file"],
                line_start=issue["line"],
                description=issue["message"],
            )
        )
    return findings


def scan_files(files: Sequence[tuple[str, str]], require_database: bool = False) -> list[dict]:
    """Scan dependency files sent by a client (path or name, content).

    Raises:
        ValueError: Too many files, a file above SECREVIEW_MAX_DEPENDENCY_CHARS, an unsupported
            or invalid file, or (with ``require_database``) a file whose vulnerability check
            could not run.
    """
    settings = get_settings()
    if not files:
        raise ValueError("No dependency file to scan")
    if len(files) > settings.max_scan_files:
        raise ValueError(
            f"Too many files ({len(files)}); the limit is {settings.max_scan_files} "
            "(SECREVIEW_MAX_SCAN_FILES)"
        )
    results: list[dict] = []
    for path, content in files:
        name = PurePosixPath(path.replace("\\", "/")).name
        if len(content) > settings.max_dependency_chars:
            raise ValueError(
                f"{name} is too large ({len(content)} characters); the limit is "
                f"{settings.max_dependency_chars} (SECREVIEW_MAX_DEPENDENCY_CHARS)"
            )
        results.append(scan_dependencies(content, name))
    unchecked = [r["file"] for r in results if r["vulnerability_check"] != "performed"]
    if require_database and unchecked:
        raise ValueError(
            f"The vulnerability check could not run for: {', '.join(unchecked)} (no advisory "
            "database for this ecosystem) and require_database was given"
        )
    return results


def blocking_count(results: Sequence[dict], fail_on: Severity) -> int:
    """Count the vulnerabilities and hygiene issues whose severity reaches the threshold."""
    threshold = SEVERITY_RANK[fail_on]
    return sum(
        1
        for result in results
        for entry in result["vulnerabilities"] + result["hygiene"]
        if SEVERITY_RANK[Severity(entry["severity"])] >= threshold
    )


def report_content(results: Sequence[dict], reviewer: str = REVIEWER) -> dict:
    """Summary, findings, scope, reviewer and review type of the report of the scans.

    Shared by ``save`` (controller) and ``security-review-mcp scan-deps --save``, which sends
    them to the ``save_security_report`` tool of a shared MCP server.
    """
    vulnerabilities = sum(r["vulnerabilities_count"] for r in results)
    hygiene = sum(r["hygiene_count"] for r in results)
    return {
        "summary": (
            f"Dependency scan of {len(results)} file(s): {vulnerabilities} vulnerable "
            f"component(s), {hygiene} hygiene issue(s)."
        ),
        "findings": [f for r in results for f in to_findings(r)],
        "reviewer": reviewer,
        "scope": ", ".join(r["file"] for r in results),
        "review_type": ReviewType.DEPENDENCY_SCAN,
    }


def save(
    results: Sequence[dict],
    project: str,
    repository: str | None = None,
    branch: str | None = None,
    commit_sha: str | None = None,
    author: str | None = None,
    submitted_by: str | None = None,
) -> dict:
    """Store the vulnerabilities and hygiene issues of the scans as one report.

    Raises:
        ValueError: Too many findings or invalid report fields (author...).
    """
    return services.save_report(
        project=project,
        repository=repository,
        branch=branch,
        commit_sha=commit_sha,
        author=author,
        submitted_by=submitted_by,
        **report_content(results),
    )
