"""Dependency scan: parse a manifest or lockfile, check it against the advisories, run hygiene."""

from .advisories import Query, advisory_status, find_vulnerabilities, severity_or_default
from .dependencies import Parsed, parse_dependency_file
from .models import SEVERITY_RANK, FindingCreate, Severity

MAX_COMPONENTS_LISTED = 200
VULNERABLE_COMPONENT_CWE = "CWE-1395"  # Dependency on Vulnerable Third-Party Component


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
