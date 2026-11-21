"""Markdown renderings, gate evaluation and SARIF items."""

from collections import Counter
from collections.abc import Collection

from sqlalchemy import func
from sqlmodel import col, select

from ...config import get_settings
from ...prompts import fenced
from ...storage.database import session_scope
from ...storage.models import (
    SEVERITY_RANK,
    Finding,
    FindingPublic,
    FindingStatus,
    SecurityReport,
    SecurityReportPublic,
    Severity,
    as_utc,
    effective_status,
    utcnow,
)
from ...storage.project_names import normalize_project
from .core import (
    DISMISSAL_EXPIRY_WARNING,
    NotFoundError,
    _current,
    _expiring_dismissal,
    _status_is,
)
from .findings import list_project_findings, project_posture
from .scope import check_project_scope


def _coverage_markdown(report: SecurityReportPublic) -> list[str]:
    """Render the declared coverage of a report (nothing when none was declared)."""
    if not report.checklist_results and not report.scan_rules:
        return []
    lines = ["", "## Coverage"]
    if report.checklist_results:
        counts = Counter(r.outcome.value for r in report.checklist_results)
        lines += [
            "",
            "Checklist: " + ", ".join(f"{n} {o}" for o, n in sorted(counts.items())) + ".",
            "",
            "| Item | Title | Outcome |",
            "|---|---|---|",
        ]
        lines += [
            f"| {r.item_id} | {r.title.replace('|', '/')} | {r.outcome.value} |"
            for r in report.checklist_results
        ]
    if report.scan_rules:
        confirmed = {f.rule_id.strip().upper() for f in report.findings if f.rule_id}
        dismissed = [x for x in report.scan_rules if x not in confirmed]
        lines += ["", f"Scan leads: {', '.join(report.scan_rules)}."]
        if dismissed:
            lines.append(f"Dismissed (no finding): {', '.join(dismissed)}.")
    return lines


def _finding_location(finding: FindingPublic) -> str:
    """Return ``path:start-end`` of a finding (empty without a file path)."""
    location = ""
    if finding.file_path:
        location = finding.file_path
        if finding.line_start:
            location += f":{finding.line_start}"
            if finding.line_end and finding.line_end != finding.line_start:
                location += f"-{finding.line_end}"
    return location


def _finding_markdown(finding: FindingPublic, report_line: str | None = None) -> list[str]:
    """Render one finding as a Markdown section (title, location, references, details)."""
    location = _finding_location(finding)
    refs = ", ".join(x for x in (finding.cwe, finding.owasp) if x)
    lines = [
        "",
        f"### [{finding.severity.value.upper()}] {finding.title} (#{finding.id}, "
        f"{finding.status.value})",
    ]
    if location:
        lines.append(f"- **Location**: `{location}`")
    if refs:
        lines.append(f"- **References**: {refs}")
    if report_line:
        lines.append(f"- **Report**: {report_line}")
    if finding.original_severity:
        # On one line: the justification is free text typed by a person
        reason = " ".join((finding.severity_reason or "").split())
        lines.append(
            f"- **Severity raised** from {finding.original_severity.value} by "
            f"{finding.severity_changed_by}: {reason}"
        )
    lines += ["", finding.description]
    if finding.evidence:
        # The evidence comes from the reviewed code: it must not close its block
        lines += ["", fenced(finding.evidence)]
    if finding.recommendation:
        lines += ["", f"**Recommendation**: {finding.recommendation}"]
    return lines


def render_report_markdown(report: SecurityReportPublic) -> str:
    """Render a stored report as Markdown (for humans, MRs and tickets)."""
    lines = [
        f"# Security report #{report.id} - {report.project}",
        "",
        f"- **Risk level**: {report.risk_level.value.upper()}",
        f"- **Date**: {report.created_at.isoformat()}",
    ]
    for label, value in (
        ("Repository", report.repository),
        ("Branch", report.branch),
        ("Commit", report.commit_sha),
        ("Review type", report.review_type and report.review_type.value),
        ("Reviewer", report.reviewer),
        ("Author", report.author),
        ("Submitted by", report.submitted_by),
        ("Scope", report.scope),
    ):
        if value:
            lines.append(f"- **{label}**: {value}")
    lines += ["", "## Summary", "", report.summary]
    lines += _coverage_markdown(report)
    lines += ["", f"## Findings ({len(report.findings)})"]

    ordered = sorted(report.findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.id))
    if not ordered:
        lines += ["", "No finding recorded."]
    for finding in ordered:
        lines += _finding_markdown(finding)
    return "\n".join(lines) + "\n"


# File name suggested to the developer for the findings report of a project
FINDINGS_REPORT_FILE = "SECURITY_REPORT.md"


def render_findings_markdown(
    project: str,
    include_resolved: bool = False,
    projects: Collection[str] | None = None,
    compact: bool = False,
) -> str:
    """Render the current findings of a project as one Markdown document (SECURITY_REPORT.md).

    Open findings by default (an expired decision counts as open), every status with
    ``include_resolved``; an issue reported again is listed once, worst severity first. At most
    SECREVIEW_MAX_LIST_LIMIT findings are detailed: the document says how many are left out.
    ``projects`` is the scope of a restricted caller. ``compact`` gives one line per finding
    (severity, title, location, id) instead of its details: a much smaller document.
    """
    project = normalize_project(project)
    check_project_scope(projects, project)
    statuses = list(FindingStatus) if include_resolved else [FindingStatus.OPEN]
    posture = project_posture(project)
    listed = list_project_findings(
        project, statuses, limit=get_settings().max_list_limit, projects=projects
    )
    counts = posture["open_findings_by_severity"]
    worst = posture["worst_open_severity"]
    lines = [
        f"# Security report - {project}",
        "",
        f"- **Generated**: {utcnow().replace(microsecond=0).isoformat()}",
        f"- **Reports**: {posture['reports_total']}",
        f"- **Open findings**: {posture['open_findings_total']}"
        + (f" (worst: {worst.upper()})" if worst else ""),
        "",
        "| Severity | Open |",
        "|---|---|",
        *(f"| {severity.value} | {counts[severity.value]} |" for severity in Severity),
        "",
        f"## {'Findings' if include_resolved else 'Open findings'} ({listed['total']})",
    ]
    if not listed["findings"]:
        lines += ["", "No finding recorded." if include_resolved else "No open finding."]
    elif compact:
        lines.append("")
    for item in listed["findings"]:
        context = [f"#{item['report_id']}", as_utc(item["report_created_at"]).date().isoformat()]
        context += [value for value in (item["branch"], item["commit_sha"]) if value]
        finding = FindingPublic.model_validate(item)
        # An expired acceptance is listed as open, as the gate counts it
        finding.status = effective_status(finding.status, finding.status_expires_at)
        if compact:
            location = _finding_location(finding)
            lines.append(
                f"- [{finding.severity.value.upper()}] {finding.title}"
                + (f" - `{location}`" if location else "")
                + f" (#{finding.id}, {finding.status.value})"
            )
        else:
            lines += _finding_markdown(finding, ", ".join(context))
    if listed["total"] > len(listed["findings"]):
        lines += [
            "",
            f"_{listed['total'] - len(listed['findings'])} more findings are not listed here "
            "(SECREVIEW_MAX_LIST_LIMIT): see the web interface or export_sarif._",
        ]
    return "\n".join(lines) + "\n"


def evaluate_gate(
    project: str,
    fail_on: Severity = Severity.HIGH,
    report_id: int | None = None,
) -> dict:
    """Decide whether a project (or one report) passes a security gate.

    The gate fails when at least one finding with status ``open`` has a severity greater than
    or equal to ``fail_on``. A triager unblocks it by marking findings ``fixed``, ``accepted``
    or ``false_positive``; an expired acceptance or false positive blocks again. For the whole
    project, an issue reported again by a later report counts once (its latest occurrence).
    ``expiring_soon`` counts the decisions at or above ``fail_on`` that expire within
    DISMISSAL_EXPIRY_WARNING: the findings that will block again unless decided anew.

    Args:
        project: Project name.
        fail_on: Lowest severity that blocks (default: high).
        report_id: Restrict the check to one report (it must belong to the project).

    Raises:
        NotFoundError: If ``report_id`` does not exist.
        ValueError: If the report belongs to another project.
    """
    project = normalize_project(project)
    threshold = SEVERITY_RANK[fail_on]
    with session_scope() as session:
        statement = (
            select(Finding.severity, func.count())
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(SecurityReport.project == project, _status_is(FindingStatus.OPEN))
        )
        if report_id is not None:
            report = session.get(SecurityReport, report_id)
            if report is None:
                raise NotFoundError(f"Report {report_id} not found")
            if report.project != project:
                raise ValueError(f"Report {report_id} belongs to project '{report.project}'")
            statement = statement.where(Finding.report_id == report_id)
        else:
            statement = statement.where(_current())
        rows = session.exec(statement.group_by(Finding.severity)).all()  # type: ignore[arg-type]
        ranked = [s for s in Severity if SEVERITY_RANK[s] >= threshold]
        expiring = (
            select(func.count())
            .select_from(Finding)
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(
                SecurityReport.project == project,
                _expiring_dismissal(utcnow()),
                col(Finding.severity).in_(ranked),
            )
        )
        expiring = (
            expiring.where(Finding.report_id == report_id)
            if report_id is not None
            else expiring.where(_current())
        )
        expiring_soon = session.exec(expiring).one()

    open_by_severity = {severity.value: 0 for severity in Severity}
    for severity, number in rows:
        open_by_severity[severity.value] = number
    blocking = sum(
        number
        for name, number in open_by_severity.items()
        if SEVERITY_RANK[Severity(name)] >= threshold
    )
    return {
        "project": project,
        "report_id": report_id,
        "fail_on": fail_on.value,
        "passed": blocking == 0,
        "blocking_findings": blocking,
        "open_findings_by_severity": open_by_severity,
        "expiring_soon": expiring_soon,
        "expiry_warning_days": DISMISSAL_EXPIRY_WARNING.days,
    }


def collect_sarif_items(
    report_id: int | None = None,
    project: str | None = None,
) -> tuple[str, list]:
    """Collect the findings to export as SARIF, with their report context.

    Give exactly one of ``report_id`` or ``project``. For a project, the findings of all its
    reports are merged and a finding reported several times is kept once (latest occurrence).

    Returns:
        ``(project_name, items)``.

    Raises:
        ValueError: If both or none of the arguments are given.
        NotFoundError: If the report does not exist.
    """
    from ..sarif import SarifItem, dedupe_latest

    if (report_id is None) == (project is None):
        raise ValueError("Provide exactly one of report_id or project")

    with session_scope() as session:
        statement = select(Finding, SecurityReport).join(
            SecurityReport, col(SecurityReport.id) == col(Finding.report_id)
        )
        if report_id is not None:
            report = session.get(SecurityReport, report_id)
            if report is None:
                raise NotFoundError(f"Report {report_id} not found")
            project = report.project
            statement = statement.where(Finding.report_id == report_id)
        else:
            project = normalize_project(str(project))
            statement = statement.where(SecurityReport.project == project, _current())
        statement = statement.order_by(col(SecurityReport.created_at), col(SecurityReport.id))

        items = [
            SarifItem(
                finding=FindingPublic.model_validate(finding, from_attributes=True),
                report_id=report.id,
                project=report.project,
                repository=report.repository,
                branch=report.branch,
                commit_sha=report.commit_sha,
                created_at=report.created_at,
            )
            for finding, report in session.exec(statement).all()
        ]
    return str(project), (dedupe_latest(items) if report_id is None else items)
