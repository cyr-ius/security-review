"""Report persistence service (business logic between MCP tools and the database)."""

import logging
from collections import Counter
from collections.abc import Collection
from datetime import timedelta

from sqlalchemy import case, func
from sqlalchemy.orm import selectinload
from sqlmodel import col, select

from .config import MAX_RETENTION_DAYS, get_settings
from .database import session_scope
from .models import (
    SEVERITY_RANK,
    Finding,
    FindingCreate,
    FindingPublic,
    FindingStatus,
    ReviewType,
    SecurityReport,
    SecurityReportPublic,
    Severity,
    utcnow,
)
from .scanner import redact_secrets

logger = logging.getLogger(__name__)


class NotFoundError(LookupError):
    """Raised when a report or a finding does not exist."""


def compute_risk_level(severities: list[Severity], override: Severity | None = None) -> Severity:
    """Return the overall risk: the highest finding severity (an override can only raise it)."""
    computed = max(severities, key=lambda s: SEVERITY_RANK[s], default=Severity.INFO)
    if override is not None and SEVERITY_RANK[override] > SEVERITY_RANK[computed]:
        return override
    return computed


def _sanitize_finding(data: FindingCreate) -> Finding:
    """Build a Finding row, masking secrets that may appear in free-text fields."""
    values = data.model_dump()
    for field in ("description", "evidence", "recommendation"):
        if values.get(field):
            values[field] = redact_secrets(values[field])
    if values["line_start"] and values["line_end"] and values["line_end"] < values["line_start"]:
        values["line_end"] = values["line_start"]
    return Finding(**values)


def save_report(
    project: str,
    summary: str,
    findings: list[FindingCreate],
    repository: str | None = None,
    branch: str | None = None,
    commit_sha: str | None = None,
    reviewer: str | None = None,
    scope: str | None = None,
    risk_level: Severity | None = None,
    review_type: ReviewType | None = None,
) -> dict:
    """Persist a security report and its findings.

    Args:
        project: Project name (used to group reports).
        summary: Executive summary.
        findings: Findings to store (may be empty for a clean review).
        repository: Repository URL or path.
        branch: Reviewed branch.
        commit_sha: Reviewed commit.
        reviewer: Agent or person who performed the review.
        scope: Description of what was reviewed.
        risk_level: Optional override; it can only raise the computed risk.
        review_type: Kind of review (the prompt used or the CLI scan).

    Returns:
        Identifier, risk level and finding counts of the stored report.

    Raises:
        ValueError: If the report contains too many findings or an unknown review type.
    """
    settings = get_settings()
    review_type = ReviewType(review_type) if review_type else None
    project = project.strip()
    summary = summary.strip()
    if not project:
        raise ValueError("project must not be empty")
    if len(summary) < 3:
        raise ValueError("summary must contain at least 3 characters")
    if len(findings) > settings.max_findings_per_report:
        raise ValueError(
            f"Too many findings ({len(findings)}); the limit is {settings.max_findings_per_report}"
        )

    rows = [_sanitize_finding(item) for item in findings]
    risk = compute_risk_level([row.severity for row in rows], risk_level)

    with session_scope() as session:
        report = SecurityReport(
            project=project,
            repository=repository,
            branch=branch,
            commit_sha=commit_sha,
            reviewer=reviewer,
            scope=scope,
            review_type=review_type,
            summary=redact_secrets(summary),
            risk_level=risk,
            findings=rows,
        )
        session.add(report)
        session.flush()  # assigns ids before the commit
        result = {
            "report_id": report.id,
            "project": report.project,
            "review_type": review_type.value if review_type else None,
            "risk_level": risk.value,
            "findings_count": len(rows),
            "findings_by_severity": dict(Counter(row.severity.value for row in rows)),
        }
    logger.info("Report saved: id=%s project=%s risk=%s", result["report_id"], project, risk)
    return result


def get_report(report_id: int) -> SecurityReportPublic:
    """Return a report with its findings.

    Raises:
        NotFoundError: If the report does not exist.
    """
    with session_scope() as session:
        report = session.exec(
            select(SecurityReport)
            .where(SecurityReport.id == report_id)
            .options(selectinload(SecurityReport.findings))  # type: ignore[arg-type]
        ).first()
        if report is None:
            raise NotFoundError(f"Report {report_id} not found")
        return SecurityReportPublic.model_validate(report, from_attributes=True)


def list_reports(
    project: str | None = None,
    risk_level: Severity | None = None,
    limit: int = 20,
    offset: int = 0,
    projects: Collection[str] | None = None,
    review_type: ReviewType | None = None,
) -> list[dict]:
    """List reports, newest first, with their number of open findings.

    ``projects`` (the scope of a restricted caller) keeps only the reports of these projects.
    """
    settings = get_settings()
    limit = max(1, min(limit, settings.max_list_limit))
    offset = max(0, offset)

    with session_scope() as session:
        statement = select(SecurityReport)
        if project:
            statement = statement.where(SecurityReport.project == project)
        if projects is not None:
            statement = statement.where(col(SecurityReport.project).in_(list(projects)))
        if risk_level:
            statement = statement.where(SecurityReport.risk_level == risk_level)
        if review_type:
            statement = statement.where(SecurityReport.review_type == review_type)
        statement = (
            statement.order_by(col(SecurityReport.created_at).desc(), col(SecurityReport.id).desc())
            .offset(offset)
            .limit(limit)
        )
        reports = session.exec(statement).all()
        ids = [r.id for r in reports if r.id is not None]

        # One query for all the counters (avoids N+1)
        counts: dict[int, dict[str, int]] = {i: {"total": 0, "open": 0} for i in ids}
        if ids:
            rows = session.exec(
                select(Finding.report_id, Finding.status, func.count())
                .where(col(Finding.report_id).in_(ids))
                .group_by(Finding.report_id, Finding.status)  # type: ignore[arg-type]
            ).all()
            for report_id, status, number in rows:
                counts[report_id]["total"] += number
                if status == FindingStatus.OPEN:
                    counts[report_id]["open"] += number

        return [
            {
                "report_id": r.id,
                "project": r.project,
                "branch": r.branch,
                "commit_sha": r.commit_sha,
                "review_type": r.review_type,
                "risk_level": r.risk_level.value,
                "reviewer": r.reviewer,
                "created_at": r.created_at.isoformat(),
                "findings_total": counts[r.id]["total"],
                "findings_open": counts[r.id]["open"],
                "summary": r.summary[:200],
            }
            for r in reports
        ]


def update_finding_status(finding_id: int, status: FindingStatus) -> FindingPublic:
    """Change the status of a finding (e.g. after a fix or a triage decision).

    Raises:
        NotFoundError: If the finding does not exist.
    """
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        if finding.status != status:
            finding.status = status
            finding.status_changed_at = utcnow()
        session.add(finding)
        session.flush()
        logger.info("Finding %s set to %s", finding_id, status)
        return FindingPublic.model_validate(finding, from_attributes=True)


def list_projects() -> list[dict]:
    """List the projects that have reports, with their open findings by severity.

    Sorted by the date of the latest report, most recent first.
    """
    with session_scope() as session:
        report_rows = session.exec(
            select(
                SecurityReport.project,
                func.count(),
                func.max(SecurityReport.created_at),
            ).group_by(SecurityReport.project)  # type: ignore[arg-type]
        ).all()
        finding_rows = session.exec(
            select(SecurityReport.project, Finding.severity, func.count())
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(Finding.status == FindingStatus.OPEN)
            .group_by(SecurityReport.project, Finding.severity)  # type: ignore[arg-type]
        ).all()

    open_counts: dict[str, dict[str, int]] = {
        name: {severity.value: 0 for severity in Severity} for name, _, _ in report_rows
    }
    for name, severity, number in finding_rows:
        open_counts[name][severity.value] = number

    projects = []
    for name, reports_total, last_report_at in report_rows:
        by_severity = open_counts[name]
        open_total = sum(by_severity.values())
        worst = compute_risk_level([Severity(k) for k, v in by_severity.items() if v > 0])
        projects.append(
            {
                "project": name,
                "reports_total": reports_total,
                "last_report_at": last_report_at.isoformat(),
                "open_findings_total": open_total,
                "open_findings_by_severity": by_severity,
                "worst_open_severity": worst.value if open_total else None,
            }
        )
    projects.sort(key=lambda p: p["last_report_at"], reverse=True)
    return projects


def project_posture(project: str) -> dict:
    """Summarize open findings of a project across all its reports (useful as a CI gate)."""
    with session_scope() as session:
        rows = session.exec(
            select(Finding.severity, func.count())
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(SecurityReport.project == project, Finding.status == FindingStatus.OPEN)
            .group_by(Finding.severity)  # type: ignore[arg-type]
        ).all()
        reports_total = session.exec(
            select(func.count())
            .select_from(SecurityReport)
            .where(SecurityReport.project == project)
        ).one()

    by_severity = {severity.value: 0 for severity in Severity}
    for severity, number in rows:
        by_severity[severity.value] = number
    open_total = sum(by_severity.values())
    worst = compute_risk_level([Severity(k) for k, v in by_severity.items() if v > 0])
    return {
        "project": project,
        "reports_total": reports_total,
        "open_findings_total": open_total,
        "open_findings_by_severity": by_severity,
        "worst_open_severity": worst.value if open_total else None,
    }


def list_project_findings(
    project: str,
    status: FindingStatus = FindingStatus.OPEN,
    severity: Severity | None = None,
    limit: int = 100,
    offset: int = 0,
    review_type: ReviewType | None = None,
) -> dict:
    """List the findings of a project across all its reports, for an expert review.

    Worst severity first, then newest report first. ``limit`` is capped by
    SECREVIEW_MAX_LIST_LIMIT; ``total`` counts every matching finding, for paging. Each finding
    carries the branch, commit, review type and date of its report; ``review_type`` keeps only
    the findings of the reports of that type.
    """
    settings = get_settings()
    limit = max(1, min(limit, settings.max_list_limit))
    offset = max(0, offset)
    filters = [SecurityReport.project == project, Finding.status == status]
    if severity is not None:
        filters.append(Finding.severity == severity)
    if review_type is not None:
        filters.append(SecurityReport.review_type == review_type)
    rank = case(*((Finding.severity == s, r) for s, r in SEVERITY_RANK.items()), else_=0)

    with session_scope() as session:
        total = session.exec(
            select(func.count())
            .select_from(Finding)
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(*filters)
        ).one()
        rows = session.exec(
            select(Finding, SecurityReport)
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(*filters)
            .order_by(rank.desc(), col(SecurityReport.created_at).desc(), col(Finding.id).desc())
            .offset(offset)
            .limit(limit)
        ).all()
        findings = [
            {
                **FindingPublic.model_validate(finding, from_attributes=True).model_dump(),
                "branch": report.branch,
                "commit_sha": report.commit_sha,
                "review_type": report.review_type,
                "report_created_at": report.created_at,
            }
            for finding, report in rows
        ]
    return {"project": project, "total": total, "findings": findings}


def prune_empty_reports(retention_days: int | None = None) -> dict:
    """Delete the reports without any finding created more than ``retention_days`` days ago.

    The latest report of each project is kept, so a project never disappears. Defaults to
    SECREVIEW_EMPTY_REPORT_RETENTION_DAYS; 0 disables the purge.

    Raises:
        ValueError: If ``retention_days`` is negative or above MAX_RETENTION_DAYS.
    """
    days = get_settings().empty_report_retention_days if retention_days is None else retention_days
    if not 0 <= days <= MAX_RETENTION_DAYS:
        raise ValueError(f"retention_days must be between 0 and {MAX_RETENTION_DAYS}")
    if days == 0:
        return {"retention_days": 0, "deleted": 0}
    cutoff = utcnow() - timedelta(days=days)

    with session_scope() as session:
        latest = (
            select(func.max(SecurityReport.id))
            .group_by(SecurityReport.project)  # type: ignore[arg-type]
            .scalar_subquery()
        )
        with_findings = select(Finding.report_id).distinct().scalar_subquery()
        reports = session.exec(
            select(SecurityReport).where(
                col(SecurityReport.created_at) < cutoff,
                col(SecurityReport.id).not_in(with_findings),
                col(SecurityReport.id).not_in(latest),
            )
        ).all()
        for report in reports:
            session.delete(report)
        deleted = len(reports)
    if deleted:
        logger.info("Deleted %d reports without findings older than %d days", deleted, days)
    return {"retention_days": days, "deleted": deleted}


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
        ("Scope", report.scope),
    ):
        if value:
            lines.append(f"- **{label}**: {value}")
    lines += ["", "## Summary", "", report.summary, "", f"## Findings ({len(report.findings)})"]

    ordered = sorted(report.findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.id))
    if not ordered:
        lines += ["", "No finding recorded."]
    for finding in ordered:
        location = ""
        if finding.file_path:
            location = finding.file_path
            if finding.line_start:
                location += f":{finding.line_start}"
                if finding.line_end and finding.line_end != finding.line_start:
                    location += f"-{finding.line_end}"
        refs = ", ".join(x for x in (finding.cwe, finding.owasp) if x)
        lines += [
            "",
            f"### [{finding.severity.value.upper()}] {finding.title} (#{finding.id}, "
            f"{finding.status.value})",
        ]
        if location:
            lines.append(f"- **Location**: `{location}`")
        if refs:
            lines.append(f"- **References**: {refs}")
        lines += ["", finding.description]
        if finding.evidence:
            lines += ["", "```", finding.evidence, "```"]
        if finding.recommendation:
            lines += ["", f"**Recommendation**: {finding.recommendation}"]
    return "\n".join(lines) + "\n"


def evaluate_gate(
    project: str,
    fail_on: Severity = Severity.HIGH,
    report_id: int | None = None,
) -> dict:
    """Decide whether a project (or one report) passes a security gate.

    The gate fails when at least one finding with status ``open`` has a severity greater than
    or equal to ``fail_on``. Mark findings ``fixed``, ``accepted`` or ``false_positive`` to
    unblock it.

    Args:
        project: Project name.
        fail_on: Lowest severity that blocks (default: high).
        report_id: Restrict the check to one report (it must belong to the project).

    Raises:
        NotFoundError: If ``report_id`` does not exist.
        ValueError: If the report belongs to another project.
    """
    threshold = SEVERITY_RANK[fail_on]
    with session_scope() as session:
        statement = (
            select(Finding.severity, func.count())
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(SecurityReport.project == project, Finding.status == FindingStatus.OPEN)
        )
        if report_id is not None:
            report = session.get(SecurityReport, report_id)
            if report is None:
                raise NotFoundError(f"Report {report_id} not found")
            if report.project != project:
                raise ValueError(f"Report {report_id} belongs to project '{report.project}'")
            statement = statement.where(Finding.report_id == report_id)
        rows = session.exec(statement.group_by(Finding.severity)).all()  # type: ignore[arg-type]

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
    }


def collect_sarif_items(
    report_id: int | None = None,
    project: str | None = None,
) -> tuple[str, list]:
    """Collect the findings to export as SARIF, with their report context.

    Give exactly one of ``report_id`` or ``project``. For a project, the findings of all its
    reports are merged and a finding reported several times is kept once (latest report).

    Returns:
        ``(project_name, items)``.

    Raises:
        ValueError: If both or none of the arguments are given.
        NotFoundError: If the report does not exist.
    """
    from .sarif import SarifItem, dedupe_latest

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
            statement = statement.where(SecurityReport.project == project)
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


# ── Project scope of a caller ────────────────────────────────────────────────


def report_project(report_id: int) -> str:
    """Return the project of a report.

    Raises:
        NotFoundError: If the report does not exist.
    """
    with session_scope() as session:
        report = session.get(SecurityReport, report_id)
        if report is None:
            raise NotFoundError(f"Report {report_id} not found")
        return report.project


def finding_project(finding_id: int) -> str:
    """Return the project of the report that holds a finding.

    Raises:
        NotFoundError: If the finding does not exist.
    """
    with session_scope() as session:
        project = session.exec(
            select(SecurityReport.project)
            .join(Finding, col(Finding.report_id) == col(SecurityReport.id))
            .where(Finding.id == finding_id)
        ).first()
        if project is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        return project


def check_project_scope(allowed: Collection[str] | None, project: str) -> None:
    """Refuse a project outside the scope of a project-restricted caller.

    ``allowed`` holds the projects of the caller's token (None: no restriction). The error is
    the same as for a missing project, so a restricted caller cannot learn which projects exist.

    Raises:
        NotFoundError: If ``allowed`` is set and does not contain ``project``.
    """
    if allowed is not None and project not in allowed:
        raise NotFoundError(f"Project '{project}' not found")


def check_report_scope(allowed: Collection[str] | None, report_id: int) -> None:
    """Refuse a report outside the scope of a project-restricted caller (as if missing)."""
    if allowed is not None and report_project(report_id) not in allowed:
        raise NotFoundError(f"Report {report_id} not found")


def check_finding_scope(allowed: Collection[str] | None, finding_id: int) -> None:
    """Refuse a finding outside the scope of a project-restricted caller (as if missing)."""
    if allowed is not None and finding_project(finding_id) not in allowed:
        raise NotFoundError(f"Finding {finding_id} not found")
