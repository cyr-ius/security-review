"""Projects, their findings, risk acceptances and comments."""

import logging
from collections.abc import Collection, Iterable

from sqlalchemy import case, func, or_
from sqlmodel import col, select

from ...config import get_settings
from ...observability import audit
from ...rules.scanner import redact_secrets
from ...storage.database import session_scope
from ...storage.models import (
    MAX_COMMENT_CHARS,
    SEVERITY_RANK,
    Finding,
    FindingComment,
    FindingCommentPublic,
    FindingPublic,
    FindingStatus,
    ReviewType,
    SecurityReport,
    Severity,
    as_utc,
    effective_status,
    utcnow,
)
from ...storage.project_names import normalize_project
from .core import (
    DISMISSAL_EXPIRY_WARNING,
    NotFoundError,
    _check_current,
    _current,
    _status_is,
    _values,
    compute_risk_level,
)
from .persistence import _contains_pattern

logger = logging.getLogger("security_review_mcp.services")


def list_projects(known: Iterable[str] = ()) -> list[dict]:
    """List the projects that have reports, with their open findings by severity, and the
    ``known`` projects without any report yet.

    Sorted by the date of the latest report, most recent first; projects without a report last.
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
            .where(_status_is(FindingStatus.OPEN), _current())
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
    with_reports = {item["project"] for item in projects}
    projects.sort(key=lambda p: p["last_report_at"], reverse=True)
    projects.extend(
        {
            "project": name,
            "reports_total": 0,
            "last_report_at": None,
            "open_findings_total": 0,
            "open_findings_by_severity": {severity.value: 0 for severity in Severity},
            "worst_open_severity": None,
        }
        for name in sorted(set(known) - with_reports)
    )
    return projects


def project_posture(project: str) -> dict:
    """Summarize open findings of a project across all its reports (useful as a CI gate).

    An issue reported again by a later report counts once (its latest occurrence)."""
    project = normalize_project(project)
    with session_scope() as session:
        rows = session.exec(
            select(Finding.severity, func.count())
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(SecurityReport.project == project, _status_is(FindingStatus.OPEN), _current())
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
    project: str | None,
    status: FindingStatus | Collection[FindingStatus] | None = FindingStatus.OPEN,
    severity: Severity | Collection[Severity] | None = None,
    limit: int = 100,
    offset: int = 0,
    review_type: ReviewType | Collection[ReviewType] | None = None,
    projects: Collection[str] | None = None,
    search: str | None = None,
    report_id: int | None = None,
    proposed: bool = False,
) -> dict:
    """List the findings of a project (or of every project) across all reports, for a review.

    An issue reported again by a later report is listed once (its latest occurrence).
    Worst severity first, then newest report first. ``limit`` is capped by
    SECREVIEW_MAX_LIST_LIMIT; ``total`` counts every matching finding, for paging. Each finding
    carries the project, branch, commit, review type and date of its report; ``review_type``
    keeps only the findings of the reports of that type. ``status``, ``severity`` and
    ``review_type`` take one value or several (any of them matches; no status: open). ``project``
    None lists every project;
    ``projects`` (the scope of a restricted caller) keeps only the findings of these projects.
    ``search`` keeps the findings whose title, rule, CWE, file, description, project or branch
    contains it (case-insensitive, first 200 characters). ``report_id`` keeps the findings of
    that report; ``proposed`` keeps the findings carrying a status proposed by an agent.
    """
    settings = get_settings()
    limit = max(1, min(limit, settings.max_list_limit))
    offset = max(0, offset)
    statuses = _values(status) or [FindingStatus.OPEN]
    now = utcnow()
    filters = [or_(*(_status_is(s, now) for s in statuses)), _current()]
    if project is not None:
        filters.append(SecurityReport.project == normalize_project(project))
    if projects is not None:
        filters.append(col(SecurityReport.project).in_(list(projects)))
    if severities := _values(severity):
        filters.append(col(Finding.severity).in_(severities))
    if types := _values(review_type):
        filters.append(col(SecurityReport.review_type).in_(types))
    if report_id is not None:
        filters.append(Finding.report_id == report_id)
    if proposed:
        filters.append(col(Finding.proposed_status).is_not(None))
    if search and search.strip():
        pattern = _contains_pattern(search.strip())
        searched = [
            Finding.title,
            Finding.rule_id,
            Finding.cwe,
            Finding.file_path,
            Finding.description,
            SecurityReport.project,
            SecurityReport.branch,
        ]
        filters.append(or_(*(col(column).ilike(pattern, escape="\\") for column in searched)))
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
        findings = [_project_finding(finding, report) for finding, report in rows]
    return {"project": project, "total": total, "findings": findings}


def _project_finding(finding: Finding, report: SecurityReport) -> dict:
    """A finding with the context of its report (project, branch, commit, review type, date)."""
    return {
        **FindingPublic.model_validate(finding, from_attributes=True).model_dump(),
        "project": report.project,
        "branch": report.branch,
        "commit_sha": report.commit_sha,
        "review_type": report.review_type,
        "report_created_at": report.created_at,
    }


def get_project_finding(finding_id: int, projects: Collection[str] | None = None) -> dict:
    """Return one finding with the context of its report.

    ``projects`` (the scope of a restricted caller) hides the findings of other projects, with
    the error of a missing finding.

    Raises:
        NotFoundError: If the finding does not exist or is outside ``projects``.
    """
    with session_scope() as session:
        row = session.exec(
            select(Finding, SecurityReport)
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(Finding.id == finding_id)
        ).first()
        if row is None or (projects is not None and row[1].project not in projects):
            raise NotFoundError(f"Finding {finding_id} not found")
        return _project_finding(*row)


def list_risk_acceptances(
    project: str | None,
    projects: Collection[str] | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict:
    """List the accepted risks of a project (or of every project), expired ones included.

    Nearest expiry first, the acceptances without expiry date last. Each acceptance carries the
    context of its report, ``expired`` (it counts as open again), ``expiring_soon`` (it expires
    within DISMISSAL_EXPIRY_WARNING) and its number of comments.
    ``limit`` is capped by SECREVIEW_MAX_LIST_LIMIT; ``total`` counts every acceptance, for
    paging.
    ``projects`` (the scope of a restricted caller) keeps only the acceptances of these projects.
    """
    settings = get_settings()
    limit = max(1, min(limit or settings.max_list_limit, settings.max_list_limit))
    offset = max(0, offset)
    filters = [Finding.status == FindingStatus.ACCEPTED, _current()]
    if project is not None:
        filters.append(SecurityReport.project == normalize_project(project))
    if projects is not None:
        filters.append(col(SecurityReport.project).in_(list(projects)))
    comments = (
        select(func.count())
        .select_from(FindingComment)
        .where(FindingComment.finding_id == Finding.id)
        .scalar_subquery()
    )
    now = utcnow()
    with session_scope() as session:
        total = session.exec(
            select(func.count())
            .select_from(Finding)
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(*filters)
        ).one()
        rows = session.exec(
            select(Finding, SecurityReport, comments)
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(*filters)
            .order_by(
                col(Finding.status_expires_at).is_(None),
                col(Finding.status_expires_at),
                col(Finding.id),
            )
            .offset(offset)
            .limit(limit)
        ).all()
        acceptances = [
            {
                **FindingPublic.model_validate(finding, from_attributes=True).model_dump(),
                "project": report.project,
                "branch": report.branch,
                "commit_sha": report.commit_sha,
                "review_type": report.review_type,
                "report_created_at": report.created_at,
                "expired": effective_status(finding.status, finding.status_expires_at, now)
                == FindingStatus.OPEN,
                "expiring_soon": finding.status_expires_at is not None
                and now < as_utc(finding.status_expires_at) <= now + DISMISSAL_EXPIRY_WARNING,
                "comments_total": comment_count,
            }
            for finding, report, comment_count in rows
        ]
    return {"project": project, "total": total, "acceptances": acceptances}


def list_finding_comments(finding_id: int) -> list[FindingCommentPublic]:
    """Return the comments of a finding, oldest first.

    Raises:
        NotFoundError: If the finding does not exist.
    """
    with session_scope() as session:
        if session.get(Finding, finding_id) is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        rows = session.exec(
            select(FindingComment)
            .where(FindingComment.finding_id == finding_id)
            .order_by(col(FindingComment.created_at), col(FindingComment.id))
        ).all()
        return [FindingCommentPublic.model_validate(row, from_attributes=True) for row in rows]


def add_finding_comment(
    finding_id: int, author: str, body: str, actor: str | None = None
) -> FindingCommentPublic:
    """Add the comment of a person to a finding; secrets in the text are masked.

    Comments are append-only: nothing edits or deletes one. The comment is written to the
    audit log (``actor``, default the author).

    Raises:
        NotFoundError: If the finding does not exist.
        ValueError: If the author is missing or the text is empty or too long.
    """
    author = author.strip()
    if not author:
        raise ValueError("An author is required")
    body = body.strip()
    if not body:
        raise ValueError("The comment is empty")
    if len(body) > MAX_COMMENT_CHARS:
        raise ValueError(f"The comment must have at most {MAX_COMMENT_CHARS} characters")
    # The mask of a secret may be longer than the secret: keep the size of the column
    body = redact_secrets(body)[:MAX_COMMENT_CHARS]
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        _check_current(finding)
        comment = FindingComment(finding_id=finding_id, author=author[:200], body=body)
        session.add(comment)
        audit.record(
            session,
            audit.AuditAction.FINDING_COMMENTED,
            actor or author,
            "finding",
            finding_id,
            finding.report.project,
            {"comment": body},
        )
        session.flush()
        logger.info("Comment added to finding %s", finding_id)
        return FindingCommentPublic.model_validate(comment, from_attributes=True)
