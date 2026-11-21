"""Saving, reading and pruning of the security reports."""

import json
import logging
from collections import Counter
from collections.abc import Collection
from datetime import datetime, timedelta
from typing import Literal

from sqlalchemy import and_, case, func, or_, update
from sqlalchemy.orm import selectinload
from sqlmodel import Session, col, select

from ...config import MAX_RETENTION_DAYS, get_settings
from ...rules.scanner import sanitize_untrusted
from ...storage.database import session_scope
from ...storage.models import (
    DISMISSED_STATUSES,
    MAX_BRANCH_CHARS,
    MAX_COMMIT_SHA_CHARS,
    MAX_REPOSITORY_CHARS,
    MAX_REVIEWER_CHARS,
    SEVERITY_RANK,
    ChecklistResult,
    Finding,
    FindingComment,
    FindingCreate,
    FindingStatus,
    ReviewType,
    SecurityReport,
    SecurityReportPublic,
    Severity,
    effective_status,
    utcnow,
)
from ...storage.project_names import normalize_project
from ...storage.projects import ensure_project
from .. import coverage
from ..sarif import issue_fingerprint
from .core import (
    NotFoundError,
    _check_author,
    _check_lengths,
    _current,
    _status_is,
    _values,
    compute_risk_level,
)

logger = logging.getLogger("security_review_mcp.services")


def _sanitize_finding(data: FindingCreate, limit: int) -> Finding:
    """Build a Finding row, masking secrets and revealing hidden characters in free text.

    A revealed character takes up to 9 characters: the text is cut again at ``limit``.
    """
    values = data.model_dump()
    for field in ("description", "evidence", "recommendation"):
        if values.get(field):
            values[field] = sanitize_untrusted(values[field])[:limit]
    if values["line_start"] and values["line_end"] and values["line_end"] < values["line_start"]:
        values["line_end"] = values["line_start"]
    return Finding(**values)


def _carry_over(previous: Finding, first_seen: datetime, row: Finding, now: datetime) -> bool:
    """Carry what people decided on an occurrence of an issue to its new occurrence.

    A pending acceptance or false positive is carried with its reason, approver and expiry
    date, as is a proposal of one of them and a severity raised above the one of the new
    report. A fixed issue that comes back is open, seen for the first time again. Return True
    when a decision was carried.
    """
    status = effective_status(previous.status, previous.status_expires_at, now)
    row.first_seen_at = None if status == FindingStatus.FIXED else first_seen
    if previous.original_severity is not None and (
        SEVERITY_RANK[previous.severity] > SEVERITY_RANK[row.severity]
    ):
        row.original_severity = row.severity
        row.severity = previous.severity
        row.severity_reason = previous.severity_reason
        row.severity_changed_by = previous.severity_changed_by
        row.severity_changed_at = previous.severity_changed_at
    if previous.proposed_status in DISMISSED_STATUSES and status == FindingStatus.OPEN:
        row.proposed_status = previous.proposed_status
        row.proposed_reason = previous.proposed_reason
        row.proposed_by = previous.proposed_by
        row.proposed_at = previous.proposed_at
    if status not in DISMISSED_STATUSES:
        return False
    row.status = previous.status
    row.status_changed_at = previous.status_changed_at
    row.status_reason = previous.status_reason
    row.status_approver = previous.status_approver
    row.status_expires_at = previous.status_expires_at
    return True


def _match_occurrences(
    session: Session, project: str, rows: list[Finding], now: datetime
) -> tuple[list[tuple[Finding, Finding]], int, int]:
    """Pair the findings of a new report with the current occurrences of the same issues.

    A rule may match several lines of a file: occurrences of one fingerprint are paired in line
    order when their number is unchanged (the code moved), else only on the same line, so that
    a new occurrence never inherits the decision taken on another one. A current occurrence
    left unpaired is replaced, without carry, by the first new one. Return the (previous, new)
    pairs, the number of new findings paired and the number of decisions carried.
    """
    reported: dict[str, list[Finding]] = {}
    for row in rows:
        row.fingerprint = issue_fingerprint(project, row)
        reported.setdefault(row.fingerprint, []).append(row)
    if not reported:
        return [], 0, 0
    current: dict[str, list[tuple[Finding, datetime]]] = {}
    for previous, created_at in session.exec(
        select(Finding, SecurityReport.created_at)
        .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
        .where(
            SecurityReport.project == project,
            col(Finding.fingerprint).in_(list(reported)),
            _current(),
        )
        .order_by(col(Finding.line_start).is_(None), col(Finding.line_start), col(Finding.id))
    ).all():
        current.setdefault(str(previous.fingerprint), []).append((previous, created_at))

    pairs: list[tuple[Finding, Finding]] = []
    recurring = carried = 0
    for digest, previous_rows in current.items():
        new_rows = sorted(
            reported[digest], key=lambda row: (row.line_start is None, row.line_start or 0)
        )
        if len(new_rows) == len(previous_rows):
            matched = dict(enumerate(new_rows))
        else:
            by_line = {row.line_start: row for row in reversed(new_rows) if row.line_start}
            matched = {}
            for index, (previous, _created_at) in enumerate(previous_rows):
                row = by_line.pop(previous.line_start, None) if previous.line_start else None
                if row is not None:
                    matched[index] = row
        for index, (previous, created_at) in enumerate(previous_rows):
            row = matched.get(index)
            if row is not None:
                recurring += 1
                first_seen = previous.first_seen_at or created_at
                carried += _carry_over(previous, first_seen, row, now)
            pairs.append((previous, row or new_rows[0]))
    return pairs, recurring, carried


def _supersede(session: Session, pairs: list[tuple[Finding, Finding]]) -> None:
    """Point the replaced occurrences (and those they replaced) to the new ones and move
    their comments, which are about the issue."""
    for previous, row in pairs:
        session.exec(
            update(Finding)
            .where(col(Finding.superseded_by) == previous.id)
            .values(superseded_by=row.id)
        )
        session.exec(
            update(FindingComment)
            .where(col(FindingComment.finding_id) == previous.id)
            .values(finding_id=row.id)
        )
        previous.superseded_by = row.id
        session.add(previous)


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
    author: str | None = None,
    submitted_by: str | None = None,
    checklist_results: list[ChecklistResult] | None = None,
    scan_rules: list[str] | None = None,
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
        author: Username of the developer: the user of a personal token, else declared by the
            client (not authenticated).
        submitted_by: Label of the token that saved the report (set by the server).
        checklist_results: Checklist items walked through by the reviewer, with their
            outcome; None for a report without declared coverage (CLI scans).
        scan_rules: Rules that raised scan_code leads, confirmed or not.

    Returns:
        Identifier, risk level and finding counts of the stored report; with declared
        coverage, also its counts, the uncovered checklist items and the warnings.

    Raises:
        ValueError: If the report contains too many findings, a field longer than its column
            or a text longer than SECREVIEW_MAX_CONTENT_CHARS, an unknown review type or an
            invalid author.
    """
    settings = get_settings()
    review_type = ReviewType(review_type) if review_type else None
    project = normalize_project(project)
    summary = summary.strip()
    if len(summary) < 3:
        raise ValueError("summary must contain at least 3 characters")
    if len(findings) > settings.max_findings_per_report:
        raise ValueError(
            f"Too many findings ({len(findings)}); the limit is {settings.max_findings_per_report}"
        )
    content = settings.max_content_chars
    _check_lengths(
        ("repository", repository, MAX_REPOSITORY_CHARS),
        ("branch", branch, MAX_BRANCH_CHARS),
        ("commit_sha", commit_sha, MAX_COMMIT_SHA_CHARS),
        ("reviewer", reviewer, MAX_REVIEWER_CHARS),
        ("summary", summary, content),
        ("scope", scope, content),
        *(
            (f"findings[{index}].{name}", getattr(item, name), content)
            for index, item in enumerate(findings)
            for name in ("description", "evidence", "recommendation")
        ),
    )
    author = _check_author(author)
    declared = None
    if checklist_results is not None or scan_rules is not None:
        declared = coverage.check(checklist_results or [], scan_rules or [], findings)

    rows = [_sanitize_finding(item, content) for item in findings]
    now = utcnow()

    with session_scope() as session:
        ensure_project(session, project, submitted_by)
        pairs, recurring, carried = _match_occurrences(session, project, rows, now)
        risk = compute_risk_level([row.severity for row in rows], risk_level)
        report = SecurityReport(
            project=project,
            repository=repository,
            branch=branch,
            commit_sha=commit_sha,
            reviewer=reviewer,
            scope=scope,
            review_type=review_type,
            author=author,
            submitted_by=submitted_by,
            summary=sanitize_untrusted(summary)[:content],
            risk_level=risk,
            findings=rows,
            created_at=now,
        )
        for row in rows:
            row.first_seen_at = row.first_seen_at or now
        if declared is not None:
            report.checklist_results = json.dumps([r.model_dump() for r in declared.checklist])
            report.scan_rules = json.dumps(declared.scan_rules)
        session.add(report)
        session.flush()  # assigns ids before the commit
        _supersede(session, pairs)
        result = {
            "report_id": report.id,
            "project": report.project,
            "review_type": review_type.value if review_type else None,
            "author": author,
            "risk_level": risk.value,
            "findings_count": len(rows),
            "findings_by_severity": dict(Counter(row.severity.value for row in rows)),
            "recurring_findings": recurring,
            "carried_decisions": carried,
        }
        if declared is not None:
            result["coverage"] = {
                "checklist_by_outcome": dict(Counter(r.outcome.value for r in declared.checklist)),
                "not_covered": declared.not_covered,
                "scan_rules": len(declared.scan_rules),
            }
            result["warnings"] = declared.warnings
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


def _contains_pattern(search: str) -> str:
    """ILIKE pattern matching ``search`` anywhere (first 200 characters, wildcards escaped)."""
    escaped = search[:200].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def list_reports(
    project: str | Collection[str] | None = None,
    risk_level: Severity | Collection[Severity] | None = None,
    limit: int = 20,
    offset: int = 0,
    projects: Collection[str] | None = None,
    review_type: ReviewType | Collection[ReviewType] | None = None,
    author: str | None = None,
    search: str | None = None,
    sort_by: Literal[
        "created_at",
        "project",
        "risk_level",
        "review_type",
        "branch",
        "author",
        "submitted_by",
        "summary",
    ] = "created_at",
    sort_direction: Literal["asc", "desc"] = "desc",
    with_author: bool = True,
) -> list[dict]:
    """List reports, newest first, with their number of open findings.

    ``project``, ``risk_level`` and ``review_type`` take one value or several (any of them
    matches); ``projects`` (the scope of a restricted caller) keeps only the reports of these
    projects; ``author`` keeps only the reports declared for this developer username. Without
    ``with_author``, the author is neither returned nor used to filter, search or sort (the
    caller cannot guess it from the order of the results).
    """
    settings = get_settings()
    limit = max(1, min(limit, settings.max_list_limit))
    offset = max(0, offset)
    if not with_author:
        author = None
        if sort_by == "author":
            sort_by = "submitted_by"

    with session_scope() as session:
        statement = select(SecurityReport)
        if names := [normalize_project(name) for name in _values(project) if name]:
            statement = statement.where(col(SecurityReport.project).in_(names))
        if projects is not None:
            statement = statement.where(col(SecurityReport.project).in_(list(projects)))
        if levels := _values(risk_level):
            statement = statement.where(col(SecurityReport.risk_level).in_(levels))
        if types := _values(review_type):
            statement = statement.where(col(SecurityReport.review_type).in_(types))
        if author:
            statement = statement.where(SecurityReport.author == author)
        if search:
            pattern = _contains_pattern(search)
            searched = [
                SecurityReport.project,
                SecurityReport.branch,
                SecurityReport.commit_sha,
                SecurityReport.reviewer,
                SecurityReport.submitted_by,
                SecurityReport.summary,
            ]
            if with_author:
                searched.append(SecurityReport.author)
            statement = statement.where(
                or_(*(col(column).ilike(pattern, escape="\\") for column in searched))
            )
        sort_columns = {
            "created_at": col(SecurityReport.created_at),
            "project": col(SecurityReport.project),
            "risk_level": col(SecurityReport.risk_level),
            "review_type": col(SecurityReport.review_type),
            "branch": col(SecurityReport.branch),
            "author": col(SecurityReport.author),
            "submitted_by": col(SecurityReport.submitted_by),
            "summary": col(SecurityReport.summary),
        }
        sort_column = sort_columns[sort_by]
        primary_order = sort_column.asc() if sort_direction == "asc" else sort_column.desc()
        statement = statement.order_by(primary_order, col(SecurityReport.id).desc())
        statement = statement.offset(offset).limit(limit)
        reports = session.exec(statement).all()
        ids = [r.id for r in reports if r.id is not None]

        # One query for all the counters (avoids N+1)
        counts: dict[int, dict[str, int]] = {i: {"total": 0, "open": 0} for i in ids}
        if ids:
            is_open = case((and_(_status_is(FindingStatus.OPEN), _current()), 1), else_=0)
            rows = session.exec(
                select(Finding.report_id, func.count(), func.sum(is_open))
                .where(col(Finding.report_id).in_(ids))
                .group_by(Finding.report_id)  # type: ignore[arg-type]
            ).all()
            for report_id, number, open_number in rows:
                counts[report_id]["total"] = number
                counts[report_id]["open"] = open_number or 0

        return [
            {
                "report_id": r.id,
                "project": r.project,
                "branch": r.branch,
                "commit_sha": r.commit_sha,
                "review_type": r.review_type,
                "risk_level": r.risk_level.value,
                "reviewer": r.reviewer,
                "author": r.author if with_author else None,
                "submitted_by": r.submitted_by,
                "created_at": r.created_at.isoformat(),
                "findings_total": counts[r.id]["total"],
                "findings_open": counts[r.id]["open"],
                "summary": r.summary[:200],
            }
            for r in reports
        ]


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
