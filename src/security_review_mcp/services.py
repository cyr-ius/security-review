"""Report persistence service (business logic between MCP tools and the database)."""

import json
import logging
import re
from collections import Counter
from collections.abc import Collection, Iterable
from datetime import datetime, timedelta
from typing import Literal

from sqlalchemy import ColumnElement, and_, case, func, or_
from sqlalchemy.orm import selectinload
from sqlmodel import col, select

from . import audit, coverage
from .config import MAX_RETENTION_DAYS, get_settings
from .database import session_scope
from .models import (
    DISMISSED_STATUSES,
    MAX_AUTHOR_CHARS,
    MAX_BRANCH_CHARS,
    MAX_COMMENT_CHARS,
    MAX_COMMIT_SHA_CHARS,
    MAX_REPOSITORY_CHARS,
    MAX_REVIEWER_CHARS,
    MAX_STATUS_REASON_CHARS,
    PROPOSABLE_STATUSES,
    SEVERITY_RANK,
    ChecklistResult,
    Finding,
    FindingComment,
    FindingCommentPublic,
    FindingCreate,
    FindingPublic,
    FindingStatus,
    ReviewType,
    SecurityReport,
    SecurityReportPublic,
    Severity,
    as_utc,
    effective_status,
    utcnow,
)
from .project_names import normalize_project
from .prompts import fenced
from .scanner import redact_secrets, sanitize_untrusted

logger = logging.getLogger(__name__)

# Characters of a developer username or email (Unicode letters and digits included): no
# Markdown or HTML syntax, as the author is copied as is into the Markdown export of a report
_AUTHOR_RE = re.compile(r"[\w .@+'’,-]+")

# Shortest reason of a triage decision or of a proposal (a word or two is not a reason)
MIN_STATUS_REASON_CHARS = 10


class NotFoundError(LookupError):
    """Raised when a report or a finding does not exist."""


def compute_risk_level(severities: list[Severity], override: Severity | None = None) -> Severity:
    """Return the overall risk: the highest finding severity (an override can only raise it)."""
    computed = max(severities, key=lambda s: SEVERITY_RANK[s], default=Severity.INFO)
    if override is not None and SEVERITY_RANK[override] > SEVERITY_RANK[computed]:
        return override
    return computed


def _expired_dismissal(now: datetime) -> ColumnElement[bool]:
    """SQL condition: an accepted or false-positive finding whose decision has expired."""
    return and_(
        col(Finding.status).in_(DISMISSED_STATUSES),
        col(Finding.status_expires_at).is_not(None),
        col(Finding.status_expires_at) <= now,
    )


def _status_is(status: FindingStatus, now: datetime | None = None) -> ColumnElement[bool]:
    """SQL condition on the effective status (an expired dismissal counts as ``open``)."""
    now = now or utcnow()
    if status == FindingStatus.OPEN:
        return or_(Finding.status == FindingStatus.OPEN, _expired_dismissal(now))
    if status in DISMISSED_STATUSES:
        return and_(Finding.status == status, ~_expired_dismissal(now))
    return Finding.status == status


def _check_author(author: str | None) -> str | None:
    """Strip and bound the developer username of a report (None when empty).

    Raises:
        ValueError: Longer than MAX_AUTHOR_CHARS, or with characters other than letters,
            digits, spaces and . @ _ + - ' , (no control character nor Markdown or HTML
            syntax: the name is shown as is in the web interface and the Markdown export).
    """
    author = (author or "").strip()
    if not author:
        return None
    if len(author) > MAX_AUTHOR_CHARS:
        raise ValueError(f"author must contain at most {MAX_AUTHOR_CHARS} characters")
    if not author.isprintable() or not _AUTHOR_RE.fullmatch(author):
        raise ValueError(
            "author may only contain letters, digits, spaces and . @ _ + - ' , characters"
        )
    return author


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


def _check_lengths(*fields: tuple[str, str | None, int]) -> None:
    """Refuse a field (name, value, limit) longer than its limit, before it is masked or stored.

    The table models do not validate their max_length: a longer value would be stored and
    break the reading of the report.

    Raises:
        ValueError: Naming the first field that is too long.
    """
    for name, value, limit in fields:
        if value is not None and len(value) > limit:
            raise ValueError(f"{name} too long ({len(value)} chars); the limit is {limit}")


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
        author: Username of the developer, declared by the client (not authenticated).
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
            author=author,
            submitted_by=submitted_by,
            summary=sanitize_untrusted(summary)[:content],
            risk_level=risk,
            findings=rows,
        )
        if declared is not None:
            report.checklist_results = json.dumps([r.model_dump() for r in declared.checklist])
            report.scan_rules = json.dumps(declared.scan_rules)
        session.add(report)
        session.flush()  # assigns ids before the commit
        result = {
            "report_id": report.id,
            "project": report.project,
            "review_type": review_type.value if review_type else None,
            "author": author,
            "risk_level": risk.value,
            "findings_count": len(rows),
            "findings_by_severity": dict(Counter(row.severity.value for row in rows)),
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


def list_reports(
    project: str | None = None,
    risk_level: Severity | None = None,
    limit: int = 20,
    offset: int = 0,
    projects: Collection[str] | None = None,
    review_type: ReviewType | None = None,
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

    ``projects`` (the scope of a restricted caller) keeps only the reports of these projects;
    ``author`` keeps only the reports declared for this developer username. Without
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
        if project:
            statement = statement.where(SecurityReport.project == normalize_project(project))
        if projects is not None:
            statement = statement.where(col(SecurityReport.project).in_(list(projects)))
        if risk_level:
            statement = statement.where(SecurityReport.risk_level == risk_level)
        if review_type:
            statement = statement.where(SecurityReport.review_type == review_type)
        if author:
            statement = statement.where(SecurityReport.author == author)
        if search:
            escaped = search[:200].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
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
            is_open = case((_status_is(FindingStatus.OPEN), 1), else_=0)
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


def _check_reason(reason: str | None, required: bool) -> str | None:
    """Strip, bound and mask a triage reason.

    Raises:
        ValueError: If a required reason is missing, too short or too long.
    """
    reason = (reason or "").strip()
    if not reason:
        if required:
            raise ValueError("A reason is required")
        return None
    if not MIN_STATUS_REASON_CHARS <= len(reason) <= MAX_STATUS_REASON_CHARS:
        raise ValueError(
            f"The reason must have {MIN_STATUS_REASON_CHARS} to {MAX_STATUS_REASON_CHARS} "
            "characters"
        )
    return redact_secrets(reason)


def _check_expiry(expires_at: datetime, now: datetime, longest: int) -> datetime:
    """Return the expiry date of a dismissal, in the future and at most ``longest`` days away.

    Raises:
        ValueError: If the date is past or too far.
    """
    if expires_at <= now:
        raise ValueError("The expiry date must be in the future")
    if expires_at > now + timedelta(days=longest):
        raise ValueError(f"The expiry date must be at most {longest} days away")
    return expires_at


def needs_formal_acceptance(severity: Severity | str) -> bool:
    """Whether accepting the risk of a finding of this severity needs a reason and an expiry.

    True from SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY up, and for every severity when it is
    empty; a less severe finding is accepted by a plain validation.
    """
    threshold = get_settings().risk_acceptance_min_severity
    return threshold is None or SEVERITY_RANK[Severity(severity)] >= SEVERITY_RANK[threshold]


def update_finding_status(
    finding_id: int,
    status: FindingStatus,
    approver: str,
    reason: str | None = None,
    expires_at: datetime | None = None,
    actor: str | None = None,
) -> FindingPublic:
    """Record a triage decision made by a person (web interface), never by an agent.

    ``accepted`` and ``false_positive`` need a reason and an expiry date, in the future and at
    most SECREVIEW_MAX_DISMISSAL_DAYS days away: once expired, the finding counts as open again.
    An acceptance may have no expiry date while SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED is on.
    A finding less severe than SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY is accepted by a plain
    validation: its reason and its expiry date are optional.
    The reason of an acceptance is also its first comment (see ``add_finding_comment``).
    ``fixed`` takes an optional reason; ``open`` clears the decision. Any decision clears the
    status proposed by an agent. The decision is written to the audit log (``actor``, default
    the approver).

    Raises:
        NotFoundError: If the finding does not exist.
        ValueError: If the approver, the reason or the expiry date is missing or invalid.
    """
    approver = approver.strip()
    if not approver:
        raise ValueError("An approver is required")
    now = utcnow()
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        if status in DISMISSED_STATUSES:
            settings = get_settings()
            plain = status == FindingStatus.ACCEPTED and not needs_formal_acceptance(
                finding.severity
            )
            reason = _check_reason(reason, required=not plain)
            if expires_at is None:
                if not plain and (
                    status != FindingStatus.ACCEPTED or not settings.permanent_acceptance_enabled
                ):
                    raise ValueError(f"An expiry date is required for the status '{status.value}'")
            else:
                expires_at = _check_expiry(as_utc(expires_at), now, settings.max_dismissal_days)
        else:
            if expires_at is not None:
                raise ValueError(f"The status '{status.value}' takes no expiry date")
            reason = _check_reason(reason, required=False) if status != FindingStatus.OPEN else None
        previous = effective_status(finding.status, finding.status_expires_at, now)
        if previous != status:
            finding.status_changed_at = now
        # The reason of an acceptance opens its comments: a new one is added when the risk is
        # accepted or its reason changes, not when only the expiry date does
        if (
            status == FindingStatus.ACCEPTED
            and reason
            and (finding.status != status or finding.status_reason != reason)
        ):
            session.add(
                FindingComment(
                    finding_id=finding_id, author=approver[:200], body=reason, created_at=now
                )
            )
        proposal = finding.proposed_status
        finding.status = status
        reopened = status == FindingStatus.OPEN
        finding.status_reason = reason
        finding.status_approver = None if reopened else approver[:200]
        finding.status_expires_at = expires_at
        finding.proposed_status = None
        finding.proposed_reason = None
        finding.proposed_by = None
        finding.proposed_at = None
        session.add(finding)
        audit.record(
            session,
            audit.AuditAction.FINDING_STATUS_CHANGED,
            actor or approver,
            "finding",
            finding_id,
            finding.report.project,
            {
                "previous_status": FindingStatus(previous).value,
                "status": status.value,
                "reason": reason,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "proposal": FindingStatus(proposal).value if proposal else None,
            },
        )
        session.flush()
        logger.info("Finding %s set to %s", finding_id, status)
        return FindingPublic.model_validate(finding, from_attributes=True)


def update_finding_severity(
    finding_id: int,
    severity: Severity,
    analyst: str,
    reason: str,
    actor: str | None = None,
) -> FindingPublic:
    """Raise the severity of a finding, decided by a security analyst (web interface).

    The new severity must be above the one given by the report, or equal to it to undo an
    escalation: a finding is never made less severe than its report says (accepting a risk is
    the way to close it). The justification is required. The severity of the report is kept
    in ``original_severity`` and its risk level is raised with the finding. The change is
    written to the audit log (``actor``, default the analyst).

    Raises:
        NotFoundError: If the finding does not exist.
        ValueError: If the analyst or the justification is missing or invalid, or the
            severity is unchanged or below the one of the report.
    """
    analyst = analyst.strip()
    if not analyst:
        raise ValueError("An analyst is required")
    severity = Severity(severity)
    checked = _check_reason(reason, required=True)
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        previous = Severity(finding.severity)
        original = Severity(finding.original_severity or previous)
        if severity == previous:
            raise ValueError(f"The finding is already {severity.value}")
        if SEVERITY_RANK[severity] < SEVERITY_RANK[original]:
            raise ValueError(
                f"The severity cannot go below the one of the report ({original.value})"
            )
        now = utcnow()
        restored = severity == original
        finding.severity = severity
        finding.original_severity = None if restored else original
        finding.severity_reason = checked
        finding.severity_changed_by = analyst[:200]
        finding.severity_changed_at = now
        report = finding.report
        if SEVERITY_RANK[severity] > SEVERITY_RANK[Severity(report.risk_level)]:
            report.risk_level = severity
            session.add(report)
        session.add(finding)
        audit.record(
            session,
            audit.AuditAction.FINDING_SEVERITY_CHANGED,
            actor or analyst,
            "finding",
            finding_id,
            report.project,
            {
                "previous_severity": previous.value,
                "severity": severity.value,
                "original_severity": original.value,
                "reason": checked,
            },
        )
        session.flush()
        logger.info("Finding %s severity set to %s", finding_id, severity)
        return FindingPublic.model_validate(finding, from_attributes=True)


def propose_finding_status(
    finding_id: int,
    status: FindingStatus,
    reason: str,
    proposed_by: str,
    actor: str | None = None,
) -> FindingPublic:
    """Store the status an agent proposes for a finding, without applying it.

    The status, the gate and the posture do not change: a triager decides in the web
    interface. A new proposal replaces the previous one. It is written to the audit log
    (``actor``, default the token ``proposed_by``).

    Raises:
        NotFoundError: If the finding does not exist.
        ValueError: If the status cannot be proposed or the reason is missing or invalid.
    """
    if status not in PROPOSABLE_STATUSES:
        allowed = ", ".join(sorted(s.value for s in PROPOSABLE_STATUSES))
        raise ValueError(f"Only these statuses can be proposed: {allowed}")
    checked = _check_reason(reason, required=True)
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        finding.proposed_status = status
        finding.proposed_reason = checked
        finding.proposed_by = (proposed_by.strip() or "unknown")[:200]
        finding.proposed_at = utcnow()
        session.add(finding)
        audit.record(
            session,
            audit.AuditAction.FINDING_STATUS_PROPOSED,
            actor or audit.token_actor(finding.proposed_by),
            "finding",
            finding_id,
            finding.report.project,
            {"status": status.value, "reason": checked},
        )
        session.flush()
        logger.info("Status %s proposed for finding %s", status, finding_id)
        return FindingPublic.model_validate(finding, from_attributes=True)


def clear_finding_proposal(finding_id: int, actor: str | None = None) -> FindingPublic:
    """Reject the status proposed by an agent for a finding (the status does not change).

    The rejection is written to the audit log when a proposal existed.

    Raises:
        NotFoundError: If the finding does not exist.
    """
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        if finding.proposed_status is not None:
            audit.record(
                session,
                audit.AuditAction.FINDING_PROPOSAL_REJECTED,
                actor,
                "finding",
                finding_id,
                finding.report.project,
                {
                    "status": FindingStatus(finding.proposed_status).value,
                    "proposed_by": finding.proposed_by,
                },
            )
        finding.proposed_status = None
        finding.proposed_reason = None
        finding.proposed_by = None
        finding.proposed_at = None
        session.add(finding)
        session.flush()
        logger.info("Proposal rejected for finding %s", finding_id)
        return FindingPublic.model_validate(finding, from_attributes=True)


def finding_status_counts() -> dict[str, int]:
    """Count the findings by effective status (an expired dismissal counts as ``open``), plus
    ``proposed``: the findings with an agent proposal waiting for a person."""
    now = utcnow()
    with session_scope() as session:
        counts = {
            status.value: session.exec(
                select(func.count()).select_from(Finding).where(_status_is(status, now))
            ).one()
            for status in FindingStatus
        }
        counts["proposed"] = session.exec(
            select(func.count())
            .select_from(Finding)
            .where(col(Finding.proposed_status).is_not(None))
        ).one()
    return counts


def list_projects(known: Iterable[str] = ()) -> list[dict]:
    """List the projects that have reports, with their open findings by severity, and the
    ``known`` projects without any report yet (created, or named by a role of a group).

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
            .where(_status_is(FindingStatus.OPEN))
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
    """Summarize open findings of a project across all its reports (useful as a CI gate)."""
    project = normalize_project(project)
    with session_scope() as session:
        rows = session.exec(
            select(Finding.severity, func.count())
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(SecurityReport.project == project, _status_is(FindingStatus.OPEN))
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
    status: FindingStatus = FindingStatus.OPEN,
    severity: Severity | None = None,
    limit: int = 100,
    offset: int = 0,
    review_type: ReviewType | None = None,
    projects: Collection[str] | None = None,
) -> dict:
    """List the findings of a project (or of every project) across all reports, for a review.

    Worst severity first, then newest report first. ``limit`` is capped by
    SECREVIEW_MAX_LIST_LIMIT; ``total`` counts every matching finding, for paging. Each finding
    carries the project, branch, commit, review type and date of its report; ``review_type``
    keeps only the findings of the reports of that type. ``project`` None lists every project;
    ``projects`` (the scope of a restricted caller) keeps only the findings of these projects.
    """
    settings = get_settings()
    limit = max(1, min(limit, settings.max_list_limit))
    offset = max(0, offset)
    filters = [_status_is(status)]
    if project is not None:
        filters.append(SecurityReport.project == normalize_project(project))
    if projects is not None:
        filters.append(col(SecurityReport.project).in_(list(projects)))
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
                "project": report.project,
                "branch": report.branch,
                "commit_sha": report.commit_sha,
                "review_type": report.review_type,
                "report_created_at": report.created_at,
            }
            for finding, report in rows
        ]
    return {"project": project, "total": total, "findings": findings}


def list_risk_acceptances(
    project: str | None,
    projects: Collection[str] | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict:
    """List the accepted risks of a project (or of every project), expired ones included.

    Nearest expiry first, the acceptances without expiry date last. Each acceptance carries the
    context of its report, ``expired`` (it counts as open again) and its number of comments.
    ``limit`` is capped by SECREVIEW_MAX_LIST_LIMIT; ``total`` counts every acceptance, for
    paging.
    ``projects`` (the scope of a restricted caller) keeps only the acceptances of these projects.
    """
    settings = get_settings()
    limit = max(1, min(limit or settings.max_list_limit, settings.max_list_limit))
    offset = max(0, offset)
    filters = [Finding.status == FindingStatus.ACCEPTED]
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
    return "\n".join(lines) + "\n"


def evaluate_gate(
    project: str,
    fail_on: Severity = Severity.HIGH,
    report_id: int | None = None,
) -> dict:
    """Decide whether a project (or one report) passes a security gate.

    The gate fails when at least one finding with status ``open`` has a severity greater than
    or equal to ``fail_on``. A triager unblocks it by marking findings ``fixed``, ``accepted``
    or ``false_positive``; an expired acceptance or false positive blocks again.

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
            project = normalize_project(str(project))
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
    project = normalize_project(project)
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
