"""Review of the whole repository asked of the MCP agent, per project.

A person asks for it in the web interface, once (``Project.codebase_review_requested_at``) or
every so many days (``Project.codebase_review_interval_days``); the MCP agent learns it from
``request_project`` and offers the developer the ``codebase-review`` prompt. It is a reminder:
the gate does not depend on it.

Nothing clears a request: it is met as soon as a codebase review is saved after it. Only a
review that went through the Controller server counts: a ``codebase-review`` report linked to
a code scan of its review group (see SecurityReport.review_group), dated by that scan, so that
an agent cannot meet a request with a report alone. This module imports nothing from the
controller: the MCP server uses it.
"""

from datetime import datetime, timedelta
from typing import Any

from sqlmodel import Session, col, func, select

from ..storage.models import Project, ReviewType, SecurityReport, as_utc, utcnow

# Longest interval between two codebase reviews, in days (ten years)
MAX_INTERVAL_DAYS = 3650


def last_reviews(session: Session, projects: list[str] | None = None) -> dict[str, datetime]:
    """Date of the latest codebase review of each project (of ``projects``, else of all) that
    has one: a ``codebase-review`` report whose review group holds a code scan of the project.

    The date is that of the code scan, saved by the Controller server with a single-use ticket:
    a new report that reuses the review group of an older review never makes it recent."""
    scanned = (
        select(SecurityReport.review_group, SecurityReport.project, SecurityReport.created_at)
        .where(
            SecurityReport.review_type == ReviewType.CODE_SCAN,
            col(SecurityReport.review_group).is_not(None),
        )
        .subquery()
    )
    query = (
        select(SecurityReport.project, func.max(scanned.c.created_at))
        .join(
            scanned,
            (scanned.c.review_group == SecurityReport.review_group)
            & (scanned.c.project == SecurityReport.project),
        )
        .where(SecurityReport.review_type == ReviewType.CODEBASE_REVIEW)
        .group_by(SecurityReport.project)  # type: ignore[arg-type]
    )
    if projects is not None:
        query = query.where(col(SecurityReport.project).in_(projects))
    return {name: as_utc(last) for name, last in session.exec(query).all()}


def review_state(
    row: Project, last_review: datetime | None, now: datetime | None = None
) -> dict[str, Any]:
    """Whether a codebase review of the project ``row`` is due, and why.

    ``reasons`` lists ``requested`` (asked by a person after the latest codebase review) and
    ``interval`` (the latest codebase review is older than the interval, or there is none).
    """
    now = now or utcnow()
    requested_at = row.codebase_review_requested_at
    requested_at = as_utc(requested_at) if requested_at else None
    interval = row.codebase_review_interval_days
    reasons = []
    # A request is met by a codebase review saved after it
    pending = requested_at is not None and (last_review is None or last_review < requested_at)
    if pending:
        reasons.append("requested")
    next_due_at = None
    if interval is not None:
        next_due_at = last_review + timedelta(days=interval) if last_review else None
        if next_due_at is None or next_due_at <= now:
            reasons.append("interval")
    return {
        "project": row.name,
        "requested": pending,
        "requested_at": requested_at.isoformat() if pending and requested_at else None,
        "interval_days": interval,
        "last_review_at": last_review.isoformat() if last_review else None,
        "next_due_at": next_due_at.isoformat() if next_due_at else None,
        "due": bool(reasons),
        "reasons": reasons,
    }


def project_state(session: Session, project: str) -> dict[str, Any] | None:
    """State of the codebase review of a known project (None for an unknown one)."""
    row = session.exec(select(Project).where(Project.name == project)).first()
    if row is None:
        return None
    return review_state(row, last_reviews(session, [project]).get(project))


def due_projects(session: Session) -> set[str]:
    """Projects with a codebase review due (asked or periodic)."""
    rows = session.exec(
        select(Project).where(
            col(Project.codebase_review_requested_at).is_not(None)
            | col(Project.codebase_review_interval_days).is_not(None)
        )
    ).all()
    if not rows:
        return set()
    last = last_reviews(session, [row.name for row in rows])
    now = utcnow()
    return {row.name for row in rows if review_state(row, last.get(row.name), now)["due"]}
