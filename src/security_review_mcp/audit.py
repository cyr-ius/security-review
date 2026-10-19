"""Audit log: who changed a finding status (or commented a finding), a token, an enrollment
request or an access, and who logged in to the web interface (or failed to) and out.

Events are written by the business modules (services, token_store, access_control) in the same
transaction as the change they describe, so that an event exists exactly when the change was
committed. They are append-only: no tool nor route edits them, and only the daily purge of the
controller (SECREVIEW_AUDIT_RETENTION_DAYS and SECREVIEW_AUDIT_MAX_EVENTS, see retention) deletes
the old ones. The controller may also forward them to syslog (see audit_syslog).

``details`` never holds a secret: the values are bounded and masked with
``scanner.redact_secrets`` before they are stored.
"""

import json
import logging
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Literal

from sqlalchemy import delete, or_
from sqlmodel import Session, col, func, select

from .config import MAX_AUDIT_EVENTS, MAX_RETENTION_DAYS, get_settings
from .database import session_scope
from .models import AuditEvent, as_utc, utcnow
from .project_names import normalize_project
from .scanner import redact_secrets

logger = logging.getLogger(__name__)

MAX_ACTOR_CHARS = 200
MAX_TARGET_CHARS = 200
MAX_DETAIL_VALUE_CHARS = 500
MAX_DETAILS_CHARS = 4000

CLI_ACTOR = "cli"
ANONYMOUS_ACTOR = "anonymous"


class AuditAction(StrEnum):
    """Kinds of audit events (stored as text: a new kind needs no migration)."""

    FINDING_STATUS_CHANGED = "finding.status_changed"
    FINDING_STATUS_PROPOSED = "finding.status_proposed"
    FINDING_PROPOSAL_REJECTED = "finding.proposal_rejected"
    FINDING_COMMENTED = "finding.commented"
    TOKEN_CREATED = "token.created"
    TOKEN_ROTATED = "token.rotated"
    TOKEN_REVOKED = "token.revoked"
    TOKEN_PROJECTS_CHANGED = "token.projects_changed"
    ENROLLMENT_REQUESTED = "enrollment.requested"
    ENROLLMENT_APPROVED = "enrollment.approved"
    ENROLLMENT_REJECTED = "enrollment.rejected"
    ROLE_CREATED = "role.created"
    ROLE_UPDATED = "role.updated"
    ROLE_DELETED = "role.deleted"
    GROUP_CREATED = "group.created"
    GROUP_UPDATED = "group.updated"
    GROUP_DELETED = "group.deleted"
    GROUP_ROLES_CHANGED = "group.roles_changed"
    GROUP_MEMBERS_CHANGED = "group.members_changed"
    USER_GROUPS_CHANGED = "user.groups_changed"
    PROJECT_CREATED = "project.created"
    PROJECT_DELETED = "project.deleted"
    # Recorded by the direct roles of a user, removed since revision 0018: kept for the history
    USER_ROLES_CHANGED = "user.roles_changed"
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login_failed"
    USER_LOGOUT = "user.logout"
    AUDIT_SYSLOG_CHANGED = "audit_syslog.changed"


def user_actor(username: str) -> str:
    """Actor of a change made by a web user logged in to the interface."""
    return f"user:{username}"


def token_actor(label: str) -> str:
    """Actor of a change made with a bearer token (agent, pipeline, API client)."""
    return f"token:{label}"


def _clean_value(value: Any) -> Any:
    """Bound and mask one detail value (lists are cleaned item by item)."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, list | tuple | set | frozenset):
        return [_clean_value(item) for item in list(value)[:50]]
    return redact_secrets(str(value))[:MAX_DETAIL_VALUE_CHARS]


def _details(details: dict[str, Any] | None) -> str:
    """Serialize the details of an event, masked and bounded."""
    cleaned = {str(key)[:50]: _clean_value(value) for key, value in (details or {}).items()}
    text = json.dumps(cleaned, sort_keys=True, default=str)
    if len(text) > MAX_DETAILS_CHARS:
        text = json.dumps({"truncated": text[: MAX_DETAILS_CHARS - 100]})
    return text


def record(
    session: Session,
    action: AuditAction,
    actor: str | None,
    target_type: str,
    target_id: str | int | None = None,
    project: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Add an audit event to ``session``: it is committed (or rolled back) with the change."""
    session.add(
        AuditEvent(
            action=action.value,
            actor=((actor or CLI_ACTOR).strip() or CLI_ACTOR)[:MAX_ACTOR_CHARS],
            target_type=target_type[:30],
            target_id=None if target_id is None else str(target_id)[:MAX_TARGET_CHARS],
            project=None if project is None else project[:200],
            details=_details(details),
        )
    )


def public_event(event: AuditEvent) -> dict[str, Any]:
    """An audit event as returned by the REST API and the CLI."""
    try:
        details = json.loads(event.details)
    except ValueError:
        details = {}
    return {
        "id": event.id,
        "created_at": as_utc(event.created_at).isoformat(),
        "action": event.action,
        "actor": event.actor,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "project": event.project,
        "details": details,
    }


def list_events(
    action: str | None = None,
    project: str | None = None,
    actor: str | None = None,
    since: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
    search: str | None = None,
    sort_by: Literal["created_at", "action", "actor", "target", "project"] = "created_at",
    sort_direction: Literal["asc", "desc"] = "desc",
) -> dict[str, Any]:
    """Return audit events, newest first, and the number of matching events.

    ``limit`` is capped by SECREVIEW_MAX_LIST_LIMIT.

    Raises:
        ValueError: If ``action`` is not a known kind of event or a bound is negative.
    """
    if action is not None and action not in {item.value for item in AuditAction}:
        allowed = ", ".join(item.value for item in AuditAction)
        raise ValueError(f"Unknown audit action '{action}' (allowed: {allowed})")
    if limit < 1 or offset < 0:
        raise ValueError("limit must be at least 1 and offset at least 0")
    limit = min(limit, get_settings().max_list_limit)
    conditions = []
    if action is not None:
        conditions.append(AuditEvent.action == action)
    if project is not None:
        conditions.append(AuditEvent.project == normalize_project(project))
    if actor is not None:
        conditions.append(AuditEvent.actor == actor)
    if since is not None:
        conditions.append(col(AuditEvent.created_at) >= as_utc(since))
    if search:
        escaped = search[:200].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        conditions.append(
            or_(
                col(AuditEvent.action).ilike(pattern, escape="\\"),
                col(AuditEvent.actor).ilike(pattern, escape="\\"),
                col(AuditEvent.target_type).ilike(pattern, escape="\\"),
                col(AuditEvent.target_id).ilike(pattern, escape="\\"),
                col(AuditEvent.project).ilike(pattern, escape="\\"),
                col(AuditEvent.details).ilike(pattern, escape="\\"),
            )
        )
    sort_columns = {
        "created_at": (col(AuditEvent.created_at),),
        "action": (col(AuditEvent.action),),
        "actor": (col(AuditEvent.actor),),
        "target": (col(AuditEvent.target_type), col(AuditEvent.target_id)),
        "project": (col(AuditEvent.project),),
    }
    sort_column = sort_columns[sort_by]
    primary_order = tuple(
        column.asc() if sort_direction == "asc" else column.desc() for column in sort_column
    )
    with session_scope() as session:
        total = session.exec(select(func.count()).select_from(AuditEvent).where(*conditions)).one()
        rows = session.exec(
            select(AuditEvent)
            .where(*conditions)
            .order_by(*primary_order, col(AuditEvent.id).desc())
            .offset(offset)
            .limit(limit)
        ).all()
        return {"total": total, "events": [public_event(row) for row in rows]}


def prune_events(
    retention_days: int | None = None, max_events: int | None = None
) -> dict[str, int]:
    """Delete the audit events older than ``retention_days`` days, then the oldest ones beyond
    ``max_events``.

    Defaults to SECREVIEW_AUDIT_RETENTION_DAYS and SECREVIEW_AUDIT_MAX_EVENTS; 0 disables each
    purge.

    Raises:
        ValueError: If a bound is negative or above its maximum.
    """
    settings = get_settings()
    days = settings.audit_retention_days if retention_days is None else retention_days
    limit = settings.audit_max_events if max_events is None else max_events
    if not 0 <= days <= MAX_RETENTION_DAYS:
        raise ValueError(f"retention_days must be between 0 and {MAX_RETENTION_DAYS}")
    if not 0 <= limit <= MAX_AUDIT_EVENTS:
        raise ValueError(f"max_events must be between 0 and {MAX_AUDIT_EVENTS}")
    deleted = 0
    with session_scope() as session:
        if days:
            cutoff = utcnow() - timedelta(days=days)
            result = session.execute(delete(AuditEvent).where(col(AuditEvent.created_at) < cutoff))
            deleted += result.rowcount or 0
        if limit:
            # Id of the newest event beyond the limit: it and every older one go
            newest_dropped = session.exec(
                select(AuditEvent.id).order_by(col(AuditEvent.id).desc()).offset(limit).limit(1)
            ).first()
            if newest_dropped is not None:
                result = session.execute(
                    delete(AuditEvent).where(col(AuditEvent.id) <= newest_dropped)
                )
                deleted += result.rowcount or 0
    if deleted:
        logger.info(
            "Deleted %d audit events (retention %d days, at most %d events)", deleted, days, limit
        )
    return {"retention_days": days, "max_events": limit, "deleted": deleted}
