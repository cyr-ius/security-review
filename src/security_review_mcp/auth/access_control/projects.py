"""Projects, autojoin and project requests (enrollment)."""

import json
import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, or_, select

from ... import app_settings
from ...config import get_settings
from ...observability import audit
from ...reports.services import NotFoundError
from ...storage import projects as project_store
from ...storage.database import session_scope
from ...storage.models import (
    ConnectorTarget,
    Finding,
    FindingComment,
    FindingExport,
    OidcRoleMapping,
    OpenGrepRuleProposal,
    Project,
    ProjectEnrollment,
    SecurityReport,
    UserProject,
    WebUser,
    as_utc,
    utcnow,
)
from ..rate_limit import RateLimit
from ..token_store import forget_project
from . import core, users
from .core import (
    REVIEW_PERMISSIONS,
    Permission,
    _empty_mapping,
    allows,
    clean_projects,
    user_grants,
)

logger = logging.getLogger("security_review_mcp.web")

# Project requests (see request_project): any token may make one, so they are bounded. At most
# MAX_PENDING_PROJECTS projects wait for an approval, the requests of one user (or of one token
# without a user) are limited per hour, and a request nobody approved within
# SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS is deleted (audited with the actor ENROLLMENT_ACTOR).
ENROLLMENT_ACTOR = "enrollment"
MAX_PENDING_PROJECTS = 20
MAX_ENROLLMENTS_PER_REQUESTER = 5
ENROLLMENT_WINDOW_SECONDS = 3600
MAX_REQUESTED_BY_CHARS = 200
MAX_ADDRESS_CHARS = 64
_enrollment_limit = RateLimit("enrollment", ENROLLMENT_WINDOW_SECONDS)


class AccessGrantDenied(PermissionError):
    """The approver may not give access to an existing project (see approve_enrollment)."""


class EnrollmentThrottled(ValueError):
    """Too many project requests from one user or token."""


# ── Projects ─────────────────────────────────────────────────────────────────


def project_exists(session: Session, project: str) -> bool:
    """True when ``project`` is known (see storage.projects)."""
    return project_store.project_exists(session, project)


def create_project(user_id: int, project: str, actor: str | None = None) -> dict[str, Any]:
    """Create a new project for the web user ``user_id`` (``projects.create``): the user gets
    its review (REVIEW_PERMISSIONS), so that it reads the project and its personal ``mcp`` token
    saves reports there.

    Raises:
        ValueError: Invalid name, project already known (see project_exists: the permission
            never opens an existing project).
        NotFoundError: If the user does not exist.
    """
    cleaned = clean_projects([Permission.REPORTS_READ], [project])[0]
    with session_scope() as session:
        if session.get(WebUser, user_id) is None:
            raise NotFoundError(f"Web user {user_id} not found")
        if project_exists(session, cleaned):
            raise ValueError(f"Project '{cleaned}' already exists")
        return _create_project(session, user_id, cleaned, actor)


def adopt_project(project: str, owner: str, actor: str | None = None) -> dict[str, Any]:
    """Settle ``project`` for the web user ``owner`` whose token already reaches every project:
    an unknown project is created as by request_project when the user holds
    ``projects.create``, given to the user to review only, so that the user keeps reaching it
    without every project. A creation counts in the rate limit of the project requests.

    Returns:
        ``project`` and ``status`` (``created`` or ``accessible``), with ``next_steps`` when
        created.

    Raises:
        ValueError: Invalid project name.
        EnrollmentThrottled: Too many project requests from this user.
    """
    cleaned = clean_projects([Permission.REPORTS_READ], [project])[0]
    with session_scope() as session:
        user = session.exec(select(WebUser).where(WebUser.username == owner)).first()
        if (
            user is not None
            and not project_exists(session, cleaned)
            and allows(user_grants(session, user.id), Permission.PROJECTS_CREATE)  # type: ignore[arg-type]
        ):
            if _enrollment_limit.hit(owner) > MAX_ENROLLMENTS_PER_REQUESTER:
                raise EnrollmentThrottled("Too many project requests; retry later")
            _create_project(session, user.id, cleaned, actor)  # type: ignore[arg-type]
            return {
                "project": cleaned,
                "status": "created",
                "next_steps": f"Project '{cleaned}' was created and the user may review it: the "
                "review can go on.",
            }
    return {"project": cleaned, "status": "accessible"}


def _create_project(
    session: Session, user_id: int, project: str, actor: str | None
) -> dict[str, Any]:
    """Create the unknown ``project`` (cleaned), reviewed by ``user_id`` (REVIEW_PERMISSIONS)."""
    project_store.ensure_project(session, project, actor)
    users.add_user_project(session, user_id, project, actor)
    # The request of this user, or without a user, is settled; the others now ask for an access
    for pending in session.exec(
        select(ProjectEnrollment).where(
            ProjectEnrollment.project == project,
            or_(
                ProjectEnrollment.requested_by_user_id == user_id,
                col(ProjectEnrollment.requested_by_user_id).is_(None),
            ),
        )
    ).all():
        session.delete(pending)
    audit.record(
        session,
        audit.AuditAction.PROJECT_CREATED,
        actor,
        "project",
        project,
        project,
        {"user_id": user_id, "permissions": sorted(REVIEW_PERMISSIONS)},
    )
    return {"project": project}


def _delete_reports(session: Session, project: str) -> dict[str, int]:
    """Delete the reports of ``project`` with their findings, comments and exports; return the
    counts."""
    reports = select(SecurityReport.id).where(SecurityReport.project == project)
    findings = select(Finding.id).where(col(Finding.report_id).in_(reports))
    counts = {
        "reports": session.exec(
            select(func.count())
            .select_from(SecurityReport)
            .where(SecurityReport.project == project)
        ).one(),
        "findings": session.exec(
            select(func.count()).select_from(Finding).where(col(Finding.report_id).in_(reports))
        ).one(),
    }
    session.exec(delete(FindingComment).where(col(FindingComment.finding_id).in_(findings)))
    session.exec(delete(FindingExport).where(col(FindingExport.finding_id).in_(findings)))
    session.exec(delete(Finding).where(col(Finding.report_id).in_(reports)))
    session.exec(delete(SecurityReport).where(SecurityReport.project == project))
    return counts


def _forget_project_access(session: Session, project: Project, actor: str | None) -> dict[str, Any]:
    """Remove ``project`` from the users and from the OIDC mappings (a mapping left giving
    nothing is deleted). Each mapping changed is audited with ``oidc.mappings_changed``."""
    members = session.exec(
        select(func.count()).select_from(UserProject).where(UserProject.project_id == project.id)
    ).one()
    session.exec(delete(UserProject).where(UserProject.project_id == project.id))  # type: ignore[arg-type]
    changed: list[str] = []
    for mapping in session.exec(select(OidcRoleMapping)).all():
        projects = json.loads(mapping.projects)
        remaining = [item for item in projects if item["project"] != project.name]
        if len(remaining) == len(projects):
            continue
        mapping.projects = json.dumps(remaining)
        if _empty_mapping(mapping):
            session.delete(mapping)
        else:
            session.add(mapping)
        changed.append(mapping.claim)
    session.flush()
    if changed:
        audit.record(
            session,
            audit.AuditAction.OIDC_MAPPINGS_CHANGED,
            actor,
            "project",
            project.name,
            project.name,
            {"claims": sorted(changed), "reason": "project deleted"},
        )
    return {"members_removed": members, "mappings_changed": sorted(changed)}


def delete_project(project: str, actor: str | None = None) -> dict[str, Any]:
    """Delete ``project`` and everything that refers to it (``projects.delete``), in one
    transaction: its reports, findings and comments, the roles of the users on it and the
    project in the OIDC mappings (see _forget_project_access), in the tokens (see
    token_store.forget_project), its connector destinations and its OpenGrep rule proposals
    (an approved rule stays installed). The audit log keeps the events
    of the project and records ``project.deleted``.

    Raises:
        ValueError: Invalid name.
        NotFoundError: If the project is not known (see project_exists).
    """
    cleaned = clean_projects([Permission.REPORTS_READ], [project])[0]
    with session_scope() as session:
        row = session.exec(select(Project).where(Project.name == cleaned)).first()
        if row is None:
            raise NotFoundError(f"Project '{cleaned}' not found")
        deleted: dict[str, Any] = {"project": cleaned}
        deleted |= _delete_reports(session, cleaned)
        deleted |= _forget_project_access(session, row, actor)
        deleted |= forget_project(session, cleaned, actor)
        # Its connector destinations (its exports went with its findings), deleted here rather
        # than by connectors: the MCP server imports this module, never the connectors
        session.exec(delete(ConnectorTarget).where(ConnectorTarget.project == cleaned))
        session.exec(delete(OpenGrepRuleProposal).where(OpenGrepRuleProposal.project == cleaned))
        session.delete(row)
        audit.record(
            session,
            audit.AuditAction.PROJECT_DELETED,
            actor,
            "project",
            cleaned,
            cleaned,
            {key: value for key, value in deleted.items() if key != "project"},
        )
        return deleted


# ── Autojoin ─────────────────────────────────────────────────────────────────


def autojoin_blocked_projects(session: Session) -> set[str]:
    """Projects whose autojoin is blocked (see set_autojoin_blocked)."""
    return set(session.exec(select(Project.name).where(col(Project.autojoin_blocked))).all())


def set_autojoin_blocked(project: str, blocked: bool, actor: str | None = None) -> dict[str, Any]:
    """Block (or allow again) the autojoin of ``project``: while it is blocked, a holder of
    ``projects.autojoin`` who requests it waits for an approval as the others do. The users
    who already joined it keep their access. A change is audited, a repeated one is not.

    Raises:
        ValueError: Invalid name.
        NotFoundError: If the project is not known (see project_exists).
    """
    cleaned = clean_projects([Permission.REPORTS_READ], [project])[0]
    with session_scope() as session:
        row = session.exec(select(Project).where(Project.name == cleaned)).first()
        if row is None:
            raise NotFoundError(f"Project '{cleaned}' not found")
        if blocked == row.autojoin_blocked:
            return {"project": cleaned, "autojoin_blocked": blocked}
        row.autojoin_blocked = blocked
        session.add(row)
        audit.record(
            session,
            audit.AuditAction.PROJECT_AUTOJOIN_CHANGED,
            actor,
            "project",
            cleaned,
            cleaned,
            {"blocked": blocked},
        )
        return {"project": cleaned, "autojoin_blocked": blocked}


def _autojoin(session: Session, user_id: int, project: str, actor: str | None) -> None:
    """Give the review of the known ``project`` (cleaned) to ``user_id`` and settle its request
    of that project.

    Raises:
        ValueError: The user already reads MAX_SESSION_PROJECTS projects.
    """
    # Counted once added, the user locked (_check_reach), with the projects of its OIDC
    # mappings: a concurrent join is seen, and the transaction is rolled back
    try:
        users.add_user_project(session, user_id, project, actor)
        user_grants(session, user_id)
    except ValueError:
        raise ValueError(
            f"The user already reads {core.MAX_SESSION_PROJECTS} projects; ask an administrator "
            "for access"
        ) from None
    for pending in session.exec(
        select(ProjectEnrollment).where(
            ProjectEnrollment.project == project, ProjectEnrollment.requested_by_user_id == user_id
        )
    ).all():
        session.delete(pending)
    audit.record(
        session,
        audit.AuditAction.PROJECT_JOINED,
        actor,
        "project",
        project,
        project,
        {"user_id": user_id, "permissions": sorted(REVIEW_PERMISSIONS)},
    )


# ── Enrollment ───────────────────────────────────────────────────────────────


def _enrollment_public(session: Session, row: ProjectEnrollment) -> dict[str, Any]:
    """A pending project, with the date its request expires; ``existing``: the project is
    already known, so the request asks for an access to it."""
    ttl = timedelta(days=get_settings().project_enrollment_ttl_days)
    return {
        "id": row.id,
        "project": row.project,
        "existing": project_exists(session, row.project),
        "requested_by": row.requested_by,
        "requested_from": row.requested_from,
        "requested_with": row.requested_with,
        "created_at": as_utc(row.created_at).isoformat(),
        "expires_at": (as_utc(row.created_at) + ttl).isoformat(),
    }


def _audit_enrollment(
    session: Session,
    action: audit.AuditAction,
    actor: str | None,
    row: ProjectEnrollment,
    **extra: Any,
) -> None:
    """Write an audit event about a pending project."""
    audit.record(
        session,
        action,
        actor,
        "project",
        row.project,
        row.project,
        {
            "requested_by": row.requested_by,
            "requested_from": row.requested_from,
            "requested_with": row.requested_with,
        }
        | extra,
    )


def _purge_expired_enrollments(session: Session) -> None:
    """Delete the pending projects nobody approved within SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS
    (audited as a rejection by ENROLLMENT_ACTOR)."""
    cutoff = utcnow() - timedelta(days=get_settings().project_enrollment_ttl_days)
    expired = session.exec(
        select(ProjectEnrollment).where(col(ProjectEnrollment.created_at) < cutoff)
    ).all()
    for row in expired:
        session.delete(row)
        _audit_enrollment(
            session, audit.AuditAction.ENROLLMENT_REJECTED, ENROLLMENT_ACTOR, row, reason="expired"
        )
    session.flush()


def request_project(
    project: str,
    owner: str | None = None,
    requested_from: str | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """Request a project the token of the caller does not reach yet; no token is created.

    ``owner`` is the username of the web user who owns the token (None: a token without a
    user). An unknown project is created at once, with that user as its first member, when the
    user holds ``projects.create``; otherwise the request waits for a user with
    ``projects.create`` (see approve_enrollment), which gives the requesting user access to the
    project. A known project the user does not read is joined at once, to review it, by a user
    who holds ``projects.autojoin`` unless its autojoin is blocked (see set_autojoin_blocked);
    otherwise, and for a project the user reads without ``reports.write`` (autojoin never
    widens what an administrator gave), the user asks for an access to it the same way, and the
    answer is the same as for a new project, so that it does not tell whether a project exists.
    A user has one request per project; nothing is recorded for a known project without a user
    to give access to, or that the user already reviews. Every request is audited (``actor``:
    the token of the caller), with the user and the client address ``requested_from``.

    Returns:
        ``project``, ``status`` (``created``, ``joined`` or ``requested``) and ``next_steps``,
        what the user does next.

    Raises:
        EnrollmentThrottled: Too many requests from this user or token.
        ValueError: Invalid project name, MAX_PENDING_PROJECTS projects already pending, or a
            user with ``projects.autojoin`` who already reads MAX_SESSION_PROJECTS projects.
    """
    cleaned = clean_projects([Permission.REPORTS_READ], [project])[0]
    actor = (actor or ENROLLMENT_ACTOR)[:MAX_REQUESTED_BY_CHARS]
    if requested_from is not None:
        requested_from = requested_from[:MAX_ADDRESS_CHARS]
    if _enrollment_limit.hit(owner or actor) > MAX_ENROLLMENTS_PER_REQUESTER:
        raise EnrollmentThrottled("Too many project requests; retry later")
    with session_scope() as session:
        _purge_expired_enrollments(session)
        user = (
            session.exec(select(WebUser).where(WebUser.username == owner)).first()
            if owner is not None
            else None
        )
        known = project_exists(session, cleaned)
        if (
            user is not None
            and not known
            and allows(user_grants(session, user.id), Permission.PROJECTS_CREATE)  # type: ignore[arg-type]
        ):
            _create_project(session, user.id, cleaned, actor)  # type: ignore[arg-type]
            return {
                "project": cleaned,
                "status": "created",
                "next_steps": f"Project '{cleaned}' was created and the user may review it: the "
                "review can go on.",
            }
        user_id = user.id if user is not None else None
        if (
            user_id is not None
            and known
            and cleaned not in autojoin_blocked_projects(session)
            and allows(grants := user_grants(session, user_id), Permission.PROJECTS_AUTOJOIN)
            and not allows(grants, Permission.REPORTS_READ, cleaned)
        ):
            _autojoin(session, user_id, cleaned, actor)
            return {
                "project": cleaned,
                "status": "joined",
                "next_steps": f"The user joined project '{cleaned}': the review can go on.",
            }
        pending = session.exec(
            select(ProjectEnrollment).where(
                ProjectEnrollment.project == cleaned,
                col(ProjectEnrollment.requested_by_user_id).is_(None)
                if user_id is None
                else ProjectEnrollment.requested_by_user_id == user_id,
            )
        ).first()
        # A known project: there must be a user who does not review it yet to give access to
        useless = known and (
            user_id is None
            or allows(user_grants(session, user_id), Permission.REPORTS_WRITE, cleaned)
        )
        requested = pending is None and not useless
        # Checked before knowing whether a row is added, so that a full queue does not tell
        # whether the project exists
        if pending is None:
            count = session.exec(select(func.count()).select_from(ProjectEnrollment)).one()
            if count >= MAX_PENDING_PROJECTS:
                raise ValueError(
                    "Too many projects are waiting for an administrator; ask one to create the "
                    "project"
                )
        if requested:
            session.add(
                ProjectEnrollment(
                    project=cleaned,
                    requested_by=owner,
                    requested_by_user_id=user_id,
                    requested_from=requested_from,
                    requested_with=actor,
                )
            )
            try:
                session.flush()
            except IntegrityError:
                # Same project requested at the same time by the same user: the first stands
                raise ValueError(f"Project '{cleaned}' was requested concurrently; retry") from None
        audit.record(
            session,
            audit.AuditAction.ENROLLMENT_REQUESTED,
            actor,
            "project",
            cleaned,
            cleaned,
            {
                "requested": requested,
                "existing": known,
                "requested_by": owner,
                "requested_from": requested_from,
            },
        )
    return {
        "project": cleaned,
        "status": "requested",
        "next_steps": enrollment_next_steps(cleaned, app_settings.web_url()),
    }


def enrollment_next_steps(project: str, web_url: str | None) -> str:
    """What the user does after requesting ``project``, which the token does not reach yet."""
    where = f" ({web_url})" if web_url else ""
    return (
        f"The token does not reach project '{project}' yet: do not review the code now. The "
        "request waits for an administrator to approve it on the Projects screen of the web "
        f"interface{where}, which gives the user access to the project. Then the user runs the "
        "review again."
    )


def list_enrollments() -> list[dict[str, Any]]:
    """The pending projects, oldest first (the expired requests are deleted first)."""
    with session_scope() as session:
        _purge_expired_enrollments(session)
        rows = session.exec(
            select(ProjectEnrollment).order_by(col(ProjectEnrollment.created_at))
        ).all()
        return [_enrollment_public(session, row) for row in rows]


def pending_project_count() -> int:
    """Number of projects waiting for an approval (expired requests included until purged)."""
    with session_scope() as session:
        return session.exec(select(func.count()).select_from(ProjectEnrollment)).one()


def _pending(session: Session, enrollment_id: int) -> ProjectEnrollment:
    """The pending project with this id (an expired one is deleted first).

    Raises:
        NotFoundError: If there is none.
    """
    _purge_expired_enrollments(session)
    row = session.get(ProjectEnrollment, enrollment_id)
    if row is None:
        raise NotFoundError(f"Pending project {enrollment_id} not found")
    return row


def approve_enrollment(
    enrollment_id: int, actor: str | None = None, *, may_grant_access: bool = False
) -> dict[str, Any]:
    """Approve a pending project: the user who requested it (none for a token without a user,
    or a user deleted since) gets the review of the project (REVIEW_PERMISSIONS), created when
    missing. For
    a known project, only an approver who manages the users may give that access
    (``may_grant_access``): ``projects.create`` alone never opens an existing project, not even
    to its holder.

    Raises:
        NotFoundError: Unknown or expired request.
        AccessGrantDenied: The project exists and ``may_grant_access`` is false.
        ValueError: The requesting user already holds roles on MAX_SESSION_PROJECTS projects.
    """
    with session_scope() as session:
        row = _pending(session, enrollment_id)
        approved = _enrollment_public(session, row)
        if approved["existing"] and not may_grant_access:
            raise AccessGrantDenied(
                f"Project '{row.project}' already exists: only a user who manages the users "
                "may give access to it"
            )
        project_store.ensure_project(session, row.project, actor)
        granted: str | None = None
        user = (
            session.get(WebUser, row.requested_by_user_id)
            if row.requested_by_user_id is not None
            else None
        )
        if user is not None:
            users.add_user_project(session, user.id, row.project, actor)  # type: ignore[arg-type]
            granted = user.username
        session.delete(row)
        _audit_enrollment(
            session, audit.AuditAction.ENROLLMENT_APPROVED, actor, row, granted_to=granted
        )
        return approved | {"granted_to": granted}


def reject_enrollment(enrollment_id: int, actor: str | None = None) -> dict[str, Any]:
    """Reject a pending project: the request is deleted, no project is created.

    Raises:
        NotFoundError: Unknown or expired request.
    """
    with session_scope() as session:
        row = _pending(session, enrollment_id)
        rejected = _enrollment_public(session, row)
        session.delete(row)
        _audit_enrollment(session, audit.AuditAction.ENROLLMENT_REJECTED, actor, row)
        return rejected
