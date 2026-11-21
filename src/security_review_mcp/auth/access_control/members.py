"""Members of a project."""

import json
import logging
from collections.abc import Iterable
from typing import Any

from sqlalchemy import delete
from sqlmodel import Session, col, select

from ...observability import audit
from ...reports.services import NotFoundError
from ...storage.database import session_scope
from ...storage.models import (
    OidcRoleMapping,
    Project,
    ProjectEnrollment,
    UserOidcClaim,
    UserProject,
    UserRole,
    WebUser,
)
from .core import (
    MAX_PROJECT_MEMBERS,
    SCOPED_PERMISSIONS,
    _check_version,
    _get_project,
    _version,
    clean_project_permissions,
)
from .users import _check_reach

logger = logging.getLogger("security_review_mcp.web")
# ── Members of a project ─────────────────────────────────────────────────────


def list_project_members(project: str) -> list[dict[str, Any]]:
    """The users who have ``project``, by username: ``permissions`` are those given on the
    project (empty for a user who only has every project), ``all_projects_permissions`` those
    held on every project, by the user or the OIDC mappings of its claims (read only here).

    Raises:
        ValueError: Invalid name.
        NotFoundError: Unknown project.
    """
    with session_scope() as session:
        row = _get_project(session, project)
        return _members_listed(session, row)


def _members_listed(session: Session, project: Project) -> list[dict[str, Any]]:
    """The members of ``project`` (_members_public) and the users who have every project."""
    members = {
        item["user_id"]: {**item, "all_projects_permissions": []}
        for item in _members_public(session, project)
    }
    every: dict[int, set[str]] = {}
    for user in session.exec(select(WebUser).where(col(WebUser.all_projects_permissions) != "[]")):
        every.setdefault(user.id, set()).update(json.loads(user.all_projects_permissions))  # type: ignore[arg-type]
    for user_id, permissions in session.exec(
        select(UserOidcClaim.user_id, OidcRoleMapping.all_projects_permissions)
        .join(OidcRoleMapping, col(OidcRoleMapping.claim) == col(UserOidcClaim.claim))
        .where(col(OidcRoleMapping.all_projects_permissions) != "[]")
    ).all():
        every.setdefault(user_id, set()).update(json.loads(permissions))
    for user_id, permissions in every.items():
        held = sorted(permissions & SCOPED_PERMISSIONS)
        if not held:
            continue
        if user_id not in members:
            user = session.get(WebUser, user_id)
            if user is None:
                continue
            members[user_id] = {
                "user_id": user.id,
                "username": user.username,
                "auth_source": user.auth_source,
                "permissions": [],
            }
        members[user_id]["all_projects_permissions"] = held
    return sorted(members.values(), key=lambda item: item["username"])


def _members_public(session: Session, project: Project) -> list[dict[str, Any]]:
    """The users given ``project``, with their permissions there."""
    rows = session.exec(
        select(WebUser, UserProject.permissions)
        .join(UserProject, col(UserProject.user_id) == col(WebUser.id))
        .where(UserProject.project_id == project.id)
        .order_by(col(WebUser.username))
    ).all()
    return [
        {
            "user_id": user.id,
            "username": user.username,
            "auth_source": user.auth_source,
            "permissions": json.loads(permissions),
        }
        for user, permissions in rows
    ]


def project_members_version(members: list[dict[str, Any]]) -> str:
    """Version of the members of a project (list_project_members), for set_project_members: the
    users who only have every project do not count."""
    return _version(
        sorted((item["user_id"], item["permissions"]) for item in members if item["permissions"])
    )


def set_project_members(
    project: str,
    members: Iterable[tuple[int, Iterable[str]]],
    actor: str | None = None,
    expected_version: str | None = None,
) -> list[dict[str, Any]]:
    """Replace the users who have ``project``: ``members`` holds (user id, per-project
    permissions). With ``expected_version`` (project_members_version of the members the caller
    read), a change made since then is not undone: the replacement is refused.

    Raises:
        NotFoundError: Unknown project or user.
        StaleVersion: The members changed since ``expected_version``.
        ValueError: Invalid project or permission, more than MAX_PROJECT_MEMBERS members, or a
            user who would have more than MAX_SESSION_PROJECTS projects.
    """
    wanted: dict[int, list[str]] = {}
    for user_id, permissions in members:
        cleaned = clean_project_permissions(permissions)
        wanted[user_id] = sorted(set(wanted.get(user_id, [])) | set(cleaned))
    if len(wanted) > MAX_PROJECT_MEMBERS:
        raise ValueError(f"At most {MAX_PROJECT_MEMBERS} members can be set at once")
    with session_scope() as session:
        row = _get_project(session, project)
        _check_version(project_members_version(_members_public(session, row)), expected_version)
        for user_id in wanted:
            if session.get(WebUser, user_id) is None:
                raise NotFoundError(f"Web user {user_id} not found")
        current = {
            item.user_id: item
            for item in session.exec(
                select(UserProject).where(UserProject.project_id == row.id)
            ).all()
        }
        changed: set[int] = set()
        for user_id, item in current.items():
            if user_id not in wanted:
                session.delete(item)
                changed.add(user_id)
            elif json.loads(item.permissions) != wanted[user_id]:
                item.permissions = json.dumps(wanted[user_id])
                session.add(item)
                changed.add(user_id)
        for user_id, permissions in wanted.items():
            if user_id not in current:
                session.add(
                    UserProject(
                        user_id=user_id,
                        project_id=row.id,  # type: ignore[arg-type]
                        permissions=json.dumps(permissions),
                        created_by=actor,
                    )
                )
                changed.add(user_id)
        session.flush()
        for user_id in sorted(changed):
            _check_reach(session, user_id)
            audit.record(
                session,
                audit.AuditAction.USER_PROJECTS_CHANGED,
                actor,
                "user",
                user_id,
                row.name,
                {
                    "projects": [f"{row.name}={','.join(wanted[user_id])}"]
                    if user_id in wanted
                    else [],
                    "removed": [] if user_id in wanted else [row.name],
                    "all_projects_permissions": None,
                },
            )
        return _members_listed(session, row)


def forget_user(session: Session, user_id: int) -> None:
    """Delete every role and OIDC claim of a user and forget it in the pending projects (before
    the user itself)."""
    for model in (UserRole, UserProject, UserOidcClaim):
        session.exec(delete(model).where(model.user_id == user_id))  # type: ignore[attr-defined]
    for row in session.exec(
        select(ProjectEnrollment).where(ProjectEnrollment.requested_by_user_id == user_id)
    ).all():
        row.requested_by_user_id = None
        session.add(row)
    session.flush()
