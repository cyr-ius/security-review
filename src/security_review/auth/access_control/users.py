"""Roles and projects of a user."""

import json
import logging
from collections.abc import Iterable
from typing import Any

from sqlmodel import Session, col, func, select

from ...observability import audit
from ...storage import projects as project_store
from ...storage.models import (
    AccessRole,
    Project,
    UserProject,
    UserRole,
    WebUser,
)
from . import core
from .core import (
    REVIEW_PERMISSIONS,
    ProtectedAccessDenied,
    _claim_mappings,
    _get_project,
    _get_role,
    _protected_roles,
    clean_project_permissions,
)

logger = logging.getLogger("security_review.web")
# ── Roles of a user ──────────────────────────────────────────────────────────


def user_access(session: Session, user_id: int) -> dict[str, Any]:
    """Roles of a user, its per-project permissions on every project and its projects with their
    permissions, and those of the mappings of its OIDC claims (``oidc``, read only)."""
    user = session.get(WebUser, user_id)
    roles = session.exec(
        select(AccessRole)
        .join(UserRole, col(UserRole.role_id) == col(AccessRole.id))
        .where(UserRole.user_id == user_id)
        .order_by(col(AccessRole.name))
    ).all()
    projects = session.exec(
        select(Project.name, UserProject.permissions)
        .join(UserProject, col(UserProject.project_id) == col(Project.id))
        .where(UserProject.user_id == user_id)
        .order_by(col(Project.name))
    ).all()
    names = {row.id: row.name for row in session.exec(select(AccessRole)).all()}
    return {
        "roles": [{"role_id": role.id, "name": role.name} for role in roles],
        "all_projects_permissions": json.loads(user.all_projects_permissions) if user else [],
        "projects": [
            {"project": name, "permissions": json.loads(permissions)}
            for name, permissions in projects
        ],
        "oidc": [
            {
                "claim": mapping.claim,
                "roles": [names[item] for item in json.loads(mapping.role_ids) if item in names],
                "all_projects_permissions": json.loads(mapping.all_projects_permissions),
                "projects": json.loads(mapping.projects),
            }
            for mapping in _claim_mappings(session, user_id)
        ],
    }


def _check_roles(session: Session, role_ids: Iterable[int]) -> list[int]:
    """Validate a list of role ids (all must exist); duplicates are dropped."""
    ids = list(dict.fromkeys(role_ids))
    if len(ids) > core.MAX_ROLES:
        raise ValueError(f"A user may hold at most {core.MAX_ROLES} roles")
    for role_id in ids:
        _get_role(session, role_id)
    return ids


def set_user_roles(
    session: Session,
    user_id: int,
    role_ids: Iterable[int],
    actor: str | None = None,
    administrator: bool = False,
) -> None:
    """Replace the roles of a user.

    Runs in the session of the caller (web_users), which checks the last manager.

    Raises:
        NotFoundError: Unknown role.
        ValueError: More than MAX_ROLES roles.
        ProtectedAccessDenied: A caller that is not an ``administrator`` gives or takes away a
            role with a protected permission.
    """
    ids = _check_roles(session, role_ids)
    current = session.exec(select(UserRole).where(UserRole.user_id == user_id)).all()
    kept = {row.role_id for row in current}
    if kept == set(ids):
        return
    if not administrator and (kept ^ set(ids)) & _protected_roles(session):
        raise ProtectedAccessDenied(
            "give or take away a role with a protected permission", "user", user_id
        )
    for row in current:
        if row.role_id not in ids:
            session.delete(row)
    for role_id in ids:
        if role_id not in kept:
            session.add(UserRole(user_id=user_id, role_id=role_id, created_by=actor))
    session.flush()
    audit.record(
        session,
        audit.AuditAction.USER_ROLES_CHANGED,
        actor,
        "user",
        user_id,
        details={"added": sorted(set(ids) - kept), "removed": sorted(kept - set(ids))},
    )


def _lock_user(session: Session, user_id: int) -> None:
    """Lock the row of a user until the end of the transaction (PostgreSQL; SQLite serializes
    the writers), before counting or replacing its projects. FOR NO KEY UPDATE: it does not wait
    for the key share locks of the user_project rows just added (no deadlock between two
    additions)."""
    session.exec(
        select(WebUser.id).where(WebUser.id == user_id).with_for_update(key_share=True)
    ).first()


def _check_reach(session: Session, user_id: int) -> None:
    """Refuse a user with more than MAX_SESSION_PROJECTS projects.

    The row of the user stays locked (_lock_user): two concurrent additions to one user are
    counted one after the other, never both against the projects read before either.
    """
    session.flush()
    _lock_user(session, user_id)
    reached = session.exec(
        select(func.count()).select_from(UserProject).where(UserProject.user_id == user_id)
    ).one()
    if reached > core.MAX_SESSION_PROJECTS:
        raise ValueError(f"A user may have at most {core.MAX_SESSION_PROJECTS} projects")


def set_user_projects(
    session: Session,
    user_id: int,
    projects: Iterable[tuple[str, Iterable[str]]],
    all_projects_permissions: Iterable[str] | None = None,
    actor: str | None = None,
) -> None:
    """Replace the projects of a user: ``projects`` holds (project, per-project permissions);
    ``all_projects_permissions`` (None: unchanged) are its per-project permissions on every
    project.

    Runs in the session of the caller (web_users). Only known projects may be given.

    Raises:
        NotFoundError: Unknown project.
        ValueError: Invalid project or permission, or more than MAX_SESSION_PROJECTS projects.
    """
    wanted: dict[int, list[str]] = {}
    names: dict[int, str] = {}
    for project, permissions in projects:
        row = _get_project(session, project)
        cleaned = clean_project_permissions(permissions)
        wanted[row.id] = sorted(set(wanted.get(row.id, [])) | set(cleaned))  # type: ignore[index]
        names[row.id] = row.name  # type: ignore[index]
    if len(wanted) > core.MAX_SESSION_PROJECTS:
        raise ValueError(f"A user may have at most {core.MAX_SESSION_PROJECTS} projects")
    user = session.get(WebUser, user_id)
    every = (
        None
        if all_projects_permissions is None
        else clean_project_permissions(all_projects_permissions, empty=True)
    )
    changed_every = (
        user is not None
        and every is not None
        and (json.loads(user.all_projects_permissions) != every)
    )
    if changed_every:
        user.all_projects_permissions = json.dumps(every)  # type: ignore[union-attr]
        session.add(user)
    # Read under the lock of the additions (_check_reach): a project joined meanwhile is seen,
    # so removed when not wanted, never left beyond MAX_SESSION_PROJECTS
    _lock_user(session, user_id)
    current = {
        row.project_id: row
        for row in session.exec(select(UserProject).where(UserProject.user_id == user_id)).all()
    }
    previous = {project_id: json.loads(row.permissions) for project_id, row in current.items()}
    if previous == wanted and not changed_every:
        return
    for project_id, row in current.items():
        if project_id not in wanted:
            session.delete(row)
        elif previous[project_id] != wanted[project_id]:
            row.permissions = json.dumps(wanted[project_id])
            session.add(row)
    for project_id, permissions in wanted.items():
        if project_id not in current:
            session.add(
                UserProject(
                    user_id=user_id,
                    project_id=project_id,
                    permissions=json.dumps(permissions),
                    created_by=actor,
                )
            )
    session.flush()
    known = {
        row.id: row.name
        for row in session.exec(
            select(Project).where(col(Project.id).in_(set(previous) | set(wanted)))
        ).all()
    }
    audit.record(
        session,
        audit.AuditAction.USER_PROJECTS_CHANGED,
        actor,
        "user",
        user_id,
        details={
            "projects": sorted(
                f"{known.get(item, '')}={','.join(wanted[item])}" for item in wanted
            ),
            "removed": sorted(known.get(item, "") for item in set(previous) - set(wanted)),
            "all_projects_permissions": every if changed_every else None,
        },
    )


def add_user_project(
    session: Session, user_id: int, project: str, actor: str | None = None
) -> None:
    """Give the review of the known ``project`` (cleaned) to a user, nothing more: added with
    REVIEW_PERMISSIONS (``reports.read`` and ``reports.write``), or those added to the
    permissions the user already holds there (no change when it holds them already); audited as
    ``user.projects_changed``.

    Raises:
        ValueError: The user would have more than MAX_SESSION_PROJECTS projects.
    """
    row = project_store.ensure_project(session, project, actor)
    current = session.exec(
        select(UserProject).where(UserProject.user_id == user_id, UserProject.project_id == row.id)
    ).first()
    if current is not None:
        held = set(json.loads(current.permissions))
        if REVIEW_PERMISSIONS <= held:
            return
        current.permissions = json.dumps(sorted(held | REVIEW_PERMISSIONS))
        session.add(current)
    else:
        session.add(
            UserProject(
                user_id=user_id,
                project_id=row.id,  # type: ignore[arg-type]
                permissions=json.dumps(sorted(REVIEW_PERMISSIONS)),
                created_by=actor,
            )
        )
    _check_reach(session, user_id)
    audit.record(
        session,
        audit.AuditAction.USER_PROJECTS_CHANGED,
        actor,
        "user",
        user_id,
        project,
        {
            "projects": [f"{project}={','.join(sorted(REVIEW_PERMISSIONS))}"],
            "removed": [],
            "all_projects_permissions": None,
        },
    )
