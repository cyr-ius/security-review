"""Roles and the roles of the role tokens."""

import json
import logging
from collections.abc import Iterable
from typing import Any

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, select

from ...observability import audit
from ...storage.database import session_scope
from ...storage.models import (
    AccessRole,
    ApiToken,
    UserRole,
    utcnow,
)
from ..token_store import MAX_PROJECTS_PER_TOKEN, _clean_project
from . import core
from .core import (
    SCOPED_PERMISSIONS,
    SYSTEM_ROLES,
    ProtectedAccessDenied,
    _empty_mapping,
    _get_role,
    _guard_managers,
    _mappings_of,
    _permissions,
    _protected,
    _role_public,
    clean_description,
    clean_permissions,
    clean_project_permissions,
    clean_role_name,
    combine,
    managers,
)

logger = logging.getLogger("security_review.web")
# ── Roles ────────────────────────────────────────────────────────────────────


def ensure_system_roles(session: Session | None = None) -> dict[str, int]:
    """Create the missing built-in roles; return the id of each one by name."""
    if session is None:
        with session_scope() as scoped:
            return ensure_system_roles(scoped)
    rows = session.exec(select(AccessRole).where(col(AccessRole.system).is_(True))).all()
    ids = {row.name: row.id for row in rows if row.id is not None}
    for name, permissions in SYSTEM_ROLES.items():
        if name not in ids:
            row = AccessRole(name=name, permissions=json.dumps(sorted(permissions)), system=True)
            session.add(row)
            session.flush()
            ids[name] = row.id  # type: ignore[assignment]
    return ids


def list_roles() -> list[dict[str, Any]]:
    """Return every role, built-in roles first, then by name."""
    with session_scope() as session:
        rows = session.exec(
            select(AccessRole).order_by(col(AccessRole.system).desc(), col(AccessRole.name))
        ).all()
        return [_role_public(session, row) for row in rows]


def create_role(
    name: str,
    permissions: Iterable[str],
    description: str | None = None,
    actor: str | None = None,
    administrator: bool = False,
) -> dict[str, Any]:
    """Create a custom role; raise ValueError when invalid, duplicated or over the limit, and
    ProtectedAccessDenied when a caller that is not an ``administrator`` gives it a protected
    permission."""
    cleaned_name = clean_role_name(name)
    cleaned = clean_permissions(permissions)
    text = clean_description(description)
    if not administrator and _protected(cleaned):
        raise ProtectedAccessDenied("create a role with a protected permission", "role")
    try:
        with session_scope() as session:
            count = session.exec(select(func.count()).select_from(AccessRole)).one()
            if count >= core.MAX_ROLES:
                raise ValueError(f"At most {core.MAX_ROLES} roles can be stored")
            row = AccessRole(
                name=cleaned_name,
                description=text,
                permissions=json.dumps(cleaned),
                created_by=actor,
            )
            session.add(row)
            session.flush()
            audit.record(
                session,
                audit.AuditAction.ROLE_CREATED,
                actor,
                "role",
                row.id,
                details={"name": cleaned_name, "permissions": cleaned},
            )
            return _role_public(session, row)
    except IntegrityError:
        raise ValueError(f"A role named '{cleaned_name}' already exists") from None


def update_role(
    role_id: int,
    permissions: Iterable[str],
    description: str | None = None,
    name: str | None = None,
    actor: str | None = None,
    administrator: bool = False,
) -> dict[str, Any]:
    """Replace the name, description and permissions of a custom role (not a built-in role).

    The users, mappings and tokens that give the role keep it. Only an ``administrator`` changes
    a role that holds, or would hold, a protected permission (ProtectedAccessDenied).
    """
    cleaned = clean_permissions(permissions)
    text = clean_description(description)
    try:
        with session_scope() as session:
            row = _get_role(session, role_id)
            if row.system:
                raise ValueError(f"The built-in role {row.name} cannot be changed")
            before = managers(session)
            previous = sorted(_permissions(row))
            if not administrator and (_protected(previous) or _protected(cleaned)):
                raise ProtectedAccessDenied(
                    "change a role with a protected permission", "role", role_id
                )
            if name is not None:
                row.name = clean_role_name(name)
            row.description = text
            row.permissions = json.dumps(cleaned)
            row.updated_at = utcnow()
            session.add(row)
            _guard_managers(session, before)
            audit.record(
                session,
                audit.AuditAction.ROLE_UPDATED,
                actor,
                "role",
                row.id,
                details={"name": row.name, "permissions": cleaned, "previous": previous},
            )
            return _role_public(session, row)
    except IntegrityError:
        raise ValueError(f"A role named '{name}' already exists") from None


def delete_role(
    role_id: int, actor: str | None = None, administrator: bool = False
) -> dict[str, Any]:
    """Delete a custom role (the users and mappings that give it lose it); raise NotFoundError,
    ValueError, and ProtectedAccessDenied for a role with a protected permission when the caller
    is not an ``administrator``."""
    with session_scope() as session:
        row = _get_role(session, role_id)
        if row.system:
            raise ValueError(f"The built-in role {row.name} cannot be deleted")
        if not administrator and _protected(_permissions(row)):
            raise ProtectedAccessDenied(
                "delete a role with a protected permission", "role", role_id
            )
        tokens = session.exec(
            select(func.count()).select_from(ApiToken).where(ApiToken.access_role_id == role_id)
        ).one()
        if tokens:
            raise ValueError(
                f"The role {row.name} is used by {tokens} API token(s): revoke them first"
            )
        before = managers(session)
        deleted = _role_public(session, row)
        session.exec(delete(UserRole).where(UserRole.role_id == role_id))  # type: ignore[arg-type]
        for mapping in _mappings_of(session, role_id):
            remaining = [item for item in json.loads(mapping.role_ids) if item != role_id]
            mapping.role_ids = json.dumps(remaining)
            if _empty_mapping(mapping):
                session.delete(mapping)
            else:
                session.add(mapping)
        session.delete(row)
        _guard_managers(session, before)
        audit.record(
            session,
            audit.AuditAction.ROLE_DELETED,
            actor,
            "role",
            role_id,
            details={"name": deleted["name"]},
        )
        return deleted


# ── Role tokens ──────────────────────────────────────────────────────────────


def list_token_roles() -> list[dict[str, Any]]:
    """The roles a role ``api`` token may have: every role, with its permissions."""
    with session_scope() as session:
        rows = session.exec(
            select(AccessRole).order_by(col(AccessRole.system).desc(), col(AccessRole.name))
        ).all()
        return [
            {"id": row.id, "name": row.name, "permissions": sorted(_permissions(row))}
            for row in rows
        ]


def role_token_scope(
    role_id: int, projects: Iterable[str] | None, project_permissions: Iterable[str] = ()
) -> tuple[list[str], list[str] | None, list[str]]:
    """Permissions of the role of a role token, its validated projects (None: every project)
    and its per-project permissions on them.

    Raises:
        NotFoundError: Unknown role.
        ValueError: An empty list of projects, or a permission that is not per project.
    """
    with session_scope() as session:
        permissions = sorted(_permissions(_get_role(session, role_id)))
    scoped = clean_project_permissions(project_permissions, empty=True)
    if projects is None:
        return permissions, None, scoped
    cleaned = list(dict.fromkeys(_clean_project(name) for name in projects))
    if not cleaned:
        raise ValueError("A token needs at least one project (None: every project)")
    if len(cleaned) > MAX_PROJECTS_PER_TOKEN:
        raise ValueError(f"A token may reach at most {MAX_PROJECTS_PER_TOKEN} projects")
    return permissions, cleaned, scoped


def role_token_grants(
    session: Session,
    role_id: int,
    projects: Iterable[str] | None,
    project_permissions: Iterable[str] = (),
) -> dict[str, Any] | None:
    """Grants of a role ``api`` token: the permissions of its role (read now) and its per-project
    permissions on its projects (None: every project); None when the role no longer exists."""
    row = session.get(AccessRole, role_id)
    if row is None:
        return None
    scoped = frozenset(project_permissions) & SCOPED_PERMISSIONS
    return combine(
        [
            (_permissions(row) - SCOPED_PERMISSIONS, None),
            (scoped, None if projects is None else list(projects)),
        ]
    )
