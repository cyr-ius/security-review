"""Access control of the web interface: permissions, roles, groups and their members.

- A **permission** (Permission) allows one kind of action. ``reports.read`` and
  ``findings.triage`` are *scoped*: a role made only of scoped permissions may be given to a
  group on a list of projects. The other permissions concern the whole controller.
- A **role** (AccessRole) is a named set of permissions. The system roles ``reader``,
  ``triager`` and ``admin`` can be neither changed nor deleted: their permissions are those of
  SYSTEM_ROLES, so that a new permission reaches ``admin`` without a migration.
- A **group** (UserGroup) has roles (GroupRole, each on every project or on a list of projects)
  and members (GroupMember). An administrator adds members (``local``); for a group with
  ``sso``, the SSO users whose groups claim holds the name of the group are members too
  (``oidc``, replaced at each login, see sync_sso_groups). A value of the claim that names no
  group is ignored.
- ``SECREVIEW_OIDC_ADMIN_GROUPS`` names SSO groups that hold the ``admin`` role: at a login, a
  listed group of the claim that does not exist yet is created (with ``sso`` and the ``admin``
  role), so that a deployment that only uses SSO gets its first administrator.
  ``SECREVIEW_OIDC_DEFAULT_GROUP`` names a group every SSO user joins at each login.
- A role may also be given **directly to a user** (UserRole), on every project or on a list of
  projects, in addition to its groups (see set_user_roles).

The grants of a user (see user_grants) are the union of the permissions of the roles of all its
groups and of its direct roles. A scoped permission reaches every project when one of its
bindings does, otherwise the union of their projects. At least one user keeps ``users.manage``:
a change that would remove the last one is refused (see _guard_managers).

The bearer tokens keep their fixed roles (see http_server.Role); token_grants gives the
permissions of the ``reader``, ``triager`` and ``admin`` tokens.
"""

import json
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, select

from . import audit
from .config import Settings
from .database import session_scope
from .http_server import Role
from .models import AccessRole, GroupMember, GroupRole, UserGroup, UserRole, WebUser, utcnow
from .services import NotFoundError
from .token_store import MAX_PROJECTS_PER_TOKEN, _clean_project


class Permission(StrEnum):
    """What a role allows in the web interface and the REST API."""

    # Projects, reports, findings, posture, trend and SARIF
    REPORTS_READ = "reports.read"
    # Change the status of a finding, reject the proposal of an agent
    FINDINGS_TRIAGE = "findings.triage"
    # Scan rules and checklists
    RULES_MANAGE = "rules.manage"
    # Development standards
    STANDARDS_MANAGE = "standards.manage"
    # Project tokens and enrollment requests
    TOKENS_MANAGE = "tokens.manage"
    # Report language, outgoing proxy and advisory database
    SETTINGS_MANAGE = "settings.manage"
    # Web users, groups, roles and SSO settings: whoever holds it can give itself any permission
    USERS_MANAGE = "users.manage"
    # Audit log
    AUDIT_READ = "audit.read"


# Permissions limited to the projects of a binding (the others concern the whole controller)
SCOPED_PERMISSIONS = frozenset({Permission.REPORTS_READ, Permission.FINDINGS_TRIAGE})
ALL_PERMISSIONS = frozenset(Permission)
SYSTEM_ROLES: dict[str, frozenset[Permission]] = {
    Role.READER.value: frozenset({Permission.REPORTS_READ}),
    Role.TRIAGER.value: frozenset({Permission.REPORTS_READ, Permission.FINDINGS_TRIAGE}),
    Role.ADMIN.value: ALL_PERMISSIONS,
}
# Group of the first administrator (not matched against the SSO groups claim)
ADMIN_GROUP = "administrators"
SOURCE_LOCAL = "local"
SOURCE_OIDC = "oidc"

MAX_ROLES = 100
MAX_GROUPS = 500
MAX_ROLES_PER_GROUP = 20
MAX_ROLES_PER_USER = 20
MAX_MEMBERS_PER_CHANGE = 500
MAX_ROLE_NAME_CHARS = 64
MAX_GROUP_NAME_CHARS = 200
MAX_DESCRIPTION_CHARS = 500
# Projects one session may reach (union of several bindings): keeps the grants small
MAX_SESSION_PROJECTS = 200

# What a user may do: each permission, with its projects (None: every project)
Grants = Mapping[str, frozenset[str] | None]


# ── Grants ───────────────────────────────────────────────────────────────────


def combine(bindings: Iterable[tuple[Iterable[str], Iterable[str] | None]]) -> dict[str, Any]:
    """Merge bindings (permissions, projects or None for every project) into grants.

    Raises:
        ValueError: If a permission reaches more than MAX_SESSION_PROJECTS projects.
    """
    grants: dict[str, frozenset[str] | None] = {}
    for permissions, projects in bindings:
        names = None if projects is None else frozenset(projects)
        for permission in permissions:
            if permission not in SCOPED_PERMISSIONS or names is None:
                grants[permission] = None
            elif permission not in grants:
                grants[permission] = names
            elif grants[permission] is not None:
                grants[permission] = grants[permission] | names
    for permission, projects in grants.items():
        if projects is not None and len(projects) > MAX_SESSION_PROJECTS:
            raise ValueError(
                f"The groups grant {permission} on more than {MAX_SESSION_PROJECTS} projects"
            )
    return grants


def token_grants(role: Role, projects: Iterable[str] | None) -> dict[str, Any]:
    """Grants of a bearer token: those of the system role of the same name (none otherwise)."""
    permissions = SYSTEM_ROLES.get(role.value, frozenset())
    return combine([(permissions, None if projects is None else list(projects))])


def allows(grants: Grants, permission: Permission, project: str | None = None) -> bool:
    """True when ``grants`` hold ``permission`` (on ``project`` when one is given)."""
    if permission not in grants:
        return False
    projects = grants[permission]
    return project is None or projects is None or project in projects


def scope(grants: Grants, permission: Permission) -> frozenset[str] | None:
    """Projects a permission reaches: None for every project, empty when it is not granted."""
    if permission not in grants:
        return frozenset()
    return grants[permission]


def summary_role(grants: Grants) -> Role:
    """Web role that sums up grants: ``admin`` with every permission on every project,
    ``triager`` with the triage permission, ``reader`` otherwise.

    Only the bearer middleware and the display use it: the routes check the permissions.
    """
    if all(grants.get(permission, frozenset()) is None for permission in ALL_PERMISSIONS):
        return Role.ADMIN
    if Permission.FINDINGS_TRIAGE in grants:
        return Role.TRIAGER
    return Role.READER


def _bindings(session: Session, user_id: int) -> list[tuple[frozenset[str], list[str] | None]]:
    """Permissions and projects of every role of every group of a user, and of its direct
    roles."""
    rows = list(
        session.exec(
            select(AccessRole, GroupRole.projects)
            .join(GroupRole, col(GroupRole.role_id) == col(AccessRole.id))
            .join(GroupMember, col(GroupMember.group_id) == col(GroupRole.group_id))
            .where(GroupMember.user_id == user_id)
        ).all()
    )
    rows += session.exec(
        select(AccessRole, UserRole.projects)
        .join(UserRole, col(UserRole.role_id) == col(AccessRole.id))
        .where(UserRole.user_id == user_id)
    ).all()
    return [(_permissions(role), json.loads(projects) or None) for role, projects in rows]


def user_grants(session: Session, user_id: int) -> dict[str, Any]:
    """Grants of a web user through its groups and its direct roles (empty without any).

    Raises:
        ValueError: If a permission reaches more than MAX_SESSION_PROJECTS projects.
    """
    return combine(_bindings(session, user_id))


def managers(session: Session) -> set[int]:
    """Ids of the users that hold ``users.manage`` (through a group or a direct role)."""
    roles = session.exec(select(AccessRole)).all()
    role_ids = [role.id for role in roles if Permission.USERS_MANAGE in _permissions(role)]
    if not role_ids:
        return set()
    group_ids = select(GroupRole.group_id).where(col(GroupRole.role_id).in_(role_ids))
    members = session.exec(
        select(GroupMember.user_id).where(col(GroupMember.group_id).in_(group_ids))
    ).all()
    direct = session.exec(select(UserRole.user_id).where(col(UserRole.role_id).in_(role_ids)))
    return set(members) | set(direct.all())


def _guard_managers(session: Session, before: set[int]) -> None:
    """Refuse a change that leaves no user with ``users.manage`` (when one had it before)."""
    session.flush()
    if before and not managers(session):
        raise ValueError("At least one user must keep the users.manage permission")


# ── Validation ───────────────────────────────────────────────────────────────


def _clean_text(value: str, label: str, limit: int) -> str:
    """Strip a name and check its length and characters."""
    cleaned = value.strip()
    if not 1 <= len(cleaned) <= limit:
        raise ValueError(f"{label} must contain between 1 and {limit} characters")
    if not cleaned.isprintable():
        raise ValueError(f"{label} must not contain control characters")
    return cleaned


def clean_role_name(name: str) -> str:
    """Validate the name of a role."""
    return _clean_text(name, "Role name", MAX_ROLE_NAME_CHARS)


def clean_group_name(name: str) -> str:
    """Validate the name of a group (for an SSO group, a value of the groups claim)."""
    return _clean_text(name, "Group name", MAX_GROUP_NAME_CHARS)


def clean_description(description: str | None) -> str:
    """Validate a description (may be empty)."""
    cleaned = (description or "").strip()
    if len(cleaned) > MAX_DESCRIPTION_CHARS:
        raise ValueError(f"Description must contain at most {MAX_DESCRIPTION_CHARS} characters")
    if not all(char.isprintable() or char in "\n\t" for char in cleaned):
        raise ValueError("Description must not contain control characters")
    return cleaned


def clean_permissions(permissions: Iterable[str]) -> list[str]:
    """Validate the permissions of a role: at least one, all known."""
    cleaned: list[str] = []
    for name in permissions:
        try:
            cleaned.append(Permission(str(name).strip()).value)
        except ValueError:
            raise ValueError(f"Unknown permission '{str(name)[:50]}'") from None
    if not cleaned:
        raise ValueError("A role needs at least one permission")
    return sorted(set(cleaned))


def clean_projects(permissions: Iterable[str], projects: Iterable[str] | None) -> list[str]:
    """Validate the projects of a binding (empty: every project).

    Only a role made of scoped permissions may list projects.
    """
    cleaned = list(dict.fromkeys(_clean_project(name) for name in projects or ()))
    if not all(name.isprintable() for name in cleaned):
        raise ValueError("Project must not contain control characters")
    if cleaned and not set(permissions) <= SCOPED_PERMISSIONS:
        raise ValueError(
            "This role holds permissions on the whole controller: it cannot list projects"
        )
    if len(cleaned) > MAX_PROJECTS_PER_TOKEN:
        raise ValueError(f"A role may be limited to at most {MAX_PROJECTS_PER_TOKEN} projects")
    return cleaned


def parse_groups(value: str) -> set[str]:
    """Group names of a comma-separated setting (``SECREVIEW_OIDC_ADMIN_GROUPS``)."""
    return {item.strip() for item in value.split(",") if item.strip()}


# ── Views ────────────────────────────────────────────────────────────────────


def _permissions(row: AccessRole) -> frozenset[str]:
    """Permissions of a role: those of the code for a system role."""
    if row.system and row.name in SYSTEM_ROLES:
        return frozenset(SYSTEM_ROLES[row.name])
    return frozenset(json.loads(row.permissions)) & ALL_PERMISSIONS


def list_permissions() -> list[dict[str, Any]]:
    """The permissions a role may hold, and whether they can be limited to projects."""
    return [
        {"name": permission.value, "scoped": permission in SCOPED_PERMISSIONS}
        for permission in Permission
    ]


def _role_public(session: Session, row: AccessRole) -> dict[str, Any]:
    """API view of a role, with the number of groups and of users that have it directly."""
    groups = session.exec(
        select(func.count()).select_from(GroupRole).where(GroupRole.role_id == row.id)
    ).one()
    users = session.exec(
        select(func.count()).select_from(UserRole).where(UserRole.role_id == row.id)
    ).one()
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "permissions": sorted(_permissions(row)),
        "system": row.system,
        "scoped": _permissions(row) <= SCOPED_PERMISSIONS,
        "groups": groups,
        "users": users,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
        "created_by": row.created_by,
    }


def _group_public(session: Session, row: UserGroup) -> dict[str, Any]:
    """API view of a group, with its roles and its members."""
    roles = session.exec(
        select(GroupRole, AccessRole)
        .join(AccessRole, col(GroupRole.role_id) == col(AccessRole.id))
        .where(GroupRole.group_id == row.id)
        .order_by(col(AccessRole.name))
    ).all()
    members = session.exec(
        select(GroupMember, WebUser)
        .join(WebUser, col(GroupMember.user_id) == col(WebUser.id))
        .where(GroupMember.group_id == row.id)
        .order_by(col(WebUser.username), col(GroupMember.source))
    ).all()
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "sso": row.sso,
        "roles": [
            {
                "role_id": role.id,
                "name": role.name,
                "projects": json.loads(binding.projects) or None,
            }
            for binding, role in roles
        ],
        "members": [
            {"user_id": user.id, "username": user.username, "source": member.source}
            for member, user in members
        ],
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
        "created_by": row.created_by,
    }


def _get_role(session: Session, role_id: int) -> AccessRole:
    """Return a role by id or raise NotFoundError."""
    row = session.get(AccessRole, role_id)
    if row is None:
        raise NotFoundError(f"Role {role_id} not found")
    return row


def _get_group(session: Session, group_id: int) -> UserGroup:
    """Return a group by id or raise NotFoundError."""
    row = session.get(UserGroup, group_id)
    if row is None:
        raise NotFoundError(f"Group {group_id} not found")
    return row


# ── Roles ────────────────────────────────────────────────────────────────────


def ensure_system_roles(session: Session | None = None) -> dict[str, int]:
    """Create the missing system roles; return the id of each one by name."""
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


def ensure_admin_group(session: Session, name: str = ADMIN_GROUP, sso: bool = False) -> UserGroup:
    """Return the group ``name``, created with the ``admin`` role when it does not exist."""
    row = session.exec(select(UserGroup).where(UserGroup.name == name)).first()
    if row is not None:
        return row
    role_id = ensure_system_roles(session)[Role.ADMIN.value]
    row = UserGroup(name=name, sso=sso, created_by="bootstrap")
    session.add(row)
    session.flush()
    session.add(GroupRole(group_id=row.id, role_id=role_id, projects="[]"))
    session.flush()
    return row


def list_roles() -> list[dict[str, Any]]:
    """Return every role, system roles first, then by name."""
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
) -> dict[str, Any]:
    """Create a custom role; raise ValueError when invalid, duplicated or over the limit."""
    cleaned_name = clean_role_name(name)
    cleaned = clean_permissions(permissions)
    text = clean_description(description)
    try:
        with session_scope() as session:
            count = session.exec(select(func.count()).select_from(AccessRole)).one()
            if count >= MAX_ROLES:
                raise ValueError(f"At most {MAX_ROLES} roles can be stored")
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
) -> dict[str, Any]:
    """Replace the name, description and permissions of a custom role (not a system role).

    The groups that have the role keep it: a role that gains a permission on the whole
    controller cannot stay limited to projects in a group (ValueError).
    """
    cleaned = clean_permissions(permissions)
    text = clean_description(description)
    try:
        with session_scope() as session:
            row = _get_role(session, role_id)
            if row.system:
                raise ValueError(f"The system role {row.name} cannot be changed")
            before = managers(session)
            if not set(cleaned) <= SCOPED_PERMISSIONS:
                limited = session.exec(
                    select(GroupRole).where(
                        GroupRole.role_id == role_id, GroupRole.projects != "[]"
                    )
                ).first()
                if limited is not None:
                    raise ValueError(
                        "This role is limited to projects in a group: it cannot hold permissions "
                        "on the whole controller"
                    )
                limited_user = session.exec(
                    select(UserRole).where(UserRole.role_id == role_id, UserRole.projects != "[]")
                ).first()
                if limited_user is not None:
                    raise ValueError(
                        "This role is limited to projects for a user: it cannot hold permissions "
                        "on the whole controller"
                    )
            previous = sorted(_permissions(row))
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


def delete_role(role_id: int, actor: str | None = None) -> dict[str, Any]:
    """Delete a custom role (the groups and users that have it lose it); raise NotFoundError,
    ValueError."""
    with session_scope() as session:
        row = _get_role(session, role_id)
        if row.system:
            raise ValueError(f"The system role {row.name} cannot be deleted")
        before = managers(session)
        deleted = _role_public(session, row)
        for model in (GroupRole, UserRole):
            for binding in session.exec(select(model).where(model.role_id == role_id)).all():
                session.delete(binding)
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


# ── Groups ───────────────────────────────────────────────────────────────────


def list_groups() -> list[dict[str, Any]]:
    """Return every group with its roles and members, by name."""
    with session_scope() as session:
        rows = session.exec(select(UserGroup).order_by(col(UserGroup.name))).all()
        return [_group_public(session, row) for row in rows]


def get_group(group_id: int) -> dict[str, Any]:
    """Return a group with its roles and members; raise NotFoundError."""
    with session_scope() as session:
        return _group_public(session, _get_group(session, group_id))


def create_group(
    name: str,
    description: str | None = None,
    sso: bool = True,
    actor: str | None = None,
) -> dict[str, Any]:
    """Create a group (no role, no member); raise ValueError when invalid or duplicated."""
    cleaned_name = clean_group_name(name)
    text = clean_description(description)
    try:
        with session_scope() as session:
            count = session.exec(select(func.count()).select_from(UserGroup)).one()
            if count >= MAX_GROUPS:
                raise ValueError(f"At most {MAX_GROUPS} groups can be stored")
            row = UserGroup(name=cleaned_name, description=text, sso=sso, created_by=actor)
            session.add(row)
            session.flush()
            audit.record(
                session,
                audit.AuditAction.GROUP_CREATED,
                actor,
                "group",
                row.id,
                details={"name": cleaned_name, "sso": sso},
            )
            return _group_public(session, row)
    except IntegrityError:
        raise ValueError(f"A group named '{cleaned_name}' already exists") from None


def update_group(
    group_id: int,
    name: str,
    description: str | None = None,
    sso: bool = True,
    actor: str | None = None,
) -> dict[str, Any]:
    """Rename a group, replace its description or its SSO matching.

    The SSO members it loses (renamed group, or ``sso`` turned off) leave it at once.
    """
    cleaned_name = clean_group_name(name)
    text = clean_description(description)
    try:
        with session_scope() as session:
            row = _get_group(session, group_id)
            before = managers(session)
            if row.name != cleaned_name or not sso:
                for member in session.exec(
                    select(GroupMember).where(
                        GroupMember.group_id == group_id, GroupMember.source == SOURCE_OIDC
                    )
                ).all():
                    session.delete(member)
            previous = {"name": row.name, "sso": row.sso}
            row.name, row.description, row.sso = cleaned_name, text, sso
            row.updated_at = utcnow()
            session.add(row)
            _guard_managers(session, before)
            audit.record(
                session,
                audit.AuditAction.GROUP_UPDATED,
                actor,
                "group",
                row.id,
                details={"name": cleaned_name, "sso": sso, "previous": previous},
            )
            return _group_public(session, row)
    except IntegrityError:
        raise ValueError(f"A group named '{cleaned_name}' already exists") from None


def delete_group(group_id: int, actor: str | None = None) -> dict[str, Any]:
    """Delete a group, its roles and its memberships; raise NotFoundError or ValueError."""
    with session_scope() as session:
        row = _get_group(session, group_id)
        before = managers(session)
        deleted = _group_public(session, row)
        for model in (GroupRole, GroupMember):
            for item in session.exec(select(model).where(model.group_id == group_id)).all():
                session.delete(item)
        session.delete(row)
        _guard_managers(session, before)
        audit.record(
            session,
            audit.AuditAction.GROUP_DELETED,
            actor,
            "group",
            group_id,
            details={"name": deleted["name"]},
        )
        return deleted


def set_group_roles(
    group_id: int,
    bindings: Iterable[tuple[int, Iterable[str] | None]],
    actor: str | None = None,
) -> dict[str, Any]:
    """Replace the roles of a group: ``bindings`` holds (role id, projects or None)."""
    items = list(bindings)
    if len(items) > MAX_ROLES_PER_GROUP:
        raise ValueError(f"A group may have at most {MAX_ROLES_PER_GROUP} roles")
    with session_scope() as session:
        row = _get_group(session, group_id)
        before = managers(session)
        cleaned: dict[int, list[str]] = {}
        names: dict[str, list[str] | None] = {}
        for role_id, projects in items:
            if role_id in cleaned:
                raise ValueError(f"Role {role_id} is given twice to the group")
            role = _get_role(session, role_id)
            cleaned[role_id] = clean_projects(_permissions(role), projects)
            names[role.name] = cleaned[role_id] or None
        for binding in session.exec(select(GroupRole).where(GroupRole.group_id == group_id)).all():
            session.delete(binding)
        session.flush()
        for role_id, projects in cleaned.items():
            session.add(
                GroupRole(group_id=group_id, role_id=role_id, projects=json.dumps(projects))
            )
        row.updated_at = utcnow()
        session.add(row)
        _guard_managers(session, before)
        audit.record(
            session,
            audit.AuditAction.GROUP_ROLES_CHANGED,
            actor,
            "group",
            group_id,
            details={"name": row.name, "roles": names},
        )
        return _group_public(session, row)


def _check_users(session: Session, user_ids: Iterable[int]) -> list[int]:
    """Validate a list of user ids (all must exist); duplicates are dropped."""
    ids = list(dict.fromkeys(user_ids))
    if len(ids) > MAX_MEMBERS_PER_CHANGE:
        raise ValueError(f"At most {MAX_MEMBERS_PER_CHANGE} members can be set at once")
    if ids:
        found = set(session.exec(select(WebUser.id).where(col(WebUser.id).in_(ids))).all())
        missing = [user_id for user_id in ids if user_id not in found]
        if missing:
            raise NotFoundError(f"Web user {missing[0]} not found")
    return ids


def set_group_members(
    group_id: int, user_ids: Iterable[int], actor: str | None = None
) -> dict[str, Any]:
    """Replace the members an administrator added to a group (its SSO members are kept)."""
    with session_scope() as session:
        row = _get_group(session, group_id)
        ids = _check_users(session, user_ids)
        before = managers(session)
        current = session.exec(
            select(GroupMember).where(
                GroupMember.group_id == group_id, GroupMember.source == SOURCE_LOCAL
            )
        ).all()
        kept = {member.user_id for member in current}
        for member in current:
            if member.user_id not in ids:
                session.delete(member)
        for user_id in ids:
            if user_id not in kept:
                session.add(GroupMember(group_id=group_id, user_id=user_id, source=SOURCE_LOCAL))
        row.updated_at = utcnow()
        session.add(row)
        _guard_managers(session, before)
        audit.record(
            session,
            audit.AuditAction.GROUP_MEMBERS_CHANGED,
            actor,
            "group",
            group_id,
            details={
                "name": row.name,
                "added": sorted(set(ids) - kept),
                "removed": sorted(kept - set(ids)),
            },
        )
        return _group_public(session, row)


# ── Groups of a user ─────────────────────────────────────────────────────────


def user_groups(session: Session, user_id: int) -> list[dict[str, Any]]:
    """Groups of a user: id, name and source of each membership, by name."""
    rows = session.exec(
        select(GroupMember, UserGroup)
        .join(UserGroup, col(GroupMember.group_id) == col(UserGroup.id))
        .where(GroupMember.user_id == user_id)
        .order_by(col(UserGroup.name), col(GroupMember.source))
    ).all()
    return [
        {"group_id": group.id, "name": group.name, "source": member.source}
        for member, group in rows
    ]


def _check_groups(session: Session, group_ids: Iterable[int]) -> list[int]:
    """Validate a list of group ids (all must exist); duplicates are dropped."""
    ids = list(dict.fromkeys(group_ids))
    if len(ids) > MAX_GROUPS:
        raise ValueError(f"A user may belong to at most {MAX_GROUPS} groups")
    if ids:
        found = set(session.exec(select(UserGroup.id).where(col(UserGroup.id).in_(ids))).all())
        missing = [group_id for group_id in ids if group_id not in found]
        if missing:
            raise NotFoundError(f"Group {missing[0]} not found")
    return ids


def find_groups(session: Session, names: Iterable[str]) -> list[int]:
    """Ids of the groups with these names (CLI); raise NotFoundError for an unknown name."""
    ids: list[int] = []
    for name in dict.fromkeys(names):
        row = session.exec(select(UserGroup).where(UserGroup.name == name.strip())).first()
        if row is None:
            raise NotFoundError(f"Group '{name}' not found")
        ids.append(row.id)  # type: ignore[arg-type]
    return ids


def find_roles(session: Session, specs: Iterable[str]) -> list[tuple[int, list[str] | None]]:
    """Direct roles named on the command line as ``role`` (every project) or
    ``role:project,project``; raise NotFoundError for an unknown role."""
    bindings: list[tuple[int, list[str] | None]] = []
    for spec in specs:
        name, _, projects = spec.partition(":")
        row = session.exec(select(AccessRole).where(AccessRole.name == name.strip())).first()
        if row is None:
            raise NotFoundError(f"Role '{name.strip()}' not found")
        listed = [item.strip() for item in projects.split(",") if item.strip()]
        bindings.append((row.id, listed or None))  # type: ignore[arg-type]
    return bindings


def set_user_groups(
    session: Session, user_id: int, group_ids: Iterable[int], actor: str | None = None
) -> None:
    """Replace the groups an administrator gave to a user (its SSO groups are kept).

    Runs in the session of the caller (web_users), which checks the last manager.
    """
    ids = _check_groups(session, group_ids)
    current = session.exec(
        select(GroupMember).where(
            GroupMember.user_id == user_id, GroupMember.source == SOURCE_LOCAL
        )
    ).all()
    kept = {member.group_id for member in current}
    if kept == set(ids):
        return
    for member in current:
        if member.group_id not in ids:
            session.delete(member)
    for group_id in ids:
        if group_id not in kept:
            session.add(GroupMember(group_id=group_id, user_id=user_id, source=SOURCE_LOCAL))
    session.flush()
    audit.record(
        session,
        audit.AuditAction.USER_GROUPS_CHANGED,
        actor,
        "user",
        user_id,
        details={"added": sorted(set(ids) - kept), "removed": sorted(kept - set(ids))},
    )


def add_user_to_group(session: Session, user_id: int, group_id: int) -> None:
    """Add a user to a group as a local member (no change when it already is one)."""
    exists = session.exec(
        select(GroupMember.id).where(
            GroupMember.group_id == group_id,
            GroupMember.user_id == user_id,
            GroupMember.source == SOURCE_LOCAL,
        )
    ).first()
    if exists is None:
        session.add(GroupMember(group_id=group_id, user_id=user_id, source=SOURCE_LOCAL))
        session.flush()


def forget_user(session: Session, user_id: int) -> None:
    """Delete every membership and direct role of a user (before the user itself)."""
    for model in (GroupMember, UserRole):
        for item in session.exec(select(model).where(model.user_id == user_id)).all():
            session.delete(item)
    session.flush()


# ── Direct roles of a user ───────────────────────────────────────────────────


def user_roles(session: Session, user_id: int) -> list[dict[str, Any]]:
    """Roles given directly to a user: id, name and projects (None: every project), by name."""
    rows = session.exec(
        select(UserRole, AccessRole)
        .join(AccessRole, col(UserRole.role_id) == col(AccessRole.id))
        .where(UserRole.user_id == user_id)
        .order_by(col(AccessRole.name))
    ).all()
    return [
        {"role_id": role.id, "name": role.name, "projects": json.loads(binding.projects) or None}
        for binding, role in rows
    ]


def set_user_roles(
    session: Session,
    user_id: int,
    bindings: Iterable[tuple[int, Iterable[str] | None]],
    actor: str | None = None,
) -> None:
    """Replace the roles given directly to a user: ``bindings`` holds (role id, projects or
    None). The roles of its groups are not concerned.

    Runs in the session of the caller (web_users), which checks the last manager.
    """
    items = list(bindings)
    if len(items) > MAX_ROLES_PER_USER:
        raise ValueError(f"A user may have at most {MAX_ROLES_PER_USER} direct roles")
    cleaned: dict[int, list[str]] = {}
    # Written as on the command line: "role" (every project) or "role:project,project"
    names: list[str] = []
    for role_id, projects in items:
        if role_id in cleaned:
            raise ValueError(f"Role {role_id} is given twice to the user")
        role = _get_role(session, role_id)
        cleaned[role_id] = clean_projects(_permissions(role), projects)
        names.append(":".join([role.name, ",".join(cleaned[role_id])] if projects else [role.name]))
    current = session.exec(select(UserRole).where(UserRole.user_id == user_id)).all()
    if {row.role_id: json.loads(row.projects) for row in current} == cleaned:
        return
    for row in current:
        session.delete(row)
    session.flush()
    for role_id, projects in cleaned.items():
        session.add(UserRole(user_id=user_id, role_id=role_id, projects=json.dumps(projects)))
    session.flush()
    audit.record(
        session,
        audit.AuditAction.USER_ROLES_CHANGED,
        actor,
        "user",
        user_id,
        details={"roles": sorted(names)},
    )


def add_user_project(
    session: Session, user_id: int, role_id: int, project: str, actor: str | None = None
) -> None:
    """Add a project to the direct role ``role_id`` of a user (given on this project only when
    the user does not have it yet); a role on every project is unchanged. The change is audited
    as ``user.roles_changed``."""
    row = session.exec(
        select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
    ).first()
    if row is None:
        row = UserRole(user_id=user_id, role_id=role_id, projects="[]")
    elif row.projects == "[]":
        return
    projects = list(dict.fromkeys([*json.loads(row.projects), _clean_project(project)]))
    if len(projects) > MAX_PROJECTS_PER_TOKEN:
        raise ValueError(f"A user may reach at most {MAX_PROJECTS_PER_TOKEN} projects")
    if projects == json.loads(row.projects):
        return
    row.projects = json.dumps(projects)
    session.add(row)
    session.flush()
    names = [
        ":".join([binding["name"], ",".join(binding["projects"])])
        if binding["projects"]
        else binding["name"]
        for binding in user_roles(session, user_id)
    ]
    audit.record(
        session,
        audit.AuditAction.USER_ROLES_CHANGED,
        actor,
        "user",
        user_id,
        details={"roles": sorted(names)},
    )


def sync_sso_groups(
    session: Session, user_id: int, claim_values: Iterable[str], settings: Settings
) -> list[str]:
    """Replace the SSO memberships of a user with the groups its claim names; return them.

    Only the groups with ``sso`` count. A group of SECREVIEW_OIDC_ADMIN_GROUPS found in the
    claim is first created with the ``admin`` role when missing; the group
    SECREVIEW_OIDC_DEFAULT_GROUP is always joined when it exists.
    """
    values = set(claim_values)
    for name in sorted(parse_groups(settings.oidc_admin_groups) & values):
        ensure_admin_group(session, name, sso=True)
    default = settings.oidc_default_group.strip()
    # At most MAX_GROUPS rows: intersect here rather than send the claim (there may be
    # thousands of values) in the query
    groups = session.exec(select(UserGroup).where(col(UserGroup.sso).is_(True))).all()
    wanted = {group.id: group.name for group in groups if group.name in values}
    if default:
        fallback = session.exec(select(UserGroup).where(UserGroup.name == default)).first()
        if fallback is not None:
            wanted[fallback.id] = fallback.name
    current = session.exec(
        select(GroupMember).where(GroupMember.user_id == user_id, GroupMember.source == SOURCE_OIDC)
    ).all()
    kept = {member.group_id for member in current}
    for member in current:
        if member.group_id not in wanted:
            session.delete(member)
    for group_id in wanted:
        if group_id not in kept:
            session.add(GroupMember(group_id=group_id, user_id=user_id, source=SOURCE_OIDC))
    session.flush()
    return sorted(wanted.values())
