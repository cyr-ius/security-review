"""Access control of the web interface: permissions, roles, groups and their members.

- A **permission** (Permission) allows one kind of action. ``reports.read`` and
  ``findings.triage`` are *scoped*: a role made only of scoped permissions may be given to a
  group on a list of projects. The other permissions concern the whole controller.
- A **role** (AccessRole) is a named set of permissions. The two built-in roles ``reader`` and
  ``admin`` can be neither changed nor deleted, because the code relies on them: ``admin`` is
  given to the first administrator and to SECREVIEW_OIDC_ADMIN_GROUPS, ``reader`` to the project
  groups. Their permissions are those of SYSTEM_ROLES, so that a new permission reaches
  ``admin`` without a migration. Every other role, ``triager`` included (created with the
  database), is an ordinary role that an administrator changes or deletes.
- A **group** (UserGroup) has roles (GroupRole, each on every project or on a list of projects)
  and members (GroupMember). An administrator adds members (``local``); for a group with
  ``sso``, the OIDC users whose groups claim holds the name of the group are members too
  (``oidc``, replaced at each login, see sync_sso_groups). A value of the claim that names no
  group is ignored.
- ``SECREVIEW_OIDC_ADMIN_GROUPS`` names OIDC groups that hold the ``admin`` role: at a login, a
  listed group of the claim that does not exist yet is created (with ``sso`` and the ``admin``
  role), so that a deployment that only uses OIDC gets its first administrator.
  ``SECREVIEW_OIDC_DEFAULT_GROUP`` names a group every OIDC user joins at each login.
- A user never holds a role of its own: every permission comes from a group. The approval of an
  enrollment adds the developer to the **project group** of the project (see
  ensure_project_group): a group without OIDC whose only role is ``reader`` on that project.

The grants of a user (see user_grants) are the union of the permissions of the roles of all its
groups. A scoped permission reaches every project when one of its
bindings does, otherwise the union of their projects. At least one user keeps ``users.manage``:
a change that would remove the last one is refused (see _guard_managers).

The bearer tokens are for machines and keep their fixed roles (see http_server.TOKEN_ROLES):
token_grants gives every permission to an ``admin`` token, none to the others. An ``api`` token
follows this model instead: a personal token holds the grants of its user (user_grants), a role
token the permissions of its role on its projects (role_token_grants), both read at each
request. A role used by a token cannot be deleted.
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
from .models import AccessRole, ApiToken, GroupMember, GroupRole, UserGroup, WebUser, utcnow
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
    # Web users, groups, roles and OIDC settings: whoever holds it can give itself any permission
    USERS_MANAGE = "users.manage"
    # Audit log
    AUDIT_READ = "audit.read"


# Permissions limited to the projects of a binding (the others concern the whole controller)
SCOPED_PERMISSIONS = frozenset({Permission.REPORTS_READ, Permission.FINDINGS_TRIAGE})
ALL_PERMISSIONS = frozenset(Permission)
# Built-in roles, which the code relies on (the ``triager`` role is an ordinary one)
SYSTEM_ROLES: dict[str, frozenset[Permission]] = {
    Role.READER.value: frozenset({Permission.REPORTS_READ}),
    Role.ADMIN.value: ALL_PERMISSIONS,
}
# Group of the first administrator (not matched against the OIDC groups claim)
ADMIN_GROUP = "administrators"
# Name of the group created to give the reading of one project (see ensure_project_group)
PROJECT_GROUP_PREFIX = "project:"
SOURCE_LOCAL = "local"
SOURCE_OIDC = "oidc"

MAX_ROLES = 100
MAX_GROUPS = 500
MAX_ROLES_PER_GROUP = 20
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
    """Grants of a bearer token: every permission for ``admin``, none otherwise (an ``mcp``,
    ``ci`` or ``metrics`` token only reaches its own endpoints)."""
    permissions = ALL_PERMISSIONS if role == Role.ADMIN else frozenset()
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
    """Permissions and projects of every role of every group of a user."""
    rows = session.exec(
        select(AccessRole, GroupRole.projects)
        .join(GroupRole, col(GroupRole.role_id) == col(AccessRole.id))
        .join(GroupMember, col(GroupMember.group_id) == col(GroupRole.group_id))
        .where(GroupMember.user_id == user_id)
    ).all()
    return [(_permissions(role), json.loads(projects) or None) for role, projects in rows]


def user_grants(session: Session, user_id: int) -> dict[str, Any]:
    """Grants of a web user through its groups (empty without any).

    Raises:
        ValueError: If a permission reaches more than MAX_SESSION_PROJECTS projects.
    """
    return combine(_bindings(session, user_id))


def managers(session: Session) -> set[int]:
    """Ids of the users that hold ``users.manage`` (through one of their groups)."""
    roles = session.exec(select(AccessRole)).all()
    role_ids = [role.id for role in roles if Permission.USERS_MANAGE in _permissions(role)]
    if not role_ids:
        return set()
    group_ids = select(GroupRole.group_id).where(col(GroupRole.role_id).in_(role_ids))
    members = session.exec(
        select(GroupMember.user_id).where(col(GroupMember.group_id).in_(group_ids))
    ).all()
    return set(members)


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
    """Validate the name of a group (for an OIDC group, a value of the groups claim)."""
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
    """Permissions of a role: those of the code for a built-in role."""
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
    """API view of a role, with the number of groups that have it."""
    groups = session.exec(
        select(func.count()).select_from(GroupRole).where(GroupRole.role_id == row.id)
    ).one()
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "permissions": sorted(_permissions(row)),
        "system": row.system,
        "scoped": _permissions(row) <= SCOPED_PERMISSIONS,
        "groups": groups,
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
    """Replace the name, description and permissions of a custom role (not a built-in role).

    The groups that have the role keep it: a role that gains a permission on the whole
    controller cannot stay limited to projects in a group (ValueError).
    """
    cleaned = clean_permissions(permissions)
    text = clean_description(description)
    try:
        with session_scope() as session:
            row = _get_role(session, role_id)
            if row.system:
                raise ValueError(f"The built-in role {row.name} cannot be changed")
            before = managers(session)
            if not set(cleaned) <= SCOPED_PERMISSIONS:
                limited = (
                    session.exec(
                        select(GroupRole).where(
                            GroupRole.role_id == role_id, GroupRole.projects != "[]"
                        )
                    ).first()
                    or session.exec(
                        select(ApiToken).where(
                            ApiToken.access_role_id == role_id, col(ApiToken.project).is_not(None)
                        )
                    ).first()
                )
                if limited is not None:
                    raise ValueError(
                        "This role is limited to projects in a group: it cannot hold permissions "
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
    """Delete a custom role (the groups that have it lose it); raise NotFoundError, ValueError."""
    with session_scope() as session:
        row = _get_role(session, role_id)
        if row.system:
            raise ValueError(f"The built-in role {row.name} cannot be deleted")
        tokens = session.exec(
            select(func.count()).select_from(ApiToken).where(ApiToken.access_role_id == role_id)
        ).one()
        if tokens:
            raise ValueError(
                f"The role {row.name} is used by {tokens} API token(s): revoke them first"
            )
        before = managers(session)
        deleted = _role_public(session, row)
        for binding in session.exec(select(GroupRole).where(GroupRole.role_id == role_id)).all():
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


# ── Role tokens ──────────────────────────────────────────────────────────────


def list_token_roles() -> list[dict[str, Any]]:
    """The roles a role ``api`` token may have: every role, with its permissions."""
    with session_scope() as session:
        rows = session.exec(
            select(AccessRole).order_by(col(AccessRole.system).desc(), col(AccessRole.name))
        ).all()
        return [
            {
                "id": row.id,
                "name": row.name,
                "permissions": sorted(_permissions(row)),
                "scoped": _permissions(row) <= SCOPED_PERMISSIONS,
            }
            for row in rows
        ]


def role_token_scope(
    role_id: int, projects: Iterable[str] | None
) -> tuple[list[str], list[str] | None]:
    """Permissions of the role of a new role token, and its validated projects (None: every
    project). Only a role made of scoped permissions may be limited to projects.

    Raises:
        NotFoundError: Unknown role.
        ValueError: Projects refused for this role, or an empty list.
    """
    with session_scope() as session:
        permissions = sorted(_permissions(_get_role(session, role_id)))
    if projects is None:
        return permissions, None
    cleaned = clean_projects(permissions, projects)
    if not cleaned:
        raise ValueError("A token needs at least one project (None: every project)")
    return permissions, cleaned


def role_token_grants(
    session: Session, role_id: int, projects: Iterable[str] | None
) -> dict[str, Any] | None:
    """Grants of a role ``api`` token: the permissions of its role (read now) on its projects
    (None: every project); None when the role no longer exists."""
    row = session.get(AccessRole, role_id)
    if row is None:
        return None
    return combine([(_permissions(row), None if projects is None else list(projects))])


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
    sso: bool = False,
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
    sso: bool = False,
    actor: str | None = None,
) -> dict[str, Any]:
    """Rename a group, replace its description or its OIDC matching.

    The OIDC members it loses (renamed group, or ``sso`` turned off) leave it at once.
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
    """Replace the members an administrator added to a group (its OIDC members are kept)."""
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


def set_user_groups(
    session: Session, user_id: int, group_ids: Iterable[int], actor: str | None = None
) -> None:
    """Replace the groups an administrator gave to a user (its OIDC groups are kept).

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


def add_user_to_group(
    session: Session, user_id: int, group_id: int, actor: str | None = None
) -> None:
    """Add a user to a group as a local member (no change when it already is one); the change
    is audited as ``user.groups_changed``."""
    exists = session.exec(
        select(GroupMember.id).where(
            GroupMember.group_id == group_id,
            GroupMember.user_id == user_id,
            GroupMember.source == SOURCE_LOCAL,
        )
    ).first()
    if exists is not None:
        return
    session.add(GroupMember(group_id=group_id, user_id=user_id, source=SOURCE_LOCAL))
    session.flush()
    audit.record(
        session,
        audit.AuditAction.USER_GROUPS_CHANGED,
        actor,
        "user",
        user_id,
        details={"added": [group_id], "removed": []},
    )


# ── Project groups ───────────────────────────────────────────────────────────


def find_project_group(session: Session, project: str) -> UserGroup | None:
    """The project group of ``project``: a group without OIDC whose only role is ``reader`` on
    this project alone (the oldest one when there are several), or None."""
    reader = ensure_system_roles(session)[Role.READER.value]
    candidates = session.exec(
        select(UserGroup)
        .join(GroupRole, col(GroupRole.group_id) == col(UserGroup.id))
        .where(
            GroupRole.role_id == reader,
            GroupRole.projects == json.dumps([project]),
            col(UserGroup.sso).is_(False),
        )
        .order_by(col(UserGroup.id))
    ).all()
    for group in candidates:
        roles = session.exec(
            select(func.count()).select_from(GroupRole).where(GroupRole.group_id == group.id)
        ).one()
        if roles == 1:
            return group
    return None


def _project_group_name(session: Session, project: str) -> str:
    """A free name for a new project group: ``project:<project>``, cut to the length of a group
    name, followed by a number when another group already has it."""
    base = f"{PROJECT_GROUP_PREFIX}{project}"
    # There are at most MAX_GROUPS groups: one of these names is free
    for number in range(1, MAX_GROUPS + 2):
        suffix = "" if number == 1 else f" ({number})"
        name = base[: MAX_GROUP_NAME_CHARS - len(suffix)] + suffix
        if session.exec(select(UserGroup.id).where(UserGroup.name == name)).first() is None:
            return name
    raise ValueError(f"At most {MAX_GROUPS} groups can be stored")


def ensure_project_group(session: Session, project: str, actor: str | None = None) -> UserGroup:
    """Return the project group of ``project`` (see find_project_group), created when missing:
    ``project:<project>``, without OIDC, with the ``reader`` role on this project only.

    Raises:
        ValueError: Invalid project, MAX_GROUPS groups already stored, or the group created at
            the same time by another approval.
    """
    cleaned = clean_projects([Permission.REPORTS_READ], [project])[0]
    row = find_project_group(session, cleaned)
    if row is not None:
        return row
    if session.exec(select(func.count()).select_from(UserGroup)).one() >= MAX_GROUPS:
        raise ValueError(f"At most {MAX_GROUPS} groups can be stored")
    reader = ensure_system_roles(session)[Role.READER.value]
    row = UserGroup(name=_project_group_name(session, cleaned), sso=False, created_by=actor)
    session.add(row)
    try:
        session.flush()
    except IntegrityError:
        # Same group created at the same time by another approval: the caller's session ends
        raise ValueError(
            f"The group of project '{cleaned}' was created concurrently; retry"
        ) from None
    session.add(GroupRole(group_id=row.id, role_id=reader, projects=json.dumps([cleaned])))
    session.flush()
    audit.record(
        session,
        audit.AuditAction.GROUP_CREATED,
        actor,
        "group",
        row.id,
        details={"name": row.name, "sso": False, "project": cleaned},
    )
    return row


def forget_user(session: Session, user_id: int) -> None:
    """Delete every membership of a user (before the user itself)."""
    for item in session.exec(select(GroupMember).where(GroupMember.user_id == user_id)).all():
        session.delete(item)
    session.flush()


def sync_sso_groups(
    session: Session, user_id: int, claim_values: Iterable[str], settings: Settings
) -> list[str]:
    """Replace the OIDC memberships of a user with the groups its claim names; return them.

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
