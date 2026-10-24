"""Access control of the web interface: permissions, roles, groups and their members.

- A **permission** (Permission) allows one kind of action. ``reports.read`` and
  ``findings.triage`` are *scoped*: a role made only of scoped permissions may be given to a
  group on a list of projects. The other permissions concern the whole controller.
- A **role** (AccessRole) is a named set of permissions. The two built-in roles ``reader`` and
  ``admin`` can be neither changed nor deleted, because the code relies on them: ``admin`` is
  given to the first administrator and to SECREVIEW_OIDC_ADMIN_GROUPS, ``reader`` to the project
  groups. Their permissions are those of SYSTEM_ROLES, so that a new permission reaches
  ``admin`` without a migration. Every other role, ``triager`` and ``mcp-user`` included
  (created with the database), is an ordinary role that an administrator changes or deletes.
- A **group** (UserGroup) has roles (GroupRole, each on every project or on a list of projects)
  and members (GroupMember). An administrator adds members (``local``); for a group with
  ``sso``, the OIDC users whose groups claim holds the name of the group are members too
  (``oidc``, replaced at each login, see sync_sso_groups). A value of the claim that names no
  group is ignored.
- ``SECREVIEW_OIDC_ADMIN_GROUPS`` names OIDC groups that hold the ``admin`` role: at a login, a
  listed group of the claim that does not exist yet is created (with ``sso`` and the ``admin``
  role), so that a deployment that only uses OIDC gets its first administrator.
  ``SECREVIEW_OIDC_DEFAULT_GROUP`` names a group every OIDC user joins at each login.
- A user never holds a role of its own: every permission comes from a group. An administrator
  gives a developer the reading of a project by adding it to the **project group** of the
  project (see ensure_project_group): a group without OIDC whose only role is ``reader`` on
  that project.
- An MCP client without a token **enrolls** a project (see enroll_project): the project waits
  (``ProjectEnrollment``) until a user with ``projects.create`` approves it, which creates its
  project group without any member, or rejects it; a request nobody approved within
  SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS is deleted. Nobody gains any access: the developer
  signs in to the web interface, creates a personal ``mcp`` token and asks an administrator to
  join the project group.
- A user with ``projects.create`` may create a **new** project (see create_project): the
  controller creates its project group and adds the user to it, so that the user reads the
  project and its personal ``mcp`` token reaches it. A project already known (reports, roles of
  a group or tokens) is refused: the permission never grants the reading of an existing
  project.
- A user with ``projects.delete`` may delete a project and everything that refers to it (see
  delete_project): its reports, findings and comments, its project group, the project in the
  roles of the other groups and in the tokens (a token left without project is revoked). The
  audit log keeps its events.
- A user needs ``mcp_tokens.create`` to create a personal ``mcp`` or ``ci`` token, held by the
  ordinary role ``mcp-user`` (created with the database). A token already created keeps working
  without it: an administrator revokes it from the Tokens screen.

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
from datetime import timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, select

from .. import audit, ticketing
from ..config import Settings, get_settings
from ..http_server import Role
from ..reports.services import NotFoundError
from ..rules.scanner import redact_secrets
from ..storage.database import session_scope
from ..storage.models import (
    AccessRole,
    ApiToken,
    ApiTokenProject,
    Finding,
    FindingComment,
    FindingTicket,
    GroupMember,
    GroupRole,
    ProjectEnrollment,
    SecurityReport,
    UserGroup,
    WebUser,
    as_utc,
    utcnow,
)
from .rate_limit import RateLimit
from .token_store import MAX_PROJECTS_PER_TOKEN, _clean_project, forget_project


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
    # Project tokens
    TOKENS_MANAGE = "tokens.manage"
    # Report language, outgoing proxy and advisory database
    SETTINGS_MANAGE = "settings.manage"
    # Web users, groups, roles and OIDC settings: whoever holds it can give itself any permission
    USERS_MANAGE = "users.manage"
    # Audit log
    AUDIT_READ = "audit.read"
    # Create a new project, read by its creator (see create_project)
    PROJECTS_CREATE = "projects.create"
    # Delete a project with its reports, findings and references (see delete_project)
    PROJECTS_DELETE = "projects.delete"
    # Create a personal mcp or ci token (My account), which reaches the projects its user may read
    MCP_TOKENS_CREATE = "mcp_tokens.create"


# Permissions limited to the projects of a binding (the others concern the whole controller)
SCOPED_PERMISSIONS = frozenset({Permission.REPORTS_READ, Permission.FINDINGS_TRIAGE})
ALL_PERMISSIONS = frozenset(Permission)
# Built-in roles, which the code relies on (``triager`` and ``mcp-user`` are ordinary ones)
READER_ROLE = "reader"
ADMIN_ROLE = "admin"
SYSTEM_ROLES: dict[str, frozenset[Permission]] = {
    READER_ROLE: frozenset({Permission.REPORTS_READ}),
    ADMIN_ROLE: ALL_PERMISSIONS,
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

# Enrollment (see enroll_project): anybody may call it, so it is bounded. At most
# MAX_PENDING_PROJECTS projects wait for an approval, the enrollments of one client address are
# limited per hour, and a request nobody approved within SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS
# is deleted (audited with the actor ENROLLMENT_ACTOR).
ENROLLMENT_ACTOR = "enrollment"
MAX_PENDING_PROJECTS = 20
MAX_ENROLLMENTS_PER_ADDRESS = 5
ENROLLMENT_WINDOW_SECONDS = 3600
MAX_REQUESTED_BY_CHARS = 200
MAX_ADDRESS_CHARS = 64
_enrollment_limit = RateLimit("enrollment", ENROLLMENT_WINDOW_SECONDS)


class EnrollmentThrottled(ValueError):
    """Too many enrollments from one client address (HTTP 429)."""


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
    """Validate and normalize the projects of a binding (empty: every project).

    Only a role made of scoped permissions may list projects.
    """
    cleaned = list(dict.fromkeys(_clean_project(name) for name in projects or ()))
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
    role_id = ensure_system_roles(session)[ADMIN_ROLE]
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
    reader = ensure_system_roles(session)[READER_ROLE]
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
    reader = ensure_system_roles(session)[READER_ROLE]
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


def bound_projects(session: Session) -> set[str]:
    """Projects named by the roles of the groups (a role on every project names none)."""
    rows = session.exec(select(GroupRole.projects).where(GroupRole.projects != "[]")).all()
    return {name for projects in rows for name in json.loads(projects)}


def project_exists(session: Session, project: str) -> bool:
    """True when ``project`` is known: it has a report, a role of a group names it, or a token
    reaches it."""
    checks = (
        select(SecurityReport.id).where(SecurityReport.project == project),
        select(ApiTokenProject.id).where(ApiTokenProject.project == project),
        select(ApiToken.id).where(ApiToken.project == project),
    )
    if any(session.exec(query.limit(1)).first() is not None for query in checks):
        return True
    return project in bound_projects(session)


def create_project(user_id: int, project: str, actor: str | None = None) -> dict[str, Any]:
    """Create a new project for the web user ``user_id`` (``projects.create``): its project
    group (see ensure_project_group) is created and the user added to it, so that the user
    reads the project and its personal ``mcp`` token reaches it.

    Raises:
        ValueError: Invalid name, project already known (see project_exists: the permission
            never opens an existing project), or MAX_GROUPS groups already stored.
        NotFoundError: If the user does not exist.
    """
    cleaned = clean_projects([Permission.REPORTS_READ], [project])[0]
    with session_scope() as session:
        if session.get(WebUser, user_id) is None:
            raise NotFoundError(f"Web user {user_id} not found")
        if project_exists(session, cleaned):
            raise ValueError(f"Project '{cleaned}' already exists")
        group = ensure_project_group(session, cleaned, actor)
        add_user_to_group(session, user_id, group.id, actor)  # type: ignore[arg-type]
        # A request for the same project is settled by its creation
        for pending in session.exec(
            select(ProjectEnrollment).where(ProjectEnrollment.project == cleaned)
        ).all():
            session.delete(pending)
        audit.record(
            session,
            audit.AuditAction.PROJECT_CREATED,
            actor,
            "project",
            cleaned,
            cleaned,
            {"group": group.name, "user_id": user_id},
        )
        return {"project": cleaned, "group_id": group.id, "group": group.name}


def _delete_reports(session: Session, project: str) -> dict[str, int]:
    """Delete the reports of ``project`` with their findings, comments and tickets; return the
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
    session.exec(delete(FindingTicket).where(col(FindingTicket.finding_id).in_(findings)))
    session.exec(delete(Finding).where(col(Finding.report_id).in_(reports)))
    session.exec(delete(SecurityReport).where(SecurityReport.project == project))
    return counts


def _forget_project_roles(
    session: Session, project: str, actor: str | None
) -> dict[str, list[str]]:
    """Remove ``project`` from the roles of the groups and return the names of the groups.

    A role left without project is removed (an empty list would reach every project). A
    project group (``project:`` name, without OIDC) left without role is deleted with its
    members; the other groups are kept. Each change is audited.
    """
    changed: set[int] = set()
    for binding in session.exec(select(GroupRole).where(GroupRole.projects != "[]")).all():
        projects = json.loads(binding.projects)
        if project not in projects:
            continue
        remaining = [name for name in projects if name != project]
        if remaining:
            binding.projects = json.dumps(remaining)
            session.add(binding)
        else:
            session.delete(binding)
        changed.add(binding.group_id)
    session.flush()
    result: dict[str, list[str]] = {"groups_deleted": [], "groups_changed": []}
    for group_id in sorted(changed):
        row = session.get(UserGroup, group_id)
        if row is None:
            continue
        roles = session.exec(
            select(GroupRole, AccessRole)
            .join(AccessRole, col(GroupRole.role_id) == col(AccessRole.id))
            .where(GroupRole.group_id == group_id)
        ).all()
        if not roles and not row.sso and row.name.startswith(PROJECT_GROUP_PREFIX):
            for member in session.exec(
                select(GroupMember).where(GroupMember.group_id == group_id)
            ).all():
                session.delete(member)
            session.delete(row)
            result["groups_deleted"].append(row.name)
            audit.record(
                session,
                audit.AuditAction.GROUP_DELETED,
                actor,
                "group",
                group_id,
                project,
                {"name": row.name},
            )
            continue
        row.updated_at = utcnow()
        session.add(row)
        result["groups_changed"].append(row.name)
        audit.record(
            session,
            audit.AuditAction.GROUP_ROLES_CHANGED,
            actor,
            "group",
            group_id,
            project,
            {
                "name": row.name,
                "roles": {
                    role.name: json.loads(binding.projects) or None for binding, role in roles
                },
            },
        )
    session.flush()
    return result


def delete_project(project: str, actor: str | None = None) -> dict[str, Any]:
    """Delete ``project`` and everything that refers to it (``projects.delete``), in one
    transaction: its reports, findings and comments, the project in the roles of the groups
    (see _forget_project_roles) and in the tokens (see token_store.forget_project). The audit
    log keeps the events of the project and records ``project.deleted``.

    Raises:
        ValueError: Invalid name.
        NotFoundError: If the project is not known (see project_exists).
    """
    cleaned = clean_projects([Permission.REPORTS_READ], [project])[0]
    with session_scope() as session:
        if not project_exists(session, cleaned):
            raise NotFoundError(f"Project '{cleaned}' not found")
        deleted: dict[str, Any] = {"project": cleaned}
        deleted |= _delete_reports(session, cleaned)
        deleted |= _forget_project_roles(session, cleaned, actor)
        deleted |= forget_project(session, cleaned, actor)
        ticketing.forget_project(session, cleaned)
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


# ── Enrollment ───────────────────────────────────────────────────────────────


def _enrollment_public(row: ProjectEnrollment) -> dict[str, Any]:
    """A pending project, with the date its request expires."""
    ttl = timedelta(days=get_settings().project_enrollment_ttl_days)
    return {
        "id": row.id,
        "project": row.project,
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


def _clean_requester(
    requested_by: str | None, requested_from: str | None
) -> tuple[str | None, str | None]:
    """Bound the requester fields; ``requested_by`` is free text, so secrets are masked."""
    if requested_by is not None:
        requested_by = redact_secrets(requested_by.strip())[:MAX_REQUESTED_BY_CHARS] or None
    if requested_from is not None:
        requested_from = requested_from[:MAX_ADDRESS_CHARS]
    return requested_by, requested_from


def enroll_project(
    project: str,
    requested_by: str | None = None,
    requested_from: str | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """Request a project for an MCP client (anybody may call it): no token is created.

    An unknown project waits for a user with ``projects.create`` (see approve_enrollment); a
    project already known, or already pending, is unchanged. The answer is the same in every
    case, so that it does not tell whether a project exists; it says what the user does next:
    sign in to the web interface (SECREVIEW_WEB_URL), create a personal MCP token and ask an
    administrator to approve the project and give access to it. Every request is audited
    (``actor``: the token of the caller, else ``anonymous``), with ``requested_by`` (free text,
    redacted) and the client address ``requested_from``.

    Raises:
        EnrollmentThrottled: Too many enrollments from this address.
        ValueError: Invalid project name, or MAX_PENDING_PROJECTS projects already pending.
    """
    cleaned = clean_projects([Permission.REPORTS_READ], [project])[0]
    requested_by, requested_from = _clean_requester(requested_by, requested_from)
    if (
        requested_from is not None
        and _enrollment_limit.hit(requested_from) > MAX_ENROLLMENTS_PER_ADDRESS
    ):
        raise EnrollmentThrottled("Too many enrollments from this address; retry later")
    actor = actor or audit.ANONYMOUS_ACTOR
    with session_scope() as session:
        _purge_expired_enrollments(session)
        pending = session.exec(
            select(ProjectEnrollment).where(ProjectEnrollment.project == cleaned)
        ).first()
        requested = pending is None and not project_exists(session, cleaned)
        if requested:
            count = session.exec(select(func.count()).select_from(ProjectEnrollment)).one()
            if count >= MAX_PENDING_PROJECTS:
                raise ValueError(
                    "Too many projects are waiting for an administrator; ask one to create the "
                    "project"
                )
            row = ProjectEnrollment(
                project=cleaned,
                requested_by=requested_by,
                requested_from=requested_from,
                requested_with=actor[:MAX_REQUESTED_BY_CHARS],
            )
            session.add(row)
            try:
                session.flush()
            except IntegrityError:
                # Same project requested at the same time: the first request stands
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
                "requested_by": requested_by,
                "requested_from": requested_from,
            },
        )
    web_url = get_settings().web_url
    return {
        "project": cleaned,
        "web_url": web_url,
        "next_steps": enrollment_next_steps(cleaned, web_url),
    }


def enrollment_next_steps(project: str, web_url: str | None) -> str:
    """What the user does after the enrollment of ``project`` (no token is created)."""
    where = f"the web interface ({web_url})" if web_url else "the web interface"
    return (
        f"No token is created by the enrollment. Ask the user to sign in to {where}, to create "
        "a personal MCP token in My account (shown once) and to put it in the MCP client "
        "configuration as 'Authorization: Bearer <token>', then to reconnect. A new project "
        "waits for an administrator to approve it (Projects screen); the token reaches the "
        f"projects the user may read: an administrator gives access to project '{project}' by "
        f"adding the user to the group '{PROJECT_GROUP_PREFIX}{project}'."
    )


def list_enrollments() -> list[dict[str, Any]]:
    """The pending projects, oldest first (the expired requests are deleted first)."""
    with session_scope() as session:
        _purge_expired_enrollments(session)
        rows = session.exec(
            select(ProjectEnrollment).order_by(col(ProjectEnrollment.created_at))
        ).all()
        return [_enrollment_public(row) for row in rows]


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


def approve_enrollment(enrollment_id: int, actor: str | None = None) -> dict[str, Any]:
    """Approve a pending project: its project group is created without any member, so that the
    project exists; nobody gains any access (an administrator adds members to the group).

    Raises:
        NotFoundError: Unknown or expired request.
        ValueError: MAX_GROUPS groups already stored.
    """
    with session_scope() as session:
        row = _pending(session, enrollment_id)
        approved = _enrollment_public(row)
        group = ensure_project_group(session, row.project, actor)
        session.delete(row)
        _audit_enrollment(
            session, audit.AuditAction.ENROLLMENT_APPROVED, actor, row, group=group.name
        )
        return approved | {"group_id": group.id, "group": group.name}


def reject_enrollment(enrollment_id: int, actor: str | None = None) -> dict[str, Any]:
    """Reject a pending project: the request is deleted, no project is created.

    Raises:
        NotFoundError: Unknown or expired request.
    """
    with session_scope() as session:
        row = _pending(session, enrollment_id)
        rejected = _enrollment_public(row)
        session.delete(row)
        _audit_enrollment(session, audit.AuditAction.ENROLLMENT_REJECTED, actor, row)
        return rejected


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
