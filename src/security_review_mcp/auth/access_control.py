"""Access control of the web interface: permissions, roles, and the roles and projects of the
users.

- A **permission** (Permission) allows one kind of action. ``reports.read``, ``reports.write``
  and ``findings.triage`` are *per project* (SCOPED_PERMISSIONS): they are given with a project,
  or with every project. The other permissions concern the whole controller (SITE_PERMISSIONS).
  ``reports.write`` lets the tokens of a user save reports and propose a status for a finding
  on the project (MCP agent, pipeline scans); it implies ``reports.read`` there.
- A **role** (AccessRole) is a named set of permissions on the whole controller: a role holds
  no per-project permission. The built-in role ``admin`` (every permission on the whole
  controller) can be neither changed nor deleted, because the code relies on it: it is given to
  the first administrator and by SECREVIEW_OIDC_ADMIN_GROUPS. Its permissions are those of
  SYSTEM_ROLES, so that a new permission reaches it without a migration.
- A user holds **roles** (UserRole), **per-project permissions on every project**
  (``WebUser.all_projects_permissions``) and **projects** (UserProject), each with its own
  per-project permissions. An administrator gives them (see set_user_roles, set_user_projects
  and set_project_members).
- An OIDC user also holds the roles, permissions on every project and projects of the
  **mappings** (OidcRoleMapping) that name a value of its roles claim (a project not known yet is
  ignored until it is created); they add up with those of the user. The values of the claim named
  by a mapping are kept at each login (UserOidcClaim, see sync_oidc_claims); a change of the
  mappings applies at once. ``SECREVIEW_OIDC_ADMIN_GROUPS`` names values of the claim that hold
  ``admin``: at a login, a listed value of the claim without a mapping gets one (``admin`` and
  every per-project permission on every project), so that a deployment that only uses OIDC gets
  its first administrator.
- The MCP agent of a user **requests** a project its token does not reach (see
  request_project): a new project is created at once for a user with ``projects.create``;
  otherwise, and always for a project that already exists, the request waits
  (``ProjectEnrollment``) until a user with ``projects.create`` approves it, which gives the
  requesting user the review of the project (``reports.read`` and ``reports.write``, created
  for a new project), or rejects it; a
  request nobody approved within SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS is deleted.
- A user with ``projects.create`` may create a **new** project (see create_project): the
  controller creates it and gives its review to the user, so that its personal ``mcp`` token
  saves reports there. A project already known (see storage.projects) is refused: the
  permission never grants the reading of an existing project.
- A user with ``projects.autojoin`` whose MCP agent requests a project that already exists
  joins it at once (see request_project), with its review. A user with ``users.manage``
  who reads a project may block this autojoin on it (see set_autojoin_blocked): the requests
  then wait for an approval as the others do. ``projects.create`` never blocks nor allows it.
- A user with ``projects.delete`` may delete a project and everything that refers to it (see
  delete_project): its reports, findings and comments, the project of the users, of the mappings
  and of the tokens (a token left without project is revoked). The audit log keeps its events.
- No permission gives the personal ``mcp`` and ``ci`` tokens: every web user may create them
  while SECREVIEW_PERSONAL_TOKENS_ENABLED is true (see token_store). They read the projects of
  ``reports.read`` and write only to those of ``reports.write``.

The grants of a user (see user_grants) are the permissions of all its roles (its own and those
of its mappings) on the whole controller, with its per-project permissions on every project and
on each of its projects. At least one user keeps ``users.manage``: a change that would remove
the last one is refused (see _guard_managers), and an OIDC login never removes it (see
sync_oidc_claims).

The bearer tokens are for machines and keep their fixed roles (see http_server.TOKEN_ROLES):
token_grants gives every permission to an ``admin`` token, none to the others. An ``api`` token
follows this model instead: a personal token holds the grants of its user (user_grants), a role
token the permissions of its role and its per-project permissions on its projects
(role_token_grants), both read at each request. A role used by a token cannot be deleted.
"""

import hashlib
import json
import logging
from collections.abc import Iterable, Mapping
from datetime import timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, or_, select

from .. import app_settings
from ..config import Settings, get_settings
from ..http_server import Role
from ..observability import audit
from ..reports.services import NotFoundError
from ..storage import projects as project_store
from ..storage.database import session_scope
from ..storage.models import (
    AccessRole,
    ApiToken,
    ConnectorTarget,
    Finding,
    FindingComment,
    FindingExport,
    OidcRoleMapping,
    Project,
    ProjectEnrollment,
    SecurityReport,
    UserOidcClaim,
    UserProject,
    UserRole,
    WebUser,
    as_utc,
    utcnow,
)
from .rate_limit import RateLimit
from .token_store import MAX_PROJECTS_PER_TOKEN, _clean_project, forget_project

logger = logging.getLogger("security_review_mcp.web")


class Permission(StrEnum):
    """What a role allows in the web interface and the REST API."""

    # Projects, reports, findings, posture, trend and SARIF
    REPORTS_READ = "reports.read"
    # Save reports and propose a status for a finding, with a personal token (MCP agent, scans)
    REPORTS_WRITE = "reports.write"
    # Change the status of a finding, reject the proposal of an agent
    FINDINGS_TRIAGE = "findings.triage"
    # Read the scan rules and checklists
    RULES_READ = "rules.read"
    # Scan rules and checklists
    RULES_MANAGE = "rules.manage"
    # Read the development standards
    STANDARDS_READ = "standards.read"
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
    # Join an existing project, to review it, when the MCP agent requests it (see request_project)
    PROJECTS_AUTOJOIN = "projects.autojoin"


# Per-project permissions: given with a project (or every project), never by a role; the others
# concern the whole controller and are given by the roles
SCOPED_PERMISSIONS = frozenset(
    {Permission.REPORTS_READ, Permission.REPORTS_WRITE, Permission.FINDINGS_TRIAGE}
)
ALL_PERMISSIONS = frozenset(Permission)
SITE_PERMISSIONS = ALL_PERMISSIONS - SCOPED_PERMISSIONS
# The built-in role, which the code relies on
ADMIN_ROLE = "admin"
SYSTEM_ROLES: dict[str, frozenset[Permission]] = {ADMIN_ROLE: SITE_PERMISSIONS}
# A permission that holds another one, on the same projects (see combine): who manages the
# rules also reads them
IMPLIED_PERMISSIONS: dict[Permission, Permission] = {
    Permission.REPORTS_WRITE: Permission.REPORTS_READ,
    Permission.RULES_MANAGE: Permission.RULES_READ,
    Permission.STANDARDS_MANAGE: Permission.STANDARDS_READ,
}

# What a user gets on a project it creates, joins or is given by an approval: its MCP agent
# reviews it (see add_user_project)
REVIEW_PERMISSIONS = frozenset({Permission.REPORTS_READ.value, Permission.REPORTS_WRITE.value})

MAX_ROLES = 100
MAX_ROLE_NAME_CHARS = 64
MAX_DESCRIPTION_CHARS = 500
# Projects one session may reach (union of several roles): keeps the grants small
MAX_SESSION_PROJECTS = 200
# Members set at once on a project (see set_project_members)
MAX_PROJECT_MEMBERS = 500
# OIDC mappings, and length of a value of the roles claim (an identity provider group)
MAX_OIDC_MAPPINGS = 500
MAX_CLAIM_CHARS = 200
# Actor of the OIDC mappings created by a login (SECREVIEW_OIDC_ADMIN_GROUPS)
OIDC_ACTOR = "oidc"

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


class StaleVersion(ValueError):
    """The list changed since the caller read it: replacing it would undo a change it did not
    see (see set_project_members, set_oidc_mappings)."""


def _version(items: Any) -> str:
    """Version of a stored list, for a caller to replace it only as it read it."""
    return hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()[:32]


def _check_version(current: str, expected: str | None) -> None:
    """Refuse a replacement read from another ``current`` version (None: not checked)."""
    if expected is not None and expected != current:
        raise StaleVersion("The list changed since it was read: reload it and try again")


# What a user may do: each permission, with its projects (None: every project)
Grants = Mapping[str, frozenset[str] | None]


# ── Grants ───────────────────────────────────────────────────────────────────


def combine(bindings: Iterable[tuple[Iterable[str], Iterable[str] | None]]) -> dict[str, Any]:
    """Merge bindings (permissions, projects or None for every project) into grants, with the
    permissions they imply (IMPLIED_PERMISSIONS).

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
    for permission, implied in IMPLIED_PERMISSIONS.items():
        if permission not in grants:
            continue
        # Never wider than the implying permission: a per-project one stays on its projects
        held, already = grants[permission], grants.get(implied, frozenset())
        grants[implied] = None if held is None or already is None else already | held
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


def _project_names(session: Session, names: Iterable[str]) -> list[str]:
    """The known projects among ``names``, in their order."""
    wanted = list(dict.fromkeys(names))
    if not wanted:
        return []
    known = set(session.exec(select(Project.name).where(col(Project.name).in_(wanted))).all())
    return [name for name in wanted if name in known]


def _bindings(session: Session, user_id: int) -> list[tuple[frozenset[str], list[str] | None]]:
    """Permissions and projects of a user: the permissions of its roles and of the roles of the
    mappings of its OIDC claims everywhere, its per-project permissions on every project and on
    each of its projects (and those of its mappings)."""
    user = session.get(WebUser, user_id)
    if user is None:
        return []
    role_ids = set(session.exec(select(UserRole.role_id).where(UserRole.user_id == user_id)).all())
    every = set(json.loads(user.all_projects_permissions))
    per_project: dict[str, set[str]] = {}
    for name, permissions in session.exec(
        select(Project.name, UserProject.permissions)
        .join(UserProject, col(UserProject.project_id) == col(Project.id))
        .where(UserProject.user_id == user_id)
    ).all():
        per_project.setdefault(name, set()).update(json.loads(permissions))
    mapped: dict[str, set[str]] = {}
    for mapping in _claim_mappings(session, user_id):
        role_ids.update(json.loads(mapping.role_ids))
        every.update(json.loads(mapping.all_projects_permissions))
        for item in json.loads(mapping.projects):
            mapped.setdefault(item["project"], set()).update(item["permissions"])
    for name in _project_names(session, mapped):
        per_project.setdefault(name, set()).update(mapped[name])
    bindings: list[tuple[frozenset[str], list[str] | None]] = []
    if role_ids:
        for role in session.exec(select(AccessRole).where(col(AccessRole.id).in_(role_ids))).all():
            bindings.append((_permissions(role) - SCOPED_PERMISSIONS, None))
    bindings.append((frozenset(every) & SCOPED_PERMISSIONS, None))
    for permission in SCOPED_PERMISSIONS - every:
        projects = sorted(name for name, held in per_project.items() if permission in held)
        if projects:
            bindings.append((frozenset({permission}), projects))
    return bindings


def _claim_mappings(session: Session, user_id: int) -> list[OidcRoleMapping]:
    """The OIDC mappings that name a claim of the user at its last login."""
    return list(
        session.exec(
            select(OidcRoleMapping)
            .join(UserOidcClaim, col(UserOidcClaim.claim) == col(OidcRoleMapping.claim))
            .where(UserOidcClaim.user_id == user_id)
            .order_by(col(OidcRoleMapping.claim))
        ).all()
    )


def user_grants(session: Session, user_id: int) -> dict[str, Any]:
    """Grants of a web user through its roles (empty without any).

    Raises:
        ValueError: If a permission reaches more than MAX_SESSION_PROJECTS projects.
    """
    return combine(_bindings(session, user_id))


def _manager_roles(session: Session) -> list[int]:
    """Ids of the roles that hold ``users.manage``."""
    return [
        role.id  # type: ignore[misc]
        for role in session.exec(select(AccessRole)).all()
        if Permission.USERS_MANAGE in _permissions(role)
    ]


def managers(session: Session) -> set[int]:
    """Ids of the users that hold ``users.manage`` (a role of the user, or of the mapping of one
    of its OIDC claims)."""
    role_ids = set(_manager_roles(session))
    if not role_ids:
        return set()
    direct = session.exec(select(UserRole.user_id).where(col(UserRole.role_id).in_(role_ids)))
    # At most MAX_OIDC_MAPPINGS mappings: their role lists are read here
    claims = [
        mapping.claim
        for mapping in session.exec(select(OidcRoleMapping)).all()
        if role_ids & set(json.loads(mapping.role_ids))
    ]
    mapped = (
        session.exec(select(UserOidcClaim.user_id).where(col(UserOidcClaim.claim).in_(claims)))
        if claims
        else []
    )
    return set(direct.all()) | set(mapped)


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


def clean_description(description: str | None) -> str:
    """Validate a description (may be empty)."""
    cleaned = (description or "").strip()
    if len(cleaned) > MAX_DESCRIPTION_CHARS:
        raise ValueError(f"Description must contain at most {MAX_DESCRIPTION_CHARS} characters")
    if not all(char.isprintable() or char in "\n\t" for char in cleaned):
        raise ValueError("Description must not contain control characters")
    return cleaned


def clean_permissions(permissions: Iterable[str]) -> list[str]:
    """Validate the permissions of a role: at least one, all known, none per project (those are
    given with the projects)."""
    cleaned: list[str] = []
    for name in permissions:
        try:
            cleaned.append(Permission(str(name).strip()).value)
        except ValueError:
            raise ValueError(f"Unknown permission '{str(name)[:50]}'") from None
    if not cleaned:
        raise ValueError("A role needs at least one permission")
    scoped = sorted(set(cleaned) & SCOPED_PERMISSIONS)
    if scoped:
        raise ValueError(
            f"A role holds no per-project permission ({', '.join(scoped)}): give it with the "
            "projects"
        )
    return sorted(set(cleaned))


def clean_project_permissions(permissions: Iterable[str], empty: bool = False) -> list[str]:
    """Validate per-project permissions (SCOPED_PERMISSIONS); at least one unless ``empty``."""
    cleaned: set[str] = set()
    for name in permissions:
        value = str(name).strip()
        if value not in SCOPED_PERMISSIONS:
            raise ValueError(f"'{value[:50]}' is not a per-project permission")
        cleaned.add(value)
    if not cleaned and not empty:
        raise ValueError("A project needs at least one per-project permission")
    return sorted(cleaned)


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


def clean_claim(value: str) -> str:
    """Validate a value of the OIDC roles claim named by a mapping."""
    return _clean_text(value, "Claim value", MAX_CLAIM_CHARS)


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


def _mappings_of(session: Session, role_id: int) -> list[OidcRoleMapping]:
    """The OIDC mappings that give a role (at most MAX_OIDC_MAPPINGS are read)."""
    return [
        mapping
        for mapping in session.exec(select(OidcRoleMapping)).all()
        if role_id in json.loads(mapping.role_ids)
    ]


def _role_public(session: Session, row: AccessRole) -> dict[str, Any]:
    """API view of a role, with the number of users and OIDC mappings that give it."""
    users = session.exec(
        select(func.count()).select_from(UserRole).where(UserRole.role_id == row.id)
    ).one()
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "permissions": sorted(_permissions(row)),
        "system": row.system,
        "users": users,
        "mappings": len(_mappings_of(session, row.id)),  # type: ignore[arg-type]
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
        "created_by": row.created_by,
    }


def _get_project(session: Session, project: str) -> Project:
    """The known project ``project`` (normalized here).

    Raises:
        ValueError: Invalid name.
        NotFoundError: Unknown project.
    """
    cleaned = _clean_project(project)
    row = session.exec(select(Project).where(Project.name == cleaned)).first()
    if row is None:
        raise NotFoundError(f"Project '{cleaned}' not found")
    return row


def _get_role(session: Session, role_id: int) -> AccessRole:
    """Return a role by id or raise NotFoundError."""
    row = session.get(AccessRole, role_id)
    if row is None:
        raise NotFoundError(f"Role {role_id} not found")
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

    The users, mappings and tokens that give the role keep it.
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
    """Delete a custom role (the users and mappings that give it lose it); raise NotFoundError,
    ValueError."""
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
    if len(ids) > MAX_ROLES:
        raise ValueError(f"A user may hold at most {MAX_ROLES} roles")
    for role_id in ids:
        _get_role(session, role_id)
    return ids


def set_user_roles(
    session: Session, user_id: int, role_ids: Iterable[int], actor: str | None = None
) -> None:
    """Replace the roles of a user.

    Runs in the session of the caller (web_users), which checks the last manager.

    Raises:
        NotFoundError: Unknown role.
        ValueError: More than MAX_ROLES roles.
    """
    ids = _check_roles(session, role_ids)
    current = session.exec(select(UserRole).where(UserRole.user_id == user_id)).all()
    kept = {row.role_id for row in current}
    if kept == set(ids):
        return
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


def _check_reach(session: Session, user_id: int) -> None:
    """Refuse a user with more than MAX_SESSION_PROJECTS projects.

    The row of the user stays locked until the end of the transaction (PostgreSQL; SQLite
    serializes the writers): two concurrent additions to one user are counted one after the
    other, never both against the projects read before either. FOR NO KEY UPDATE: it does not
    wait for the key share locks of the rows just added (no deadlock between two additions).
    """
    session.flush()
    session.exec(
        select(WebUser.id).where(WebUser.id == user_id).with_for_update(key_share=True)
    ).first()
    reached = session.exec(
        select(func.count()).select_from(UserProject).where(UserProject.user_id == user_id)
    ).one()
    if reached > MAX_SESSION_PROJECTS:
        raise ValueError(f"A user may have at most {MAX_SESSION_PROJECTS} projects")


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
    if len(wanted) > MAX_SESSION_PROJECTS:
        raise ValueError(f"A user may have at most {MAX_SESSION_PROJECTS} projects")
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


# ── Members of a project ─────────────────────────────────────────────────────


def list_project_members(project: str) -> list[dict[str, Any]]:
    """The users who have ``project``, by username (those who have every project and those of
    the OIDC mappings are not listed).

    Raises:
        ValueError: Invalid name.
        NotFoundError: Unknown project.
    """
    with session_scope() as session:
        row = _get_project(session, project)
        return _members_public(session, row)


def _members_public(session: Session, project: Project) -> list[dict[str, Any]]:
    """The users who have ``project``, with their permissions there."""
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
    """Version of the members of a project (list_project_members), for set_project_members."""
    return _version(sorted((item["user_id"], item["permissions"]) for item in members))


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
        return _members_public(session, row)


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
    add_user_project(session, user_id, project, actor)
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
    token_store.forget_project) and its connector destinations. The audit log keeps the events
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
        add_user_project(session, user_id, project, actor)
        user_grants(session, user_id)
    except ValueError:
        raise ValueError(
            f"The user already reads {MAX_SESSION_PROJECTS} projects; ask an administrator "
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
            add_user_project(session, user.id, row.project, actor)  # type: ignore[arg-type]
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


# ── OIDC mappings ────────────────────────────────────────────────────────────


def _empty_mapping(mapping: OidcRoleMapping) -> bool:
    """True for a mapping that gives nothing: no role, no project."""
    return (
        not json.loads(mapping.role_ids)
        and not json.loads(mapping.all_projects_permissions)
        and not json.loads(mapping.projects)
    )


def _mapping_public(mapping: OidcRoleMapping, names: Mapping[int, str]) -> dict[str, Any]:
    """API view of an OIDC mapping (``names``: name of each role by id)."""
    role_ids = json.loads(mapping.role_ids)
    return {
        "id": mapping.id,
        "claim": mapping.claim,
        "role_ids": role_ids,
        "roles": [names[item] for item in role_ids if item in names],
        "all_projects_permissions": json.loads(mapping.all_projects_permissions),
        "projects": json.loads(mapping.projects),
        "created_at": mapping.created_at.isoformat(),
        "created_by": mapping.created_by,
    }


def _list_mappings(session: Session) -> list[dict[str, Any]]:
    """Every OIDC mapping, by claim."""
    names = {row.id: row.name for row in session.exec(select(AccessRole)).all()}
    rows = session.exec(select(OidcRoleMapping).order_by(col(OidcRoleMapping.claim))).all()
    return [_mapping_public(mapping, names) for mapping in rows]  # type: ignore[arg-type]


def list_oidc_mappings() -> list[dict[str, Any]]:
    """Every OIDC mapping (value of the roles claim, roles, per-project permissions on every
    project and projects with their permissions)."""
    with session_scope() as session:
        return _list_mappings(session)


def oidc_mappings_version(mappings: list[dict[str, Any]]) -> str:
    """Version of the OIDC mappings (list_oidc_mappings), for set_oidc_mappings."""
    return _version(
        [
            [item["claim"], item["role_ids"], item["all_projects_permissions"], item["projects"]]
            for item in sorted(mappings, key=lambda item: item["claim"])
        ]
    )


def set_oidc_mappings(
    mappings: Iterable[
        tuple[str, Iterable[int], Iterable[str], Iterable[tuple[str, Iterable[str]]]]
    ],
    actor: str | None = None,
    expected_version: str | None = None,
) -> list[dict[str, Any]]:
    """Replace the OIDC mappings: ``mappings`` holds (claim value, role ids, per-project
    permissions on every project, (project, per-project permissions) pairs). A project not known
    yet is kept and ignored until it is created. The change applies at once to the OIDC users
    (their claims of the last login); a change that removes the last holder of ``users.manage``
    is refused. With ``expected_version`` (oidc_mappings_version of the mappings the caller
    read), a change made since then is not undone: the replacement is refused.

    Raises:
        NotFoundError: Unknown role.
        StaleVersion: The mappings changed since ``expected_version``.
        ValueError: Invalid claim, project or permission, a claim given twice, a mapping that
            gives nothing, more than MAX_PROJECTS_PER_TOKEN projects or MAX_ROLES roles in a
            mapping, or more than MAX_OIDC_MAPPINGS mappings.
    """
    items = list(mappings)
    if len(items) > MAX_OIDC_MAPPINGS:
        raise ValueError(f"At most {MAX_OIDC_MAPPINGS} OIDC mappings can be stored")
    with session_scope() as session:
        _check_version(oidc_mappings_version(_list_mappings(session)), expected_version)
        cleaned: dict[str, tuple[list[int], list[str], list[dict[str, Any]]]] = {}
        for claim, role_ids, every, projects in items:
            value = clean_claim(claim)
            if value in cleaned:
                raise ValueError(f"The claim '{value}' is given twice")
            roles = _check_roles(session, role_ids)
            scoped = clean_project_permissions(every, empty=True)
            given: dict[str, list[str]] = {}
            for name, permissions in projects:
                project = _clean_project(name)
                given[project] = sorted(
                    set(given.get(project, [])) | set(clean_project_permissions(permissions))
                )
            if len(given) > MAX_PROJECTS_PER_TOKEN:
                raise ValueError(f"A mapping may name at most {MAX_PROJECTS_PER_TOKEN} projects")
            if not roles and not scoped and not given:
                raise ValueError(f"The mapping of '{value}' gives neither a role nor a project")
            cleaned[value] = (
                roles,
                scoped,
                [{"project": name, "permissions": held} for name, held in sorted(given.items())],
            )
        before = managers(session)
        previous = {row["claim"] for row in _list_mappings(session)}
        session.exec(delete(OidcRoleMapping))  # type: ignore[arg-type]
        session.flush()
        for claim, (roles, scoped, projects) in cleaned.items():
            session.add(
                OidcRoleMapping(
                    claim=claim,
                    role_ids=json.dumps(roles),
                    all_projects_permissions=json.dumps(scoped),
                    projects=json.dumps(projects),
                    created_by=actor,
                )
            )
        session.flush()
        # The claims no mapping names any more give nothing: forget them
        session.exec(
            delete(UserOidcClaim).where(  # type: ignore[arg-type]
                col(UserOidcClaim.claim).not_in(set(cleaned))
            )
        )
        _guard_managers(session, before)
        audit.record(
            session,
            audit.AuditAction.OIDC_MAPPINGS_CHANGED,
            actor,
            "oidc",
            None,
            details={
                "added": sorted(set(cleaned) - previous),
                "removed": sorted(previous - set(cleaned)),
                "count": len(cleaned),
            },
        )
        return _list_mappings(session)


def _ensure_admin_mapping(session: Session, claim: str) -> None:
    """Map ``claim`` (a value of SECREVIEW_OIDC_ADMIN_GROUPS) to ``admin`` and every
    per-project permission on every project, when no mapping names it yet: a mapping an
    administrator changed is left as it is."""
    admin = ensure_system_roles(session)[ADMIN_ROLE]
    if session.exec(select(OidcRoleMapping.id).where(OidcRoleMapping.claim == claim)).first():
        return
    if session.exec(select(func.count()).select_from(OidcRoleMapping)).one() >= MAX_OIDC_MAPPINGS:
        logger.warning("OIDC admin group %s not mapped: too many OIDC mappings", claim)
        return
    session.add(
        OidcRoleMapping(
            claim=claim,
            role_ids=json.dumps([admin]),
            all_projects_permissions=json.dumps(sorted(SCOPED_PERMISSIONS)),
            projects="[]",
            created_by=OIDC_ACTOR,
        )
    )
    session.flush()
    audit.record(
        session,
        audit.AuditAction.OIDC_MAPPINGS_CHANGED,
        OIDC_ACTOR,
        "oidc",
        None,
        details={"added": [claim], "removed": [], "reason": "SECREVIEW_OIDC_ADMIN_GROUPS"},
    )


def sync_oidc_claims(
    session: Session, user_id: int, claim_values: Iterable[str], settings: Settings
) -> list[str]:
    """Replace the claims kept for an OIDC user with the values of its roles claim that a
    mapping names; return them.

    A value of SECREVIEW_OIDC_ADMIN_GROUPS found in the claim is first mapped to ``admin``
    when it is not yet. A login never removes the last holder of ``users.manage``: the claims
    that gave it to this user are then kept (and the change is logged and audited).
    """
    values = {value for value in claim_values if 0 < len(value) <= MAX_CLAIM_CHARS}
    for name in sorted(parse_groups(settings.oidc_admin_groups) & values):
        _ensure_admin_mapping(session, name)
    # At most MAX_OIDC_MAPPINGS claims: intersect here rather than send the claim (there may be
    # thousands of values) in the query
    mapped = set(session.exec(select(OidcRoleMapping.claim).distinct()).all())
    wanted = values & mapped
    before = managers(session)
    current = session.exec(select(UserOidcClaim).where(UserOidcClaim.user_id == user_id)).all()
    kept = {row.claim for row in current}
    removed = [row.claim for row in current if row.claim not in wanted]
    for row in current:
        if row.claim not in wanted:
            session.delete(row)
    session.flush()
    for claim in sorted(wanted - kept):
        session.add(UserOidcClaim(user_id=user_id, claim=claim))
    session.flush()
    if before and not managers(session):
        manager_roles = set(_manager_roles(session))
        restored = sorted(
            mapping.claim
            for mapping in session.exec(
                select(OidcRoleMapping).where(col(OidcRoleMapping.claim).in_(removed))
            ).all()
            if manager_roles & set(json.loads(mapping.role_ids))
        )
        for claim in restored:
            session.add(UserOidcClaim(user_id=user_id, claim=claim))
        session.flush()
        wanted |= set(restored)
        logger.warning(
            "OIDC login of web user %s kept %s: it holds the last users.manage", user_id, restored
        )
        audit.record(
            session,
            audit.AuditAction.USER_ROLES_CHANGED,
            OIDC_ACTOR,
            "user",
            user_id,
            details={"kept_claims": restored, "reason": "last holder of users.manage"},
        )
    return sorted(wanted)
