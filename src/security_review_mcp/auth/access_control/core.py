"""Shared base of the access control: permissions, limits, grants and validation."""

import hashlib
import json
import logging
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Any

from sqlmodel import Session, col, func, select

from ...http_server import Role
from ...observability import audit
from ...reports.services import NotFoundError
from ...storage.database import session_scope
from ...storage.models import (
    AccessRole,
    OidcRoleMapping,
    Project,
    UserOidcClaim,
    UserProject,
    UserRole,
    WebUser,
)
from ..token_store import MAX_PROJECTS_PER_TOKEN, _clean_project

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
    # Delete a project with its reports, findings and references (see delete_project), or
    # rename it (see rename_project)
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
# Permissions only an administrator (see is_administrator) gives or takes away: users.manage
# decides who holds every other permission, settings.manage the URL of the Controller server to
# which the MCP servers send the tokens of the agents (see ProtectedAccessDenied)
PROTECTED_PERMISSIONS = frozenset({Permission.USERS_MANAGE, Permission.SETTINGS_MANAGE})
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


class ProtectedAccessDenied(PermissionError):
    """A caller that is not an administrator touched a protected permission (see
    PROTECTED_PERMISSIONS): ``target_type`` and ``target_id`` name what it tried to change."""

    def __init__(self, action: str, target_type: str, target_id: str | int | None = None) -> None:
        super().__init__(
            f"Only an administrator may {action} (users.manage and settings.manage are protected)"
        )
        self.action = action
        self.target_type = target_type
        self.target_id = target_id


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


def is_administrator(grants: Grants) -> bool:
    """True for grants that hold every permission on the whole controller: the ``admin`` role, an
    ``admin`` token or an ``api`` token of the ``admin`` role. Only an administrator may give or
    take away a protected permission (see PROTECTED_PERMISSIONS)."""
    return all(
        permission in grants and grants[permission] is None for permission in SITE_PERMISSIONS
    )


def _protected(permissions: Iterable[str]) -> bool:
    """True when ``permissions`` hold a protected permission."""
    return not PROTECTED_PERMISSIONS.isdisjoint(permissions)


def _protected_roles(session: Session) -> set[int]:
    """Ids of the roles that hold a protected permission (``admin`` among them)."""
    return {
        role.id  # type: ignore[misc]
        for role in session.exec(select(AccessRole)).all()
        if _protected(_permissions(role))
    }


def holds_protected(session: Session, user_id: int) -> bool:
    """True when a user holds a protected permission, by its roles or those of its mappings."""
    return any(_protected(permissions) for permissions, _ in _bindings(session, user_id))


def check_protected_user(session: Session, user_id: int, administrator: bool, action: str) -> None:
    """Refuse a change of a user who holds a protected permission, by a caller that is not an
    administrator: it would take its permissions away or log in with its account.

    Raises:
        ProtectedAccessDenied: If the caller is not an administrator and the user holds one.
    """
    if not administrator and holds_protected(session, user_id):
        raise ProtectedAccessDenied(
            f"{action} a user who holds a protected permission", "user", user_id
        )


def record_protected_denial(exc: ProtectedAccessDenied, actor: str | None) -> None:
    """Write a refused change of a protected permission to the audit log, in its own transaction:
    the refused one is rolled back."""
    with session_scope() as session:
        audit.record(
            session,
            audit.AuditAction.ACCESS_DENIED,
            actor,
            exc.target_type,
            exc.target_id,
            details={"action": exc.action},
        )
    logger.warning("Change of a protected permission refused to %s: %s", actor, exc.action)


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


def _empty_mapping(mapping: OidcRoleMapping) -> bool:
    """True for a mapping that gives nothing: no role, no project."""
    return (
        not json.loads(mapping.role_ids)
        and not json.loads(mapping.all_projects_permissions)
        and not json.loads(mapping.projects)
    )
