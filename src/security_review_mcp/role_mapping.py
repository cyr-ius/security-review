"""OIDC role mapping: the web role, and the projects, granted to a user of the identity provider.

A mapping associates a value of the groups or roles claim (``SECREVIEW_OIDC_ROLES_CLAIM``) with
a web role (``reader``, ``triager`` or ``admin``) and, for ``reader`` and ``triager``, an
optional list of projects. Two sources are combined at each login:

- the mappings stored in the database (``OidcRoleMapping``), managed by administrators in the
  web interface or the REST API;
- the static groups of ``SECREVIEW_OIDC_ADMIN_GROUPS``, ``..._TRIAGER_GROUPS`` and
  ``..._READER_GROUPS``, which reach every project (used to bootstrap the first administrator).

A user grant (``OidcUserGrant``) gives ``reader`` on some projects to one user, named by the
``SECREVIEW_OIDC_USERNAME_CLAIM`` claim. It is usually created when an administrator approves an
enrollment request, so that the developer who enrolled a project reads its reports on the web.

Resolution (see resolve): the highest role among the matching mappings and grants wins. The
session then reaches every project if one of the mappings granting that role is unrestricted,
otherwise the union of their projects. Without any group match, ``SECREVIEW_OIDC_DEFAULT_ROLE``
applies (every project); without any match at all, the login is refused. A change applies at the
next login of the user.
"""

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlmodel import col, func, select

from .config import Settings
from .database import session_scope
from .http_server import Role
from .models import OidcRoleMapping, OidcUserGrant, utcnow
from .services import NotFoundError
from .token_store import MAX_PROJECTS_PER_TOKEN, _clean_project

MAX_MAPPINGS = 200
MAX_CLAIM_VALUE_CHARS = 200
MAX_USER_GRANTS = 1000
MAX_USERNAME_CHARS = 200
# Projects one session may reach (union of several mappings): keeps the session token small
MAX_SESSION_PROJECTS = 200
# Roles a mapping may grant: "mcp" is reserved to the tokens of the MCP server
MAPPING_ROLES = (Role.READER, Role.TRIAGER, Role.ADMIN)
ROLE_RANK = {Role.READER: 1, Role.TRIAGER: 2, Role.ADMIN: 3}
DATABASE = "database"
ENVIRONMENT = "environment"


@dataclass(frozen=True)
class Access:
    """What a login grants: a web role and the projects it reaches (None: every project)."""

    role: Role
    projects: frozenset[str] | None = None


def clean_claim_value(value: str) -> str:
    """Validate a group or role name of the identity provider."""
    cleaned = value.strip()
    if not 1 <= len(cleaned) <= MAX_CLAIM_VALUE_CHARS:
        raise ValueError(f"Group must contain between 1 and {MAX_CLAIM_VALUE_CHARS} characters")
    if not cleaned.isprintable():
        raise ValueError("Group must not contain control characters")
    return cleaned


def clean_role(role: Role | str) -> Role:
    """Validate the role of a mapping."""
    try:
        parsed = Role(role)
    except ValueError:
        parsed = None
    if parsed not in MAPPING_ROLES:
        raise ValueError("Role must be reader, triager or admin")
    return parsed


def clean_projects(role: Role, projects: Iterable[str] | None) -> list[str]:
    """Validate the projects of a mapping (empty: every project); none for ``admin``."""
    cleaned = list(dict.fromkeys(_clean_project(name) for name in projects or ()))
    if not all(name.isprintable() for name in cleaned):
        raise ValueError("Project must not contain control characters")
    if cleaned and role == Role.ADMIN:
        raise ValueError("An admin mapping reaches every project: it cannot list projects")
    if len(cleaned) > MAX_PROJECTS_PER_TOKEN:
        raise ValueError(f"A mapping may list at most {MAX_PROJECTS_PER_TOKEN} projects")
    return cleaned


def _public(row: OidcRoleMapping) -> dict[str, Any]:
    """API view of a stored mapping."""
    projects = json.loads(row.projects) or None
    return {
        "id": row.id,
        "claim_value": row.claim_value,
        "role": row.role,
        "projects": projects,
        "source": DATABASE,
        "created_at": row.created_at.isoformat(),
        "created_by": row.created_by,
    }


def list_mappings() -> list[dict[str, Any]]:
    """Return the stored mappings, by group then role."""
    with session_scope() as session:
        rows = session.exec(
            select(OidcRoleMapping).order_by(
                col(OidcRoleMapping.claim_value), col(OidcRoleMapping.role)
            )
        ).all()
        return [_public(row) for row in rows]


def static_mappings(settings: Settings) -> list[dict[str, Any]]:
    """The mappings of the ``SECREVIEW_OIDC_*_GROUPS`` variables (every project, read-only)."""
    sources = (
        (Role.ADMIN, settings.oidc_admin_groups),
        (Role.TRIAGER, settings.oidc_triager_groups),
        (Role.READER, settings.oidc_reader_groups),
    )
    return [
        {"claim_value": group, "role": role.value, "projects": None, "source": ENVIRONMENT}
        for role, groups in sources
        for group in sorted({item.strip() for item in groups.split(",") if item.strip()})
    ]


def create_mapping(
    claim_value: str,
    role: Role | str,
    projects: Iterable[str] | None = None,
    created_by: str | None = None,
) -> dict[str, Any]:
    """Store a mapping; raise ValueError when invalid, duplicated or over the limit."""
    value = clean_claim_value(claim_value)
    parsed = clean_role(role)
    names = clean_projects(parsed, projects)
    with session_scope() as session:
        count = session.exec(select(func.count()).select_from(OidcRoleMapping)).one()
        if count >= MAX_MAPPINGS:
            raise ValueError(f"At most {MAX_MAPPINGS} role mappings can be stored")
        row = OidcRoleMapping(
            claim_value=value,
            role=parsed.value,
            projects=json.dumps(names),
            created_by=created_by,
        )
        session.add(row)
        try:
            session.flush()
        except IntegrityError:
            raise ValueError(f"Group '{value}' is already mapped to the role {parsed}") from None
        session.refresh(row)
        return _public(row)


def update_mapping(mapping_id: int, projects: Iterable[str] | None) -> dict[str, Any]:
    """Replace the projects of a mapping; raise NotFoundError or ValueError."""
    with session_scope() as session:
        row = session.get(OidcRoleMapping, mapping_id)
        if row is None:
            raise NotFoundError(f"Role mapping {mapping_id} not found")
        row.projects = json.dumps(clean_projects(Role(row.role), projects))
        session.add(row)
        session.flush()
        session.refresh(row)
        return _public(row)


def delete_mapping(mapping_id: int) -> dict[str, Any]:
    """Delete a mapping and return it; raise NotFoundError."""
    with session_scope() as session:
        row = session.get(OidcRoleMapping, mapping_id)
        if row is None:
            raise NotFoundError(f"Role mapping {mapping_id} not found")
        deleted = _public(row)
        session.delete(row)
        return deleted


# ── User grants (reader access given by name, usually at enrollment) ─────────


def clean_username(value: str) -> str:
    """Validate the name of an identity provider user (exact value of the username claim)."""
    cleaned = value.strip()
    if not 1 <= len(cleaned) <= MAX_USERNAME_CHARS:
        raise ValueError(f"User name must contain between 1 and {MAX_USERNAME_CHARS} characters")
    if not cleaned.isprintable():
        raise ValueError("User name must not contain control characters")
    return cleaned


def _grant_projects(projects: Iterable[str]) -> list[str]:
    """Validate the projects of a user grant: at least one, at most MAX_PROJECTS_PER_TOKEN."""
    cleaned = clean_projects(Role.READER, projects)
    if not cleaned:
        raise ValueError("A user grant needs at least one project")
    return cleaned


def _public_grant(row: OidcUserGrant) -> dict[str, Any]:
    """API view of a stored user grant."""
    return {
        "id": row.id,
        "username": row.username,
        "role": Role.READER.value,
        "projects": json.loads(row.projects),
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
        "created_by": row.created_by,
    }


def list_user_grants() -> list[dict[str, Any]]:
    """Return the stored user grants, by user name."""
    with session_scope() as session:
        rows = session.exec(select(OidcUserGrant).order_by(col(OidcUserGrant.username))).all()
        return [_public_grant(row) for row in rows]


def check_user_grant(username: str) -> str:
    """Validate a user name and check that a grant can be added to it; return the clean name.

    Called before approving an enrollment, so that a grant refused for capacity reasons does
    not leave an approved request without its web access.
    """
    name = clean_username(username)
    with session_scope() as session:
        row = session.exec(select(OidcUserGrant).where(OidcUserGrant.username == name)).first()
        if row is None:
            count = session.exec(select(func.count()).select_from(OidcUserGrant)).one()
            if count >= MAX_USER_GRANTS:
                raise ValueError(f"At most {MAX_USER_GRANTS} user grants can be stored")
        elif len(json.loads(row.projects)) >= MAX_PROJECTS_PER_TOKEN:
            raise ValueError(
                f"User '{name}' already reads {MAX_PROJECTS_PER_TOKEN} projects, the maximum"
            )
    return name


def grant_user_projects(
    username: str, projects: Iterable[str], created_by: str | None = None
) -> dict[str, Any]:
    """Give ``reader`` on ``projects`` to a user, added to the projects it already reads.

    Raises:
        ValueError: Invalid name or projects, or a limit reached.
    """
    name = check_user_grant(username)
    added = _grant_projects(projects)
    with session_scope() as session:
        row = session.exec(select(OidcUserGrant).where(OidcUserGrant.username == name)).first()
        if row is None:
            row = OidcUserGrant(username=name, created_by=created_by)
            current: list[str] = []
        else:
            current = json.loads(row.projects)
        row.projects = json.dumps(_grant_projects([*current, *added]))
        row.updated_at = utcnow()
        session.add(row)
        try:
            session.flush()
        except IntegrityError:
            # Same user granted twice at the same time
            raise ValueError(f"User '{name}' was granted access concurrently; retry") from None
        session.refresh(row)
        return _public_grant(row)


def update_user_grant(grant_id: int, projects: Iterable[str]) -> dict[str, Any]:
    """Replace the projects of a user grant (at least one); raise NotFoundError or ValueError."""
    with session_scope() as session:
        row = session.get(OidcUserGrant, grant_id)
        if row is None:
            raise NotFoundError(f"User grant {grant_id} not found")
        row.projects = json.dumps(_grant_projects(projects))
        row.updated_at = utcnow()
        session.add(row)
        session.flush()
        session.refresh(row)
        return _public_grant(row)


def delete_user_grant(grant_id: int) -> dict[str, Any]:
    """Delete a user grant and return it; raise NotFoundError."""
    with session_scope() as session:
        row = session.get(OidcUserGrant, grant_id)
        if row is None:
            raise NotFoundError(f"User grant {grant_id} not found")
        deleted = _public_grant(row)
        session.delete(row)
        return deleted


# ── Resolution of a login ────────────────────────────────────────────────────


def resolve(values: set[str], settings: Settings, username: str | None = None) -> Access | None:
    """Return the access granted to a user, or None (refused).

    ``values`` is the content of the groups or roles claim, ``username`` the value of the
    username claim, matched exactly against the user grants.

    Raises:
        ValueError: If the matching mappings add up to more than MAX_SESSION_PROJECTS projects.
    """
    matches = [
        (Role(item["role"]), item["projects"])
        for item in static_mappings(settings)
        if item["claim_value"] in values
    ]
    # At most MAX_MAPPINGS rows: intersect here rather than send the groups of the user (there
    # may be thousands) in the query
    with session_scope() as session:
        rows = session.exec(select(OidcRoleMapping)).all()
        matches.extend(
            (Role(row.role), json.loads(row.projects) or None)
            for row in rows
            if row.claim_value in values
        )
        if not matches and settings.oidc_default_role:
            # The default role applies without any group match, also next to a user grant
            matches.append((Role(settings.oidc_default_role), None))
        if username:
            grant = session.exec(
                select(OidcUserGrant).where(OidcUserGrant.username == username)
            ).first()
            if grant is not None:
                matches.append((Role.READER, json.loads(grant.projects)))
    if not matches:
        return None
    role = max((role for role, _ in matches), key=ROLE_RANK.__getitem__)
    granted = [projects for matched, projects in matches if matched == role]
    if role == Role.ADMIN or any(projects is None for projects in granted):
        return Access(role)
    names = frozenset(name for projects in granted for name in projects)
    if len(names) > MAX_SESSION_PROJECTS:
        raise ValueError(f"The role mappings grant more than {MAX_SESSION_PROJECTS} projects")
    return Access(role, names)
