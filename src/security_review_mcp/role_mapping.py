"""OIDC role mapping: the web role, and the projects, granted to a user of the identity provider.

A mapping associates a value of the groups or roles claim (``SECREVIEW_OIDC_ROLES_CLAIM``) with
a web role (``reader``, ``triager`` or ``admin``) and, for ``reader`` and ``triager``, an
optional list of projects. Two sources are combined at each login:

- the mappings stored in the database (``OidcRoleMapping``), managed by administrators in the
  web interface or the REST API;
- the static groups of ``SECREVIEW_OIDC_ADMIN_GROUPS``, ``..._TRIAGER_GROUPS`` and
  ``..._READER_GROUPS``, which reach every project (used to bootstrap the first administrator).

The SSO settings named here are those variables, possibly overridden in the web interface (see
app_settings.effective_settings): ``settings`` is always the effective one.

Resolution (see resolve): the highest role among the matching mappings wins. The session then
reaches every project if one of the mappings granting that role is unrestricted, otherwise the
union of their projects. Without any group match, ``SECREVIEW_OIDC_DEFAULT_ROLE`` applies (every
project). The access of the groups is stored in the SSO web user at each login and combined
with the role given to the user itself (see web_users and combine).
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
from .models import OidcRoleMapping
from .services import NotFoundError
from .token_store import MAX_PROJECTS_PER_TOKEN, _clean_project

MAX_MAPPINGS = 200
MAX_CLAIM_VALUE_CHARS = 200
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
    """The mappings of the ``*_groups`` SSO settings (every project, read-only here)."""
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


# ── Resolution of a login ────────────────────────────────────────────────────


def combine(matches: Iterable[tuple[Role, Iterable[str] | None]]) -> Access | None:
    """Combine several accesses (role, projects or None for every project); None if empty.

    The highest role wins; the result reaches every project if one of the accesses granting
    that role does, otherwise the union of their projects.

    Raises:
        ValueError: If the union holds more than MAX_SESSION_PROJECTS projects.
    """
    found = [(role, None if projects is None else list(projects)) for role, projects in matches]
    if not found:
        return None
    role = max((role for role, _ in found), key=ROLE_RANK.__getitem__)
    granted = [projects for matched, projects in found if matched == role]
    if role == Role.ADMIN or any(projects is None for projects in granted):
        return Access(role)
    names = frozenset(name for projects in granted for name in projects or ())
    if len(names) > MAX_SESSION_PROJECTS:
        raise ValueError(f"The role mappings grant more than {MAX_SESSION_PROJECTS} projects")
    return Access(role, names)


def resolve(values: set[str], settings: Settings) -> Access | None:
    """Return the access the groups of a user grant, or None (no mapping, no default role).

    ``values`` is the content of the groups or roles claim.

    Raises:
        ValueError: If the matching mappings add up to more than MAX_SESSION_PROJECTS projects.
    """
    matches: list[tuple[Role, list[str] | None]] = [
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
        matches.append((Role(settings.oidc_default_role), None))
    return combine(matches)
