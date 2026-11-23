"""OIDC mappings: roles and projects given by a value of the roles claim."""

import json
import logging
from collections.abc import Iterable, Mapping
from typing import Any

from sqlalchemy import delete
from sqlmodel import Session, col, func, select

from ...config import Settings
from ...observability import audit
from ...storage import projects as project_store
from ...storage.database import session_scope
from ...storage.models import (
    AccessRole,
    OidcRoleMapping,
    UserOidcClaim,
)
from ..token_store import MAX_PROJECTS_PER_TOKEN, _clean_project
from .core import (
    ADMIN_ROLE,
    MAX_CLAIM_CHARS,
    MAX_OIDC_MAPPINGS,
    OIDC_ACTOR,
    SCOPED_PERMISSIONS,
    ProtectedAccessDenied,
    _check_version,
    _guard_managers,
    _manager_roles,
    _protected_roles,
    _version,
    clean_claim,
    clean_project_permissions,
    managers,
    parse_groups,
)
from .roles import ensure_system_roles
from .users import _check_roles

logger = logging.getLogger("security_review.web")
# ── OIDC mappings ────────────────────────────────────────────────────────────


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
    administrator: bool = True,
) -> list[dict[str, Any]]:
    """Replace the OIDC mappings: ``mappings`` holds (claim value, role ids, per-project
    permissions on every project, (project, per-project permissions) pairs). A project not known
    yet is created, so that no holder of ``projects.create`` takes its name first. The change
    applies at once to the OIDC users (their claims of the last login); a change that removes
    the last holder of ``users.manage`` is refused. With ``expected_version``
    (oidc_mappings_version of the mappings the caller read), a change made since then is not
    undone: the replacement is refused. A caller that is not an ``administrator`` keeps the
    roles with a protected permission of each claim as they are: it changes everything else.

    Raises:
        NotFoundError: Unknown role.
        ProtectedAccessDenied: A caller that is not an administrator gives or takes away a role
            with a protected permission.
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
        if not administrator:
            protected = _protected_roles(session)
            held = {
                row["claim"]: set(row["role_ids"]) & protected for row in _list_mappings(session)
            }
            given = {claim: set(roles) & protected for claim, (roles, _, _) in cleaned.items()}
            if {k: v for k, v in held.items() if v} != {k: v for k, v in given.items() if v}:
                raise ProtectedAccessDenied(
                    "give or take away a role with a protected permission in the OIDC mappings",
                    "oidc",
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
        # A project a mapping names is created now: left unknown, its name could be taken first
        # by any holder of projects.create, who would then read what the mapped team saves there
        for claim, (_, _, projects) in cleaned.items():
            for item in projects:
                if project_store.project_exists(session, item["project"]):
                    continue
                project_store.ensure_project(session, item["project"], actor)
                audit.record(
                    session,
                    audit.AuditAction.PROJECT_CREATED,
                    actor,
                    "project",
                    item["project"],
                    item["project"],
                    {"oidc_claim": claim},
                )
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
