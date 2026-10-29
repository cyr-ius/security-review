"""Routes of the access control (``users.manage``): permissions, roles, web users and their
roles, the members of the projects, the OIDC mappings and the OIDC settings."""

import logging
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi import Path as APIPath
from fastapi.concurrency import run_in_threadpool

from .. import app_settings
from ..auth import access_control, oidc, web_users
from ..storage import projects as project_store
from ..storage.database import session_scope
from ..storage.project_names import ProjectName
from .auth_routes import LOGIN_HEADERS, OidcLogins, current_oidc
from .deps import UsersManager, actor_of, unprocessable
from .schemas import (
    AccessRole,
    KnownProject,
    OidcMappingCatalog,
    OidcMappingsUpdate,
    OidcSettings,
    OidcSettingsUpdate,
    OidcTestResult,
    PasswordReset,
    PermissionInfo,
    ProjectMember,
    ProjectMembersUpdate,
    RevokedUser,
    RoleWrite,
    WebUser,
    WebUserCreate,
    WebUserUpdate,
    WebUserWithPassword,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["access"])

UsernamePath = Annotated[str, APIPath(min_length=1, max_length=web_users.MAX_USERNAME_CHARS)]


def _conflict(exc: ValueError) -> HTTPException:
    """409 answer for a deletion refused by a service (a role in use, last admin)."""
    return HTTPException(status.HTTP_409_CONFLICT, str(exc))


# ── Permissions and roles ────────────────────────────────────────────────────


@router.get("/permissions")
async def permissions(identity: UsersManager) -> list[PermissionInfo]:
    """List the permissions a role may hold, and whether they can be limited to projects."""
    return access_control.list_permissions()


@router.get("/roles")
async def roles(identity: UsersManager) -> list[AccessRole]:
    """List the roles: the built-in roles, then the custom roles."""
    return await run_in_threadpool(access_control.list_roles)


@router.post("/roles", status_code=status.HTTP_201_CREATED)
async def create_role(body: RoleWrite, identity: UsersManager) -> AccessRole:
    """Create a custom role."""
    try:
        created = await run_in_threadpool(
            access_control.create_role,
            body.name,
            body.permissions,
            body.description,
            actor_of(identity),
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Role %s created by %s", created["name"], identity.client)
    return created


@router.put("/roles/{role_id}")
async def update_role(role_id: int, body: RoleWrite, identity: UsersManager) -> AccessRole:
    """Replace the name, description and permissions of a custom role (applies at once)."""
    try:
        updated = await run_in_threadpool(
            access_control.update_role,
            role_id,
            body.permissions,
            body.description,
            body.name,
            actor_of(identity),
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Role %s updated by %s", updated["name"], identity.client)
    return updated


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(role_id: int, identity: UsersManager) -> Response:
    """Delete a custom role: the users and OIDC mappings that give it lose it at once."""
    try:
        deleted = await run_in_threadpool(access_control.delete_role, role_id, actor_of(identity))
    except ValueError as exc:
        raise _conflict(exc) from exc
    logger.info("Role %s deleted by %s", deleted["name"], identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Projects and their members ───────────────────────────────────────────────

# Names returned by one search of the known projects
MAX_PROJECT_SEARCH = 200


def _search_projects(text: str | None, limit: int) -> list[dict[str, str]]:
    """The known projects whose name contains ``text``."""
    with session_scope() as session:
        return [{"name": name} for name in project_store.search_projects(session, text, limit)]


@router.get("/access/projects")
async def known_projects(
    identity: UsersManager,
    search: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PROJECT_SEARCH)] = 50,
) -> list[KnownProject]:
    """Search the known projects by name, to give roles on them (every project, also those the
    caller does not read)."""
    return await run_in_threadpool(_search_projects, (search or "").strip().lower(), limit)


@router.get("/access/projects/{project}/members")
async def project_members(
    project: Annotated[ProjectName, APIPath()], identity: UsersManager
) -> list[ProjectMember]:
    """List the users who have a project (not those who have every project)."""
    try:
        return await run_in_threadpool(access_control.list_project_members, project)
    except ValueError as exc:
        raise unprocessable(exc) from exc


@router.put("/access/projects/{project}/members")
async def set_project_members(
    project: Annotated[ProjectName, APIPath()],
    body: ProjectMembersUpdate,
    identity: UsersManager,
) -> list[ProjectMember]:
    """Replace the users who have a project (applies to their sessions at once)."""
    try:
        members = await run_in_threadpool(
            access_control.set_project_members,
            project,
            [(item.user_id, item.read_only) for item in body.members],
            actor_of(identity),
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Members of project %s changed by %s", project, identity.client)
    return members


# ── OIDC mappings ────────────────────────────────────────────────────────────


@router.get("/oidc/mappings", tags=["sso"])
async def oidc_mappings(request: Request, identity: UsersManager) -> OidcMappingCatalog:
    """List the OIDC mappings, and the OIDC settings that use them."""
    settings = await run_in_threadpool(app_settings.effective_settings)
    return OidcMappingCatalog.model_validate(
        {
            "oidc_enabled": await current_oidc(request) is not None,
            "roles_claim": settings.oidc_roles_claim,
            "admin_groups": sorted(access_control.parse_groups(settings.oidc_admin_groups)),
            "mappings": await run_in_threadpool(access_control.list_oidc_mappings),
        }
    )


@router.put("/oidc/mappings", tags=["sso"])
async def set_oidc_mappings(
    request: Request, body: OidcMappingsUpdate, identity: UsersManager
) -> OidcMappingCatalog:
    """Replace the OIDC mappings (applies at once to the OIDC users, by their claims of the last
    login); a change that removes the last holder of users.manage is refused."""
    try:
        await run_in_threadpool(
            access_control.set_oidc_mappings,
            [
                (item.claim, item.role_ids, None if item.all_projects else item.projects)
                for item in body.mappings
            ],
            actor_of(identity),
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("OIDC mappings changed by %s", identity.client)
    return await oidc_mappings(request, identity)


# ── OIDC settings ─────────────────────────────────────────────────────────────


async def _describe_oidc(request: Request) -> dict[str, Any]:
    """OIDC settings of the web interface, with whether the login is active."""
    described = await run_in_threadpool(app_settings.describe_oidc)
    return described | {"active": await current_oidc(request) is not None}


# The OIDC settings decide who gets which role (roles claim, admin groups, identity provider):
# they need users.manage, not only settings.manage
@router.get("/oidc/settings", tags=["sso"])
async def get_oidc_settings(request: Request, identity: UsersManager) -> OidcSettings:
    """Return the OIDC settings: stored value, variable and effective value of each one.

    A set client secret is replaced by ``***``.
    """
    return OidcSettings.model_validate(await _describe_oidc(request))


@router.put("/oidc/settings", tags=["sso"])
async def set_oidc_settings(
    request: Request, body: OidcSettingsUpdate, identity: UsersManager
) -> OidcSettings:
    """Change OIDC settings; they apply at the next login where the SECREVIEW_OIDC_* variable
    is not set.

    Refused (422) when a changed setting has its variable set (it takes precedence), or when the
    resulting settings enable an invalid login.
    """
    values = body.model_dump(exclude_unset=True)
    try:
        await run_in_threadpool(app_settings.set_oidc, values, identity.client)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    # Names only: the values may hold the client secret
    logger.info("OIDC settings %s changed by %s", ", ".join(sorted(values)), identity.client)
    return OidcSettings.model_validate(await _describe_oidc(request))


@router.post("/oidc/settings/test", tags=["sso"])
async def test_oidc_settings(
    request: Request, body: OidcSettingsUpdate, identity: UsersManager
) -> OidcTestResult:
    """Test the identity provider of the given settings (applied over the effective ones,
    nothing stored): discovery document and signing keys."""
    values = body.model_dump(exclude_unset=True)
    try:
        candidate = await run_in_threadpool(app_settings.oidc_candidate, values)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logins: OidcLogins = request.app.state.oidc
    steps = await run_in_threadpool(oidc.OidcLogin(candidate, logins.signer).check)
    logger.info("OIDC provider %s tested by %s", candidate.oidc_issuer, identity.client)
    return OidcTestResult.model_validate(
        {"success": all(step["ok"] for step in steps), "steps": steps}
    )


# ── Web users ────────────────────────────────────────────────────────────────


@router.get("/users")
async def users(identity: UsersManager) -> list[WebUser]:
    """List the web users (never their password hash)."""
    return await run_in_threadpool(web_users.list_users)


@router.post("/users", status_code=status.HTTP_201_CREATED, response_model_exclude_unset=True)
async def create_user(
    body: WebUserCreate, identity: UsersManager, response: Response
) -> WebUserWithPassword:
    """Create a web user (local or OIDC); a generated password is returned once in ``password``."""
    try:
        created = await run_in_threadpool(
            web_users.create_user,
            body.username,
            body.password,
            body.role_ids,
            [(item.project, item.read_only) for item in body.projects],
            identity.client,
            body.auth_source,
            actor_of(identity),
            body.all_projects,
        )
    except ValueError as exc:
        if "already exists" in str(exc):
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        raise unprocessable(exc) from exc
    logger.info(
        "Web user %s (%s) created by %s",
        created["username"],
        created["auth_source"],
        identity.client,
    )
    response.headers.update(LOGIN_HEADERS)
    return WebUserWithPassword.model_validate(created)


# Declared before /users/{user_id}: "revoked" is not a user id
@router.get("/users/revoked")
async def revoked_users(identity: UsersManager) -> list[RevokedUser]:
    """List the deleted OIDC users, which a login never creates again."""
    return await run_in_threadpool(web_users.list_revoked_users)


@router.delete("/users/revoked/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def lift_user_revocation(username: UsernamePath, identity: UsersManager) -> Response:
    """Let a deleted OIDC user be created again at its next login (automatic creation)."""
    lifted = await run_in_threadpool(web_users.lift_revocation, username)
    logger.info("Revocation of OIDC user %s lifted by %s", lifted["username"], identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/users/{user_id}")
async def update_user(user_id: int, body: WebUserUpdate, identity: UsersManager) -> WebUser:
    """Replace the roles and projects an administrator gave to a web user (applies to its sessions
    at once); a missing field is left unchanged."""
    projects = (
        None
        if body.projects is None
        else [(item.project, item.read_only) for item in body.projects]
    )
    try:
        updated = await run_in_threadpool(
            web_users.update_user,
            user_id,
            body.role_ids,
            projects,
            actor_of(identity),
            body.all_projects,
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Access of web user %s changed by %s", updated["username"], identity.client)
    return updated


@router.post("/users/{user_id}/password", response_model_exclude_unset=True)
async def reset_user_password(
    user_id: int, body: PasswordReset, identity: UsersManager, response: Response
) -> WebUserWithPassword:
    """Replace the password of a web user (generated when not given) and end its sessions."""
    try:
        updated = await run_in_threadpool(web_users.set_password, user_id, body.password)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Password of web user %s reset by %s", updated["username"], identity.client)
    response.headers.update(LOGIN_HEADERS)
    return WebUserWithPassword.model_validate(updated)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: int, identity: UsersManager) -> Response:
    """Delete a web user (its sessions stop at once); the last holder of users.manage is kept.

    A deleted OIDC user is revoked: a login never creates it again until an administrator
    creates it again or lifts the revocation (DELETE /users/revoked/{username}).
    """
    try:
        deleted = await run_in_threadpool(web_users.delete_user, user_id, identity.client)
    except ValueError as exc:
        raise _conflict(exc) from exc
    logger.info(
        "Web user %s (%s) deleted by %s",
        deleted["username"],
        deleted["auth_source"],
        identity.client,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
