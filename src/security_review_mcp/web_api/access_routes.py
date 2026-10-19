"""Routes of the access control (``users.manage``): permissions, roles, groups, web users and
the OIDC settings, which decide who joins which group."""

import logging
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi import Path as APIPath
from fastapi.concurrency import run_in_threadpool

from .. import access_control, app_settings, oidc, web_users
from .auth_routes import LOGIN_HEADERS, OidcLogins, current_oidc
from .deps import UsersManager, actor_of, unprocessable
from .schemas import (
    AccessRole,
    GroupCatalog,
    GroupMembersUpdate,
    GroupRolesUpdate,
    GroupWrite,
    OidcSettings,
    OidcSettingsUpdate,
    OidcTestResult,
    PasswordReset,
    PermissionInfo,
    RevokedUser,
    RoleWrite,
    UserGroup,
    WebUser,
    WebUserCreate,
    WebUserUpdate,
    WebUserWithPassword,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["access"])

UsernamePath = Annotated[str, APIPath(min_length=1, max_length=web_users.MAX_USERNAME_CHARS)]


def _conflict(exc: ValueError) -> HTTPException:
    """409 answer for a deletion refused by a service (a role or group in use, last admin)."""
    return HTTPException(status.HTTP_409_CONFLICT, str(exc))


# ── Permissions and roles ────────────────────────────────────────────────────


@router.get("/permissions")
async def permissions(identity: UsersManager) -> list[PermissionInfo]:
    """List the permissions a role may hold, and whether they can be limited to projects."""
    return access_control.list_permissions()


@router.get("/roles")
async def roles(identity: UsersManager) -> list[AccessRole]:
    """List the roles: the system roles, then the custom roles."""
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
    """Delete a custom role: the groups that have it lose it at once."""
    try:
        deleted = await run_in_threadpool(access_control.delete_role, role_id, actor_of(identity))
    except ValueError as exc:
        raise _conflict(exc) from exc
    logger.info("Role %s deleted by %s", deleted["name"], identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Groups ───────────────────────────────────────────────────────────────────


@router.get("/groups")
async def groups(request: Request, identity: UsersManager) -> GroupCatalog:
    """List the groups with their roles and members, and the OIDC settings that use them."""
    settings = await run_in_threadpool(app_settings.effective_settings)
    return GroupCatalog.model_validate(
        {
            "oidc_enabled": await current_oidc(request) is not None,
            "roles_claim": settings.oidc_roles_claim,
            "admin_groups": sorted(access_control.parse_groups(settings.oidc_admin_groups)),
            "default_group": settings.oidc_default_group.strip() or None,
            "groups": await run_in_threadpool(access_control.list_groups),
        }
    )


@router.post("/groups", status_code=status.HTTP_201_CREATED)
async def create_group(body: GroupWrite, identity: UsersManager) -> UserGroup:
    """Create a group, without role nor member."""
    try:
        created = await run_in_threadpool(
            access_control.create_group,
            body.name,
            body.description,
            body.sso,
            actor_of(identity),
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Group %s created by %s", created["name"], identity.client)
    return created


@router.put("/groups/{group_id}")
async def update_group(group_id: int, body: GroupWrite, identity: UsersManager) -> UserGroup:
    """Rename a group, change its description or whether the OIDC groups claim names it."""
    try:
        updated = await run_in_threadpool(
            access_control.update_group,
            group_id,
            body.name,
            body.description,
            body.sso,
            actor_of(identity),
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Group %s updated by %s", updated["name"], identity.client)
    return updated


@router.put("/groups/{group_id}/roles")
async def set_group_roles(
    group_id: int, body: GroupRolesUpdate, identity: UsersManager
) -> UserGroup:
    """Replace the roles of a group (applies to its members at once)."""
    try:
        updated = await run_in_threadpool(
            access_control.set_group_roles,
            group_id,
            [(item.role_id, item.projects) for item in body.roles],
            actor_of(identity),
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Roles of group %s changed by %s", updated["name"], identity.client)
    return updated


@router.put("/groups/{group_id}/members")
async def set_group_members(
    group_id: int, body: GroupMembersUpdate, identity: UsersManager
) -> UserGroup:
    """Replace the members added by an administrator (the OIDC members are kept)."""
    try:
        updated = await run_in_threadpool(
            access_control.set_group_members, group_id, body.user_ids, actor_of(identity)
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Members of group %s changed by %s", updated["name"], identity.client)
    return updated


@router.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(group_id: int, identity: UsersManager) -> Response:
    """Delete a group: its members lose its roles at once."""
    try:
        deleted = await run_in_threadpool(access_control.delete_group, group_id, actor_of(identity))
    except ValueError as exc:
        raise _conflict(exc) from exc
    logger.info("Group %s deleted by %s", deleted["name"], identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── OIDC settings ─────────────────────────────────────────────────────────────


async def _describe_oidc(request: Request) -> dict[str, Any]:
    """OIDC settings of the web interface, with whether the login is active."""
    described = await run_in_threadpool(app_settings.describe_oidc)
    return described | {"active": await current_oidc(request) is not None}


# The OIDC settings decide who joins which group (groups claim, admin and default groups,
# identity provider): they need users.manage, not only settings.manage
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
            body.group_ids,
            identity.client,
            body.auth_source,
            actor_of(identity),
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
    """Replace the groups an administrator gave to a web user (applies to its sessions at once);
    a missing field is left unchanged."""
    try:
        updated = await run_in_threadpool(
            web_users.update_user, user_id, body.group_ids, actor_of(identity)
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
