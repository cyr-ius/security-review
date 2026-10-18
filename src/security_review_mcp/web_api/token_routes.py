"""Routes of the project tokens and of the enrollment requests (``tokens.manage``).

A token never grants more than its creator holds: every change is checked against the
projects the caller reads and, for an api token, the permissions of its role.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi import Path as APIPath
from fastapi.concurrency import run_in_threadpool

from .. import access_control, services, token_store, web_users
from .auth_routes import LOGIN_HEADERS, current_oidc
from .deps import (
    Identity,
    Permission,
    TokensManager,
    actor_of,
    has_permission,
    permission_scope,
    unprocessable,
)
from .schemas import (
    EnrollmentApproval,
    EnrollmentApproved,
    EnrollmentRequest,
    ProjectToken,
    ProjectTokenCreate,
    ProjectTokenProjects,
    ProjectTokenRotation,
    ProjectTokenSecret,
    TokenRoleChoice,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["tokens"])

TokenIdPath = Annotated[str, APIPath(min_length=1, max_length=64)]
RequestIdPath = Annotated[str, APIPath(min_length=1, max_length=64)]


def _not_found_or_unprocessable(exc: ValueError) -> HTTPException:
    """404 for an unknown token, 422 for any other refusal."""
    if "not found" in str(exc):
        return HTTPException(status.HTTP_404_NOT_FOUND, str(exc))
    return unprocessable(exc)


async def _check_known_projects(projects: list[str] | None) -> None:
    """Refuse a token for a project that has no report yet (None: every project)."""
    if projects is None:
        return
    known = {item["project"] for item in await run_in_threadpool(services.list_projects)}
    if not set(projects) <= known:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")


def _describe_projects(projects: list[str] | None) -> str:
    """Projects of a token for the logs."""
    return "every project" if projects is None else ", ".join(projects)


def _check_delegation(
    identity: Identity, projects: list[str] | None, permissions: list[str] | None = None
) -> None:
    """Refuse (403) a token that would reach projects the caller cannot read itself, or hold a
    permission of its role (``permissions``, api token) the caller does not hold on them: a
    token never grants more than its creator holds."""
    for permission in dict.fromkeys([Permission.REPORTS_READ, *(permissions or [])]):
        reached = permission_scope(identity, Permission(permission))
        if reached is not None and (projects is None or not set(projects) <= set(reached)):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"A token cannot hold '{permission}' where you do not hold it",
            )


async def _role_permissions(role_id: int | None) -> list[str]:
    """Permissions of the role of an api token (none for another token); 404 when unknown."""
    if role_id is None:
        return []
    try:
        permissions, _ = await run_in_threadpool(access_control.role_token_scope, role_id, None)
    except services.NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return permissions


def _reaches(identity: Identity, projects: list[str] | None) -> bool:
    """True when the caller reads every project of a token or request (None: every project)."""
    reached = permission_scope(identity, Permission.REPORTS_READ)
    return reached is None or (projects is not None and set(projects) <= set(reached))


async def _check_enrollment_scope(identity: Identity, request_id: str) -> None:
    """Refuse (403) to handle an enrollment request for a project the caller cannot read."""
    pending = await run_in_threadpool(token_store.list_enrollments)
    for item in pending:
        if request_id in (item["id"], item["token_id"], item["label"]):
            _check_delegation(identity, [item["project"]])


async def _check_token_delegation(
    identity: Identity, token_id: str, projects: list[str] | None, keep: bool = False
) -> None:
    """Delegation check of a change to a stored token (see _check_delegation): with its new
    ``projects``, or with its current ones when ``keep``. An unknown token is left to the call
    that follows (404)."""
    tokens = await run_in_threadpool(token_store.list_tokens)
    token = next((item for item in tokens if item["id"] == token_id), None)
    if token is not None:
        permissions = await _role_permissions(token.get("access_role_id"))
        _check_delegation(identity, token["projects"] if keep else projects, permissions)


# ── Project tokens ───────────────────────────────────────────────────────────


@router.get("/project-tokens/roles")
async def project_token_roles(identity: TokensManager) -> list[TokenRoleChoice]:
    """The roles an api token may hold, with their permissions."""
    return await run_in_threadpool(access_control.list_token_roles)


@router.get("/project-tokens")
async def project_tokens(identity: TokensManager) -> list[ProjectToken]:
    """List project-token metadata without returning hashes or token values; only the tokens
    whose projects the caller reads."""
    tokens = await run_in_threadpool(token_store.list_project_tokens)
    return [token for token in tokens if _reaches(identity, token["projects"])]


@router.post("/project-tokens", status_code=status.HTTP_201_CREATED)
async def create_project_token(
    body: ProjectTokenCreate, identity: TokensManager, response: Response
) -> ProjectTokenSecret:
    """Create a token for existing projects (or every project, ``projects`` null) and return
    its secret exactly once. An ``api`` token holds the permissions of ``access_role_id``: the
    caller must hold each of them on the projects of the token."""
    _check_delegation(identity, body.projects, await _role_permissions(body.access_role_id))
    await _check_known_projects(body.projects)
    try:
        created = await run_in_threadpool(
            token_store.create_project_token,
            body.label,
            body.projects,
            body.role,
            body.expires_in_days,
            actor_of(identity),
            body.access_role_id,
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info(
        "Project token %s (%s) created for %s by %s",
        body.label,
        body.role,
        _describe_projects(created["projects"]),
        identity.client,
    )
    # The secret is shown once: never cached
    response.headers.update(LOGIN_HEADERS)
    return created


@router.put("/project-tokens/{token_id}/projects")
async def update_project_token_projects(
    token_id: TokenIdPath, body: ProjectTokenProjects, identity: TokensManager
) -> ProjectToken:
    """Change the projects of a token (``projects`` null: every project); its secret stays.

    The caller must reach the current projects of the token as well as the new ones.
    """
    await _check_token_delegation(identity, token_id, None, keep=True)
    await _check_token_delegation(identity, token_id, body.projects)
    await _check_known_projects(body.projects)
    try:
        updated = await run_in_threadpool(
            token_store.set_token_projects, token_id, body.projects, actor_of(identity)
        )
    except ValueError as exc:
        raise _not_found_or_unprocessable(exc) from exc
    logger.info(
        "Projects of token %s set to %s by %s",
        updated["label"],
        _describe_projects(updated["projects"]),
        identity.client,
    )
    return updated


@router.delete("/project-tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project_token(token_id: TokenIdPath, identity: TokensManager) -> Response:
    """Revoke a project token: the next request presenting it is rejected."""
    await _check_token_delegation(identity, token_id, None, keep=True)
    try:
        await run_in_threadpool(token_store.revoke_project_token, token_id, actor_of(identity))
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info("Project token %s revoked by %s", token_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/project-tokens/{token_id}/rotate")
async def rotate_project_token(
    token_id: TokenIdPath,
    identity: TokensManager,
    response: Response,
    body: ProjectTokenRotation | None = None,
) -> ProjectTokenSecret:
    """Replace the secret of a project token and return the new one exactly once.

    The previous secret keeps working for ``grace_hours`` (0: it stops at once). The caller
    receives the new secret: it must reach every project of the token itself.
    """
    await _check_token_delegation(identity, token_id, None, keep=True)
    rotation = body or ProjectTokenRotation()
    try:
        rotated = await run_in_threadpool(
            lambda: token_store.rotate_token(
                token_id,
                rotation.grace_hours,
                rotation.expires_in_days,
                actor_of(identity),
                project_token=True,
            )
        )
    except ValueError as exc:
        raise _not_found_or_unprocessable(exc) from exc
    logger.info(
        "Project token %s rotated by %s (grace %d h)",
        rotated["label"],
        identity.client,
        rotation.grace_hours,
    )
    response.headers.update(LOGIN_HEADERS)
    return rotated


# ── Enrollment requests ──────────────────────────────────────────────────────


@router.get("/enrollments")
async def enrollments(identity: TokensManager) -> list[EnrollmentRequest]:
    """List the enrollment requests waiting for approval (never a secret).

    ``kind`` is ``new`` for a first enrollment (new token) and ``additional`` for a
    complementary one (one more project for an active token). Only the requests for the
    projects the caller reads are listed.
    """
    pending = await run_in_threadpool(token_store.list_enrollments)
    return [item for item in pending if _reaches(identity, [item["project"]])]


@router.post("/enrollments/{request_id}/approve", response_model_exclude_unset=True)
async def approve_enrollment(
    request: Request,
    request_id: RequestIdPath,
    identity: TokensManager,
    body: EnrollmentApproval | None = None,
) -> EnrollmentApproved:
    """Approve an enrollment request: the project is reachable from the next request.

    With ``portal_user``, that web user also reads the project in the web interface (at once);
    when OIDC is enabled, an unknown name becomes an OIDC user, ready for its first login. Giving
    that access also needs the ``users.manage`` permission.
    """
    portal_user = body.portal_user if body is not None else None
    create_sso = await current_oidc(request) is not None
    # The approved token reaches the requested project: the caller must read it itself
    await _check_enrollment_scope(identity, request_id)
    if portal_user is not None:
        if not has_permission(identity, Permission.USERS_MANAGE):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"Permission '{Permission.USERS_MANAGE}' required"
            )
        try:
            portal_user = await run_in_threadpool(
                web_users.check_project_grant, portal_user, create_sso
            )
        except ValueError as exc:
            raise unprocessable(exc) from exc
    try:
        approved = await run_in_threadpool(
            token_store.approve_enrollment, request_id, actor_of(identity)
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info(
        "Enrollment %s for %s approved by %s",
        approved["label"],
        approved["project"],
        identity.client,
    )
    if portal_user is None:
        return EnrollmentApproved.model_validate(approved)
    try:
        user = await run_in_threadpool(
            web_users.grant_project,
            portal_user,
            approved["project"],
            identity.client,
            create_sso,
            actor_of(identity),
        )
    except ValueError as exc:
        # Checked before the approval: only a concurrent change gets here
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Enrollment approved, web access not granted: {exc}"
        ) from exc
    logger.info(
        "Web access to %s given to web user %s by %s",
        approved["project"],
        user["username"],
        identity.client,
    )
    return EnrollmentApproved.model_validate(approved | {"portal_user": user})


@router.delete("/enrollments/{request_id}", status_code=status.HTTP_204_NO_CONTENT)
async def reject_enrollment(request_id: RequestIdPath, identity: TokensManager) -> Response:
    """Reject an enrollment request: a new token is deleted, an additional project dropped."""
    await _check_enrollment_scope(identity, request_id)
    try:
        rejected = await run_in_threadpool(
            token_store.reject_enrollment, request_id, actor_of(identity)
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info(
        "Enrollment %s for %s rejected by %s",
        rejected["label"],
        rejected["project"],
        identity.client,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
