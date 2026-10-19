"""Routes of the caller itself: liveness probe, identity and password of a web user."""

import logging
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, metadata

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool

from .. import __version__, app_settings, rate_limit, token_store, update_check, web_users
from ..config import get_settings
from ..http_server import API_HEALTH_PATH, DOCS_PATH
from .auth_routes import LOGIN_HEADERS, open_session
from .deps import (
    CurrentIdentity,
    Permission,
    actor_of,
    client_address,
    has_permission,
    unprocessable,
    web_user_id,
)
from .schemas import (
    About,
    HealthStatus,
    Identity,
    LoginSession,
    PasswordChange,
    PersonalTokenCreate,
    Preferences,
    ProjectToken,
    ProjectTokenSecret,
    UpdateStatus,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["account"])


@router.get("/health")
async def health() -> HealthStatus:
    """Liveness probe."""
    return HealthStatus()


@lru_cache(maxsize=1)
def project_urls() -> dict[str, str]:
    """Links of the project ([project.urls] of pyproject.toml), by lowercase name."""
    try:
        entries = metadata("security-review-mcp").get_all("Project-URL") or []
    except PackageNotFoundError:
        return {}
    urls = {}
    for entry in entries:
        name, _, url = entry.partition(",")
        urls[name.strip().lower()] = url.strip()
    return urls


@router.get("/about")
async def about(request: Request) -> About:
    """Version of the controller and links of the About page (any web user)."""
    urls = project_urls()
    return About(
        version=__version__,
        documentation_url=urls.get("documentation"),
        repository_url=urls.get("repository"),
        issues_url=urls.get("issues"),
        swagger_url=DOCS_PATH if request.app.state.swagger_served else None,
        health_url=API_HEALTH_PATH,
    )


@router.get("/about/update")
async def about_update() -> UpdateStatus:
    """Latest release on GitHub against the running version (any web user).

    Disabled by default (SECREVIEW_UPDATE_CHECK_ENABLED); the answer of GitHub is cached.
    """
    settings = app_settings.effective_settings(get_settings())
    return UpdateStatus(**await run_in_threadpool(update_check.check, settings))


@router.get("/me")
async def me(identity: CurrentIdentity) -> Identity:
    """Return the identity and permissions of the caller, with the triage options it has."""
    permanent = (
        identity.can_triage
        and identity.auth_source is not None
        and get_settings().permanent_acceptance_enabled
    )
    return identity.model_copy(update={"permanent_acceptance": permanent})


@router.post("/me/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, identity: CurrentIdentity) -> Response:
    """Record the logout of a web user in the audit log; the interface then drops its session.

    A bearer token has no session to end (403).
    """
    if identity.auth_source is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only a web user logged in has a session")
    await run_in_threadpool(web_users.record_logout, identity.client, client_address(request))
    logger.info("Web user %s logged out", identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me/tokens")
async def my_tokens(request: Request, _: CurrentIdentity) -> list[ProjectToken]:
    """The personal tokens (api and mcp) of the logged-in web user (never their secret)."""
    user_id = web_user_id(request)
    return await run_in_threadpool(token_store.list_personal_tokens, user_id)


@router.post("/me/tokens", status_code=status.HTTP_201_CREATED)
async def create_my_token(
    request: Request, body: PersonalTokenCreate, identity: CurrentIdentity, response: Response
) -> ProjectTokenSecret:
    """Create a personal token of the logged-in web user and return its secret exactly once.

    An ``api`` token (REST API, Swagger) holds the current rights of the user; an ``mcp`` token
    (MCP agent) reaches the projects the user may read. Both are read at each request; like
    every token, they never accept a risk nor mark a false positive. An ``mcp`` token needs
    the ``mcp_tokens.create`` permission (403 without it). A user holds at most
    SECREVIEW_PERSONAL_TOKENS_PER_USER tokens of each role (422 beyond)."""
    user_id = web_user_id(request)
    if body.role == "mcp" and not has_permission(identity, Permission.MCP_TOKENS_CREATE):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"Permission '{Permission.MCP_TOKENS_CREATE}' required"
        )
    try:
        created = await run_in_threadpool(
            token_store.create_personal_token,
            user_id,
            body.label,
            body.expires_in_days,
            body.role,
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Personal %s token %s created by %s", body.role, created["label"], identity.client)
    # The secret is shown once: never cached
    response.headers.update(LOGIN_HEADERS)
    return created


@router.delete("/me/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_my_token(request: Request, token_id: str, identity: CurrentIdentity) -> Response:
    """Revoke a personal token of the logged-in web user (that of another user is not found)."""
    user_id = web_user_id(request)
    try:
        await run_in_threadpool(
            token_store.revoke_personal_token, user_id, token_id[:64], actor_of(identity)
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info("Personal token %s revoked by %s", token_id[:64], identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me/preferences")
async def my_preferences(request: Request, _: CurrentIdentity) -> Preferences:
    """Preferences of the logged-in web user (its theme)."""
    return Preferences(**await run_in_threadpool(web_users.get_preferences, web_user_id(request)))


@router.put("/me/preferences")
async def set_my_preferences(
    request: Request, body: Preferences, _: CurrentIdentity
) -> Preferences:
    """Remember the preferences of the logged-in web user, for every browser it uses."""
    user_id = web_user_id(request)
    return Preferences(**await run_in_threadpool(web_users.set_theme, user_id, body.theme))


@router.put("/me/password")
async def change_password(
    request: Request, body: PasswordChange, identity: CurrentIdentity, response: Response
) -> LoginSession:
    """Change the password of the logged-in web user and return a new session.

    The other sessions of the user end. Wrong current passwords count as failed logins.
    """
    user_id = (request.scope.get("state") or {}).get("auth_user_id")
    if user_id is None or not identity.local_account:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only a local web user logged in with a password has one"
        )
    throttle: rate_limit.LoginThrottle = request.app.state.login_throttle
    address = client_address(request)
    if await run_in_threadpool(throttle.blocked, identity.client, address):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed attempts: try again later",
            headers={"Retry-After": str(int(throttle.window))},
        )
    try:
        user = await run_in_threadpool(
            web_users.change_own_password, user_id, body.current_password, body.new_password
        )
    except ValueError as exc:
        if "current password" in str(exc):
            await run_in_threadpool(throttle.failed, identity.client, address)
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    result = await open_session(request, user["id"], response)
    logger.info("Password of web user %s changed by the user", user["username"])
    return result
