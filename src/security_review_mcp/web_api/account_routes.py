"""Routes of the caller itself: liveness probe, identity and password of a web user."""

import logging

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool

from .. import web_users
from .auth_routes import open_session
from .deps import CurrentIdentity, client_address
from .schemas import HealthStatus, Identity, LoginSession, PasswordChange

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["account"])


@router.get("/health")
async def health() -> HealthStatus:
    """Liveness probe."""
    return HealthStatus()


@router.get("/me")
async def me(identity: CurrentIdentity) -> Identity:
    """Return the identity and permissions of the caller."""
    return identity


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
    throttle: web_users.LoginThrottle = request.app.state.login_throttle
    address = client_address(request)
    if throttle.blocked(identity.client, address):
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
            throttle.failed(identity.client, address)
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    result = await open_session(request, user["id"], response)
    logger.info("Password of web user %s changed by the user", user["username"])
    return result
