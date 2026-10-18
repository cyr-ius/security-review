"""Public routes of the login flow (``/api/v1/auth``): password login and single sign-on.

The bearer middleware lets them through without a token (http_server.AUTH_PREFIX), so they
never read the identity of the caller.
"""

import logging
import threading
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import RedirectResponse

from .. import app_settings, oidc, rate_limit, web_users
from ..config import Settings, get_settings
from .deps import client_address
from .schemas import AuthConfig, LoginSession, PasswordLogin

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# The callback URL holds the authorization code, the redirect the session token
LOGIN_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


class OidcLogins:
    """Current OIDC login flow of the controller.

    A ``fixed`` flow (tests) is always used. Otherwise the flow follows the effective settings,
    the ``SECREVIEW_OIDC_*`` variables overridden in the web interface (see
    app_settings.effective_settings), read at each call: it is rebuilt when they change, so that
    every replica applies a change at its next login.
    """

    def __init__(self, signer: oidc.SessionSigner, fixed: oidc.OidcLogin | None = None) -> None:
        self.signer = signer
        self.fixed = fixed
        self._lock = threading.Lock()
        self._login: oidc.OidcLogin | None = None
        # Settings refused by validate_settings, logged once
        self._refused: Settings | None = None

    def current(self) -> oidc.OidcLogin | None:
        """Return the login flow of the effective settings, or None when SSO is disabled."""
        if self.fixed is not None:
            return self.fixed
        settings = app_settings.effective_settings(get_settings())
        if not settings.oidc_enabled:
            return None
        with self._lock:
            if self._login is not None and self._login.settings == settings:
                return self._login
            if self._refused == settings:
                return None
            try:
                self._login = oidc.from_settings(settings, self.signer)
            except ValueError as exc:
                logger.error("SSO login disabled, invalid settings: %s", exc)
                self._login, self._refused = None, settings
                return None
            self._refused = None
            logger.info("OIDC login enabled with %s", self._login.issuer)
            return self._login


async def current_oidc(request: Request) -> oidc.OidcLogin | None:
    """Return the current OIDC login flow, or None when SSO is disabled."""
    logins: OidcLogins = request.app.state.oidc
    return await run_in_threadpool(logins.current)


async def _oidc_login(request: Request) -> oidc.OidcLogin:
    """Return the current OIDC login flow; 404 when OIDC is disabled."""
    login = await current_oidc(request)
    if login is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC is not enabled")
    return login


def _to_login_page(login: oidc.OidcLogin, query: dict[str, str], fragment: str = "") -> Response:
    """Redirect to the login page of the web application and drop the state cookie."""
    url = f"{oidc.UI_LOGIN_PATH}?{urlencode(query)}" + (f"#{fragment}" if fragment else "")
    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER, headers=LOGIN_HEADERS)
    response.delete_cookie(
        oidc.STATE_COOKIE,
        path=login.cookie_path,
        secure=login.secure_cookie,
        httponly=True,
        samesite="lax",
    )
    return response


def _log_name(username: str) -> str:
    """Username as written in the logs: only a valid one, never arbitrary input."""
    try:
        return web_users.clean_username(username)
    except ValueError:
        return "<invalid username>"


async def open_session(request: Request, user_id: int, response: Response) -> LoginSession:
    """Open a session for a web user; the answer is never cached."""
    signer: oidc.SessionSigner = request.app.state.signer
    session = await run_in_threadpool(web_users.new_session, signer, user_id)
    response.headers.update(LOGIN_HEADERS)
    return LoginSession(**session)


@router.get("/config")
async def auth_config(request: Request) -> AuthConfig:
    """Tell the login page whether single sign-on (OIDC) is available."""
    login = await current_oidc(request)
    return AuthConfig(
        password=True,
        oidc=login is not None,
        oidc_display_name=login.display_name if login else None,
    )


@router.post("/login")
async def password_login(request: Request, body: PasswordLogin, response: Response) -> LoginSession:
    """Log a web user in with a username and a password; return a session token.

    Failed attempts are throttled per username and address (429 once the limit is reached);
    the answer never tells whether the username exists.
    """
    throttle: rate_limit.LoginThrottle = request.app.state.login_throttle
    address = client_address(request)
    username = body.username.strip()
    if await run_in_threadpool(throttle.blocked, username, address):
        logger.warning(
            "Web login of %s from %s refused: too many failures", _log_name(username), address
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed logins: try again later",
            headers={"Retry-After": str(int(throttle.window))},
        )
    user = await run_in_threadpool(web_users.authenticate, username, body.password, address)
    if user is None:
        await run_in_threadpool(throttle.failed, username, address)
        logger.warning("Failed web login of %s from %s", _log_name(username), address)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    await run_in_threadpool(throttle.succeeded, username, address)
    result = await open_session(request, user["id"], response)
    logger.info("Web login of %s (role %s) from %s", result.username, result.role, address)
    return result


@router.get("/oidc/login", response_class=RedirectResponse, status_code=302)
async def oidc_login(
    request: Request,
    return_url: Annotated[str | None, Query(max_length=oidc.MAX_RETURN_URL_CHARS)] = None,
) -> Response:
    """Start an OIDC login: redirect to the identity provider (code flow with PKCE)."""
    login = await _oidc_login(request)
    try:
        started = await run_in_threadpool(login.start, return_url)
    except oidc.OidcError as exc:
        return _to_login_page(login, {"oidcError": exc.code})
    response = RedirectResponse(
        started.authorization_url, status_code=status.HTTP_302_FOUND, headers=LOGIN_HEADERS
    )
    response.set_cookie(
        oidc.STATE_COOKIE,
        started.state_cookie,
        max_age=oidc.STATE_TTL_SECONDS,
        path=login.cookie_path,
        secure=login.secure_cookie,
        httponly=True,
        # Lax: the cookie comes back with the top-level redirect from the provider
        samesite="lax",
    )
    return response


@router.get("/oidc/callback", response_class=RedirectResponse, status_code=303)
async def oidc_callback(
    request: Request,
    code: Annotated[str | None, Query(max_length=4096)] = None,
    state: Annotated[str | None, Query(max_length=512)] = None,
    error: Annotated[str | None, Query(max_length=100)] = None,
) -> Response:
    """End an OIDC login: hand a session token to the web application, or an error code.

    The token goes in the URL fragment of the login page, which the browser never sends to a
    server; the page removes it from the address bar and keeps it in the tab only.
    """
    login = await _oidc_login(request)
    address = client_address(request)
    if error or not code or not state:
        reason = "".join(c for c in (error or "missing code or state") if c.isprintable())
        logger.warning("OIDC login not completed: %s", reason)
        await run_in_threadpool(web_users.record_login_failure, None, "oidc", address)
        return _to_login_page(login, {"oidcError": "denied" if error else "state"})
    user: oidc.OidcIdentity | None = None
    try:
        user = await run_in_threadpool(
            login.finish, code, state, request.cookies.get(oidc.STATE_COOKIE)
        )
        result = await run_in_threadpool(
            web_users.oidc_login, login.signer, user, login.settings, address
        )
    except oidc.OidcError as exc:
        logger.warning("OIDC login failed: %s", exc)
        await run_in_threadpool(
            web_users.record_login_failure, user.username if user else None, "oidc", address
        )
        return _to_login_page(login, {"oidcError": exc.code})
    return _to_login_page(
        login, {"returnUrl": user.return_url}, urlencode({"session": result["session"]})
    )
