"""Controller: REST API (``/api/v1``) and the bundled Angular application (``/ui``).

Served by ``security-review-controller serve``, in its own process, apart from the MCP server
(see http_server). The bearer middleware authenticates the requests and stores the token label
and role in the ASGI scope; this module checks the permissions of each route. The public
enrollment endpoint is served by the MCP server (see enrollment_api); approving or rejecting
the requests is done here.

The services are synchronous (SQLModel sessions), so every call runs in the thread pool.
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi import Path as APIPath
from fastapi.concurrency import run_in_threadpool
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import Scope

from . import (
    __version__,
    advisories,
    advisory_sync,
    app_settings,
    oidc,
    proxy,
    registry,
    role_mapping,
    rule_store,
    rules_loader,
    services,
    standards,
    token_store,
    trends,
    web_users,
)
from .config import REPORT_LANGUAGE_MAX_CHARS, Settings, get_settings
from .http_server import (
    BEARER_CHALLENGE,
    CI_ROUTE_ROLES,
    DOCS_PATH,
    FAVICON_PATH,
    HEALTH_PATH,
    LOOPBACK_HOSTS,
    OPENAPI_PATH,
    TRIAGE_ROLES,
    Role,
)
from .models import FindingPublic, FindingStatus, ReviewType, SecurityReportPublic, Severity
from .sarif import build_sarif

logger = logging.getLogger("security_review_mcp.web")

BUNDLED_UI_DIR = Path(__file__).parent / "webui"
# Icon of the web interface and of the Swagger documentation (the brand mark of the UI)
FAVICON = (Path(__file__).parent / "favicon.svg").read_bytes()

# Declares the bearer scheme in the OpenAPI document (Swagger "Authorize" button). The token
# itself is validated by the bearer middleware: auto_error=False leaves the 401 to
# current_identity, which also covers an app served without that middleware.
bearer_scheme = HTTPBearer(
    auto_error=False, description="API token (`security-review-controller token create`)"
)

# The Angular build loads no inline script and no external resource. Component styles are
# injected as <style> elements at runtime, hence 'unsafe-inline' for styles only.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


# ── Schemas ──────────────────────────────────────────────────────────────────


class Identity(BaseModel):
    """Who is calling and what they may do."""

    client: str
    role: Role
    can_triage: bool
    # Always true: the API answers authenticated requests only (kept for API compatibility)
    auth_enabled: bool
    # Projects a restricted token reaches; None: every project
    projects: list[str] | None = None
    # True for a local web user (logged in with a password, which it may change)
    local_account: bool = False
    # Source of the account of a web user ("local" or "oidc"); None for a bearer token
    auth_source: Literal["local", "oidc"] | None = None
    version: str


class FindingStatusUpdate(BaseModel):
    """Body of PATCH /findings/{id}."""

    status: FindingStatus


class RuleWrite(BaseModel):
    """A custom scan rule sent to the web API."""

    id: str = Field(min_length=3, max_length=rules_loader.MAX_ID_CHARS)
    title: str = Field(min_length=1, max_length=rules_loader.MAX_TITLE_CHARS)
    severity: Severity
    cwe: str = Field(default="", max_length=20)
    languages: list[Annotated[str, Field(max_length=32)]] = Field(min_length=1, max_length=32)
    pattern: str = Field(min_length=1, max_length=rules_loader.MAX_PATTERN_CHARS)
    advice: str = Field(default="", max_length=rules_loader.MAX_TEXT_CHARS)
    ignore_case: bool = True


class RuleEnabledUpdate(BaseModel):
    """Enabled state of a custom scan rule."""

    enabled: bool


class ChecklistItemWrite(BaseModel):
    """A checklist item sent to the web API."""

    domain: str = Field(min_length=1, max_length=31)
    id: str = Field(min_length=3, max_length=rules_loader.MAX_ID_CHARS)
    title: str = Field(min_length=1, max_length=rules_loader.MAX_TITLE_CHARS)
    what_to_look_for: str = Field(min_length=1, max_length=rules_loader.MAX_TEXT_CHARS)
    cwe: str = Field(default="", max_length=20)


class StandardWrite(BaseModel):
    """A development standard sent to the web API (validated again by standards.normalize)."""

    slug: str = Field(min_length=1, max_length=50)
    title: str = Field(min_length=1, max_length=standards.MAX_TITLE_CHARS)
    description: str = Field(default="", max_length=standards.MAX_DESCRIPTION_CHARS)
    technologies: list[Annotated[str, Field(max_length=standards.MAX_KEYWORD_CHARS)]] = Field(
        default_factory=list, max_length=standards.MAX_KEYWORDS
    )
    file_patterns: list[Annotated[str, Field(max_length=standards.MAX_PATTERN_CHARS)]] = Field(
        default_factory=list, max_length=standards.MAX_KEYWORDS
    )
    content: str = Field(min_length=1, max_length=standards.MAX_CONTENT_CHARS)
    enabled: bool = True


class RoleMappingCreate(BaseModel):
    """An identity provider group or role mapped to a web role (and projects)."""

    claim_value: str = Field(min_length=1, max_length=role_mapping.MAX_CLAIM_VALUE_CHARS)
    role: Literal["reader", "triager", "admin"]
    # Empty: every project (always for admin)
    projects: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )


class RoleMappingUpdate(BaseModel):
    """New projects of a role mapping (empty: every project)."""

    projects: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )


class WebUserCreate(BaseModel):
    """A web user. A local one without ``password`` gets a random one, returned once; an SSO
    one (``auth_source="oidc"``) has no password and may have no role (``role`` null)."""

    username: str = Field(min_length=1, max_length=web_users.MAX_USERNAME_CHARS)
    auth_source: Literal["local", "oidc"] = "local"
    password: str | None = Field(
        default=None,
        min_length=web_users.MIN_PASSWORD_CHARS,
        max_length=web_users.MAX_PASSWORD_CHARS,
    )
    role: Literal["reader", "triager", "admin"] | None = "reader"
    # Empty: every project (always for admin)
    projects: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )


class WebUserUpdate(BaseModel):
    """New role and projects of a web user (empty projects: every project; null role: only
    the role of the groups, for an SSO user)."""

    role: Literal["reader", "triager", "admin"] | None
    projects: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )


class PasswordReset(BaseModel):
    """New password of a web user, set by an administrator (null: generate one)."""

    password: str | None = Field(
        default=None,
        min_length=web_users.MIN_PASSWORD_CHARS,
        max_length=web_users.MAX_PASSWORD_CHARS,
    )


class PasswordChange(BaseModel):
    """Body of PUT /me/password: the current password and the new one."""

    current_password: str = Field(min_length=1, max_length=web_users.MAX_PASSWORD_CHARS)
    new_password: str = Field(
        min_length=web_users.MIN_PASSWORD_CHARS, max_length=web_users.MAX_PASSWORD_CHARS
    )


class EnrollmentApproval(BaseModel):
    """Optional body of an approval: the web user who also reads the project on the web (an
    unknown name becomes an SSO user when OIDC is enabled)."""

    portal_user: str | None = Field(default=None, max_length=web_users.MAX_USERNAME_CHARS)


class ProjectTokenCreate(BaseModel):
    """A role-specific token scoped to one or several projects."""

    label: str = Field(min_length=1, max_length=64)
    # ci: pipeline token (gate, SARIF and trend of its projects only, see ci_client)
    role: Literal["mcp", "reader", "triager", "ci"] = "reader"
    projects: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        min_length=1, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )


class ReportLanguageUpdate(BaseModel):
    """Body of PUT /settings/report-language: "" lets the agent choose, null restores the
    SECREVIEW_REPORT_LANGUAGE variable."""

    value: str | None = Field(default=None, max_length=REPORT_LANGUAGE_MAX_CHARS)


class ProxyUpdate(BaseModel):
    """Body of PUT /settings/proxy: proxy of the outgoing connections of the controller.

    A field left out is unchanged, ``null`` applies the variable again (SECREVIEW_PROXY,
    SECREVIEW_NO_PROXY). ``url`` ``""`` connects directly, despite the variables; a password
    sent back as returned by the API (``***``) keeps the stored one.
    """

    model_config = ConfigDict(extra="forbid")

    url: str | None = Field(default=None, max_length=proxy.MAX_PROXY_URL_CHARS)
    no_proxy: str | None = Field(default=None, max_length=proxy.MAX_NO_PROXY_CHARS)


_OidcText = Annotated[str, Field(max_length=app_settings.MAX_OIDC_VALUE_CHARS)]


class OidcSettingsUpdate(BaseModel):
    """Body of PUT /oidc/settings and POST /oidc/settings/test.

    A field left out is unchanged, ``null`` applies the ``SECREVIEW_OIDC_*`` variable again. A
    client secret sent back as returned by the API (``***``) keeps the stored one; ``""`` makes
    the client public.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    issuer: _OidcText | None = None
    client_id: _OidcText | None = None
    client_secret: _OidcText | None = None
    redirect_uri: _OidcText | None = None
    scopes: _OidcText | None = None
    roles_claim: _OidcText | None = None
    username_claim: _OidcText | None = None
    admin_groups: _OidcText | None = None
    triager_groups: _OidcText | None = None
    reader_groups: _OidcText | None = None
    default_role: Literal["", "reader", "triager"] | None = None
    auto_create_users: bool | None = None
    display_name: _OidcText | None = None


class ProjectSummary(BaseModel):
    """One project with its open findings."""

    project: str
    reports_total: int
    last_report_at: str
    open_findings_total: int
    open_findings_by_severity: dict[str, int]
    worst_open_severity: Severity | None


class ReportSummary(BaseModel):
    """One line of the report list."""

    report_id: int
    project: str
    branch: str | None
    commit_sha: str | None
    review_type: ReviewType | None
    risk_level: Severity
    reviewer: str | None
    created_at: str
    findings_total: int
    findings_open: int
    summary: str


class ProjectFinding(FindingPublic):
    """A finding of a project, with the context of its report."""

    branch: str | None
    commit_sha: str | None
    review_type: ReviewType | None
    report_created_at: datetime


class ProjectFindingPage(BaseModel):
    """One page of the findings of a project (``total`` counts every matching finding)."""

    project: str
    total: int
    findings: list[ProjectFinding]


# ── Dependencies ─────────────────────────────────────────────────────────────


def _scope_identity(request: Request) -> Identity:
    """Identity set by the bearer middleware once it has validated the token.

    Fails closed: a request that reaches a route without an identity in its scope (app served
    without BearerAuthMiddleware, or a public path mistakenly routed here) gets 401, never an
    implicit administrator.
    """
    state = request.scope.get("state") or {}
    if "auth_role" not in state:
        logger.warning(
            "Rejected API request without an authenticated identity: %s", request.url.path
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid bearer token",
            headers={"WWW-Authenticate": BEARER_CHALLENGE},
        )
    role = Role(state["auth_role"])
    return Identity(
        client=state["auth_client"],
        role=role,
        can_triage=role in TRIAGE_ROLES,
        auth_enabled=True,
        projects=None if state.get("auth_projects") is None else sorted(state["auth_projects"]),
        local_account=state.get("auth_source") == web_users.AUTH_LOCAL,
        auth_source=state.get("auth_source"),
        version=__version__,
    )


def current_identity(
    request: Request,
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> Identity:
    """Identity of a web role (reader, triager, admin): a ``ci`` token is refused here even if
    the bearer middleware let it through (it only reaches the pipeline routes)."""
    identity = _scope_identity(request)
    if identity.role == Role.CI:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{identity.role}' cannot access this endpoint",
        )
    return identity


def pipeline_identity(
    request: Request,
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> Identity:
    """Identity of the pipeline routes: a ``ci`` token or a web role, scoped to its projects."""
    identity = _scope_identity(request)
    if identity.role not in CI_ROUTE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{identity.role}' cannot access this endpoint",
        )
    return identity


CurrentIdentity = Annotated[Identity, Depends(current_identity)]
PipelineIdentity = Annotated[Identity, Depends(pipeline_identity)]


def require_triage(identity: CurrentIdentity) -> Identity:
    """Only triagers and administrators may change a finding status."""
    if not identity.can_triage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{identity.role}' cannot change finding status",
        )
    return identity


def require_admin(identity: CurrentIdentity) -> Identity:
    """Only web administrators may change rule packs."""
    if identity.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{identity.role}' cannot manage rules",
        )
    return identity


def _in_scope(identity: Identity, project: str) -> bool:
    """True when the caller may see this project (always for an unrestricted token)."""
    return identity.projects is None or project in identity.projects


def _scoped_project(identity: Identity, requested: str) -> str:
    """Refuse a project outside a project token's scope without disclosing other projects."""
    if not _in_scope(identity, requested):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return requested


def _ensure_report_scope(identity: Identity, report: SecurityReportPublic) -> None:
    """Hide reports outside a project token's scope, with the answer of a missing report (the
    caller cannot tell which report ids exist in other projects)."""
    if not _in_scope(identity, report.project):
        raise services.NotFoundError(f"Report {report.id} not found")


def _rule_catalog() -> dict:
    """Return the rules stored in the database (default and custom) and the diagnostics."""
    return {
        "rules": rule_store.list_rules(),
        "load_errors": list(registry.snapshot().errors),
    }


async def _refresh_rules() -> dict:
    """Reload the active registry and return its diagnostics."""
    snapshot = await run_in_threadpool(registry.reload)
    return {"loaded_rules": len(snapshot.custom_rule_ids), "load_errors": list(snapshot.errors)}


async def _refresh_checklists() -> dict:
    """Reload the active registry and return checklist-specific diagnostics."""
    snapshot = await run_in_threadpool(registry.reload)
    count = sum(len(items) for items in snapshot.checklists.values())
    return {"loaded_checklist_items": count, "load_errors": list(snapshot.errors)}


# ── Login (public) ───────────────────────────────────────────────────────────


# Public routes of the login flow: the bearer middleware lets them through without a token
# (http_server.AUTH_PREFIX), so they never read the identity of the caller.
auth_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# The callback URL holds the authorization code, the redirect the session token
LOGIN_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


class AuthConfig(BaseModel):
    """Login methods offered by the login page (web users only: tokens are for the API)."""

    # Username and password of a web user (always offered by the controller)
    password: bool = True
    oidc: bool
    oidc_display_name: str | None = None


class PasswordLogin(BaseModel):
    """Body of POST /auth/login."""

    username: str = Field(min_length=1, max_length=web_users.MAX_USERNAME_CHARS)
    password: str = Field(min_length=1, max_length=web_users.MAX_PASSWORD_CHARS)


class LoginSession(BaseModel):
    """Session opened by a password login, sent back as a bearer token."""

    session: str
    expires_in: int
    username: str
    role: Role


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


async def _current_oidc(request: Request) -> oidc.OidcLogin | None:
    """Return the current OIDC login flow, or None when SSO is disabled."""
    logins: OidcLogins = request.app.state.oidc
    return await run_in_threadpool(logins.current)


async def _oidc_login(request: Request) -> oidc.OidcLogin:
    """Return the current OIDC login flow; 404 when OIDC is disabled."""
    login = await _current_oidc(request)
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


@auth_router.get("/config")
async def auth_config(request: Request) -> AuthConfig:
    """Tell the login page whether single sign-on (OIDC) is available."""
    login = await _current_oidc(request)
    return AuthConfig(
        password=True,
        oidc=login is not None,
        oidc_display_name=login.display_name if login else None,
    )


def _client_address(request: Request) -> str:
    """Address of the caller, for the login throttling and the logs."""
    return request.client.host if request.client else "unknown"


def _log_name(username: str) -> str:
    """Username as written in the logs: only a valid one, never arbitrary input."""
    try:
        return web_users.clean_username(username)
    except ValueError:
        return "<invalid username>"


@auth_router.post("/login")
async def password_login(request: Request, body: PasswordLogin) -> JSONResponse:
    """Log a web user in with a username and a password; return a session token.

    Failed attempts are throttled per username and address (429 once the limit is reached);
    the answer never tells whether the username exists.
    """
    signer: oidc.SessionSigner = request.app.state.signer
    throttle: web_users.LoginThrottle = request.app.state.login_throttle
    address = _client_address(request)
    username = body.username.strip()
    if throttle.blocked(username, address):
        logger.warning(
            "Web login of %s from %s refused: too many failures", _log_name(username), address
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed logins: try again later",
            headers={"Retry-After": str(int(throttle.window))},
        )
    user = await run_in_threadpool(web_users.authenticate, username, body.password)
    if user is None:
        throttle.failed(username, address)
        logger.warning("Failed web login of %s from %s", _log_name(username), address)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    throttle.succeeded(username, address)
    result = LoginSession(**await run_in_threadpool(web_users.new_session, signer, user["id"]))
    logger.info("Web login of %s (role %s) from %s", result.username, result.role, address)
    return JSONResponse(result.model_dump(mode="json"), headers=LOGIN_HEADERS)


@auth_router.get("/oidc/login", response_class=RedirectResponse, status_code=302)
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


@auth_router.get("/oidc/callback", response_class=RedirectResponse, status_code=303)
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
    if error or not code or not state:
        reason = "".join(c for c in (error or "missing code or state") if c.isprintable())
        logger.warning("OIDC login not completed: %s", reason)
        return _to_login_page(login, {"oidcError": "denied" if error else "state"})
    try:
        user = await run_in_threadpool(
            login.finish, code, state, request.cookies.get(oidc.STATE_COOKIE)
        )
        result = await run_in_threadpool(web_users.oidc_login, login.signer, user, login.settings)
    except oidc.OidcError as exc:
        logger.warning("OIDC login failed: %s", exc)
        return _to_login_page(login, {"oidcError": exc.code})
    return _to_login_page(
        login, {"returnUrl": user.return_url}, urlencode({"session": result["session"]})
    )


# ── Routes ───────────────────────────────────────────────────────────────────


# Every route needs an authenticated identity, even those that do not use it (health)
router = APIRouter(prefix="/api/v1", dependencies=[Depends(current_identity)])


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@router.get("/me")
async def me(identity: CurrentIdentity) -> Identity:
    """Return the identity and permissions of the caller."""
    return identity


@router.put("/me/password")
async def change_password(
    request: Request, body: PasswordChange, identity: CurrentIdentity
) -> JSONResponse:
    """Change the password of the logged-in web user and return a new session.

    The other sessions of the user end. Wrong current passwords count as failed logins.
    """
    user_id = (request.scope.get("state") or {}).get("auth_user_id")
    if user_id is None or not identity.local_account:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only a local web user logged in with a password has one"
        )
    throttle: web_users.LoginThrottle = request.app.state.login_throttle
    address = _client_address(request)
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
    signer: oidc.SessionSigner = request.app.state.signer
    result = LoginSession(**await run_in_threadpool(web_users.new_session, signer, user["id"]))
    logger.info("Password of web user %s changed by the user", user["username"])
    return JSONResponse(result.model_dump(mode="json"), headers=LOGIN_HEADERS)


@router.get("/projects")
async def projects(identity: CurrentIdentity) -> list[ProjectSummary]:
    """List the projects with their open findings, latest activity first."""
    projects = await run_in_threadpool(services.list_projects)
    return [item for item in projects if _in_scope(identity, item["project"])]


@router.get("/posture")
async def posture(
    project: Annotated[str, Query(min_length=1, max_length=200)], identity: CurrentIdentity
) -> dict:
    """Open findings of a project across all its reports."""
    return await run_in_threadpool(services.project_posture, _scoped_project(identity, project))


@router.get("/findings")
async def project_findings(
    project: Annotated[str, Query(min_length=1, max_length=200)],
    identity: CurrentIdentity,
    finding_status: Annotated[FindingStatus, Query(alias="status")] = FindingStatus.OPEN,
    severity: Severity | None = None,
    review_type: ReviewType | None = None,
    limit: Annotated[int, Query(ge=1)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ProjectFindingPage:
    """Findings of a project across all its reports (open by default), worst first.

    Gives an expert the whole list to review; limit is capped by SECREVIEW_MAX_LIST_LIMIT.
    """
    return await run_in_threadpool(
        services.list_project_findings,
        _scoped_project(identity, project),
        finding_status,
        severity,
        limit,
        offset,
        review_type,
    )


@router.get("/trend")
async def trend(
    project: Annotated[str, Query(min_length=1, max_length=200)],
    identity: CurrentIdentity,
    days: Annotated[int, Query(ge=1, le=1095)] = 90,
    granularity: Literal["day", "week", "month"] = "week",
) -> dict:
    """Evolution of the security posture of a project."""
    try:
        return await run_in_threadpool(
            trends.get_trend, _scoped_project(identity, project), days, granularity
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


@router.get("/sarif")
async def sarif(
    identity: CurrentIdentity,
    project: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    report_id: Annotated[int | None, Query(ge=1)] = None,
    include_resolved: bool = False,
) -> Response:
    """Download the findings of a project or of a report as SARIF 2.1.0."""
    try:
        if identity.projects is not None:
            if project is not None:
                _scoped_project(identity, project)
            if report_id is not None:
                scoped_report = await run_in_threadpool(services.get_report, report_id)
                _ensure_report_scope(identity, scoped_report)
            elif project is None and len(identity.projects) == 1:
                project = identity.projects[0]
        name, items = await run_in_threadpool(services.collect_sarif_items, report_id, project)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    filename = f"report-{report_id}.sarif" if report_id else "project.sarif"
    return _sarif_response(name, items, include_resolved, filename)


def _sarif_response(name: str, items: list, include_resolved: bool, filename: str) -> Response:
    """SARIF 2.1.0 download of collected findings."""
    document = build_sarif(items, name, include_resolved)
    return Response(
        content=json.dumps(document, indent=2),
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Pipeline routes (ci tokens, see ci_client) ───────────────────────────────


# Read only, scoped to the projects of the token; a ci token reaches nothing else
ci_router = APIRouter(prefix="/api/v1/ci", dependencies=[Depends(pipeline_identity)])

ProjectQuery = Annotated[str, Query(min_length=1, max_length=200)]


@ci_router.get("/gate")
async def ci_gate(
    project: ProjectQuery,
    identity: PipelineIdentity,
    fail_on: Severity = Severity.HIGH,
    report_id: Annotated[int | None, Query(ge=1)] = None,
) -> dict:
    """Security gate of a project: ``passed`` is false while open findings reach ``fail_on``.

    ``report_id`` judges one report of the project only.
    """
    project = _scoped_project(identity, project)
    if report_id is not None:
        report = await run_in_threadpool(services.get_report, report_id)
        _ensure_report_scope(identity, report)
    try:
        return await run_in_threadpool(services.evaluate_gate, project, fail_on, report_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


@ci_router.get("/sarif")
async def ci_sarif(
    project: ProjectQuery, identity: PipelineIdentity, include_resolved: bool = False
) -> Response:
    """Findings of a project as SARIF 2.1.0 (open ones only by default)."""
    project = _scoped_project(identity, project)
    name, items = await run_in_threadpool(services.collect_sarif_items, None, project)
    return _sarif_response(name, items, include_resolved, "project.sarif")


@ci_router.get("/trend")
async def ci_trend(
    project: ProjectQuery,
    identity: PipelineIdentity,
    days: Annotated[int, Query(ge=1, le=1095)] = 90,
    granularity: Literal["day", "week", "month"] = "week",
    output: Annotated[Literal["json", "markdown"], Query(alias="format")] = "json",
) -> Response:
    """Evolution of the security posture of a project, as JSON or Markdown."""
    try:
        result = await run_in_threadpool(
            trends.get_trend, _scoped_project(identity, project), days, granularity
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    if output == "markdown":
        return PlainTextResponse(
            trends.render_trend_markdown(result), media_type="text/markdown; charset=utf-8"
        )
    return JSONResponse(result)


@router.get("/reports")
async def reports(
    identity: CurrentIdentity,
    project: Annotated[str | None, Query(max_length=200)] = None,
    risk_level: Severity | None = None,
    review_type: ReviewType | None = None,
    limit: Annotated[int, Query(ge=1)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ReportSummary]:
    """List reports, newest first (limit is capped by SECREVIEW_MAX_LIST_LIMIT)."""
    if project:
        _scoped_project(identity, project)
    return await run_in_threadpool(
        services.list_reports,
        project or None,
        risk_level,
        limit,
        offset,
        identity.projects,
        review_type,
    )


@router.get("/reports/{report_id}")
async def report(report_id: int, identity: CurrentIdentity) -> SecurityReportPublic:
    """Return a report with its findings."""
    stored = await run_in_threadpool(services.get_report, report_id)
    _ensure_report_scope(identity, stored)
    return stored


@router.get("/reports/{report_id}/markdown", response_class=PlainTextResponse)
async def report_markdown(report_id: int, identity: CurrentIdentity) -> PlainTextResponse:
    """Download a report as Markdown."""
    stored = await run_in_threadpool(services.get_report, report_id)
    _ensure_report_scope(identity, stored)
    return PlainTextResponse(
        services.render_report_markdown(stored),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report-{report_id}.md"'},
    )


@router.patch("/findings/{finding_id}")
async def update_finding(
    finding_id: int,
    body: FindingStatusUpdate,
    identity: Annotated[Identity, Depends(require_triage)],
) -> FindingPublic:
    """Change the status of a finding (triage). The change is logged with the caller."""
    await run_in_threadpool(services.check_finding_scope, identity.projects, finding_id)
    finding = await run_in_threadpool(services.update_finding_status, finding_id, body.status)
    logger.info("Finding %s set to %s by %s", finding_id, body.status, identity.client)
    return finding


@router.get("/rules")
async def list_custom_rules(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """List the rules stored in the database (default and custom)."""
    return await run_in_threadpool(_rule_catalog)


@router.get("/checklists")
async def list_checklist_items(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """List the checklist items stored in the database (default and custom)."""
    return {
        "checklist_items": await run_in_threadpool(rule_store.list_checklist_items),
        "load_errors": list(registry.snapshot().errors),
    }


@router.post("/checklists", status_code=status.HTTP_201_CREATED)
async def create_checklist_item(
    body: ChecklistItemWrite, identity: Annotated[Identity, Depends(require_admin)]
) -> dict:
    """Create a custom checklist item."""
    try:
        await run_in_threadpool(rule_store.create_check_item, body.model_dump(mode="json"))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Checklist item %s/%s created by %s", body.domain, body.id, identity.client)
    return await _refresh_checklists()


@router.put("/checklists/{domain}/{item_id}")
async def update_checklist_item(
    domain: Annotated[str, APIPath(min_length=1, max_length=31)],
    item_id: Annotated[str, APIPath(min_length=3, max_length=rules_loader.MAX_ID_CHARS)],
    body: ChecklistItemWrite,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict:
    """Update a checklist item without changing its domain or id."""
    try:
        await run_in_threadpool(
            rule_store.update_check_item, domain, item_id, body.model_dump(mode="json")
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Checklist item %s/%s updated by %s", domain, item_id, identity.client)
    return await _refresh_checklists()


@router.delete("/checklists/{domain}/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_checklist_item(
    domain: Annotated[str, APIPath(min_length=1, max_length=31)],
    item_id: Annotated[str, APIPath(min_length=3, max_length=rules_loader.MAX_ID_CHARS)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """Delete one custom checklist item."""
    try:
        await run_in_threadpool(rule_store.delete_check_item, domain, item_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await _refresh_checklists()
    logger.info("Checklist item %s/%s deleted by %s", domain, item_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


SlugPath = Annotated[str, APIPath(min_length=1, max_length=50)]


@router.get("/standards")
async def list_standards(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """List the development standards (without content), disabled ones included.

    Administrators only, like the rules and checklists; the MCP tools serve the enabled
    standards to the assistants.
    """
    listed = await run_in_threadpool(standards.list_standards, True)
    return {"standards": listed}


@router.get("/standards/{slug}")
async def get_standard(
    slug: SlugPath, identity: Annotated[Identity, Depends(require_admin)]
) -> dict:
    """Return one development standard with its content (administrators only)."""
    return await run_in_threadpool(standards.get_standard, slug, True)


@router.post("/standards", status_code=status.HTTP_201_CREATED)
async def create_standard(
    body: StandardWrite, identity: Annotated[Identity, Depends(require_admin)]
) -> dict:
    """Create a development standard."""
    try:
        created = await run_in_threadpool(
            standards.create_standard, body.model_dump(), identity.client
        )
    except ValueError as exc:
        code = status.HTTP_409_CONFLICT if "already exists" in str(exc) else 422
        raise HTTPException(code, str(exc)) from exc
    logger.info("Development standard %s created by %s", created["slug"], identity.client)
    return created


@router.put("/standards/{slug}")
async def update_standard(
    slug: SlugPath, body: StandardWrite, identity: Annotated[Identity, Depends(require_admin)]
) -> dict:
    """Replace a development standard without changing its slug."""
    try:
        updated = await run_in_threadpool(
            standards.update_standard, slug, body.model_dump(), identity.client
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Development standard %s updated by %s", updated["slug"], identity.client)
    return updated


@router.delete("/standards/{slug}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_standard(
    slug: SlugPath, identity: Annotated[Identity, Depends(require_admin)]
) -> Response:
    """Delete a development standard."""
    await run_in_threadpool(standards.delete_standard, slug)
    logger.info("Development standard %s deleted by %s", slug, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/rules/reload")
async def reload_custom_rules(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """Reload the internal rules now (after a change made with the CLI)."""
    logger.info("Internal rules reloaded by %s", identity.client)
    return await _refresh_rules()


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_custom_rule(
    body: RuleWrite, identity: Annotated[Identity, Depends(require_admin)]
) -> dict:
    """Create a custom rule in the database."""
    try:
        await run_in_threadpool(rule_store.create_rule, body.model_dump(mode="json"))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Rule %s created by %s", body.id, identity.client)
    return await _refresh_rules()


@router.put("/rules/{rule_id}")
async def update_custom_rule(
    rule_id: Annotated[str, APIPath(min_length=3, max_length=50)],
    body: RuleWrite,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict:
    """Update a stored rule (default or custom) while keeping its stable id."""
    try:
        await run_in_threadpool(rule_store.update_rule, rule_id, body.model_dump(mode="json"))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Rule %s updated by %s", rule_id, identity.client)
    return await _refresh_rules()


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_custom_rule(
    rule_id: Annotated[str, APIPath(min_length=3, max_length=50)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """Delete a custom rule from the database (default rules can only be disabled)."""
    try:
        await run_in_threadpool(rule_store.delete_entries, [rule_id], False)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await _refresh_rules()
    logger.info("Rule %s deleted by %s", rule_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.patch("/rules/{rule_id}/enabled")
async def set_custom_rule_enabled(
    rule_id: Annotated[str, APIPath(min_length=3, max_length=50)],
    body: RuleEnabledUpdate,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict:
    """Enable or disable a default or custom rule."""
    try:
        await run_in_threadpool(rule_store.set_enabled, [rule_id], body.enabled)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Rule %s enabled=%s by %s", rule_id, body.enabled, identity.client)
    return await _refresh_rules()


@router.get("/project-tokens")
async def project_tokens(
    identity: Annotated[Identity, Depends(require_admin)],
) -> list[dict[str, Any]]:
    """List project-token metadata without returning hashes or token values."""
    return await run_in_threadpool(token_store.list_project_tokens)


@router.post("/project-tokens", status_code=status.HTTP_201_CREATED)
async def create_project_token(
    body: ProjectTokenCreate,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict[str, Any]:
    """Create a scoped token for existing projects and return its secret exactly once."""
    known = {item["project"] for item in await run_in_threadpool(services.list_projects)}
    if not set(body.projects) <= known:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    try:
        created = await run_in_threadpool(
            token_store.create_project_token, body.label, body.projects, body.role
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info(
        "Project token %s (%s) created for %s by %s",
        body.label,
        body.role,
        ", ".join(created["projects"]),
        identity.client,
    )
    return created


@router.delete("/project-tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project_token(
    token_id: Annotated[str, APIPath(min_length=1, max_length=64)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """Revoke a project token: the next request presenting it is rejected."""
    try:
        await run_in_threadpool(token_store.revoke_project_token, token_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info("Project token %s revoked by %s", token_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/enrollments")
async def enrollments(
    identity: Annotated[Identity, Depends(require_admin)],
) -> list[dict[str, Any]]:
    """List the enrollment requests waiting for approval (never a secret).

    ``kind`` is ``new`` for a first enrollment (new token) and ``additional`` for a
    complementary one (one more project for an active token).
    """
    return await run_in_threadpool(token_store.list_enrollments)


@router.post("/enrollments/{request_id}/approve")
async def approve_enrollment(
    request: Request,
    request_id: Annotated[str, APIPath(min_length=1, max_length=64)],
    identity: Annotated[Identity, Depends(require_admin)],
    body: EnrollmentApproval | None = None,
) -> dict[str, Any]:
    """Approve an enrollment request: the project is reachable from the next request.

    With ``portal_user``, that web user also reads the project in the web interface (at once);
    when OIDC is enabled, an unknown name becomes an SSO user, ready for its first login.
    """
    portal_user = body.portal_user if body is not None else None
    create_sso = await _current_oidc(request) is not None
    if portal_user is not None:
        try:
            portal_user = await run_in_threadpool(
                web_users.check_project_grant, portal_user, create_sso
            )
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    try:
        approved = await run_in_threadpool(token_store.approve_enrollment, request_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info(
        "Enrollment %s for %s approved by %s",
        approved["label"],
        approved["project"],
        identity.client,
    )
    if portal_user is None:
        return approved
    try:
        user = await run_in_threadpool(
            web_users.grant_project, portal_user, approved["project"], identity.client, create_sso
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
    return approved | {"portal_user": user}


@router.delete("/enrollments/{request_id}", status_code=status.HTTP_204_NO_CONTENT)
async def reject_enrollment(
    request_id: Annotated[str, APIPath(min_length=1, max_length=64)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """Reject an enrollment request: a new token is deleted, an additional project dropped."""
    try:
        rejected = await run_in_threadpool(token_store.reject_enrollment, request_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info(
        "Enrollment %s for %s rejected by %s",
        rejected["label"],
        rejected["project"],
        identity.client,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/settings")
async def get_app_settings(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """Return the settings of the web interface, the variables and the effective values.

    Passwords of proxy URLs are replaced by ``***``.
    """
    return await run_in_threadpool(app_settings.describe)


@router.put("/settings/report-language")
async def set_report_language(
    body: ReportLanguageUpdate, identity: Annotated[Identity, Depends(require_admin)]
) -> dict:
    """Set the language of the review reports (used by the MCP server for the next prompts)."""
    try:
        await run_in_threadpool(app_settings.set_report_language, body.value, identity.client)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Report language set to %r by %s", body.value, identity.client)
    return await run_in_threadpool(app_settings.describe)


@router.put("/settings/proxy")
async def set_proxy(
    body: ProxyUpdate, identity: Annotated[Identity, Depends(require_admin)]
) -> dict:
    """Set the proxy of the OSV download and of the SSO provider (applied at the next download
    or login; the URL is never logged)."""
    values = body.model_dump(exclude_unset=True)
    try:
        await run_in_threadpool(app_settings.set_proxy, values, identity.client)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    # Names only: the URL may hold credentials
    logger.info("Proxy settings %s changed by %s", ", ".join(sorted(values)), identity.client)
    return await run_in_threadpool(app_settings.describe)


def _advisory_overview(limit: int) -> dict:
    """State of the advisory database and history of its updates."""
    settings = get_settings()
    return {
        "database": advisories.advisory_status(),
        "download_enabled": settings.osv_auto_update,
        "running": advisory_sync.running_update() is not None,
        "updates": advisory_sync.list_updates(limit),
    }


@router.get("/advisories")
async def advisory_overview(
    identity: Annotated[Identity, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=advisory_sync.HISTORY_SIZE)] = 20,
) -> dict:
    """Return the state of the advisory database and the latest OSV updates."""
    return await run_in_threadpool(_advisory_overview, limit)


@router.post("/advisories/update", status_code=status.HTTP_202_ACCEPTED)
async def start_advisory_update(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """Start downloading the OSV exports in the background; follow it with GET /advisories.

    Refused (409) when the download is disabled (SECREVIEW_OSV_AUTO_UPDATE=false) or an update
    is already running.
    """
    try:
        update_id = await run_in_threadpool(
            advisory_sync.start_web_update, get_settings(), identity.client
        )
    except (advisory_sync.DownloadDisabled, advisory_sync.UpdateInProgress) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("OSV update %d started by %s", update_id, identity.client)
    return {"id": update_id}


@router.get("/oidc/role-mappings")
async def role_mappings(
    request: Request, identity: Annotated[Identity, Depends(require_admin)]
) -> dict[str, Any]:
    """List the OIDC role mappings: stored ones and the groups of the SSO settings."""
    settings = await run_in_threadpool(app_settings.effective_settings)
    return {
        "oidc_enabled": await _current_oidc(request) is not None,
        "roles_claim": settings.oidc_roles_claim,
        "default_role": settings.oidc_default_role or None,
        "username_claim": settings.oidc_username_claim,
        "auto_create_users": settings.oidc_auto_create_users,
        "mappings": await run_in_threadpool(role_mapping.list_mappings),
        "static_mappings": role_mapping.static_mappings(settings),
    }


async def _describe_oidc(request: Request) -> dict[str, Any]:
    """SSO settings of the web interface, with whether the login is active."""
    described = await run_in_threadpool(app_settings.describe_oidc)
    return described | {"active": await _current_oidc(request) is not None}


@router.get("/oidc/settings")
async def get_oidc_settings(
    request: Request, identity: Annotated[Identity, Depends(require_admin)]
) -> dict[str, Any]:
    """Return the SSO settings: stored value, variable and effective value of each one.

    A set client secret is replaced by ``***``.
    """
    return await _describe_oidc(request)


@router.put("/oidc/settings")
async def set_oidc_settings(
    request: Request,
    body: OidcSettingsUpdate,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict[str, Any]:
    """Change SSO settings; they override the SECREVIEW_OIDC_* variables at the next login.

    Refused (422) when the resulting settings enable an invalid login.
    """
    values = body.model_dump(exclude_unset=True)
    try:
        await run_in_threadpool(app_settings.set_oidc, values, identity.client)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    # Names only: the values may hold the client secret
    logger.info("SSO settings %s changed by %s", ", ".join(sorted(values)), identity.client)
    return await _describe_oidc(request)


@router.post("/oidc/settings/test")
async def test_oidc_settings(
    request: Request,
    body: OidcSettingsUpdate,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict[str, Any]:
    """Test the identity provider of the given settings (applied over the effective ones,
    nothing stored): discovery document and signing keys."""
    values = body.model_dump(exclude_unset=True)
    try:
        candidate = await run_in_threadpool(app_settings.oidc_candidate, values)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logins: OidcLogins = request.app.state.oidc
    steps = await run_in_threadpool(oidc.OidcLogin(candidate, logins.signer).check)
    logger.info("SSO provider %s tested by %s", candidate.oidc_issuer, identity.client)
    return {"success": all(step["ok"] for step in steps), "steps": steps}


@router.post("/oidc/role-mappings", status_code=status.HTTP_201_CREATED)
async def create_role_mapping(
    body: RoleMappingCreate, identity: Annotated[Identity, Depends(require_admin)]
) -> dict[str, Any]:
    """Map a group or role of the identity provider to a web role, optionally per project."""
    try:
        created = await run_in_threadpool(
            role_mapping.create_mapping,
            body.claim_value,
            body.role,
            body.projects,
            identity.client,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info(
        "Role mapping %s -> %s (%s) created by %s",
        created["claim_value"],
        created["role"],
        ", ".join(created["projects"] or ["every project"]),
        identity.client,
    )
    return created


@router.put("/oidc/role-mappings/{mapping_id}")
async def update_role_mapping(
    mapping_id: int,
    body: RoleMappingUpdate,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict[str, Any]:
    """Replace the projects of a role mapping (applies at the next login of its users)."""
    try:
        updated = await run_in_threadpool(role_mapping.update_mapping, mapping_id, body.projects)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Role mapping %s updated by %s", mapping_id, identity.client)
    return updated


@router.delete("/oidc/role-mappings/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role_mapping(
    mapping_id: int, identity: Annotated[Identity, Depends(require_admin)]
) -> Response:
    """Delete a role mapping (open sessions keep their role until they expire)."""
    deleted = await run_in_threadpool(role_mapping.delete_mapping, mapping_id)
    logger.info(
        "Role mapping %s -> %s deleted by %s",
        deleted["claim_value"],
        deleted["role"],
        identity.client,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/users")
async def users(identity: Annotated[Identity, Depends(require_admin)]) -> list[dict[str, Any]]:
    """List the web users (never their password hash)."""
    return await run_in_threadpool(web_users.list_users)


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: WebUserCreate, identity: Annotated[Identity, Depends(require_admin)]
) -> JSONResponse:
    """Create a web user (local or SSO); a generated password is returned once in ``password``."""
    try:
        created = await run_in_threadpool(
            web_users.create_user,
            body.username,
            body.password,
            body.role,
            body.projects,
            identity.client,
            body.auth_source,
        )
    except ValueError as exc:
        code = status.HTTP_409_CONFLICT if "already exists" in str(exc) else 422
        raise HTTPException(code, str(exc)) from exc
    logger.info(
        "Web user %s (%s, role %s) created by %s",
        created["username"],
        created["auth_source"],
        created["role"] or "none",
        identity.client,
    )
    return JSONResponse(created, status_code=status.HTTP_201_CREATED, headers=LOGIN_HEADERS)


@router.put("/users/{user_id}")
async def update_user(
    user_id: int, body: WebUserUpdate, identity: Annotated[Identity, Depends(require_admin)]
) -> dict[str, Any]:
    """Replace the role and projects of a web user (applies to its sessions at once)."""
    try:
        updated = await run_in_threadpool(web_users.update_user, user_id, body.role, body.projects)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info(
        "Web user %s set to %s by %s",
        updated["username"],
        updated["role"] or "no role",
        identity.client,
    )
    return updated


@router.post("/users/{user_id}/password")
async def reset_user_password(
    user_id: int, body: PasswordReset, identity: Annotated[Identity, Depends(require_admin)]
) -> JSONResponse:
    """Replace the password of a web user (generated when not given) and end its sessions."""
    try:
        updated = await run_in_threadpool(web_users.set_password, user_id, body.password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Password of web user %s reset by %s", updated["username"], identity.client)
    return JSONResponse(updated, headers=LOGIN_HEADERS)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int, identity: Annotated[Identity, Depends(require_admin)]
) -> Response:
    """Delete a web user (its sessions stop at once); the last administrator is kept.

    A deleted SSO user is revoked: a login never creates it again until an administrator
    creates it again or lifts the revocation (DELETE /users/revoked/{username}).
    """
    try:
        deleted = await run_in_threadpool(web_users.delete_user, user_id, identity.client)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    logger.info(
        "Web user %s (%s) deleted by %s",
        deleted["username"],
        deleted["auth_source"],
        identity.client,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/users/revoked")
async def revoked_users(
    identity: Annotated[Identity, Depends(require_admin)],
) -> list[dict[str, Any]]:
    """List the deleted SSO users, which a login never creates again."""
    return await run_in_threadpool(web_users.list_revoked_users)


@router.delete("/users/revoked/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def lift_user_revocation(
    username: Annotated[str, APIPath(min_length=1, max_length=web_users.MAX_USERNAME_CHARS)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """Let a deleted SSO user be created again at its next login (automatic creation)."""
    lifted = await run_in_threadpool(web_users.lift_revocation, username)
    logger.info("Revocation of SSO user %s lifted by %s", lifted["username"], identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Static files ─────────────────────────────────────────────────────────────


class SinglePageApp(StaticFiles):
    """Static files with a fallback on index.html for the client-side routes."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND:
                raise
            response = await super().get_response("index.html", scope)
        response.headers.update(SECURITY_HEADERS)
        if path in ("", ".", "index.html") or response.media_type == "text/html":
            # The page references hashed bundles: always revalidate it after an upgrade
            response.headers["Cache-Control"] = "no-cache"
        return response


def resolve_ui_dir(configured: str | None) -> Path | None:
    """Directory of the built Angular application, or None when it is not available."""
    directory = Path(configured) if configured else BUNDLED_UI_DIR
    if (directory / "index.html").is_file():
        return directory
    if configured:
        raise ValueError(f"SECREVIEW_WEB_UI_DIR: no index.html in {directory}")
    return None


# ── Application ──────────────────────────────────────────────────────────────


def create_app(
    host: str = "127.0.0.1",
    ui_dir: str | None = None,
    ui: bool = True,
    oidc_login: oidc.OidcLogin | None = None,
    signer: oidc.SessionSigner | None = None,
) -> FastAPI:
    """Build the controller app (REST API and, when it is built, the Angular application).

    ``ui=False`` (SECREVIEW_WEB_UI=false) serves the REST API only. The single sign-on routes
    under ``/api/v1/auth/oidc`` follow the effective SSO settings (see OidcLogins);
    ``oidc_login`` (tests) replaces them with a fixed flow.
    ``signer`` (see oidc.session_signer) signs the sessions of the password login; the
    session tokens are checked by the bearer middleware (build_controller_app).

    Raises:
        ValueError: If ``ui_dir`` (SECREVIEW_WEB_UI_DIR) is set but holds no application.
    """
    settings = get_settings()
    app = FastAPI(
        title="security-review-mcp",
        version=__version__,
        # Served below, with the application icon instead of the FastAPI one
        docs_url=None,
        redoc_url=None,
        openapi_url=OPENAPI_PATH,
    )
    app.state.signer = signer or (
        oidc_login.signer
        if oidc_login
        else oidc.SessionSigner(settings.session_secret, settings.session_hours)
    )
    app.state.oidc = OidcLogins(app.state.signer, oidc_login)
    app.state.login_throttle = web_users.LoginThrottle()
    app.include_router(auth_router)
    app.include_router(router)
    app.include_router(ci_router)

    @app.get(HEALTH_PATH, include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Public liveness probe (containers, Kubernetes)."""
        return {"status": "ok"}

    @app.get(FAVICON_PATH, include_in_schema=False)
    async def favicon() -> Response:
        """Public icon of the web interface and of the API documentation."""
        return Response(
            FAVICON,
            media_type="image/svg+xml",
            headers={
                "Cache-Control": "public, max-age=86400",
                # Opened on its own, an SVG is a document: it may run nothing
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get(DOCS_PATH, include_in_schema=False)
    async def swagger_ui() -> Response:
        """Public Swagger documentation of the REST API."""
        return get_swagger_ui_html(
            openapi_url=OPENAPI_PATH,
            title=f"{app.title} - API",
            swagger_favicon_url=FAVICON_PATH,
        )

    @app.exception_handler(services.NotFoundError)
    async def not_found(_: Request, exc: services.NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    configured = ui_dir if ui_dir is not None else settings.web_ui_dir
    directory = resolve_ui_dir(configured) if ui else None
    if directory is not None:
        app.mount("/ui", SinglePageApp(directory=directory, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        async def root() -> RedirectResponse:
            return RedirectResponse("/ui/")
    elif ui:
        logger.warning("Web interface not built: only the REST API is served (/api/v1)")

    if host in LOOPBACK_HOSTS:
        # Same protection as the MCP endpoint against DNS rebinding on a local server
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])
    return app
