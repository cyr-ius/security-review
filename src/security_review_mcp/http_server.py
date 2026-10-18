"""HTTP serving of the two processes: bearer-token authentication, TLS and health checks.

The MCP SDK starts uvicorn without TLS options and its own auth expects an OAuth authorization
server. For a shared server we only need API tokens, stored in the database (see token_store),
so the apps are wrapped in a small ASGI middleware and served by uvicorn directly.

Two apps are built, meant to run in separate processes (containers, pods) sharing the database:

- the MCP server (``build_mcp_app``): the MCP endpoint, the public enrollment endpoint and
  ``/healthz``. With enrollment, an MCP client that presents no token (or a token still waiting
  for approval) is sent to a restricted MCP server that only lets it request a project token.
  It requires a token even while none is stored (fail closed), except on a loopback address
  or with ``SECREVIEW_ALLOW_UNAUTHENTICATED`` (see allows_open_mcp);
- the controller (``build_controller_app``): the REST API under ``/api`` and the Angular
  application under ``/ui`` (see web_api).

Each token carries a role that decides which of the two it may use. A ``ci`` token only reaches
the read-only pipeline routes of the controller (``/api/v1/ci/``, see web_api and ci_client), a
``metrics`` token only its Prometheus endpoint (``/metrics``, see metrics). An expired token
authenticates nothing.
"""

import argparse
import hashlib
import json
import logging
import ssl
from collections import Counter
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

import anyio.to_thread
import uvicorn
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Settings, secret_value
from .rate_limit import RateLimitMiddleware

logger = logging.getLogger("security_review_mcp.http")

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class Role(StrEnum):
    """What a token may do.

    ``mcp`` (default) only reaches the MCP endpoint; ``reader`` and ``triager`` only reach the
    web API; ``admin`` reaches both MCP and the web API; ``ci`` (always restricted to projects)
    only reaches the pipeline routes of the web API (gate, SARIF, trend); ``metrics`` (never
    restricted to projects) only reaches the Prometheus endpoint of the controller.
    """

    MCP = "mcp"
    READER = "reader"
    TRIAGER = "triager"
    ADMIN = "admin"
    CI = "ci"
    METRICS = "metrics"


DEFAULT_ROLE = Role.MCP
MCP_ROLES = frozenset({Role.MCP, Role.ADMIN})
WEB_ROLES = frozenset({Role.READER, Role.TRIAGER, Role.ADMIN})
TRIAGE_ROLES = frozenset({Role.TRIAGER, Role.ADMIN})
# Roles accepted by the pipeline routes of the controller (read only, scoped to projects)
CI_ROUTE_ROLES = WEB_ROLES | {Role.CI}
# Roles accepted by the Prometheus endpoint of the controller
METRICS_ROLES = frozenset({Role.METRICS, Role.ADMIN})

API_PREFIX = "/api/"
# Pipeline routes of the controller, the only ones a ``ci`` token reaches
CI_PREFIX = "/api/v1/ci/"
UI_PREFIX = "/ui"
# Public endpoint of the MCP server where a client without a token requests one
# (see enrollment_api)
ENROLL_PATH = "/api/v1/enroll"
# Title of the MCP server that the clients without an approved token reach (see
# server.enrollment_mcp): scan-deps recognizes it to suggest a new enrollment
ENROLLMENT_SERVER_TITLE = "Security Review (enrollment)"
# Public liveness endpoint of both processes (container and Kubernetes probes)
HEALTH_PATH = "/healthz"
# Public liveness endpoint of the controller API, polled by the web interface at load: it tells
# whether the controller answers, nothing about its version or configuration
API_HEALTH_PATH = "/api/health"
# Prometheus endpoint of the controller (see metrics)
METRICS_PATH = "/metrics"
# Public files of the controller: the API documentation and the application icon
DOCS_PATH = "/api/docs"
OPENAPI_PATH = "/api/openapi.json"
# Files of Swagger UI, served by the controller (never from a CDN)
DOCS_ASSETS_PREFIX = "/api/swagger"
FAVICON_PATH = "/api/favicon.svg"
# Public login routes of the controller (OpenID Connect, see oidc)
AUTH_PREFIX = "/api/v1/auth/"
# Value of WWW-Authenticate on a 401 / 403 (an error="..." parameter may follow)
BEARER_CHALLENGE = 'Bearer realm="security-review-mcp"'


@dataclass(frozen=True)
class TokenInfo:
    """Identity attached to a token: a label for the logs and a role.

    ``projects`` lists the projects a restricted token reaches (None: every project).
    ``pending`` marks an enrollment request not approved yet: it grants no access.
    ``expired`` marks a token past its expiry date: it grants no access either.
    ``user_id`` and ``auth_source`` (``local`` or ``oidc``) are set for the session of a web
    user (see web_users), None for a token. ``grants`` holds the permissions of a web user, each
    with its projects (None: every project, see access_control); for a token they follow from
    ``role`` and ``projects``, and ``role`` of a session only sums them up.
    """

    label: str
    role: Role = DEFAULT_ROLE
    projects: frozenset[str] | None = None
    token_id: str | None = None
    pending: bool = False
    expired: bool = False
    user_id: int | None = None
    auth_source: str | None = None
    grants: Mapping[str, frozenset[str] | None] | None = field(
        default=None, compare=False, hash=False
    )
    # A web user whose password was set by someone else: it may only change it
    must_change_password: bool = False


class TokenStore(Protocol):
    """Source of the bearer tokens (see token_store.DatabaseTokenStore)."""

    def lookup(self, digest: bytes) -> TokenInfo | None:
        """Return the identity of the token with this SHA-256 digest, or None."""

    def has_tokens(self) -> bool:
        """True when at least one token is stored."""


class SessionVerifier(Protocol):
    """Verifier of the web sessions issued after a password or OIDC login (see
    web_users.SessionVerifier)."""

    def owns(self, credentials: str) -> bool:
        """True when the bearer value is a session token (not a database token)."""

    def verify_session(self, credentials: str) -> TokenInfo | None:
        """Return the identity of a valid, unexpired session token, or None."""


def hash_token(token: str) -> bytes:
    """Return the SHA-256 digest of a raw token: the only form that is ever stored."""
    return hashlib.sha256(token.encode("utf-8")).digest()


# ── Middleware ───────────────────────────────────────────────────────────────

# Requests rejected by the bearer middleware of this process since it started, by reason
# (invalid_token, token_expired, enrollment_pending, insufficient_scope), see metrics
AUTH_REJECTIONS: Counter[str] = Counter()


def is_controller_public_path(path: str) -> bool:
    """Controller paths reachable without a token: the web UI shell, the API documentation,
    the application icon, the health check and the login routes."""
    public = ("/", UI_PREFIX, DOCS_PATH, OPENAPI_PATH, FAVICON_PATH, HEALTH_PATH, API_HEALTH_PATH)
    return path in public or (
        path.startswith((UI_PREFIX + "/", AUTH_PREFIX, DOCS_ASSETS_PREFIX + "/"))
    )


def has_credentials(authorization: str) -> bool:
    """False for a missing header or an empty ``Bearer`` value.

    MCP hosts send ``Authorization: Bearer `` when the token input or variable is left empty:
    such a client has no token yet and is treated like one that sends no header.
    """
    scheme, _, credentials = authorization.strip().partition(" ")
    return bool(scheme) and not (scheme.lower() == "bearer" and not credentials.strip())


class BearerAuthMiddleware:
    """Reject HTTP requests that do not carry a valid bearer token.

    Pure ASGI (no response buffering) so that streamed MCP responses are not affected.
    The label, role, projects and id of the accepted token are stored in ``scope["state"]``
    (``auth_client``, ``auth_role``, ``auth_projects``, ``auth_token_id``, and ``auth_user_id``
    and ``auth_source`` for the session of a web user).

    With ``web=False`` (MCP server) every path needs an MCP role, except ``public_paths``.
    With ``web=True`` (controller) the static files of the web interface are public and the
    REST API needs a web role. While ``store`` holds no token at all, the controller API
    answers 503 (authentication not configured) and the MCP server stays closed, unless
    ``allow_open`` (see allows_open_mcp) lets every request through.

    ``enrollment_app`` receives the MCP requests sent without an ``Authorization`` header (or
    with an empty bearer value), with a pending enrollment token, or with a token that is
    unknown, revoked or expired; ``scope["state"]["enrollment_token_id"]`` then holds the id of
    that pending token (None otherwise) and ``scope["state"]["enrollment_rejected_token"]`` the
    reason a token was rejected (None otherwise). Without it they get 401 / 403.

    ``sessions`` (controller only) also accepts the session tokens issued after a login.
    ``require_auth`` (controller with OIDC) asks for credentials even while the store holds no
    token, instead of answering 503.
    """

    def __init__(
        self,
        app: ASGIApp,
        store: TokenStore,
        web: bool = False,
        enrollment_app: ASGIApp | None = None,
        public_paths: frozenset[str] = frozenset(),
        sessions: SessionVerifier | None = None,
        require_auth: bool = False,
        allow_open: bool = False,
    ) -> None:
        self.app = app
        self.store = store
        self.web = web
        self.enrollment_app = None if web else enrollment_app
        self.public_paths = public_paths
        self.sessions = sessions if web else None
        self.require_auth = require_auth and web
        self.allow_open = allow_open and not web

    async def identify(self, authorization: str) -> TokenInfo | None:
        """Return the identity of the presented bearer token, or None."""
        scheme, _, credentials = authorization.partition(" ")
        credentials = credentials.strip()
        if scheme.lower() != "bearer" or not credentials:
            return None
        if self.sessions is not None and self.sessions.owns(credentials):
            # The session of a web user is checked against the database
            return await anyio.to_thread.run_sync(self.sessions.verify_session, credentials)
        return await anyio.to_thread.run_sync(self.store.lookup, hash_token(credentials))

    async def has_tokens(self) -> bool:
        """True when at least one token is stored."""
        return await anyio.to_thread.run_sync(self.store.has_tokens)

    def is_public(self, path: str) -> bool:
        """True for the paths reachable without a token."""
        return is_controller_public_path(path) if self.web else path in self.public_paths

    def role_allowed(self, role: Role, path: str) -> bool:
        """True when a token of this role may reach ``path`` on this process.

        A ``ci`` token only reaches the pipeline routes of the controller, a ``metrics`` token
        only its Prometheus endpoint.
        """
        if not self.web:
            return role in MCP_ROLES
        if path == METRICS_PATH:
            return role in METRICS_ROLES
        if path.startswith(CI_PREFIX):
            return role in CI_ROUTE_ROLES
        return role in WEB_ROLES

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if self.is_public(path):
            await self.app(scope, receive, send)
            return

        # Without any token the controller answers 503 and an open MCP server lets the request
        # through; a closed MCP server (the default) goes on and asks for a token
        open_check = (self.web and not self.require_auth) or self.allow_open
        if open_check and not await self.has_tokens():
            if self.web:
                await _send_error(
                    send,
                    503,
                    "authentication_not_configured",
                    "Configure a web authentication token before using the web interface",
                )
            else:
                await self.app(scope, receive, send)
            return

        client = scope.get("client")
        address = client[0] if client else "unknown"
        authorization = Headers(scope=scope).get("authorization", "")
        if self.enrollment_app is not None and not has_credentials(authorization):
            await self.enroll(scope, receive, send, None)
            return
        info = await self.identify(authorization)
        if info is None:
            AUTH_REJECTIONS["invalid_token"] += 1
            logger.warning("Rejected unauthenticated request from %s to %s", address, path)
            if self.enrollment_app is not None:
                # Unknown or revoked token: the client is offered a new enrollment
                await self.enroll(scope, receive, send, None, rejection="invalid_token")
                return
            await _send_error(send, 401, "invalid_token", "Missing or invalid bearer token")
            return
        if info.expired:
            AUTH_REJECTIONS["token_expired"] += 1
            logger.warning("Rejected expired token %s from %s to %s", info.label, address, path)
            if self.enrollment_app is not None:
                await self.enroll(scope, receive, send, None, rejection="token_expired")
                return
            # RFC 6750: an expired token is an invalid_token
            await _send_error(send, 401, "invalid_token", "The bearer token has expired")
            return
        if info.pending:
            if self.enrollment_app is not None:
                await self.enroll(scope, receive, send, info.token_id)
                return
            AUTH_REJECTIONS["enrollment_pending"] += 1
            await _send_error(
                send,
                403,
                "enrollment_pending",
                "This token is waiting for an administrator to approve its enrollment",
            )
            return
        if not self.role_allowed(info.role, path):
            AUTH_REJECTIONS["insufficient_scope"] += 1
            logger.warning(
                "Rejected request from %s (%s, role %s) to %s", address, info.label, info.role, path
            )
            await _send_error(
                send, 403, "insufficient_scope", f"Role '{info.role}' cannot access this endpoint"
            )
            return

        state = scope.setdefault("state", {})
        state["auth_client"] = info.label
        state["auth_role"] = info.role
        state["auth_projects"] = info.projects
        state["auth_token_id"] = info.token_id
        state["auth_user_id"] = info.user_id
        state["auth_source"] = info.auth_source
        state["auth_grants"] = info.grants
        state["auth_must_change_password"] = info.must_change_password
        await self.app(scope, receive, send)

    async def enroll(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        token_id: str | None,
        rejection: str | None = None,
    ) -> None:
        """Forward a request to the enrollment MCP server, with the pending token id if any.

        ``rejection`` (``invalid_token`` or ``token_expired``) tells the enrollment server
        that the client presented a token that no longer grants access, so that the model
        offers a new enrollment.
        """
        if self.enrollment_app is None:
            raise RuntimeError("Enrollment is not enabled")
        state = scope.setdefault("state", {})
        state["enrollment_token_id"] = token_id
        state["enrollment_rejected_token"] = rejection
        await self.enrollment_app(scope, receive, send)


async def _send_error(send: Send, status: int, error: str, description: str) -> None:
    """Send a 401/403 response with a JSON body and a WWW-Authenticate challenge."""
    body = json.dumps({"error": error, "error_description": description}).encode("utf-8")
    challenge = f'{BEARER_CHALLENGE}, error="{error}"'.encode("ascii")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"www-authenticate", challenge),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class PathDispatcher:
    """Send the HTTP requests of a few exact paths to their app, everything else (and the
    lifespan events) to the main app."""

    def __init__(self, main_app: ASGIApp, routes: dict[str, ASGIApp]) -> None:
        self.main_app = main_app
        self.routes = routes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        app = self.routes.get(scope.get("path", "")) if scope["type"] == "http" else None
        await (app or self.main_app)(scope, receive, send)


async def health_app(scope: Scope, receive: Receive, send: Send) -> None:
    """Liveness probe: answers ``{"status": "ok"}`` without touching the database."""
    body = b'{"status":"ok"}'
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


# ── TLS ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TLSOptions:
    """TLS files for uvicorn; ``client_ca`` enables mutual TLS (client certificates)."""

    certfile: str
    keyfile: str | None = None
    keyfile_password: str | None = None
    client_ca: str | None = None

    def uvicorn_kwargs(self) -> dict[str, Any]:
        """Translate the options into uvicorn.run keyword arguments."""
        options: dict[str, Any] = {
            "ssl_certfile": self.certfile,
            "ssl_keyfile": self.keyfile,
            "ssl_keyfile_password": self.keyfile_password,
        }
        if self.client_ca:
            options["ssl_ca_certs"] = self.client_ca
            options["ssl_cert_reqs"] = ssl.CERT_REQUIRED
        return options


def tls_options(settings: Settings) -> TLSOptions | None:
    """Validate the TLS settings; None when TLS is disabled (no certificate configured)."""
    if not settings.tls_certfile:
        if settings.tls_keyfile:
            raise ValueError("SECREVIEW_TLS_KEYFILE needs SECREVIEW_TLS_CERTFILE")
        if settings.tls_client_ca:
            raise ValueError("SECREVIEW_TLS_CLIENT_CA needs SECREVIEW_TLS_CERTFILE")
    for name in ("tls_certfile", "tls_keyfile", "tls_client_ca"):
        value = getattr(settings, name)
        if value and not Path(value).is_file():
            raise ValueError(f"SECREVIEW_{name.upper()}: file not found: {value}")
    if not settings.tls_certfile:
        return None
    return TLSOptions(
        certfile=settings.tls_certfile,
        keyfile=settings.tls_keyfile,
        keyfile_password=secret_value(settings.tls_keyfile_password),
        client_ca=settings.tls_client_ca,
    )


def add_listen_arguments(parser: argparse.ArgumentParser, settings: Settings) -> None:
    """Add the --host, --port and TLS options shared by the MCP server and the controller."""
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--tls-certfile", help="enable TLS (overrides SECREVIEW_TLS_CERTFILE)")
    parser.add_argument("--tls-keyfile", help="private key (overrides SECREVIEW_TLS_KEYFILE)")


def with_tls_arguments(settings: Settings, args: argparse.Namespace) -> Settings:
    """Return the settings with the TLS options given on the command line, if any."""
    if not (args.tls_certfile or args.tls_keyfile):
        return settings
    return settings.model_copy(
        update={
            "tls_certfile": args.tls_certfile or settings.tls_certfile,
            "tls_keyfile": args.tls_keyfile or settings.tls_keyfile,
        }
    )


# ── Entry point ──────────────────────────────────────────────────────────────


def allows_open_mcp(host: str, allow_unauthenticated: bool) -> bool:
    """True when the MCP server may accept requests without a token while none is stored.

    Only on a loopback address, or when the operator explicitly sets
    ``SECREVIEW_ALLOW_UNAUTHENTICATED``: an exposed server stays closed (fail closed) and its
    clients get a token by enrollment or from an administrator.
    """
    return allow_unauthenticated or host in LOOPBACK_HOSTS


def _enrollment_app(main: Starlette, enrollment_server: MCPServer, host: str) -> Starlette:
    """Build the enrollment MCP app and run its session manager with the main one.

    Lifespan events only reach the main MCP app, so its lifespan also starts the session
    manager of the enrollment server. That server keeps no session (stateless, JSON answers).
    """
    app = enrollment_server.streamable_http_app(host=host, stateless_http=True, json_response=True)
    manager = enrollment_server.session_manager
    main_lifespan = main.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application: Starlette) -> AsyncIterator[Any]:
        async with manager.run(), main_lifespan(application) as state:
            yield state

    main.router.lifespan_context = lifespan
    return app


def build_mcp_app(
    server: MCPServer,
    host: str,
    store: TokenStore,
    enrollment_server: MCPServer | None = None,
    enroll_endpoint: ASGIApp | None = None,
    allow_open: bool = False,
) -> ASGIApp:
    """Build the HTTP app of the MCP server, protected by the bearer tokens of ``store``.

    ``enrollment_server`` answers the MCP clients that have no token yet and
    ``enroll_endpoint`` (see enrollment_api.create_app) serves the public ``ENROLL_PATH``.
    ``allow_open`` (see allows_open_mcp) lets every request through while no token is stored.
    """
    main = server.streamable_http_app(host=host)
    enrollment_app = (
        _enrollment_app(main, enrollment_server, host) if enrollment_server is not None else None
    )
    routes: dict[str, ASGIApp] = {HEALTH_PATH: health_app}
    if enroll_endpoint is not None:
        routes[ENROLL_PATH] = enroll_endpoint
    return BearerAuthMiddleware(
        PathDispatcher(main, routes),
        store,
        enrollment_app=enrollment_app,
        public_paths=frozenset(routes),
        allow_open=allow_open,
    )


# Headers of every answer of the controller; a header already set by the route (the CSP of the
# web interface and of Swagger) is kept
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
)
# HTTPS only (TLS of uvicorn, or X-Forwarded-Proto of a trusted proxy): one year
HSTS_HEADER = (b"strict-transport-security", b"max-age=31536000")


class SecurityHeadersMiddleware:
    """Add the security headers to every HTTP answer, and HSTS to the HTTPS ones."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Add the missing security headers at the start of the answer."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        extra = SECURITY_HEADERS + ((HSTS_HEADER,) if scope.get("scheme") == "https" else ())

        async def send_with_headers(message: dict[str, Any]) -> None:
            """Complete the headers of the answer."""
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                headers.extend((name, value) for name, value in extra if name not in present)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def build_controller_app(
    web_app: ASGIApp,
    store: TokenStore,
    sessions: SessionVerifier | None = None,
    require_auth: bool = False,
    settings: Settings | None = None,
) -> ASGIApp:
    """Build the HTTP app of the controller (see web_api.create_app), protected by ``store``
    and by the session tokens of ``sessions`` (password and OIDC logins), with the security
    headers on every answer (see SecurityHeadersMiddleware).

    ``require_auth`` (OIDC enabled) asks for a login even while no token nor user is stored.
    With ``settings`` and SECREVIEW_RATE_LIMIT_ENABLED, the requests of each address are
    limited before the token is checked, so that guessing tokens is limited too.
    """
    app: ASGIApp = BearerAuthMiddleware(
        web_app, store, web=True, sessions=sessions, require_auth=require_auth
    )
    if settings is not None and settings.rate_limit_enabled:
        app = RateLimitMiddleware(
            app,
            max_requests=settings.rate_limit_max_requests,
            max_auth_requests=settings.rate_limit_auth_max_requests,
            window=settings.rate_limit_window_seconds,
            auth_prefix=AUTH_PREFIX,
        )
    # Outermost: the refusals (401, 429) get the headers too
    return SecurityHeadersMiddleware(app)


def _log_exposure(
    host: str, store: TokenStore, tls: TLSOptions | None, allow_open: bool = True
) -> None:
    """Warn when the server listens on a public address without authentication or TLS.

    ``allow_open`` is False for a closed MCP server (see allows_open_mcp): without any token it
    refuses every client, which is not an exposure but needs a first token to be usable.
    """
    exposed = host not in LOOPBACK_HOSTS
    if store.has_tokens():
        logger.info("Bearer authentication enabled (tokens stored in the database)")
    elif not allow_open:
        logger.warning(
            "No token stored: every MCP client is refused (except enrollment requests) until "
            "an administrator creates a token with `security-review-controller token create` "
            "or approves an enrollment."
        )
    elif exposed and not (tls and tls.client_ca):
        logger.warning(
            "Listening on %s without authentication: create a token with "
            "`security-review-controller token create`, or put the server behind a reverse "
            "proxy that enforces authentication.",
            host,
        )
    if tls:
        logger.info("TLS enabled%s", " with client certificates" if tls.client_ca else "")
    elif exposed:
        logger.warning(
            "Listening on %s without TLS: set SECREVIEW_TLS_CERTFILE and SECREVIEW_TLS_KEYFILE, "
            "or terminate TLS on a reverse proxy.",
            host,
        )


def serve(
    app: ASGIApp,
    host: str,
    port: int,
    store: TokenStore,
    tls: TLSOptions | None,
    log_level: str = "INFO",
    forwarded_allow_ips: str | None = None,
    allow_open: bool = True,
) -> None:
    """Serve an app built by build_mcp_app or build_controller_app with uvicorn.

    ``tls`` comes from tls_options (validated beforehand). ``forwarded_allow_ips``
    (SECREVIEW_FORWARDED_ALLOW_IPS) lists the reverse proxies trusted for the client address;
    None keeps the uvicorn default. ``allow_open`` is the one given to build_mcp_app (always
    True for the controller), used for the start-up warnings only.
    """
    _log_exposure(host, store, tls, allow_open)
    proxies: dict[str, Any] = {}
    if forwarded_allow_ips is not None:
        proxies = {"proxy_headers": True, "forwarded_allow_ips": forwarded_allow_ips}
        if forwarded_allow_ips == "*":
            logger.warning(
                "SECREVIEW_FORWARDED_ALLOW_IPS=*: any client may set its address with "
                "X-Forwarded-For; list the addresses of the reverse proxies instead."
            )
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level.lower(),
        **proxies,
        **(tls.uvicorn_kwargs() if tls else {}),
    )
