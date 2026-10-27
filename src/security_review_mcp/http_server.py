"""HTTP serving of the two processes: bearer-token authentication, TLS and health checks.

The MCP SDK starts uvicorn without TLS options and its own auth expects an OAuth authorization
server. For a shared server we only need API tokens, stored in the database (see token_store),
so the apps are wrapped in a small ASGI middleware and served by uvicorn directly.

Two apps are built, meant to run in separate processes (containers, pods) sharing the database:

- the MCP server (``build_mcp_app``): the MCP endpoint and ``/healthz``. With enrollment, an
  MCP client that presents no token is sent to a restricted MCP server, without any tool, that
  tells the user how to create a personal MCP token; a token that is unknown, revoked or expired
  gets a 401 that tells the user to sign in to the web interface and create a new personal MCP
  token (see renew_token_hint). It requires a token even while none is stored (fail closed),
  except on a loopback address or with ``SECREVIEW_ALLOW_UNAUTHENTICATED`` (see
  allows_open_mcp);
- the controller (``build_controller_app``): the REST API under ``/api`` and the Angular
  application under ``/ui`` (see web_api).

Each token carries a role that decides which of the two it may use. A ``ci`` token only reaches
the pipeline routes of the controller (``/api/v1/ci/``, see web_api and ci_client: gate, SARIF,
trend, and the scans that store reports of its projects), a ``metrics`` token only its
Prometheus endpoint (``/metrics``, see metrics). An expired token authenticates nothing.
"""

import argparse
import hashlib
import json
import logging
import ssl
from collections import Counter
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import anyio.to_thread
import uvicorn
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .auth.rate_limit import RateLimitMiddleware
from .config import Settings, get_settings, secret_value

logger = logging.getLogger("security_review_mcp.http")

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class Role(StrEnum):
    """What a bearer credential may do.

    Tokens (TOKEN_ROLES): ``mcp`` (default) only reaches the MCP endpoint; ``admin`` reaches
    both MCP and the web API; ``api`` only reaches the web API (Swagger, scripts), with the
    permissions of its owner (personal token) or of its role (role token, see token_store);
    ``ci`` (always restricted to projects) only reaches the pipeline
    routes of the web API (gate, SARIF, trend, and the code and dependency scans, which store
    reports); ``metrics`` (never restricted to projects) only reaches the Prometheus endpoint of
    the controller.

    ``user`` is never the role of a token: it marks a web session, whose rights are the
    permissions of its groups (see access_control.user_grants), checked by each route.
    """

    MCP = "mcp"
    API = "api"
    USER = "user"
    ADMIN = "admin"
    CI = "ci"
    METRICS = "metrics"


DEFAULT_ROLE = Role.MCP
# Roles a bearer token may have (a person reaches the web API through a session only)
TOKEN_ROLES = frozenset({Role.MCP, Role.API, Role.ADMIN, Role.CI, Role.METRICS})
MCP_ROLES = frozenset({Role.MCP, Role.ADMIN})
# Role of a web session, whatever its permissions
WEB_ROLES = frozenset({Role.USER})
# Roles accepted by the REST API of the controller: web sessions, admin and api tokens
API_ROLES = WEB_ROLES | {Role.API, Role.ADMIN}
# Roles accepted by the pipeline routes of the controller (scoped to projects)
CI_ROUTE_ROLES = API_ROLES | {Role.CI}
# Roles accepted by the scans of the pipeline routes, which may store a report
SCAN_ROUTE_ROLES = frozenset({Role.CI, Role.ADMIN})
# Roles accepted by the Prometheus endpoint of the controller
METRICS_ROLES = frozenset({Role.METRICS, Role.ADMIN})

# Pipeline routes of the controller, the only ones a ``ci`` token reaches
CI_PREFIX = "/api/v1/ci/"
UI_PREFIX = "/ui"
# Title of the MCP server that the clients without a token reach (see
# server.enrollment_mcp): scan-deps recognizes it to report a missing token
ENROLLMENT_SERVER_TITLE = "Security Review (enrollment)"
# Public liveness endpoint of both processes (container and Kubernetes probes)
HEALTH_PATH = "/healthz"
# Body of a request of an MCP client without a token, served by the enrollment server (its
# initialization and a prompt): a few KiB
MAX_ENROLLMENT_BODY_BYTES = 64 * 1024
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
# Public download of the pipeline client by uv --find-links (see ci_client_routes), when enabled
CI_CLIENT_PREFIX = "/api/ci-client"
# Public login routes of the controller (OpenID Connect, see oidc)
AUTH_PREFIX = "/api/v1/auth/"
# OAuth login of the MCP clients (see oauth_server): routes of the authorization server, at the
# root of the controller (its issuer), public; all but the metadata are login routes
OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server"
OAUTH_LOGIN_PATHS = ("/authorize", "/token", "/register", "/revoke")
OAUTH_PATHS = (OAUTH_METADATA_PATH, *OAUTH_LOGIN_PATHS)
# Protected resource metadata of the MCP server (RFC 9728), public, followed by the path of the
# MCP endpoint
PROTECTED_RESOURCE_PREFIX = "/.well-known/oauth-protected-resource"
# The only scope of the OAuth tokens (see oauth_server.SCOPE)
OAUTH_SCOPE = "mcp"
# Value of WWW-Authenticate on a 401 / 403 (an error="..." parameter may follow)
BEARER_CHALLENGE = 'Bearer realm="security-review-mcp"'


@dataclass(frozen=True)
class TokenInfo:
    """Identity attached to a token: a label for the logs and a role.

    ``projects`` lists the projects a restricted token reaches (None: every project).
    ``expired`` marks a token past its expiry date: it grants no access either.
    ``user_id`` and ``auth_source`` (``local`` or ``oidc``) are set for the session of a web
    user (see web_users), None for a token. ``owner`` is the username of the web user who owns
    a personal token, the author of the reports it saves (None otherwise). ``grants`` holds the
    permissions of a web user, each with its projects (None: every project, see
    access_control); for a token they follow from ``role`` and ``projects``, and ``role`` of a
    session only sums them up.
    """

    label: str
    role: Role = DEFAULT_ROLE
    projects: frozenset[str] | None = None
    token_id: str | None = None
    expired: bool = False
    user_id: int | None = None
    auth_source: str | None = None
    owner: str | None = None
    grants: Mapping[str, frozenset[str] | None] | None = field(
        default=None, compare=False, hash=False
    )
    # A web user whose password was set by someone else: it may only change it
    must_change_password: bool = False
    # A personal mcp token: on the pipeline routes of the controller it acts as a ci token on
    # the same projects, so that one SECREVIEW_TOKEN serves both the MCP agent and
    # security-review-ci on a workstation
    pipeline: bool = False


@dataclass(frozen=True)
class OAuthResource:
    """The OAuth login of the MCP clients, as published by the controller (see
    app_settings.sync_mcp_oauth): the URL of the MCP endpoint, the resource of the tokens, and
    the URL of the controller, their issuer."""

    resource: str
    issuer: str

    @property
    def metadata_url(self) -> str:
        """URL of the protected resource metadata (RFC 9728 §3.1)."""
        parts = urlsplit(self.resource)
        return f"{parts.scheme}://{parts.netloc}{PROTECTED_RESOURCE_PREFIX}{parts.path}"

    def metadata(self) -> bytes:
        """Protected resource metadata document (RFC 9728 §2)."""
        document = {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": [OAUTH_SCOPE],
            "bearer_methods_supported": ["header"],
            "resource_name": "Security Review",
        }
        return json.dumps(document).encode("utf-8")

    def challenge(self, error: str | None = None) -> str:
        """WWW-Authenticate value of a 401 that starts the OAuth login of the client."""
        value = (
            f'{BEARER_CHALLENGE}, resource_metadata="{self.metadata_url}", scope="{OAUTH_SCOPE}"'
        )
        return f'{value}, error="{error}"' if error else value


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
# (invalid_token, token_expired, insufficient_scope), see metrics
AUTH_REJECTIONS: Counter[str] = Counter()


def is_controller_public_path(path: str) -> bool:
    """Controller paths reachable without a token: the web UI shell, the API documentation,
    the application icon, the health check, the login routes, the OAuth routes and the download
    of the pipeline client (the last two served only when enabled)."""
    public = (
        "/",
        UI_PREFIX,
        DOCS_PATH,
        OPENAPI_PATH,
        FAVICON_PATH,
        HEALTH_PATH,
        API_HEALTH_PATH,
        CI_CLIENT_PREFIX,
        *OAUTH_PATHS,
    )
    return path in public or (
        path.startswith(
            (UI_PREFIX + "/", AUTH_PREFIX, DOCS_ASSETS_PREFIX + "/", CI_CLIENT_PREFIX + "/")
        )
    )


def renew_token_hint(web_url: str | None) -> str:
    """What a user does when the MCP server refuses its token (or receives none): sign in to the
    web interface (``web_url``, from SECREVIEW_CONTROLLER_URL, when known) and create a personal
    MCP token."""
    where = f"the web interface ({web_url})" if web_url else "the web interface"
    return (
        f"sign in to {where} and create a new personal MCP token, then put it in the MCP "
        "client configuration as 'Authorization: Bearer <token>'"
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
    with an empty bearer value): the client may create its project there. A token that is
    unknown, revoked or expired always gets a 401; on the MCP server, its description tells the
    user to sign in to the web interface and create a new personal MCP token. ``web_url``
    returns the address of that interface (stored by the controller); it is called in a
    thread before each request sent to the enrollment server, which it keeps up to date, and for
    each 401.

    ``oauth`` (MCP server) returns the OAuth login of the MCP clients while the controller
    serves it (see OAuthResource), None otherwise; it is called in a thread. A request without
    credentials then gets a 401 whose WWW-Authenticate challenge names the protected resource
    metadata, which starts the login in the client, instead of the enrollment server; the 401
    of an invalid or expired token carries it too.

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
        web_url: Callable[[], str | None] | None = None,
        oauth: Callable[[], OAuthResource | None] | None = None,
    ) -> None:
        self.app = app
        self.oauth = None if web else oauth
        self.store = store
        self.web = web
        self.enrollment_app = None if web else enrollment_app
        self.public_paths = public_paths
        self.sessions = sessions if web else None
        self.require_auth = require_auth and web
        self.allow_open = allow_open and not web
        self.web_url = web_url

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

        A ``ci`` token only reaches the pipeline routes of the controller (a personal ``mcp``
        token reaches them as a ``ci`` token, see TokenInfo.pipeline), a ``metrics`` token only
        its Prometheus endpoint.
        """
        if not self.web:
            return role in MCP_ROLES
        if path == METRICS_PATH:
            return role in METRICS_ROLES
        if path.startswith(CI_PREFIX):
            return role in CI_ROUTE_ROLES
        return role in API_ROLES

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
        if not has_credentials(authorization):
            if await self.oauth_resource() is not None:
                # No token: the client signs in with OAuth (RFC 6750 §3: no error code)
                AUTH_REJECTIONS["invalid_token"] += 1
                await self.unauthorized(send, "Missing bearer token", error=None)
                return
            if self.enrollment_app is not None:
                # No token yet: the enrollment server tells the user how to create one
                if self.web_url is not None:
                    await anyio.to_thread.run_sync(self.web_url)
                await self.enrollment_app(scope, receive, send)
                return
        info = await self.identify(authorization)
        if info is None:
            AUTH_REJECTIONS["invalid_token"] += 1
            logger.warning("Rejected unauthenticated request from %s to %s", address, path)
            await self.unauthorized(send, "Missing or invalid bearer token")
            return
        if info.expired:
            AUTH_REJECTIONS["token_expired"] += 1
            logger.warning("Rejected expired token %s from %s to %s", info.label, address, path)
            # RFC 6750: an expired token is an invalid_token
            await self.unauthorized(send, "The bearer token has expired")
            return
        if info.pipeline and self.web and path.startswith(CI_PREFIX):
            info = replace(info, role=Role.CI)
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
        state["auth_owner"] = info.owner
        state["auth_source"] = info.auth_source
        state["auth_grants"] = info.grants
        state["auth_must_change_password"] = info.must_change_password
        await self.app(scope, receive, send)

    async def oauth_resource(self) -> OAuthResource | None:
        """The OAuth login of the MCP clients, None when the controller does not serve it."""
        if self.oauth is None:
            return None
        return await anyio.to_thread.run_sync(self.oauth)

    async def unauthorized(
        self, send: Send, reason: str, error: str | None = "invalid_token"
    ) -> None:
        """Send a 401. On the MCP server its description tells the user how to get a new token
        (see renew_token_hint) and, while the OAuth login is on, its challenge names the
        protected resource metadata (``error`` None: a request without credentials)."""
        if self.web:
            await _send_error(send, 401, "invalid_token", reason)
            return
        url = await anyio.to_thread.run_sync(self.web_url) if self.web_url is not None else None
        oauth = await self.oauth_resource()
        hint = renew_token_hint(url)
        if oauth is not None:
            hint = f"sign in again through the OAuth login of the MCP client, or {hint}"
        challenge = oauth.challenge(error) if oauth is not None else None
        await _send_error(send, 401, "invalid_token", f"{reason}: {hint}", challenge)


async def _send_error(
    send: Send, status: int, error: str, description: str, challenge: str | None = None
) -> None:
    """Send a 401/403 response with a JSON body and a WWW-Authenticate challenge (by default
    the bearer challenge with ``error``)."""
    body = json.dumps({"error": error, "error_description": description}).encode("utf-8")
    challenge_value = challenge or f'{BEARER_CHALLENGE}, error="{error}"'
    challenge_bytes = challenge_value.encode("ascii")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"www-authenticate", challenge_bytes),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class ProtectedResourceMetadata:
    """Serve the protected resource metadata of the MCP server (RFC 9728), public: any path
    under PROTECTED_RESOURCE_PREFIX, 404 while the OAuth login is off. Every other request goes
    to ``app``."""

    def __init__(self, app: ASGIApp, oauth: Callable[[], OAuthResource | None]) -> None:
        self.app = app
        self.oauth = oauth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "") if scope["type"] == "http" else ""
        if not path.startswith(PROTECTED_RESOURCE_PREFIX):
            await self.app(scope, receive, send)
            return
        oauth = await anyio.to_thread.run_sync(self.oauth)
        if oauth is None or scope.get("method") not in ("GET", "HEAD"):
            status, body = 404, b'{"detail":"Not Found"}'
        else:
            status, body = 200, oauth.metadata()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"public, max-age=300"),
                    # A static public document: browser-based clients may read it
                    (b"access-control-allow-origin", b"*"),
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


class BodyLimit:
    """Refuse (413) a request whose body exceeds the bound of its path, before the app reads it.

    ``limits`` gives the bound (in bytes) of a path and the hint of its 413 answer. The declared
    ``Content-Length`` is checked first; a body without it (chunked) is read here, bounded, and
    replayed to the application.
    """

    def __init__(self, app: ASGIApp, limits: Callable[[str], tuple[int, str]]) -> None:
        self.app = app
        self.limits = limits

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit, hint = self.limits(scope.get("path", ""))
        declared = Headers(scope=scope).get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            await self._too_large(scope, send, limit, hint)
            return
        chunks: list[bytes] = []
        size = 0
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > limit:
                await self._too_large(scope, send, limit, hint)
                return
            chunks.append(chunk)
            more = message.get("more_body", False)
        body = b"".join(chunks)
        replayed = False

        async def replay() -> Message:
            """Give the buffered body once, then the next messages of the connection."""
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)

    @staticmethod
    async def _too_large(scope: Scope, send: Send, limit: int, hint: str) -> None:
        """Send the 413 answer."""
        logger.warning("Rejected request body above %d bytes: %s", limit, scope.get("path"))
        detail = f"Request body too large (limit {limit} bytes, {hint}"
        body = json.dumps({"detail": detail}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def mcp_body_limit(_path: str) -> tuple[int, str]:
    """Bound of the body of an authenticated request to the MCP server (see BodyLimit)."""
    return get_settings().max_mcp_request_mb * 1024 * 1024, "SECREVIEW_MAX_MCP_REQUEST_MB)"


def enrollment_body_limit(_path: str) -> tuple[int, str]:
    """Bound of the body of a request without a token, served by the enrollment server."""
    return MAX_ENROLLMENT_BODY_BYTES, "request without a token)"


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
    parser.add_argument(
        "--host",
        default=settings.host,
        help="listening address (overrides SECREVIEW_HOST, default: %(default)s)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=settings.port,
        help="listening port (overrides SECREVIEW_PORT, default: %(default)s)",
    )
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
    users create a personal token in the web interface.
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
    allow_open: bool = False,
    web_url: Callable[[], str | None] | None = None,
    oauth: Callable[[], OAuthResource | None] | None = None,
) -> ASGIApp:
    """Build the HTTP app of the MCP server, protected by the bearer tokens of ``store``.

    ``enrollment_server`` answers the MCP clients that have no token yet.
    ``allow_open`` (see allows_open_mcp) lets every request through while no token is stored.
    ``web_url`` returns the address of the web interface, given in the 401 answers, where a new
    token is created (see BearerAuthMiddleware).
    ``oauth`` returns the OAuth login of the MCP clients while the controller serves it: the
    protected resource metadata is then served, and a client without a token gets a 401 that
    starts the login (see ProtectedResourceMetadata and BearerAuthMiddleware).
    """
    main = server.streamable_http_app(host=host)
    enrollment_app = (
        BodyLimit(_enrollment_app(main, enrollment_server, host), enrollment_body_limit)
        if enrollment_server is not None
        else None
    )
    routes: dict[str, ASGIApp] = {HEALTH_PATH: health_app}
    # The bodies are bounded after authentication: a request without a valid token is refused
    # (or sent to the enrollment server, with its own small bound) before its body is read
    app: ASGIApp = BearerAuthMiddleware(
        PathDispatcher(BodyLimit(main, mcp_body_limit), routes),
        store,
        enrollment_app=enrollment_app,
        public_paths=frozenset(routes),
        allow_open=allow_open,
        web_url=web_url,
        oauth=oauth,
    )
    return ProtectedResourceMetadata(app, oauth) if oauth is not None else app


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
            auth_prefix=(AUTH_PREFIX, *OAUTH_LOGIN_PATHS),
            counted=OAUTH_PATHS,
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
            "a token exists: a personal MCP token created in the web interface, or a token "
            "created with `security-review-controller token create`."
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
