"""Streamable HTTP transport: optional built-in bearer-token authentication and TLS.

The MCP SDK starts uvicorn without TLS options and its own auth expects an OAuth authorization
server. For a shared server we only need API tokens, stored in the database (see token_store),
so the Starlette app built by the SDK is wrapped in a small ASGI middleware and served by
uvicorn directly.

The same server can also expose the web interface (REST API under ``/api`` and the Angular
application under ``/ui``). Each token carries a role that decides which part it may use.

With enrollment, an MCP client that presents no token (or a token still waiting for approval)
is not rejected but sent to a restricted MCP server that only lets it request a project token.
"""

import hashlib
import json
import logging
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

import anyio.to_thread
import uvicorn
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Settings

logger = logging.getLogger("security_review_mcp.http")

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class Role(StrEnum):
    """What a token may do.

    ``mcp`` (default) only reaches the MCP endpoint; ``reader`` and ``triager`` only reach the
    web API; ``admin`` reaches both MCP and the web API.
    """

    MCP = "mcp"
    READER = "reader"
    TRIAGER = "triager"
    ADMIN = "admin"


DEFAULT_ROLE = Role.MCP
MCP_ROLES = frozenset({Role.MCP, Role.ADMIN})
WEB_ROLES = frozenset({Role.READER, Role.TRIAGER, Role.ADMIN})
TRIAGE_ROLES = frozenset({Role.TRIAGER, Role.ADMIN})

# Paths served by the web interface; everything else goes to the MCP app
API_PREFIX = "/api/"
UI_PREFIX = "/ui"
# Public REST endpoint where a client without a token requests one (see web_api)
ENROLL_PATH = "/api/v1/enroll"


@dataclass(frozen=True)
class TokenInfo:
    """Identity attached to a token: a label for the logs and a role.

    ``pending`` marks an enrollment request not approved yet: it grants no access.
    """

    label: str
    role: Role = DEFAULT_ROLE
    project: str | None = None
    token_id: str | None = None
    pending: bool = False


class TokenStore(Protocol):
    """Source of the bearer tokens (see token_store.DatabaseTokenStore)."""

    def lookup(self, digest: bytes) -> TokenInfo | None:
        """Return the identity of the token with this SHA-256 digest, or None."""

    def has_tokens(self) -> bool:
        """True when at least one token is stored."""


def hash_token(token: str) -> bytes:
    """Return the SHA-256 digest of a raw token: the only form that is ever stored."""
    return hashlib.sha256(token.encode("utf-8")).digest()


# ── Middleware ───────────────────────────────────────────────────────────────


def is_public_path(path: str) -> bool:
    """Paths reachable without a token: the web UI shell, the API documentation and the
    enrollment endpoint (which checks itself whether enrollment is enabled)."""
    return path in ("/", UI_PREFIX, "/api/docs", "/api/openapi.json", ENROLL_PATH) or (
        path.startswith(UI_PREFIX + "/")
    )


def is_web_path(path: str) -> bool:
    """True for the paths of the web interface (REST API, Angular application, root)."""
    return path.startswith(API_PREFIX) or is_public_path(path)


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
    The label and role of the accepted token are stored in ``scope["state"]["auth_client"]``
    and ``scope["state"]["auth_role"]``. With ``web=True`` the static files of the web
    interface are public, the REST API needs a web role and the MCP endpoint an MCP role.
    While ``store`` holds no token at all, the MCP endpoint is open and the REST API answers
    503 (authentication not configured).

    ``enrollment_app`` receives the MCP requests sent without an ``Authorization`` header (or
    with an empty bearer value) or with a pending enrollment token;
    ``scope["state"]["enrollment_token_id"]`` then holds the id of that pending token (None
    without a token). Without it they get 401 / 403.
    """

    def __init__(
        self,
        app: ASGIApp,
        store: TokenStore,
        web: bool = False,
        enrollment_app: ASGIApp | None = None,
    ) -> None:
        self.app = app
        self.store = store
        self.web = web
        self.enrollment_app = enrollment_app

    async def identify(self, authorization: str) -> TokenInfo | None:
        """Return the identity of the presented bearer token, or None."""
        scheme, _, credentials = authorization.partition(" ")
        credentials = credentials.strip()
        if scheme.lower() != "bearer" or not credentials:
            return None
        return await anyio.to_thread.run_sync(self.store.lookup, hash_token(credentials))

    async def has_tokens(self) -> bool:
        """True when at least one token is stored."""
        return await anyio.to_thread.run_sync(self.store.has_tokens)

    def allowed_roles(self, path: str) -> frozenset[Role]:
        """Roles accepted for a path."""
        if self.web and path.startswith(API_PREFIX):
            return WEB_ROLES
        return MCP_ROLES

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if self.web and is_public_path(path):
            await self.app(scope, receive, send)
            return

        if not await self.has_tokens():
            if self.web and path.startswith(API_PREFIX):
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
        is_mcp = not (self.web and path.startswith(API_PREFIX))
        if is_mcp and self.enrollment_app is not None and not has_credentials(authorization):
            await self.enroll(scope, receive, send, None)
            return
        info = await self.identify(authorization)
        if info is None:
            logger.warning("Rejected unauthenticated request from %s to %s", address, path)
            await _send_error(send, 401, "invalid_token", "Missing or invalid bearer token")
            return
        if info.pending:
            if is_mcp and self.enrollment_app is not None:
                await self.enroll(scope, receive, send, info.token_id)
                return
            await _send_error(
                send,
                403,
                "enrollment_pending",
                "This token is waiting for an administrator to approve its enrollment",
            )
            return
        if info.role not in self.allowed_roles(path):
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
        state["auth_project"] = info.project
        await self.app(scope, receive, send)

    async def enroll(
        self, scope: Scope, receive: Receive, send: Send, token_id: str | None
    ) -> None:
        """Forward a request to the enrollment MCP server, with the pending token id if any."""
        if self.enrollment_app is None:
            raise RuntimeError("Enrollment is not enabled")
        state = scope.setdefault("state", {})
        state["enrollment_token_id"] = token_id
        await self.enrollment_app(scope, receive, send)


async def _send_error(send: Send, status: int, error: str, description: str) -> None:
    """Send a 401/403 response with a JSON body and a WWW-Authenticate challenge."""
    body = json.dumps({"error": error, "error_description": description}).encode("utf-8")
    challenge = f'Bearer realm="security-review-mcp", error="{error}"'.encode("ascii")
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
    """Send web-interface paths to the web app and everything else (and lifespan) to MCP."""

    def __init__(self, mcp_app: ASGIApp, web_app: ASGIApp) -> None:
        self.mcp_app = mcp_app
        self.web_app = web_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and is_web_path(scope.get("path", "")):
            await self.web_app(scope, receive, send)
        else:
            await self.mcp_app(scope, receive, send)


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
        if settings.tls_keyfile or settings.tls_client_ca:
            raise ValueError(
                "SECREVIEW_TLS_KEYFILE and SECREVIEW_TLS_CLIENT_CA need SECREVIEW_TLS_CERTFILE"
            )
        return None
    for name in ("tls_certfile", "tls_keyfile", "tls_client_ca"):
        value = getattr(settings, name)
        if value and not Path(value).is_file():
            raise ValueError(f"SECREVIEW_{name.upper()}: file not found: {value}")
    return TLSOptions(
        certfile=settings.tls_certfile,
        keyfile=settings.tls_keyfile,
        keyfile_password=settings.tls_keyfile_password,
        client_ca=settings.tls_client_ca,
    )


# ── Entry point ──────────────────────────────────────────────────────────────


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


def build_app(
    server: MCPServer,
    host: str,
    store: TokenStore,
    web_app: ASGIApp | None = None,
    enrollment_server: MCPServer | None = None,
) -> ASGIApp:
    """Build the streamable HTTP app, protected by the bearer tokens of ``store``.

    ``web_app`` (see web_api.create_app) is served next to MCP under ``/api`` and ``/ui``.
    ``enrollment_server`` answers the MCP clients that have no token yet.
    """
    main = server.streamable_http_app(host=host)
    enrollment_app = (
        _enrollment_app(main, enrollment_server, host) if enrollment_server is not None else None
    )
    app: ASGIApp = main
    if web_app is not None:
        app = PathDispatcher(app, web_app)
    return BearerAuthMiddleware(app, store, web=web_app is not None, enrollment_app=enrollment_app)


def run(
    server: MCPServer,
    host: str,
    port: int,
    store: TokenStore,
    tls: TLSOptions | None,
    log_level: str = "INFO",
    web_app: ASGIApp | None = None,
    enrollment_server: MCPServer | None = None,
) -> None:
    """Serve the MCP server over streamable HTTP, with optional authentication and TLS.

    ``tls`` comes from tls_options (validated beforehand).
    """
    exposed = host not in LOOPBACK_HOSTS

    if store.has_tokens():
        logger.info("Bearer authentication enabled (tokens stored in the database)")
    elif exposed and not (tls and tls.client_ca):
        logger.warning(
            "Listening on %s without authentication: create a token with "
            "`security-review-mcp token create`, or put the server behind a reverse proxy "
            "that enforces authentication.",
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
    if web_app is not None:
        logger.info("Web interface enabled on /ui (REST API on /api/v1)")
    if enrollment_server is not None:
        logger.info("Enrollment enabled: clients without a token may request one")

    uvicorn.run(
        build_app(server, host, store, web_app, enrollment_server),
        host=host,
        port=port,
        log_level=log_level.lower(),
        **(tls.uvicorn_kwargs() if tls else {}),
    )
