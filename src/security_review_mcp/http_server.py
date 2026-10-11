"""Streamable HTTP transport: optional built-in bearer-token authentication and TLS.

The MCP SDK starts uvicorn without TLS options and its own auth expects an OAuth authorization
server. For a shared server we only need static API tokens, so the Starlette app built by the
SDK is wrapped in a small ASGI middleware and served by uvicorn directly.

The same server can also expose the web interface (REST API under ``/api`` and the Angular
application under ``/ui``). Each token carries a role that decides which part it may use.
"""

import hashlib
import hmac
import json
import logging
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import uvicorn
from mcp.server.mcpserver import MCPServer
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Settings

logger = logging.getLogger("security_review_mcp.http")

HASH_PREFIX = "sha256:"
MIN_TOKEN_LENGTH = 24
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class Role(StrEnum):
    """What a token may do.

    ``mcp`` (default) only reaches the MCP endpoint; ``reader`` and ``triager`` only reach the
    web API (read, and read + change finding status); ``admin`` reaches everything.
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


@dataclass(frozen=True)
class TokenInfo:
    """Identity attached to a token: a label for the logs and a role."""

    label: str
    role: Role = DEFAULT_ROLE


# ── Tokens ───────────────────────────────────────────────────────────────────


def hash_token(token: str) -> str:
    """Return the ``sha256:<hex>`` form of a token, safe to store in the configuration."""
    return HASH_PREFIX + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_entry(entry: str, index: int) -> tuple[bytes, TokenInfo]:
    """Parse ``[label[:role]:]token`` or ``[label[:role]:]sha256:<hex>`` into (digest, info)."""
    label = f"token-{index}"
    role = DEFAULT_ROLE
    if not entry.startswith(HASH_PREFIX) and ":" in entry:
        label, entry = entry.split(":", 1)
        label = label.strip()
        entry = entry.strip()
        if not label:
            raise ValueError(f"Auth token entry #{index} has an empty label")
        if not entry.startswith(HASH_PREFIX) and ":" in entry:
            name, entry = entry.split(":", 1)
            entry = entry.strip()
            try:
                role = Role(name.strip().lower())
            except ValueError:
                allowed = ", ".join(r.value for r in Role)
                raise ValueError(
                    f"Auth token '{label}' has an unknown role '{name}' (allowed: {allowed})"
                ) from None

    if entry.startswith(HASH_PREFIX):
        hex_digest = entry.removeprefix(HASH_PREFIX).lower()
        try:
            digest = bytes.fromhex(hex_digest)
        except ValueError:
            digest = b""
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError(f"Auth token '{label}' is not a valid sha256 digest")
        return digest, TokenInfo(label, role)

    if len(entry) < MIN_TOKEN_LENGTH:
        raise ValueError(
            f"Auth token '{label}' is too short (minimum {MIN_TOKEN_LENGTH} characters): "
            "generate one with `security-review-mcp token`"
        )
    return hashlib.sha256(entry.encode("utf-8")).digest(), TokenInfo(label, role)


def parse_tokens(entries: Iterable[str]) -> dict[bytes, TokenInfo]:
    """Parse token entries into a ``{sha256 digest: info}`` mapping (empty entries skipped)."""
    tokens: dict[bytes, TokenInfo] = {}
    labels: set[str] = set()
    for index, raw in enumerate((e.strip() for e in entries if e.strip()), start=1):
        digest, info = _parse_entry(raw, index)
        if info.label in labels:
            raise ValueError(f"Duplicate auth token label: '{info.label}'")
        labels.add(info.label)
        tokens[digest] = info
    return tokens


def load_tokens(settings: Settings) -> dict[bytes, TokenInfo]:
    """Collect the tokens of SECREVIEW_AUTH_TOKENS and SECREVIEW_AUTH_TOKENS_FILE."""
    entries: list[str] = []
    if settings.auth_tokens:
        entries.extend(settings.auth_tokens.split(","))
    if settings.auth_tokens_file:
        path = Path(settings.auth_tokens_file)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ValueError(f"Cannot read the auth tokens file {path}: {exc}") from exc
        entries.extend(line for line in lines if not line.lstrip().startswith("#"))
    return parse_tokens(entries)


# ── Middleware ───────────────────────────────────────────────────────────────


def is_public_path(path: str) -> bool:
    """Static files of the web interface: no token needed to load the login page."""
    return path in ("/", UI_PREFIX) or path.startswith(UI_PREFIX + "/")


def is_web_path(path: str) -> bool:
    """True for the paths of the web interface (REST API, Angular application, root)."""
    return path.startswith(API_PREFIX) or is_public_path(path)


class BearerAuthMiddleware:
    """Reject HTTP requests that do not carry one of the configured bearer tokens.

    Pure ASGI (no response buffering) so that streamed MCP responses are not affected.
    The label and role of the accepted token are stored in ``scope["state"]["auth_client"]``
    and ``scope["state"]["auth_role"]``. With ``web=True`` the static files of the web
    interface are public, the REST API needs a web role and the MCP endpoint an MCP role.
    """

    def __init__(self, app: ASGIApp, tokens: dict[bytes, TokenInfo], web: bool = False) -> None:
        if not tokens:
            raise ValueError("BearerAuthMiddleware needs at least one token")
        self.app = app
        self.tokens = tokens
        self.web = web

    def authenticate(self, authorization: str) -> TokenInfo | None:
        """Return the identity of the matching token, or None."""
        scheme, _, credentials = authorization.partition(" ")
        credentials = credentials.strip()
        if scheme.lower() != "bearer" or not credentials:
            return None
        presented = hashlib.sha256(credentials.encode("utf-8")).digest()
        info = None
        # Compare against every token so the timing does not reveal which one matched
        for digest, candidate in self.tokens.items():
            if hmac.compare_digest(presented, digest):
                info = candidate
        return info

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

        client = scope.get("client")
        address = client[0] if client else "unknown"
        info = self.authenticate(Headers(scope=scope).get("authorization", ""))
        if info is None:
            logger.warning("Rejected unauthenticated request from %s to %s", address, path)
            await _send_error(send, 401, "invalid_token", "Missing or invalid bearer token")
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
        await self.app(scope, receive, send)


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


def build_app(
    server: MCPServer,
    host: str,
    tokens: dict[bytes, TokenInfo],
    web_app: ASGIApp | None = None,
) -> ASGIApp:
    """Build the streamable HTTP app, protected by bearer tokens when some are configured.

    ``web_app`` (see web_api.create_app) is served next to MCP under ``/api`` and ``/ui``.
    """
    app: ASGIApp = server.streamable_http_app(host=host)
    if web_app is not None:
        app = PathDispatcher(app, web_app)
    return BearerAuthMiddleware(app, tokens, web=web_app is not None) if tokens else app


def run(
    server: MCPServer,
    host: str,
    port: int,
    tokens: dict[bytes, TokenInfo],
    tls: TLSOptions | None,
    log_level: str = "INFO",
    web_app: ASGIApp | None = None,
) -> None:
    """Serve the MCP server over streamable HTTP, with optional authentication and TLS.

    ``tokens`` and ``tls`` come from load_tokens and tls_options (validated beforehand).
    """
    exposed = host not in LOOPBACK_HOSTS

    if tokens:
        logger.info("Bearer authentication enabled (%d token(s))", len(tokens))
    elif exposed and not (tls and tls.client_ca):
        logger.warning(
            "Listening on %s without authentication: set SECREVIEW_AUTH_TOKENS (or _FILE), "
            "or put the server behind a reverse proxy that enforces authentication.",
            host,
        )
    if tls:
        logger.info("TLS enabled%s", " with client certificates" if tls.client_ca else "")
    if web_app is not None:
        logger.info("Web interface enabled on /ui (REST API on /api/v1)")
    elif exposed:
        logger.warning(
            "Listening on %s without TLS: set SECREVIEW_TLS_CERTFILE and SECREVIEW_TLS_KEYFILE, "
            "or terminate TLS on a reverse proxy.",
            host,
        )

    uvicorn.run(
        build_app(server, host, tokens, web_app),
        host=host,
        port=port,
        log_level=log_level.lower(),
        **(tls.uvicorn_kwargs() if tls else {}),
    )
