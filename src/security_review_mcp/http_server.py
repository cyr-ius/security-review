"""HTTP serving of the two processes: bearer-token authentication, TLS and health checks.

The MCP SDK starts uvicorn without TLS options and its own auth expects an OAuth authorization
server. For a shared server we only need API tokens, stored in the database (see token_store),
so the apps are wrapped in a small ASGI middleware and served by uvicorn directly.

Two apps are built, meant to run in separate processes (containers, pods) sharing the database:

- the MCP server (``build_mcp_app``): the MCP endpoint, the public enrollment endpoint and
  ``/healthz``. With enrollment, an MCP client that presents no token (or a token still waiting
  for approval) is sent to a restricted MCP server that only lets it request a project token;
- the controller (``build_controller_app``): the REST API under ``/api`` and the Angular
  application under ``/ui`` (see web_api).

Each token carries a role that decides which of the two it may use.
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import socket
import ssl
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

import anyio.to_thread
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
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

API_PREFIX = "/api/"
UI_PREFIX = "/ui"
# Public endpoint of the MCP server where a client without a token requests one
# (see enrollment_api)
ENROLL_PATH = "/api/v1/enroll"
# Public liveness endpoint of both processes (container and Kubernetes probes)
HEALTH_PATH = "/healthz"
# Public login routes of the controller (OpenID Connect, see oidc)
AUTH_PREFIX = "/api/v1/auth/"
# Value of WWW-Authenticate on a 401 / 403 (an error="..." parameter may follow)
BEARER_CHALLENGE = 'Bearer realm="security-review-mcp"'


@dataclass(frozen=True)
class TokenInfo:
    """Identity attached to a token: a label for the logs and a role.

    ``projects`` lists the projects a restricted token reaches (None: every project).
    ``pending`` marks an enrollment request not approved yet: it grants no access.
    """

    label: str
    role: Role = DEFAULT_ROLE
    projects: frozenset[str] | None = None
    token_id: str | None = None
    pending: bool = False


class TokenStore(Protocol):
    """Source of the bearer tokens (see token_store.DatabaseTokenStore)."""

    def lookup(self, digest: bytes) -> TokenInfo | None:
        """Return the identity of the token with this SHA-256 digest, or None."""

    def has_tokens(self) -> bool:
        """True when at least one token is stored."""


class SessionVerifier(Protocol):
    """Verifier of the web sessions issued after an OIDC login (see oidc.SessionSigner)."""

    def owns(self, credentials: str) -> bool:
        """True when the bearer value is a session token (not a database token)."""

    def verify_session(self, credentials: str) -> TokenInfo | None:
        """Return the identity of a valid, unexpired session token, or None."""


def hash_token(token: str) -> bytes:
    """Return the SHA-256 digest of a raw token: the only form that is ever stored."""
    return hashlib.sha256(token.encode("utf-8")).digest()


# ── Middleware ───────────────────────────────────────────────────────────────


def is_controller_public_path(path: str) -> bool:
    """Controller paths reachable without a token: the web UI shell, the API documentation,
    the health check and the login routes."""
    return path in ("/", UI_PREFIX, "/api/docs", "/api/openapi.json", HEALTH_PATH) or (
        path.startswith((UI_PREFIX + "/", AUTH_PREFIX))
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
    (``auth_client``, ``auth_role``, ``auth_projects``, ``auth_token_id``).

    With ``web=False`` (MCP server) every path needs an MCP role, except ``public_paths``.
    With ``web=True`` (controller) the static files of the web interface are public and the
    REST API needs a web role. While ``store`` holds no token at all, the MCP server is open
    and the controller API answers 503 (authentication not configured).

    ``enrollment_app`` receives the MCP requests sent without an ``Authorization`` header (or
    with an empty bearer value) or with a pending enrollment token;
    ``scope["state"]["enrollment_token_id"]`` then holds the id of that pending token (None
    without a token). Without it they get 401 / 403.

    ``sessions`` (controller only) also accepts the session tokens issued after an OIDC login;
    the web API then works even while the store holds no token.
    """

    def __init__(
        self,
        app: ASGIApp,
        store: TokenStore,
        web: bool = False,
        enrollment_app: ASGIApp | None = None,
        public_paths: frozenset[str] = frozenset(),
        sessions: SessionVerifier | None = None,
    ) -> None:
        self.app = app
        self.store = store
        self.web = web
        self.enrollment_app = None if web else enrollment_app
        self.public_paths = public_paths
        self.sessions = sessions if web else None

    async def identify(self, authorization: str) -> TokenInfo | None:
        """Return the identity of the presented bearer token, or None."""
        scheme, _, credentials = authorization.partition(" ")
        credentials = credentials.strip()
        if scheme.lower() != "bearer" or not credentials:
            return None
        if self.sessions is not None and self.sessions.owns(credentials):
            return self.sessions.verify_session(credentials)
        return await anyio.to_thread.run_sync(self.store.lookup, hash_token(credentials))

    async def has_tokens(self) -> bool:
        """True when at least one token is stored."""
        return await anyio.to_thread.run_sync(self.store.has_tokens)

    def is_public(self, path: str) -> bool:
        """True for the paths reachable without a token."""
        return is_controller_public_path(path) if self.web else path in self.public_paths

    @property
    def allowed_roles(self) -> frozenset[Role]:
        """Roles accepted by this process."""
        return WEB_ROLES if self.web else MCP_ROLES

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if self.is_public(path):
            await self.app(scope, receive, send)
            return

        if self.sessions is None and not await self.has_tokens():
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
            logger.warning("Rejected unauthenticated request from %s to %s", address, path)
            await _send_error(send, 401, "invalid_token", "Missing or invalid bearer token")
            return
        if info.pending:
            if self.enrollment_app is not None:
                await self.enroll(scope, receive, send, info.token_id)
                return
            await _send_error(
                send,
                403,
                "enrollment_pending",
                "This token is waiting for an administrator to approve its enrollment",
            )
            return
        if info.role not in self.allowed_roles:
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


SELF_SIGNED_VALIDITY = datetime.timedelta(days=365)


@dataclass(frozen=True)
class TLSOptions:
    """TLS files for uvicorn; ``client_ca`` enables mutual TLS (client certificates).

    ``fingerprint`` (SHA-256 of the certificate) is set when the certificate was self-signed at
    start-up, so that the operator can check it from the clients.
    """

    certfile: str
    keyfile: str | None = None
    keyfile_password: str | None = None
    client_ca: str | None = None
    fingerprint: str | None = None

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


# One DNS label (no wildcard): letters, digits and inner hyphens, 63 characters at most
DNS_LABEL_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
MAX_SELF_SIGNED_HOSTS = 20


def self_signed_hosts(value: str | None) -> list[str]:
    """Parse SECREVIEW_TLS_SELF_SIGNED_HOSTS: extra DNS names or IP addresses, comma-separated."""
    names = [name.strip() for name in (value or "").split(",") if name.strip()]
    if len(names) > MAX_SELF_SIGNED_HOSTS:
        raise ValueError(f"SECREVIEW_TLS_SELF_SIGNED_HOSTS: at most {MAX_SELF_SIGNED_HOSTS} names")
    for name in names:
        try:
            ipaddress.ip_address(name)
        except ValueError:
            labels = name.split(".")
            if len(name) > 253 or not all(DNS_LABEL_PATTERN.fullmatch(label) for label in labels):
                raise ValueError(
                    f"SECREVIEW_TLS_SELF_SIGNED_HOSTS: invalid DNS name or IP address: {name!r}"
                ) from None
    return names


def _subject_alt_names(host: str, extra_hosts: list[str]) -> list[x509.GeneralName]:
    """Names the certificate is valid for: loopback, this machine, ``host`` and ``extra_hosts``."""
    names = ["localhost", socket.gethostname(), "127.0.0.1", "::1"]
    if host and host not in ("0.0.0.0", "::"):
        names.append(host)
    names.extend(extra_hosts)
    alt_names: list[x509.GeneralName] = []
    for name in dict.fromkeys(names):
        try:
            alt_names.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            alt_names.append(x509.DNSName(name))
    return alt_names


def generate_self_signed(
    host: str, directory: Path, extra_hosts: list[str] | None = None
) -> tuple[Path, Path, str]:
    """Write a self-signed certificate and its private key (EC P-256) into ``directory``.

    ``extra_hosts`` (see self_signed_hosts) are the names the clients use to reach the server.
    Returns the certificate path, the key path and the SHA-256 fingerprint of the certificate.
    The key file is created with mode 0600 and is never logged.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    alt_names = x509.SubjectAlternativeName(_subject_alt_names(host, extra_hosts or []))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "security-review-mcp")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + SELF_SIGNED_VALIDITY)
        .add_extension(alt_names, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = directory / "cert.pem", directory / "key.pem"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    descriptor = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex(":").upper()
    return certfile, keyfile, fingerprint


def _self_signed_options(settings: Settings, host: str) -> TLSOptions:
    """Generate a certificate in a private temporary directory (mode 0700), removed by serve."""
    extra_hosts = self_signed_hosts(settings.tls_self_signed_hosts)
    directory = Path(tempfile.mkdtemp(prefix="secreview-tls-"))
    certfile, keyfile, fingerprint = generate_self_signed(host, directory, extra_hosts)
    return TLSOptions(
        certfile=str(certfile),
        keyfile=str(keyfile),
        client_ca=settings.tls_client_ca,
        fingerprint=fingerprint,
    )


def tls_options(settings: Settings, host: str = "127.0.0.1") -> TLSOptions | None:
    """Validate the TLS settings; None when TLS is disabled (no certificate configured).

    Without a certificate, ``tls_self_signed`` generates one valid for ``host``.
    """
    if not settings.tls_certfile:
        if settings.tls_keyfile:
            raise ValueError("SECREVIEW_TLS_KEYFILE needs SECREVIEW_TLS_CERTFILE")
        if settings.tls_client_ca and not settings.tls_self_signed:
            raise ValueError(
                "SECREVIEW_TLS_CLIENT_CA needs SECREVIEW_TLS_CERTFILE or SECREVIEW_TLS_SELF_SIGNED"
            )
    for name in ("tls_certfile", "tls_keyfile", "tls_client_ca"):
        value = getattr(settings, name)
        if value and not Path(value).is_file():
            raise ValueError(f"SECREVIEW_{name.upper()}: file not found: {value}")
    if not settings.tls_certfile:
        return _self_signed_options(settings, host) if settings.tls_self_signed else None
    return TLSOptions(
        certfile=settings.tls_certfile,
        keyfile=settings.tls_keyfile,
        keyfile_password=settings.tls_keyfile_password,
        client_ca=settings.tls_client_ca,
    )


def add_listen_arguments(parser: argparse.ArgumentParser, settings: Settings) -> None:
    """Add the --host, --port and TLS options shared by the MCP server and the controller."""
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--tls-certfile", help="enable TLS (overrides SECREVIEW_TLS_CERTFILE)")
    parser.add_argument("--tls-keyfile", help="private key (overrides SECREVIEW_TLS_KEYFILE)")
    parser.add_argument(
        "--tls-self-signed",
        action="store_true",
        help="without a certificate, serve HTTPS with a self-signed one generated at start-up "
        "(SECREVIEW_TLS_SELF_SIGNED)",
    )


def with_tls_arguments(settings: Settings, args: argparse.Namespace) -> Settings:
    """Return the settings with the TLS options given on the command line, if any."""
    if not (args.tls_certfile or args.tls_keyfile or args.tls_self_signed):
        return settings
    return settings.model_copy(
        update={
            "tls_certfile": args.tls_certfile or settings.tls_certfile,
            "tls_keyfile": args.tls_keyfile or settings.tls_keyfile,
            "tls_self_signed": args.tls_self_signed or settings.tls_self_signed,
        }
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


def build_mcp_app(
    server: MCPServer,
    host: str,
    store: TokenStore,
    enrollment_server: MCPServer | None = None,
    enroll_endpoint: ASGIApp | None = None,
) -> ASGIApp:
    """Build the HTTP app of the MCP server, protected by the bearer tokens of ``store``.

    ``enrollment_server`` answers the MCP clients that have no token yet and
    ``enroll_endpoint`` (see enrollment_api.create_app) serves the public ``ENROLL_PATH``.
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
    )


def build_controller_app(
    web_app: ASGIApp, store: TokenStore, sessions: SessionVerifier | None = None
) -> ASGIApp:
    """Build the HTTP app of the controller (see web_api.create_app), protected by ``store``
    and, with OIDC, by the session tokens of ``sessions``."""
    return BearerAuthMiddleware(web_app, store, web=True, sessions=sessions)


def _log_exposure(host: str, store: TokenStore, tls: TLSOptions | None) -> None:
    """Warn when the server listens on a public address without authentication or TLS."""
    exposed = host not in LOOPBACK_HOSTS
    if store.has_tokens():
        logger.info("Bearer authentication enabled (tokens stored in the database)")
    elif exposed and not (tls and tls.client_ca):
        logger.warning(
            "Listening on %s without authentication: create a token with "
            "`security-review-controller token create`, or put the server behind a reverse "
            "proxy that enforces authentication.",
            host,
        )
    if tls:
        logger.info("TLS enabled%s", " with client certificates" if tls.client_ca else "")
        if tls.fingerprint:
            logger.warning(
                "Self-signed TLS certificate generated for this start (clients must trust it "
                "explicitly), SHA-256 fingerprint: %s",
                tls.fingerprint,
            )
    elif exposed:
        logger.warning(
            "Listening on %s without TLS: set SECREVIEW_TLS_CERTFILE and SECREVIEW_TLS_KEYFILE, "
            "or terminate TLS on a reverse proxy.",
            host,
        )


def _exit_on_signal(signum: int, _frame: Any) -> None:
    """Turn a termination signal into SystemExit so that cleanup code runs."""
    raise SystemExit(128 + signum)


def serve(
    app: ASGIApp,
    host: str,
    port: int,
    store: TokenStore,
    tls: TLSOptions | None,
    log_level: str = "INFO",
) -> None:
    """Serve an app built by build_mcp_app or build_controller_app with uvicorn.

    ``tls`` comes from tls_options (validated beforehand); a self-signed certificate it
    generated is deleted when the server stops.
    """
    _log_exposure(host, store, tls)
    generated = tls is not None and tls.fingerprint is not None
    if generated:
        # uvicorn re-raises SIGTERM after its graceful shutdown: exit through `finally` instead
        # of being killed by the default handler, so that the generated key is removed.
        previous = signal.signal(signal.SIGTERM, _exit_on_signal)
    try:
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level=log_level.lower(),
            **(tls.uvicorn_kwargs() if tls else {}),
        )
    finally:
        if generated:
            signal.signal(signal.SIGTERM, previous)
            shutil.rmtree(Path(tls.certfile).parent, ignore_errors=True)
