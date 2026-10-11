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
import os
import secrets
import ssl
import tempfile
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
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
MAX_PROJECT_TOKENS = 500
MAX_PROJECT_TOKEN_FILE_BYTES = 1_000_000
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
_managed_tokens_lock = threading.Lock()


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


@dataclass(frozen=True)
class TokenInfo:
    """Identity attached to a token: a label for the logs and a role."""

    label: str
    role: Role = DEFAULT_ROLE
    project: str | None = None
    token_id: str | None = None


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


def ensure_bootstrap_admin_token(path: str | Path) -> tuple[dict[bytes, TokenInfo], str | None]:
    """Create or load the administrator token, storing only its SHA-256 digest."""
    token_path = Path(path)
    token_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            contents = token_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"Cannot read bootstrap admin token file {token_path}: {exc}") from exc
        migrated_contents = contents.replace("bootstrap-admin:web-admin:", "bootstrap-admin:admin:")
        entries = [
            line for line in migrated_contents.splitlines() if not line.lstrip().startswith("#")
        ]
        tokens = parse_tokens(entries)
        if not tokens:
            raise ValueError(f"Bootstrap admin token file is empty: {token_path}") from None
        if migrated_contents != contents:
            temporary_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", dir=token_path.parent, delete=False
                ) as stream:
                    stream.write(migrated_contents)
                    stream.flush()
                    os.fsync(stream.fileno())
                    temporary_path = Path(stream.name)
                os.chmod(temporary_path, 0o600)
                os.replace(temporary_path, token_path)
            except OSError as exc:
                if temporary_path:
                    temporary_path.unlink(missing_ok=True)
                raise ValueError(
                    f"Cannot migrate bootstrap admin token file {token_path}: {exc}"
                ) from exc
        return tokens, None
    except OSError as exc:
        raise ValueError(f"Cannot create bootstrap admin token file {token_path}: {exc}") from exc

    token = secrets.token_urlsafe(32)
    entry = f"bootstrap-admin:admin:{hash_token(token)}\n"
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(entry)
    except OSError as exc:
        token_path.unlink(missing_ok=True)
        raise ValueError(f"Cannot write bootstrap admin token file {token_path}: {exc}") from exc
    return parse_tokens([entry]), token


def _read_project_token_entries(path: str | Path) -> list[dict[str, str]]:
    """Read and validate the project-token JSON file; hashes never enter SQL storage."""
    token_path = Path(path)
    if token_path.is_symlink():
        raise ValueError(f"Refusing to read symlinked project token file: {token_path}")
    try:
        if token_path.stat().st_size > MAX_PROJECT_TOKEN_FILE_BYTES:
            raise ValueError(f"Project token file exceeds {MAX_PROJECT_TOKEN_FILE_BYTES} bytes")
        document = json.loads(token_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read project token file {token_path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError(f"Unsupported project token file format: {token_path}")
    entries = document.get("tokens")
    if not isinstance(entries, list) or len(entries) > MAX_PROJECT_TOKENS:
        raise ValueError(f"Invalid project token list in {token_path}")

    identifiers: set[str] = set()
    labels: set[str] = set()
    hashes: set[str] = set()
    validated: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"Invalid project token entry in {token_path}")
        token_id = entry.get("id")
        label = entry.get("label")
        project = entry.get("project")
        token_hash = entry.get("sha256")
        created_at = entry.get("created_at")
        if (
            not isinstance(token_id, str)
            or not token_id
            or len(token_id) > 64
            or not isinstance(label, str)
            or not 1 <= len(label) <= 64
            or not isinstance(project, str)
            or not 1 <= len(project) <= 200
            or not isinstance(token_hash, str)
            or len(token_hash) != 64
            or not isinstance(created_at, str)
            or len(created_at) > 64
        ):
            raise ValueError(f"Invalid project token entry in {token_path}")
        try:
            digest = bytes.fromhex(token_hash)
        except ValueError as exc:
            raise ValueError(f"Invalid project token hash in {token_path}") from exc
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError(f"Invalid project token hash in {token_path}")
        if token_id in identifiers or label in labels or token_hash in hashes:
            raise ValueError(f"Duplicate project token entry in {token_path}")
        identifiers.add(token_id)
        labels.add(label)
        hashes.add(token_hash)
        validated.append(
            {
                "id": token_id,
                "label": label,
                "project": project,
                "sha256": token_hash.lower(),
                "created_at": created_at,
            }
        )
    return validated


def load_project_tokens(path: str | Path | None) -> dict[bytes, TokenInfo]:
    """Load project-scoped reader tokens from their dedicated local file."""
    if not path:
        return {}
    tokens: dict[bytes, TokenInfo] = {}
    for entry in _read_project_token_entries(path):
        digest = bytes.fromhex(entry["sha256"])
        tokens[digest] = TokenInfo(
            entry["label"], Role.READER, project=entry["project"], token_id=entry["id"]
        )
    return tokens


def list_project_tokens(path: str | Path | None) -> list[dict[str, str]]:
    """Return project token metadata without exposing the stored hashes."""
    if not path:
        raise ValueError("SECREVIEW_AUTH_MANAGED_TOKENS_FILE must be configured")
    return [
        {key: entry[key] for key in ("id", "label", "project", "created_at")}
        for entry in _read_project_token_entries(path)
    ]


def create_project_token(
    path: str | Path | None,
    active_tokens: dict[bytes, TokenInfo],
    label: str,
    project: str,
) -> dict[str, str]:
    """Create a project-scoped reader token and persist only its digest in a local file."""
    if not path:
        raise ValueError("SECREVIEW_AUTH_MANAGED_TOKENS_FILE must be configured")
    label, project = label.strip(), project.strip()
    if not 1 <= len(label) <= 64:
        raise ValueError("Token label must contain between 1 and 64 characters")
    if not 1 <= len(project) <= 200:
        raise ValueError("Project must contain between 1 and 200 characters")

    with _managed_tokens_lock:
        entries = _read_project_token_entries(path)
        if len(entries) >= MAX_PROJECT_TOKENS:
            raise ValueError(f"The limit of {MAX_PROJECT_TOKENS} project tokens has been reached")
        if any(entry["label"] == label for entry in entries) or any(
            info.label == label for info in active_tokens.values()
        ):
            raise ValueError(f"A project token named '{label}' already exists")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        if digest in active_tokens:
            raise ValueError("Generated token collision; retry the request")
        entry = {
            "id": str(uuid.uuid4()),
            "label": label,
            "project": project,
            "sha256": digest.hex(),
            "created_at": datetime.now(UTC).isoformat(),
        }
        _write_project_token_entries(path, [*entries, entry])
        active_tokens[digest] = TokenInfo(label, Role.READER, project=project, token_id=entry["id"])
    return {key: entry[key] for key in ("id", "label", "project", "created_at")} | {"token": token}


def revoke_project_token(
    path: str | Path | None, active_tokens: dict[bytes, TokenInfo], token_id: str
) -> None:
    """Revoke a managed project token and remove it from the active middleware registry."""
    if not path:
        raise ValueError("SECREVIEW_AUTH_MANAGED_TOKENS_FILE must be configured")
    with _managed_tokens_lock:
        entries = _read_project_token_entries(path)
        kept = [entry for entry in entries if entry["id"] != token_id]
        if len(kept) == len(entries):
            raise ValueError(f"Project token '{token_id}' was not found")
        _write_project_token_entries(path, kept)
        for digest, info in list(active_tokens.items()):
            if info.token_id == token_id:
                del active_tokens[digest]


def _write_project_token_entries(path: str | Path, entries: list[dict[str, str]]) -> None:
    """Atomically write project token metadata with owner-only file permissions."""
    token_path = Path(path)
    if token_path.is_symlink():
        raise ValueError(f"Refusing to write symlinked project token file: {token_path}")
    token_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=token_path.parent, delete=False
        ) as stream:
            json.dump({"version": 1, "tokens": entries}, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            temporary_path = Path(stream.name)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, token_path)
    except OSError as exc:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
        raise ValueError(f"Cannot write project token file {token_path}: {exc}") from exc


# ── Middleware ───────────────────────────────────────────────────────────────


def is_public_path(path: str) -> bool:
    """Paths that expose only the web UI shell or API documentation without a token."""
    return path in ("/", UI_PREFIX, "/api/docs", "/api/openapi.json") or path.startswith(
        UI_PREFIX + "/"
    )


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
        if not tokens and not web:
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
        with _managed_tokens_lock:
            candidates = tuple(self.tokens.items())
        for digest, candidate in candidates:
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

        if self.web and not self.tokens:
            if path.startswith(API_PREFIX):
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
        state["auth_project"] = info.project
        state["auth_tokens"] = self.tokens
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
    return BearerAuthMiddleware(app, tokens, web=web_app is not None) if tokens or web_app else app


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
    elif exposed:
        logger.warning(
            "Listening on %s without TLS: set SECREVIEW_TLS_CERTFILE and SECREVIEW_TLS_KEYFILE, "
            "or terminate TLS on a reverse proxy.",
            host,
        )
    if web_app is not None:
        logger.info("Web interface enabled on /ui (REST API on /api/v1)")

    uvicorn.run(
        build_app(server, host, tokens, web_app),
        host=host,
        port=port,
        log_level=log_level.lower(),
        **(tls.uvicorn_kwargs() if tls else {}),
    )
