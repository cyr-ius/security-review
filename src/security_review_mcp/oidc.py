"""OpenID Connect login to the web interface of the controller (opt-in).

When ``SECREVIEW_OIDC_ENABLED`` is set, the login page offers a button that signs the user in
with an identity provider (Keycloak, Entra ID, Okta, Authentik...) using the authorization code
flow with PKCE:

1. ``GET /api/v1/auth/oidc/login`` stores a random state, nonce and PKCE verifier in a signed,
   short-lived HttpOnly cookie and redirects the browser to the provider;
2. ``GET /api/v1/auth/oidc/callback`` checks the state, exchanges the code at the token endpoint
   (server to server), validates the ID token (signature from the provider JWKS, issuer,
   audience, expiry, nonce) and maps its groups or roles claim to a web role;
3. the controller then issues a **session token**: a JWT signed with a key derived from
   ``SECREVIEW_OIDC_SESSION_SECRET``, valid ``SECREVIEW_OIDC_SESSION_HOURS``, handed to the web
   application in the URL fragment of ``/ui/login``. The application sends it as a bearer token,
   like a token of the database; the bearer middleware of the controller verifies it (see
   http_server.BearerAuthMiddleware). It never reaches the MCP server.

Nothing is stored in the database. The provider is contacted only by the controller, over HTTPS
(plain HTTP is accepted for a provider on the loopback interface, for development), with
bounded response sizes; tokens, codes and secrets are never logged.
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt

from . import __version__
from .config import Settings
from .http_server import AUTH_PREFIX, LOOPBACK_HOSTS, WEB_ROLES, Role, TokenInfo

logger = logging.getLogger("security_review_mcp.oidc")

# Paths of the login flow, public on the controller (see http_server.is_controller_public_path)
LOGIN_PATH = f"{AUTH_PREFIX}oidc/login"
CALLBACK_PATH = f"{AUTH_PREFIX}oidc/callback"
# Page of the web application that receives the session token or the error
UI_LOGIN_PATH = "/ui/login"

STATE_COOKIE = "secreview_oidc"
STATE_TTL_SECONDS = 600
HTTP_TIMEOUT = 10
MAX_RESPONSE_BYTES = 1024 * 1024
DISCOVERY_TTL_SECONDS = 3600
# Minimum delay between two JWKS downloads triggered by an unknown key id
JWKS_REFRESH_SECONDS = 30
CLOCK_LEEWAY_SECONDS = 60
MIN_SESSION_SECRET_CHARS = 32
MAX_LABEL_CHARS = 64
MAX_RETURN_URL_CHARS = 512
MAX_DISPLAY_NAME_CHARS = 40

SESSION_ISSUER = "security-review-controller"
SESSION_AUDIENCE = "secreview-web"
STATE_AUDIENCE = "secreview-oidc-state"
# Asymmetric algorithms accepted for ID tokens: never "none" nor a shared-secret algorithm
ID_TOKEN_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)
# Roles an identity provider may grant; "mcp" is reserved to the tokens of the MCP server
DEFAULT_ROLES = ("", Role.READER.value, Role.TRIAGER.value)


class OidcError(Exception):
    """A login that failed; ``code`` is the short reason shown by the web application."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ── Settings ─────────────────────────────────────────────────────────────────


def _split(value: str) -> frozenset[str]:
    """Parse a comma-separated list of groups or roles."""
    return frozenset(item.strip() for item in value.split(",") if item.strip())


def _check_url(name: str, value: str) -> urllib.parse.SplitResult:
    """Accept an https URL, or an http URL on the loopback interface (development)."""
    url = urllib.parse.urlsplit(value)
    secure = url.scheme == "https" or (url.scheme == "http" and url.hostname in LOOPBACK_HOSTS)
    if not secure or not url.hostname:
        raise ValueError(f"{name} must be an https:// URL (http:// only on localhost)")
    if url.username or url.password:
        raise ValueError(f"{name} must not contain credentials")
    return url


def validate_settings(settings: Settings) -> None:
    """Check the OIDC settings; raise ValueError with the name of the wrong variable."""
    if not settings.oidc_issuer:
        raise ValueError("SECREVIEW_OIDC_ISSUER is required with SECREVIEW_OIDC_ENABLED")
    _check_url("SECREVIEW_OIDC_ISSUER", settings.oidc_issuer)
    if not settings.oidc_client_id:
        raise ValueError("SECREVIEW_OIDC_CLIENT_ID is required with SECREVIEW_OIDC_ENABLED")
    if not settings.oidc_redirect_uri:
        raise ValueError(
            "SECREVIEW_OIDC_REDIRECT_URI is required with SECREVIEW_OIDC_ENABLED, for example "
            f"https://secreview.example.com{CALLBACK_PATH}"
        )
    _check_url("SECREVIEW_OIDC_REDIRECT_URI", settings.oidc_redirect_uri)
    if "openid" not in settings.oidc_scopes.split():
        raise ValueError("SECREVIEW_OIDC_SCOPES must include openid")
    if settings.oidc_default_role not in DEFAULT_ROLES:
        raise ValueError("SECREVIEW_OIDC_DEFAULT_ROLE must be empty, reader or triager")
    if not 1 <= settings.oidc_session_hours <= 24:
        raise ValueError("SECREVIEW_OIDC_SESSION_HOURS must be between 1 and 24")
    secret = settings.oidc_session_secret
    if secret is not None and len(secret) < MIN_SESSION_SECRET_CHARS:
        raise ValueError(
            "SECREVIEW_OIDC_SESSION_SECRET must hold at least "
            f"{MIN_SESSION_SECRET_CHARS} characters"
        )
    if settings.oidc_cafile and not Path(settings.oidc_cafile).is_file():
        raise ValueError(f"SECREVIEW_OIDC_CAFILE: file not found: {settings.oidc_cafile}")
    if not settings.oidc_roles_claim.strip():
        raise ValueError("SECREVIEW_OIDC_ROLES_CLAIM is empty")
    if not 1 <= len(settings.oidc_display_name.strip()) <= MAX_DISPLAY_NAME_CHARS:
        raise ValueError(
            f"SECREVIEW_OIDC_DISPLAY_NAME must hold 1 to {MAX_DISPLAY_NAME_CHARS} characters"
        )


# ── Role mapping ─────────────────────────────────────────────────────────────


def claim_values(claims: dict[str, Any], path: str) -> set[str]:
    """Return the values of a claim; ``path`` may be dotted (``realm_access.roles``, Keycloak).

    A list gives its strings, a string gives itself (or its space/comma-separated parts).
    """
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return set()
        value = value.get(part)
    if isinstance(value, str):
        return {item for item in value.replace(",", " ").split() if item}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def role_from_claims(claims: dict[str, Any], settings: Settings) -> Role | None:
    """Return the highest web role granted by the groups or roles of the user, or None."""
    values = claim_values(claims, settings.oidc_roles_claim)
    for role, groups in (
        (Role.ADMIN, settings.oidc_admin_groups),
        (Role.TRIAGER, settings.oidc_triager_groups),
        (Role.READER, settings.oidc_reader_groups),
    ):
        if values & _split(groups):
            return role
    return Role(settings.oidc_default_role) if settings.oidc_default_role else None


def user_label(claims: dict[str, Any], settings: Settings) -> str:
    """Label of the session in the logs and the triage history: ``oidc:<username>``."""
    name = claims.get(settings.oidc_username_claim) or claims.get("email") or claims["sub"]
    printable = "".join(c for c in str(name) if c.isprintable())
    return f"oidc:{printable}"[:MAX_LABEL_CHARS]


def safe_return_url(value: str | None) -> str:
    """Keep only a local path of the web application (no open redirect)."""
    if (
        not value
        or len(value) > MAX_RETURN_URL_CHARS
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or not value.isprintable()
    ):
        return "/"
    return value


# ── Signed tokens issued by the controller ───────────────────────────────────


def _b64url(data: bytes) -> str:
    """Base64url without padding (PKCE)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def same_value(left: object, right: str) -> bool:
    """Constant-time comparison of two values as UTF-8 bytes (any text, never TypeError)."""
    return hmac.compare_digest(str(left).encode("utf-8"), right.encode("utf-8"))


def pkce_challenge(verifier: str) -> str:
    """S256 code challenge of a PKCE verifier (RFC 7636)."""
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


class SessionSigner:
    """Sign and verify the session tokens and the state cookies of the login flow.

    Two keys are derived from the secret, so that a state cookie can never be used as a session
    token. Without a configured secret a random one is generated: sessions then end when the
    controller restarts, and replicas must share ``SECREVIEW_OIDC_SESSION_SECRET``.
    """

    def __init__(self, secret: str | None, session_hours: int = 8) -> None:
        master = (secret or secrets.token_urlsafe(48)).encode("utf-8")
        self._session_key = hmac.new(master, b"secreview-oidc-session", hashlib.sha256).digest()
        self._state_key = hmac.new(master, b"secreview-oidc-state", hashlib.sha256).digest()
        self.session_seconds = session_hours * 3600

    def issue_session(self, label: str, role: Role) -> str:
        """Return a session token for a web role."""
        if role not in WEB_ROLES:
            raise ValueError(f"Role '{role}' cannot use the web interface")
        now = int(time.time())
        payload = {
            "iss": SESSION_ISSUER,
            "aud": SESSION_AUDIENCE,
            "sub": label,
            "role": role.value,
            "iat": now,
            "exp": now + self.session_seconds,
        }
        return jwt.encode(payload, self._session_key, algorithm="HS256")

    @staticmethod
    def owns(credentials: str) -> bool:
        """True when a bearer value looks like a JWT (database tokens contain no dot)."""
        return credentials.startswith("eyJ") and credentials.count(".") == 2

    def verify_session(self, credentials: str) -> TokenInfo | None:
        """Return the identity of a valid, unexpired session token, or None."""
        try:
            payload = jwt.decode(
                credentials,
                self._session_key,
                algorithms=["HS256"],
                audience=SESSION_AUDIENCE,
                issuer=SESSION_ISSUER,
                options={"require": ["exp", "iat", "sub"]},
            )
            role = Role(payload.get("role"))
        except jwt.InvalidTokenError, ValueError:
            return None
        if role not in WEB_ROLES or not isinstance(payload["sub"], str):
            return None
        return TokenInfo(label=payload["sub"][:MAX_LABEL_CHARS], role=role)

    def sign_state(self, data: dict[str, str]) -> str:
        """Return the signed state cookie of a login in progress."""
        now = int(time.time())
        payload = {"aud": STATE_AUDIENCE, "iat": now, "exp": now + STATE_TTL_SECONDS, **data}
        return jwt.encode(payload, self._state_key, algorithm="HS256")

    def read_state(self, cookie: str | None) -> dict[str, Any]:
        """Return the content of a valid state cookie; raise OidcError otherwise."""
        if not cookie:
            raise OidcError("state", "Login state cookie missing (expired or blocked)")
        try:
            return jwt.decode(
                cookie,
                self._state_key,
                algorithms=["HS256"],
                audience=STATE_AUDIENCE,
                options={"require": ["exp"]},
            )
        except jwt.InvalidTokenError as exc:
            raise OidcError("state", "Invalid or expired login state") from exc


# ── Identity provider ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LoginRequest:
    """Where to send the browser and the state cookie to set."""

    authorization_url: str
    state_cookie: str


@dataclass(frozen=True)
class LoginResult:
    """A successful login: the session token and the page to open."""

    session_token: str
    label: str
    role: Role
    return_url: str


class _HttpsRedirectOnly(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect to another scheme than HTTPS."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        """Refuse a redirect to plain HTTP, file, ftp..."""
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise urllib.error.HTTPError(
                req.full_url, code, "redirect to a non-HTTPS URL refused", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class OidcLogin:
    """The login flow with one identity provider, configured by the ``SECREVIEW_OIDC_*``
    settings (validated by validate_settings).

    The discovery document and the JWKS are downloaded on first use and cached.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.issuer = settings.oidc_issuer.rstrip("/")
        self.display_name = settings.oidc_display_name.strip()
        self.signer = SessionSigner(settings.oidc_session_secret, settings.oidc_session_hours)
        # The state cookie is only sent back to the callback (path as seen by the browser)
        self.secure_cookie = settings.oidc_redirect_uri.startswith("https://")
        self.cookie_path = urllib.parse.urlsplit(settings.oidc_redirect_uri).path or "/"
        self._lock = threading.Lock()
        self._discovery: dict[str, Any] | None = None
        self._discovery_at = 0.0
        self._jwks: jwt.PyJWKSet | None = None
        self._jwks_at = 0.0
        context = ssl.create_default_context(cafile=settings.oidc_cafile)
        # Without an explicit ProxyHandler, urllib applies HTTPS_PROXY and NO_PROXY
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), _HttpsRedirectOnly()
        )

    # HTTP

    def fetch_json(
        self, url: str, data: dict[str, str] | None = None, headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """GET (or POST a form to) ``url`` and return its JSON object; raise OidcError."""
        body = urllib.parse.urlencode(data).encode("ascii") if data is not None else None
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Accept": "application/json",
                "User-Agent": f"security-review-mcp/{__version__}",
                **(headers or {}),
            },
        )
        try:
            with self._opener.open(request, timeout=HTTP_TIMEOUT) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            # The body of an error may echo the request: only its status is logged
            logger.warning("Identity provider answered HTTP %s for %s", exc.code, _path_of(url))
            raise OidcError("provider", f"Identity provider error (HTTP {exc.code})") from None
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("Identity provider unreachable (%s): %s", _path_of(url), exc)
            raise OidcError("provider", "Identity provider unreachable") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise OidcError("provider", "Identity provider response too large")
        try:
            document = json.loads(raw)
        except ValueError:
            raise OidcError("provider", "Identity provider sent invalid JSON") from None
        if not isinstance(document, dict):
            raise OidcError("provider", "Identity provider sent an unexpected document")
        return document

    def discovery(self) -> dict[str, Any]:
        """Return the provider metadata (``/.well-known/openid-configuration``), cached."""
        with self._lock:
            if self._discovery and time.monotonic() - self._discovery_at < DISCOVERY_TTL_SECONDS:
                return self._discovery
        document = self.fetch_json(f"{self.issuer}/.well-known/openid-configuration")
        if str(document.get("issuer", "")).rstrip("/") != self.issuer:
            raise OidcError("provider", "Discovery document of another issuer")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = document.get(key)
            if not isinstance(value, str):
                raise OidcError("provider", f"Discovery document without {key}")
            _check_url(key, value)
        with self._lock:
            self._discovery, self._discovery_at = document, time.monotonic()
        return document

    def signing_key(self, kid: str | None) -> jwt.PyJWK:
        """Return the provider key with this id, downloading the JWKS again for a new id."""
        for attempt in range(2):
            with self._lock:
                keys = self._jwks
                stale = time.monotonic() - self._jwks_at >= JWKS_REFRESH_SECONDS
            if keys is None or (attempt and stale):
                document = self.fetch_json(self.discovery()["jwks_uri"])
                try:
                    keys = jwt.PyJWKSet.from_dict(document)
                except jwt.PyJWTError:
                    raise OidcError("provider", "Invalid JWKS") from None
                with self._lock:
                    self._jwks, self._jwks_at = keys, time.monotonic()
            candidates = [key for key in keys.keys if kid is None or key.key_id == kid]
            if kid is None and len(candidates) == 1 or kid is not None and candidates:
                return candidates[0]
        raise OidcError("token", "ID token signed with an unknown key")

    # Flow

    def start(self, return_url: str | None) -> LoginRequest:
        """Build the authorization request (code flow with PKCE S256)."""
        endpoint = self.discovery()["authorization_endpoint"]
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        params = {
            "response_type": "code",
            "client_id": self.settings.oidc_client_id,
            "redirect_uri": self.settings.oidc_redirect_uri,
            "scope": self.settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        separator = "&" if urllib.parse.urlsplit(endpoint).query else "?"
        cookie = self.signer.sign_state(
            {
                "state": state,
                "nonce": nonce,
                "verifier": verifier,
                "return_url": safe_return_url(return_url),
            }
        )
        return LoginRequest(endpoint + separator + urllib.parse.urlencode(params), cookie)

    def finish(self, code: str, state: str, cookie: str | None) -> LoginResult:
        """Check the callback, exchange the code and return a session; raise OidcError."""
        saved = self.signer.read_state(cookie)
        if not same_value(saved.get("state", ""), state):
            raise OidcError("state", "Login state mismatch")
        tokens = self.exchange(code, str(saved["verifier"]))
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str):
            raise OidcError("token", "Token response without an ID token")
        claims = self.validate_id_token(id_token, str(saved["nonce"]))
        if not claim_values(claims, self.settings.oidc_roles_claim):
            claims = {**self.userinfo(tokens.get("access_token"), claims["sub"]), **claims}
        role = role_from_claims(claims, self.settings)
        label = user_label(claims, self.settings)
        if role is None:
            logger.warning("OIDC login refused for %s: no web role in its groups", label)
            raise OidcError("forbidden", "No web role granted to this user")
        logger.info("OIDC login of %s with role %s", label, role)
        return LoginResult(
            session_token=self.signer.issue_session(label, role),
            label=label,
            role=role,
            return_url=safe_return_url(saved.get("return_url")),
        )

    def exchange(self, code: str, verifier: str) -> dict[str, Any]:
        """Exchange the authorization code at the token endpoint (client secret if any)."""
        discovery = self.discovery()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.settings.oidc_redirect_uri,
            "code_verifier": verifier,
            "client_id": self.settings.oidc_client_id,
        }
        headers: dict[str, str] = {}
        secret = self.settings.oidc_client_secret
        if secret:
            methods = discovery.get("token_endpoint_auth_methods_supported") or [
                "client_secret_basic"
            ]
            if "client_secret_basic" in methods:
                credentials = ":".join(
                    urllib.parse.quote(value, safe="")
                    for value in (self.settings.oidc_client_id, secret)
                )
                encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {encoded}"
            else:
                data["client_secret"] = secret
        return self.fetch_json(discovery["token_endpoint"], data=data, headers=headers)

    def validate_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        """Verify the signature and the claims of an ID token (OIDC Core 3.1.3.7)."""
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.InvalidTokenError:
            raise OidcError("token", "Malformed ID token") from None
        algorithm = header.get("alg")
        supported = self.discovery().get("id_token_signing_alg_values_supported") or ["RS256"]
        if algorithm not in ID_TOKEN_ALGORITHMS or algorithm not in supported:
            raise OidcError("token", f"ID token algorithm not accepted: {algorithm}")
        key = self.signing_key(header.get("kid"))
        try:
            claims = jwt.decode(
                id_token,
                key,
                algorithms=[algorithm],
                audience=self.settings.oidc_client_id,
                issuer=self.discovery()["issuer"],
                leeway=CLOCK_LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.InvalidTokenError as exc:
            raise OidcError("token", f"Invalid ID token: {exc}") from None
        audience = claims["aud"]
        if isinstance(audience, list) and len(audience) > 1:
            if claims.get("azp") != self.settings.oidc_client_id:
                raise OidcError("token", "ID token issued to another party (azp)")
        if not same_value(claims.get("nonce", ""), nonce):
            raise OidcError("token", "ID token nonce mismatch")
        if not isinstance(claims["sub"], str) or not claims["sub"]:
            raise OidcError("token", "ID token without a subject")
        return claims

    def userinfo(self, access_token: Any, subject: str) -> dict[str, Any]:
        """Claims of the userinfo endpoint (groups missing from the ID token), if available."""
        endpoint = self.discovery().get("userinfo_endpoint")
        if not isinstance(endpoint, str) or not isinstance(access_token, str):
            return {}
        _check_url("userinfo_endpoint", endpoint)
        claims = self.fetch_json(endpoint, headers={"Authorization": f"Bearer {access_token}"})
        # OIDC Core 5.3.2: the userinfo response must be about the same user
        if claims.get("sub") != subject:
            raise OidcError("token", "Userinfo response about another subject")
        return claims


def _path_of(url: str) -> str:
    """Host and path of a URL, without its query string (for the logs)."""
    parts = urllib.parse.urlsplit(url)
    return f"{parts.hostname}{parts.path}"


def from_settings(settings: Settings) -> OidcLogin | None:
    """Return the configured login flow, or None when OIDC is disabled.

    Raises:
        ValueError: If a ``SECREVIEW_OIDC_*`` setting is invalid.
    """
    if not settings.oidc_enabled:
        return None
    validate_settings(settings)
    if not settings.oidc_session_secret:
        logger.warning(
            "SECREVIEW_OIDC_SESSION_SECRET is not set: web sessions end when the controller "
            "restarts and are not shared between replicas"
        )
    return OidcLogin(settings)
