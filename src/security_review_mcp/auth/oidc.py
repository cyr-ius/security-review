"""OpenID Connect login to the web interface of the controller (opt-in).

When ``SECREVIEW_OIDC_ENABLED`` is set, the login page offers a button that signs the user in
with an identity provider (Keycloak, Entra ID, Okta, Authentik...) using the authorization code
flow with PKCE:

1. ``GET /api/v1/auth/oidc/login`` stores a random state, nonce and PKCE verifier in a signed,
   short-lived HttpOnly cookie and redirects the browser to the provider;
2. ``GET /api/v1/auth/oidc/callback`` checks the state, exchanges the code at the token endpoint
   (server to server), validates the ID token (signature from the provider JWKS, issuer,
   audience, expiry, nonce) and returns the identity it holds (OidcIdentity);
3. web_users.oidc_login finds the OIDC web user of that identity (or creates it when
   ``SECREVIEW_OIDC_AUTO_CREATE_USERS`` is set), records the values of its roles claim
   (see access_control) and issues a **session token**: a JWT signed with a key derived from
   ``SECREVIEW_SECRET_KEY``, valid ``SECREVIEW_SESSION_HOURS``, handed to the web application
   in the URL fragment of ``/ui/login``. The application sends it as a bearer token; the bearer
   middleware of the controller verifies it (see http_server.BearerAuthMiddleware) and reads the
   user again at each request. It never reaches the MCP server. The password login of the local
   web users issues the same session tokens.

This module stores nothing in the database: its settings are the ``SECREVIEW_OIDC_*`` variables,
or the web interface for those not set (see app_settings.effective_settings). The provider is
contacted only by the controller, over HTTPS (plain HTTP is accepted for a provider on the
loopback interface, for development), through the proxy of the controller (see proxy), with
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

from .. import __version__
from ..config import Settings, secret_value
from ..http_server import AUTH_PREFIX, LOOPBACK_HOSTS
from ..proxy import masked_url, proxy_handler

logger = logging.getLogger("security_review_mcp.oidc")

# Callback of the login flow, public on the controller (see http_server.is_controller_public_path)
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
MIN_SECRET_KEY_CHARS = 32
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


class OidcError(Exception):
    """A login that failed; ``code`` is the short reason shown by the web application."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ── Settings ─────────────────────────────────────────────────────────────────


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
    if "openid" not in settings.oidc_scope.split():
        raise ValueError("SECREVIEW_OIDC_SCOPE must include openid")
    if settings.oidc_cafile and not Path(settings.oidc_cafile).is_file():
        raise ValueError(f"SECREVIEW_OIDC_CAFILE: file not found: {settings.oidc_cafile}")
    if not settings.oidc_roles_claim.strip():
        raise ValueError("SECREVIEW_OIDC_ROLES_CLAIM is empty")
    if not 1 <= len(settings.oidc_display_name.strip()) <= MAX_DISPLAY_NAME_CHARS:
        raise ValueError(
            f"SECREVIEW_OIDC_DISPLAY_NAME must hold 1 to {MAX_DISPLAY_NAME_CHARS} characters"
        )


# ── Claims ─────────────────────────────────────────────────────────────


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


def user_label(claims: dict[str, Any], settings: Settings) -> str:
    """Label of the session in the logs and the triage history: ``oidc:<username>``."""
    name = claims.get(settings.oidc_username_claim) or claims.get("email") or claims["sub"]
    printable = "".join(c for c in str(name) if c.isprintable())
    return f"oidc:{printable}"[:MAX_LABEL_CHARS]


def account_name(claims: dict[str, Any], settings: Settings) -> str | None:
    """Name of the OIDC web user of a login: the raw username claim, or None.

    Unlike the label, there is no fallback to ``email`` or ``sub`` and nothing is stripped: a
    value with control or invisible characters would otherwise match the name of another user.
    """
    value = claims.get(settings.oidc_username_claim)
    if isinstance(value, str) and value and value.isprintable():
        return value
    return None


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


def validate_session_settings(settings: Settings) -> None:
    """Check SECREVIEW_SESSION_HOURS and SECREVIEW_SECRET_KEY; raise ValueError."""
    if not 1 <= settings.session_hours <= 24:
        raise ValueError("SECREVIEW_SESSION_HOURS must be between 1 and 24")
    secret = secret_value(settings.secret_key)
    if secret is not None and len(secret) < MIN_SECRET_KEY_CHARS:
        raise ValueError(
            f"SECREVIEW_SECRET_KEY must hold at least {MIN_SECRET_KEY_CHARS} characters"
        )


def session_signer(settings: Settings) -> SessionSigner:
    """Return the signer of the web sessions of the controller (password and OIDC logins).

    Without ``SECREVIEW_SECRET_KEY`` a random secret is drawn at each start: sessions then end
    when the controller restarts and are not shared between replicas.

    Raises:
        ValueError: If ``SECREVIEW_SESSION_HOURS`` or ``SECREVIEW_SECRET_KEY`` is invalid.
    """
    validate_session_settings(settings)
    secret = secret_value(settings.secret_key)
    if not secret:
        logger.warning(
            "SECREVIEW_SECRET_KEY is not set: a random session secret is used, web sessions "
            "end when the controller restarts and are not shared between replicas"
        )
    return SessionSigner(secret, settings.session_hours)


class SessionSigner:
    """Sign and verify the session tokens and the state cookies of the login flow.

    Two keys are derived from the secret, so that a state cookie can never be used as a session
    token. Without a configured secret a random one is generated: sessions then end when the
    controller restarts, and replicas must share ``SECREVIEW_SECRET_KEY``.
    """

    def __init__(self, secret: str | None, session_hours: int = 8) -> None:
        master = (secret or secrets.token_urlsafe(48)).encode("utf-8")
        self._session_key = hmac.new(master, b"secreview-oidc-session", hashlib.sha256).digest()
        self._state_key = hmac.new(master, b"secreview-oidc-state", hashlib.sha256).digest()
        self.session_seconds = session_hours * 3600

    def issue_session(
        self,
        label: str,
        projects: frozenset[str] | None,
        user_id: int,
        user_version: int,
    ) -> str:
        """Return a session token of a web user, with the projects it reads (None: all).

        ``user_id`` names the web user, whose current permissions are read from the database
        at each request (see web_users.session_identity); ``user_version`` is its session
        version, changed by a password change.
        """
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": SESSION_ISSUER,
            "aud": SESSION_AUDIENCE,
            "sub": label,
            "projects": None if projects is None else sorted(projects),
            "iat": now,
            "exp": now + self.session_seconds,
            "uid": user_id,
            "uver": user_version,
        }
        return jwt.encode(payload, self._session_key, algorithm="HS256")

    @staticmethod
    def owns(credentials: str) -> bool:
        """True when a bearer value looks like a JWT (database tokens contain no dot)."""
        return credentials.startswith("eyJ") and credentials.count(".") == 2

    def decode_session(self, credentials: str) -> dict[str, Any] | None:
        """Return the claims of a valid, unexpired session token, or None."""
        try:
            payload = jwt.decode(
                credentials,
                self._session_key,
                algorithms=["HS256"],
                audience=SESSION_AUDIENCE,
                issuer=SESSION_ISSUER,
                options={"require": ["exp", "iat", "sub", "uid", "uver"]},
            )
        except jwt.InvalidTokenError:
            return None
        for claim in ("uid", "uver"):
            value = payload[claim]
            if not isinstance(value, int) or isinstance(value, bool):
                return None
        if not isinstance(payload["sub"], str):
            return None
        return payload

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
class OidcIdentity:
    """The user of a verified login, and the page to open.

    ``username`` is the raw username claim (see account_name, None when missing), ``subject``
    the ``sub`` claim, ``issuer`` the provider that signed the ID token, ``groups`` the values
    of the groups or roles claim and ``label`` the name written in the logs.
    """

    username: str | None
    subject: str
    issuer: str
    groups: frozenset[str]
    label: str
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

    The discovery document and the JWKS are downloaded on first use and cached. ``signer`` is
    shared with the password login (see session_signer); a random one is used without it.
    """

    def __init__(self, settings: Settings, signer: SessionSigner | None = None) -> None:
        self.settings = settings
        self.issuer = settings.oidc_issuer.rstrip("/")
        self.display_name = settings.oidc_display_name.strip()
        self.signer = signer or SessionSigner(
            secret_value(settings.secret_key), settings.session_hours
        )
        # The state cookie is only sent back to the callback (path as seen by the browser)
        self.secure_cookie = settings.oidc_redirect_uri.startswith("https://")
        self.cookie_path = urllib.parse.urlsplit(settings.oidc_redirect_uri).path or "/"
        self._lock = threading.Lock()
        self._discovery: dict[str, Any] | None = None
        self._discovery_at = 0.0
        self._jwks: jwt.PyJWKSet | None = None
        self._jwks_at = 0.0
        context = ssl.create_default_context(cafile=settings.oidc_cafile)
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPSHandler(context=context),
            _HttpsRedirectOnly(),
            # The proxy of the controller (see proxy)
            proxy_handler(settings),
        ]
        self._opener = urllib.request.build_opener(*handlers)

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
            message = str(exc)
            if self.settings.proxy:
                # The error may name the proxy: never log its credentials
                message = message.replace(self.settings.proxy, masked_url(self.settings.proxy))
            logger.warning("Identity provider unreachable (%s): %s", _path_of(url), message)
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
            "scope": self.settings.oidc_scope,
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

    def finish(self, code: str, state: str, cookie: str | None) -> OidcIdentity:
        """Check the callback, exchange the code and return the user; raise OidcError."""
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
        return OidcIdentity(
            username=account_name(claims, self.settings),
            subject=claims["sub"],
            issuer=self.issuer,
            groups=frozenset(claim_values(claims, self.settings.oidc_roles_claim)),
            label=user_label(claims, self.settings),
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
        secret = secret_value(self.settings.oidc_client_secret)
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

    def check(self) -> list[dict[str, Any]]:
        """Test the provider without logging in: discovery document, then signing keys.

        Each step is ``{"name", "ok", "detail"}``; the test stops at the first failed step.
        """
        try:
            document = self.discovery()
        except OidcError as exc:
            return [{"name": "discovery", "ok": False, "detail": str(exc)}]
        steps = [
            {
                "name": "discovery",
                "ok": True,
                "detail": f"Issuer {self.issuer} publishes the authorization, token and JWKS "
                "endpoints",
            }
        ]
        try:
            keys = jwt.PyJWKSet.from_dict(self.fetch_json(document["jwks_uri"])).keys
        except OidcError as exc:
            steps.append({"name": "jwks", "ok": False, "detail": str(exc)})
        except jwt.PyJWTError:
            steps.append({"name": "jwks", "ok": False, "detail": "Invalid JWKS"})
        else:
            steps.append({"name": "jwks", "ok": True, "detail": f"{len(keys)} signing key(s)"})
        return steps


def _path_of(url: str) -> str:
    """Host and path of a URL, without its query string (for the logs)."""
    parts = urllib.parse.urlsplit(url)
    return f"{parts.hostname}{parts.path}"


def from_settings(settings: Settings, signer: SessionSigner | None = None) -> OidcLogin | None:
    """Return the configured login flow, or None when OIDC is disabled.

    ``signer`` signs the sessions (see session_signer, shared with the password login).

    Raises:
        ValueError: If a ``SECREVIEW_OIDC_*`` setting is invalid.
    """
    if not settings.oidc_enabled:
        return None
    validate_settings(settings)
    return OidcLogin(settings, signer)
