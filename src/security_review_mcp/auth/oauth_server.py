"""OAuth 2.1 authorization server of the controller for the MCP clients (opt-in).

When ``SECREVIEW_MCP_OAUTH_ENABLED`` is set, an MCP client (Claude Code, VS Code...) needs no
token in its configuration: the MCP server answers its first request with a 401 that points
to its protected resource metadata (RFC 9728, see http_server), which names the controller as
authorization server. The client then:

1. registers itself at ``/register`` (dynamic registration, RFC 7591). Every client is a
   **public** client: the requested secret-based method is replaced by ``none`` and no secret is
   issued nor kept, since anyone may register; PKCE protects the code. Only its redirect URIs
   that point to the loopback interface, to a host of SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS (https)
   or use a scheme of SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES are kept, at least one (see
   check_redirect_uri);
2. opens ``/authorize`` in the browser of the user: the request is stored (OAuthAuthorization,
   digest of a random handle) and the browser goes to the consent screen of the web interface
   (``/ui/oauth/authorize``), behind the usual login (password or OIDC);
3. the web user approves (or denies) the client there (approve and deny below, a web session
   only, never a bearer token): the browser goes back to the client with a single-use code;
4. exchanges the code with its PKCE verifier at ``/token`` for an access token and a refresh
   token (OAuthGrant, SHA-256 digests only), bound to SECREVIEW_MCP_URL (RFC 8707).

The routes are those of the MCP SDK (``mcp.server.auth``: request validation, PKCE check,
answers), served by the controller at the root of its URL, the issuer; this module is their
provider and stores everything in the database, so that every replica sees the same state.

An access token acts as a personal ``mcp`` token of the user who approved the client (see
token_store.DatabaseTokenStore.lookup): the projects the user may read now, the MCP server
only, never the routes of the controller. Each refresh replaces both tokens; a replaced refresh
token presented again revokes the grant (it may have been stolen). The user sees and revokes
its grants in My account; deleting the user deletes them.

Every registration, decision and revocation is written to the audit log. The MCP server never
imports this module.
"""

import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import anyio.to_thread
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    IdentityAssertionParams,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.shared.auth_utils import check_resource_allowed
from pydantic import AnyUrl
from sqlalchemy import delete, update
from sqlmodel import Session, col, func, or_, select

from .. import app_settings
from ..config import Settings, get_settings, redirect_hosts, redirect_schemes
from ..observability import audit
from ..observability.audit import AuditAction
from ..reports.services import NotFoundError
from ..storage.database import session_scope
from ..storage.models import (
    OAuthAuthorization,
    OAuthClient,
    OAuthGrant,
    WebUser,
    as_utc,
    utcnow,
)

logger = logging.getLogger("security_review_mcp.oauth")

# The only scope: the tools, prompts and resources of the MCP server
SCOPE = "mcp"
# Consent screen of the web interface, given the request handle
CONSENT_PATH = "/ui/oauth/authorize"
# Time to log in and approve a request, then to exchange its code
REQUEST_TTL = timedelta(minutes=10)
CODE_TTL = timedelta(seconds=60)
# A client nobody approved within this time is deleted at the next registration
UNAPPROVED_CLIENT_TTL = timedelta(days=1)
# Pending requests at once (/authorize is public): beyond, a request is refused until some expire
MAX_PENDING_REQUESTS = 10_000
# Grants a user holds at once: the oldest is revoked beyond
MAX_GRANTS_PER_USER = 20
MAX_REDIRECT_URIS = 10
MAX_REDIRECT_URI_CHARS = 2000
MAX_CLIENT_NAME_CHARS = 200
MAX_METADATA_CHARS = 8000
MAX_RESOURCE_CHARS = 500
MAX_STATE_CHARS = 500
LOOPBACK = ("localhost", "127.0.0.1", "::1")
# Writes of the last use of a grant are spaced by this much (one per request would be a write
# per MCP call)
LAST_USED_RESOLUTION = timedelta(minutes=5)


def digest(value: str) -> str:
    """Stored form of a handle, code or token: its SHA-256 digest (hex)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def check_redirect_uri(uri: str, hosts: list[str], schemes: list[str]) -> None:
    """Accept a redirect URI of a client: http or https on the loopback interface (RFC 8252),
    https on a host of SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS, or a custom scheme of
    SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES; never credentials nor a fragment. Any other https site
    is refused: a link to /authorize would otherwise send the code of a user to an attacker.

    Raises:
        ValueError: If the URI is not accepted.
    """
    if len(uri) > MAX_REDIRECT_URI_CHARS or not uri.isprintable():
        raise ValueError("The redirect URI is too long or not printable")
    parts = urlsplit(uri)
    scheme = parts.scheme.lower()
    if parts.fragment or parts.username or parts.password:
        raise ValueError("The redirect URI must not hold a fragment nor credentials")
    if scheme in ("http", "https") and parts.hostname in LOOPBACK:
        return
    if scheme == "https" and parts.hostname in hosts:
        return
    if scheme in schemes:
        return
    raise ValueError(
        f"Redirect URI not allowed: {uri[:100]} (loopback, or SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS "
        "and SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES)"
    )


def _expires_at(when: datetime) -> int:
    """Unix time of a stored date."""
    return int(as_utc(when).timestamp())


def _client_info(row: OAuthClient) -> OAuthClientInformationFull:
    """Registered metadata of a client."""
    return OAuthClientInformationFull.model_validate_json(row.client_metadata)


def _user_ok(session: Session, user_id: int | None) -> WebUser | None:
    """The web user of a grant or code, None when deleted or bound to change its password."""
    user = session.get(WebUser, user_id) if user_id is not None else None
    return None if user is None or user.must_change_password else user


def _new_tokens(settings: Settings, now: datetime) -> tuple[str, str, datetime, datetime]:
    """A new access token and refresh token with their expiry dates.

    The refresh token lives SECREVIEW_MCP_OAUTH_REFRESH_DAYS, at most SECREVIEW_TOKEN_MAX_DAYS
    when that is set.
    """
    days = settings.mcp_oauth_refresh_days
    if settings.token_max_days:
        days = min(days, settings.token_max_days)
    return (
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        now + timedelta(minutes=settings.mcp_oauth_access_minutes),
        now + timedelta(days=days),
    )


def _token_answer(settings: Settings, access: str, refresh: str) -> OAuthToken:
    """Answer of the token endpoint."""
    return OAuthToken(
        access_token=access,
        expires_in=settings.mcp_oauth_access_minutes * 60,
        refresh_token=refresh,
        scope=SCOPE,
    )


def _grant_details(session: Session, grant: OAuthGrant) -> dict[str, Any]:
    """Audit details of a grant: its client and its user (never a token)."""
    client = session.get(OAuthClient, grant.client_id)
    user = session.get(WebUser, grant.user_id)
    return {
        "client_id": grant.client_id,
        "client_name": client.client_name if client else None,
        "user": user.username if user else None,
    }


def _revoke(session: Session, grant: OAuthGrant, action: AuditAction, actor: str | None) -> None:
    """Delete a grant and record it in the audit log."""
    audit.record(
        session, action, actor, "oauth_grant", grant.id, details=_grant_details(session, grant)
    )
    session.delete(grant)


class OAuthProvider:
    """Provider of the OAuth routes of the MCP SDK (OAuthAuthorizationServerProvider), backed
    by the database. Each method runs its queries in a thread."""

    def __init__(self, issuer: str, settings: Settings | None = None) -> None:
        self.issuer = issuer.rstrip("/")
        self.settings = settings or get_settings()

    # ── Clients ─────────────────────────────────────────────────────────────

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Return a registered client, or None."""
        return await anyio.to_thread.run_sync(self._get_client, client_id)

    def _get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if len(client_id) > 64:
            return None
        with session_scope() as session:
            row = session.get(OAuthClient, client_id)
            return _client_info(row) if row is not None else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Store a new client as a public client with the ``mcp`` scope.

        The SDK answers with ``client_info`` once stored: the replaced values (no secret,
        ``none`` method, scope, grant types) reach the client.
        """
        hosts = redirect_hosts(self.settings.mcp_oauth_redirect_hosts)
        schemes = redirect_schemes(self.settings.mcp_oauth_redirect_schemes)
        uris = list(client_info.redirect_uris or [])
        if not uris or len(uris) > MAX_REDIRECT_URIS:
            raise RegistrationError(
                "invalid_redirect_uri", f"Give between 1 and {MAX_REDIRECT_URIS} redirect URIs"
            )
        # A refused URI is dropped, not the client: VS Code also lists https://vscode.dev/redirect
        # next to its loopback URI. Only the accepted ones are stored, so /authorize refuses the
        # others.
        accepted = []
        refused: ValueError | None = None
        for uri in uris:
            try:
                check_redirect_uri(str(uri), hosts, schemes)
            except ValueError as exc:
                refused = exc
            else:
                accepted.append(uri)
        if not accepted:
            raise RegistrationError("invalid_redirect_uri", str(refused)) from refused
        client_info.redirect_uris = accepted
        client_info.client_secret = None
        client_info.client_secret_expires_at = None
        client_info.token_endpoint_auth_method = "none"
        client_info.scope = SCOPE
        client_info.grant_types = ["authorization_code", "refresh_token"]
        if client_info.client_name:
            client_info.client_name = client_info.client_name[:MAX_CLIENT_NAME_CHARS]
        stored = client_info.model_dump_json(exclude_none=True)
        if len(stored) > MAX_METADATA_CHARS:
            raise RegistrationError("invalid_client_metadata", "The client metadata is too large")
        await anyio.to_thread.run_sync(self._store_client, client_info, stored)

    def _store_client(self, client_info: OAuthClientInformationFull, stored: str) -> None:
        with session_scope() as session:
            _purge_unapproved_clients(session)
            count = session.exec(select(func.count()).select_from(OAuthClient)).one()
            if count >= self.settings.mcp_oauth_max_clients:
                logger.warning("OAuth registration refused: too many clients")
                raise RegistrationError(
                    "invalid_client_metadata", "Too many registered clients, retry later"
                )
            session.add(
                OAuthClient(
                    client_id=client_info.client_id,
                    client_name=client_info.client_name,
                    client_metadata=stored,
                )
            )
            audit.record(
                session,
                AuditAction.OAUTH_CLIENT_REGISTERED,
                audit.ANONYMOUS_ACTOR,
                "oauth_client",
                client_info.client_id,
                details={"client_name": client_info.client_name},
            )

    # ── Authorization ───────────────────────────────────────────────────────

    def _check_resource(self, resource: str | None) -> None:
        """A requested resource must be the MCP endpoint (or below it).

        Raises:
            ValueError: If it is another resource.
        """
        target = self.settings.mcp_url
        if resource is None or target is None:
            return
        if len(resource) > MAX_RESOURCE_CHARS or not check_resource_allowed(resource, target):
            raise ValueError(f"Unknown resource; tokens are issued for {target}")

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Store the request and send the browser to the consent screen."""
        try:
            self._check_resource(params.resource)
        except ValueError as exc:
            raise AuthorizeError("invalid_target", str(exc)) from exc
        if params.state is not None and len(params.state) > MAX_STATE_CHARS:
            raise AuthorizeError("invalid_request", "The state is too long")
        if len(params.code_challenge) > 128:
            raise AuthorizeError("invalid_request", "The code challenge is too long")
        handle = secrets.token_urlsafe(32)
        row = OAuthAuthorization(
            id=digest(handle),
            client_id=client.client_id,
            redirect_uri=str(params.redirect_uri),
            redirect_uri_explicit=params.redirect_uri_provided_explicitly,
            code_challenge=params.code_challenge,
            state=params.state,
            resource=params.resource,
            expires_at=utcnow() + REQUEST_TTL,
        )
        await anyio.to_thread.run_sync(_store_request, row)
        return f"{self.issuer}{CONSENT_PATH}?request={handle}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Return an unexpired code of this client, or None."""
        return await anyio.to_thread.run_sync(self._load_code, client.client_id, authorization_code)

    def _load_code(self, client_id: str, code: str) -> AuthorizationCode | None:
        with session_scope() as session:
            row = session.exec(
                select(OAuthAuthorization).where(OAuthAuthorization.code_hash == digest(code))
            ).first()
            if row is None or row.client_id != client_id or row.user_id is None:
                return None
            return AuthorizationCode(
                code=code,
                scopes=[SCOPE],
                expires_at=as_utc(row.expires_at).timestamp(),
                client_id=row.client_id,
                code_challenge=row.code_challenge,
                redirect_uri=AnyUrl(row.redirect_uri),
                redirect_uri_provided_explicitly=row.redirect_uri_explicit,
                resource=row.resource,
                subject=str(row.user_id),
            )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Use the code once (deleted first, so a concurrent exchange fails) and issue tokens."""
        return await anyio.to_thread.run_sync(self._exchange_code, authorization_code)

    def _exchange_code(self, code: AuthorizationCode) -> OAuthToken:
        settings = self.settings
        now = utcnow()
        with session_scope() as session:
            deleted = session.execute(
                delete(OAuthAuthorization).where(
                    col(OAuthAuthorization.code_hash) == digest(code.code),
                    col(OAuthAuthorization.expires_at) > now,
                )
            )
            user = _user_ok(session, int(code.subject)) if code.subject else None
            if deleted.rowcount != 1 or user is None:
                raise TokenError("invalid_grant", "authorization code does not exist")
            access, refresh, access_expiry, refresh_expiry = _new_tokens(settings, now)
            session.add(
                OAuthGrant(
                    id=str(uuid.uuid4()),
                    client_id=code.client_id,
                    user_id=user.id,  # type: ignore[arg-type]
                    access_token_hash=digest(access),
                    access_expires_at=access_expiry,
                    refresh_token_hash=digest(refresh),
                    refresh_expires_at=refresh_expiry,
                    resource=code.resource or settings.mcp_url,
                )
            )
            session.flush()
            _limit_grants(session, user.id)  # type: ignore[arg-type]
        return _token_answer(settings, access, refresh)

    # ── Refresh and revocation ──────────────────────────────────────────────

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        """Return the refresh token of a grant of this client, or None. A replaced refresh
        token revokes its grant."""
        return await anyio.to_thread.run_sync(self._load_refresh, client.client_id, refresh_token)

    def _load_refresh(self, client_id: str, token: str) -> RefreshToken | None:
        hashed = digest(token)
        with session_scope() as session:
            grant = session.exec(
                select(OAuthGrant).where(
                    or_(
                        OAuthGrant.refresh_token_hash == hashed,
                        OAuthGrant.previous_refresh_hash == hashed,
                    )
                )
            ).first()
            if grant is None or grant.client_id != client_id:
                return None
            if not hmac.compare_digest(grant.refresh_token_hash, hashed):
                logger.warning("Replaced OAuth refresh token reused: grant %s revoked", grant.id)
                _revoke(session, grant, AuditAction.OAUTH_REFRESH_REUSED, audit.ANONYMOUS_ACTOR)
                return None
            # Issued for another URL of the MCP endpoint: the client logs in again
            if _user_ok(session, grant.user_id) is None or not app_settings.mcp_oauth_accepts(
                session, grant.resource
            ):
                return None
            return RefreshToken(
                token=token,
                client_id=grant.client_id,
                scopes=[SCOPE],
                expires_at=_expires_at(grant.refresh_expires_at),
                resource=grant.resource,
                subject=str(grant.user_id),
            )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        """Replace both tokens of the grant (the old refresh token is kept to detect a reuse)."""
        return await anyio.to_thread.run_sync(self._rotate, refresh_token.token)

    def _rotate(self, token: str) -> OAuthToken:
        settings = self.settings
        hashed = digest(token)
        access, refresh, access_expiry, refresh_expiry = _new_tokens(settings, utcnow())
        with session_scope() as session:
            grant = session.exec(
                select(OAuthGrant).where(OAuthGrant.refresh_token_hash == hashed)
            ).first()
            if grant is None:
                raise TokenError("invalid_grant", "refresh token does not exist")
            if settings.token_max_days:
                # SECREVIEW_TOKEN_MAX_DAYS bounds the whole grant, not each refresh: a client in
                # use logs in again once it is over
                end = as_utc(grant.created_at) + timedelta(days=settings.token_max_days)
                refresh_expiry = min(refresh_expiry, end)
                access_expiry = min(access_expiry, end)
            # Conditional on the current refresh token: of two concurrent refreshes, one wins
            changed = session.execute(
                update(OAuthGrant)
                .where(col(OAuthGrant.refresh_token_hash) == hashed)
                .values(
                    access_token_hash=digest(access),
                    access_expires_at=access_expiry,
                    refresh_token_hash=digest(refresh),
                    refresh_expires_at=refresh_expiry,
                    previous_refresh_hash=hashed,
                )
            )
            if changed.rowcount != 1:
                raise TokenError("invalid_grant", "refresh token does not exist")
        return _token_answer(settings, access, refresh)

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Return an unexpired access token (the MCP server checks them in token_store)."""
        return await anyio.to_thread.run_sync(_load_access, token)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoke the grant of an access or refresh token (RFC 7009)."""
        await anyio.to_thread.run_sync(_revoke_by_token, token.token)

    async def exchange_identity_assertion(
        self, client: OAuthClientInformationFull, params: IdentityAssertionParams
    ) -> OAuthToken:
        """Not supported: the server does not advertise it."""
        raise TokenError("unsupported_grant_type", "The JWT bearer grant is not supported")


def _store_request(row: OAuthAuthorization) -> None:
    """Store a pending request, after deleting the expired ones.

    Raises:
        AuthorizeError: If MAX_PENDING_REQUESTS are pending already.
    """
    with session_scope() as session:
        session.execute(
            delete(OAuthAuthorization).where(col(OAuthAuthorization.expires_at) <= utcnow())
        )
        pending = session.exec(select(func.count()).select_from(OAuthAuthorization)).one()
        if pending >= MAX_PENDING_REQUESTS:
            logger.warning("OAuth authorization refused: too many pending requests")
            raise AuthorizeError(
                "temporarily_unavailable", "Too many pending requests, retry later"
            )
        session.add(row)


def _purge_unapproved_clients(session: Session) -> None:
    """Delete the clients registered more than a day ago that hold no grant nor request."""
    used = select(OAuthGrant.client_id).union(select(OAuthAuthorization.client_id))
    session.execute(
        delete(OAuthClient).where(
            col(OAuthClient.created_at) < utcnow() - UNAPPROVED_CLIENT_TTL,
            col(OAuthClient.client_id).not_in(used),
        )
    )


def _limit_grants(session: Session, user_id: int) -> None:
    """Keep the MAX_GRANTS_PER_USER newest grants of a user; delete the expired ones."""
    grants = session.exec(
        select(OAuthGrant)
        .where(OAuthGrant.user_id == user_id)
        .order_by(col(OAuthGrant.created_at).desc())
    ).all()
    now = utcnow()
    for index, grant in enumerate(grants):
        if index >= MAX_GRANTS_PER_USER or as_utc(grant.refresh_expires_at) <= now:
            session.delete(grant)


def _load_access(token: str) -> AccessToken | None:
    with session_scope() as session:
        grant = session.exec(
            select(OAuthGrant).where(OAuthGrant.access_token_hash == digest(token))
        ).first()
        if grant is None or as_utc(grant.access_expires_at) <= utcnow():
            return None
        return AccessToken(
            token=token,
            client_id=grant.client_id,
            scopes=[SCOPE],
            expires_at=_expires_at(grant.access_expires_at),
            resource=grant.resource,
            subject=str(grant.user_id),
        )


def _revoke_by_token(token: str) -> None:
    hashed = digest(token)
    with session_scope() as session:
        grant = session.exec(
            select(OAuthGrant).where(
                or_(OAuthGrant.access_token_hash == hashed, OAuthGrant.refresh_token_hash == hashed)
            )
        ).first()
        if grant is not None:
            _revoke(session, grant, AuditAction.OAUTH_GRANT_REVOKED, audit.ANONYMOUS_ACTOR)


# ── Consent screen and My account (web session only) ─────────────────────────


def _pending(session: Session, handle: str) -> OAuthAuthorization:
    """The pending, unexpired request of a handle.

    Raises:
        NotFoundError: If there is none (unknown, expired or already decided).
    """
    row = session.get(OAuthAuthorization, digest(handle)) if len(handle) <= 100 else None
    if row is None or row.code_hash is not None or as_utc(row.expires_at) <= utcnow():
        raise NotFoundError("Authorization request not found or expired: start again")
    return row


def pending_request(handle: str) -> dict[str, Any]:
    """What the consent screen shows of a pending request: the client and where it goes back.

    Raises:
        NotFoundError: If the request is unknown, expired or already decided.
    """
    with session_scope() as session:
        row = _pending(session, handle)
        client = session.get(OAuthClient, row.client_id)
        return {
            "client_id": row.client_id,
            "client_name": client.client_name if client else None,
            "redirect_host": urlsplit(row.redirect_uri).hostname
            or urlsplit(row.redirect_uri).scheme,
            "expires_at": as_utc(row.expires_at).isoformat(),
        }


def approve(handle: str, user_id: int, username: str) -> str:
    """Approve a pending request for a web user: return the redirect URI with a single-use code.

    Raises:
        NotFoundError: If the request is unknown, expired or already decided.
    """
    code = secrets.token_urlsafe(32)
    with session_scope() as session:
        row = _pending(session, handle)
        # Conditional on a pending request: of two concurrent decisions, one wins
        changed = session.execute(
            update(OAuthAuthorization)
            .where(
                col(OAuthAuthorization.id) == row.id, col(OAuthAuthorization.code_hash).is_(None)
            )
            .values(user_id=user_id, code_hash=digest(code), expires_at=utcnow() + CODE_TTL)
        )
        if changed.rowcount != 1:
            raise NotFoundError("Authorization request not found or expired: start again")
        client = session.get(OAuthClient, row.client_id)
        audit.record(
            session,
            AuditAction.OAUTH_GRANT_APPROVED,
            audit.user_actor(username),
            "oauth_client",
            row.client_id,
            details={"client_name": client.client_name if client else None},
        )
        return construct_redirect_uri(row.redirect_uri, code=code, state=row.state)


def deny(handle: str, username: str) -> str:
    """Deny a pending request: return the redirect URI with the access_denied error.

    Raises:
        NotFoundError: If the request is unknown, expired or already decided.
    """
    with session_scope() as session:
        row = _pending(session, handle)
        session.delete(row)
        client = session.get(OAuthClient, row.client_id)
        audit.record(
            session,
            AuditAction.OAUTH_GRANT_DENIED,
            audit.user_actor(username),
            "oauth_client",
            row.client_id,
            details={"client_name": client.client_name if client else None},
        )
        return construct_redirect_uri(row.redirect_uri, error="access_denied", state=row.state)


def list_user_grants(user_id: int) -> list[dict[str, Any]]:
    """The MCP clients a web user approved, newest first (never a token)."""
    with session_scope() as session:
        rows = session.exec(
            select(OAuthGrant, OAuthClient)
            .join(OAuthClient, col(OAuthClient.client_id) == col(OAuthGrant.client_id))
            .where(OAuthGrant.user_id == user_id)
            .order_by(col(OAuthGrant.created_at).desc())
        ).all()
        return [
            {
                "id": grant.id,
                "client_id": grant.client_id,
                "client_name": client.client_name,
                "created_at": as_utc(grant.created_at).isoformat(),
                "last_used_at": as_utc(grant.last_used_at).isoformat()
                if grant.last_used_at
                else None,
                "expires_at": as_utc(grant.refresh_expires_at).isoformat(),
            }
            for grant, client in rows
        ]


def revoke_user_grant(user_id: int, grant_id: str, username: str) -> None:
    """Revoke a grant of a web user.

    Raises:
        NotFoundError: If the user holds no such grant.
    """
    with session_scope() as session:
        grant = session.get(OAuthGrant, grant_id) if len(grant_id) <= 64 else None
        if grant is None or grant.user_id != user_id:
            raise NotFoundError(f"OAuth client {grant_id} not found")
        _revoke(session, grant, AuditAction.OAUTH_GRANT_REVOKED, audit.user_actor(username))


# ── Administration (tokens.manage) ───────────────────────────────────────────


def overview(settings: Settings | None = None) -> dict[str, Any]:
    """The OAuth login as configured, every registered client and every grant (never a token)."""
    settings = settings or get_settings()
    with session_scope() as session:
        clients = session.exec(
            select(OAuthClient).order_by(col(OAuthClient.created_at).desc())
        ).all()
        rows = session.exec(
            select(OAuthGrant, OAuthClient, WebUser)
            .join(OAuthClient, col(OAuthClient.client_id) == col(OAuthGrant.client_id))
            .join(WebUser, col(WebUser.id) == col(OAuthGrant.user_id))
            .order_by(col(OAuthGrant.created_at).desc())
        ).all()
        approved: dict[str, int] = {}
        for grant, _, _ in rows:
            approved[grant.client_id] = approved.get(grant.client_id, 0) + 1
        return {
            "enabled": settings.mcp_oauth_enabled,
            "mcp_url": settings.mcp_url,
            "redirect_hosts": redirect_hosts(settings.mcp_oauth_redirect_hosts),
            "redirect_schemes": redirect_schemes(settings.mcp_oauth_redirect_schemes),
            "access_minutes": settings.mcp_oauth_access_minutes,
            "refresh_days": settings.mcp_oauth_refresh_days,
            "max_clients": settings.mcp_oauth_max_clients,
            "clients": [
                {
                    "client_id": client.client_id,
                    "client_name": client.client_name,
                    "redirect_uris": [str(uri) for uri in _client_info(client).redirect_uris or []],
                    "created_at": as_utc(client.created_at).isoformat(),
                    "grants": approved.get(client.client_id, 0),
                }
                for client in clients
            ],
            "grants": [
                {
                    "id": grant.id,
                    "client_id": grant.client_id,
                    "client_name": client.client_name,
                    "username": user.username,
                    "created_at": as_utc(grant.created_at).isoformat(),
                    "last_used_at": as_utc(grant.last_used_at).isoformat()
                    if grant.last_used_at
                    else None,
                    "expires_at": as_utc(grant.refresh_expires_at).isoformat(),
                }
                for grant, client, user in rows
            ],
        }


def revoke_grant(grant_id: str, actor: str) -> None:
    """Revoke the grant of any user (administration).

    Raises:
        NotFoundError: If there is no such grant.
    """
    with session_scope() as session:
        grant = session.get(OAuthGrant, grant_id) if len(grant_id) <= 64 else None
        if grant is None:
            raise NotFoundError(f"OAuth grant {grant_id} not found")
        _revoke(session, grant, AuditAction.OAUTH_GRANT_REVOKED, actor)


def delete_client(client_id: str, actor: str) -> None:
    """Delete a registered client with its grants and requests: its tokens stop at once and it
    must register again (administration).

    Raises:
        NotFoundError: If there is no such client.
    """
    with session_scope() as session:
        client = session.get(OAuthClient, client_id) if len(client_id) <= 64 else None
        if client is None:
            raise NotFoundError(f"OAuth client {client_id} not found")
        for grant in session.exec(
            select(OAuthGrant).where(OAuthGrant.client_id == client_id)
        ).all():
            _revoke(session, grant, AuditAction.OAUTH_GRANT_REVOKED, actor)
        session.execute(
            delete(OAuthAuthorization).where(col(OAuthAuthorization.client_id) == client_id)
        )
        session.flush()
        session.delete(client)


def revoke_all_grants(actor: str) -> int:
    """Revoke every grant (administration): the tokens already issued stop for good, even once
    a suspended OAuth login is turned on again. Return how many were revoked."""
    with session_scope() as session:
        grants = session.exec(select(OAuthGrant)).all()
        for grant in grants:
            _revoke(session, grant, AuditAction.OAUTH_GRANT_REVOKED, actor)
        session.execute(delete(OAuthAuthorization))
    return len(grants)


def delete_user_grants(session: Session, user_id: int, actor: str | None = None) -> None:
    """Delete the grants and the requests of a web user (before the user), each grant audited."""
    for grant in session.exec(select(OAuthGrant).where(OAuthGrant.user_id == user_id)).all():
        _revoke(session, grant, AuditAction.OAUTH_GRANT_REVOKED, actor)
    session.execute(delete(OAuthAuthorization).where(col(OAuthAuthorization.user_id) == user_id))
    session.flush()
