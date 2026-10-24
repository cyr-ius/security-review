"""Web users: the accounts of the web interface of the controller, local or OIDC.

Only web users log in to the web interface; the bearer tokens of the database are for the MCP
server and the REST API (scripts, CI). A web user has an ``auth_source``:

- ``local``: a username and a password. Only a scrypt hash of the password is stored
  (``WebUser``); the parameters are part of the hash, so that they can be raised later.
  ``POST /api/v1/auth/login`` checks the password and issues a session token;
- ``oidc``: an account of the identity provider (see oidc), without a password, identified by
  the issuer and the ``sub`` claim bound at its first login. The username claim only names a
  user not bound yet: with ``SECREVIEW_OIDC_AUTO_CREATE_USERS`` it is created at the first
  login, otherwise an administrator creates it beforehand. It never opens a local account nor a
  user bound to another identity, and a name changed at the provider keeps its account. A
  deleted OIDC user is revoked by its name and its identity (``RevokedSsoUser``): a login never
  creates it again, even under another name, until an administrator creates it again.

What a web user may do comes only from the roles of its groups (see access_control): a user
never holds a role or a project of its own. Its groups are those an administrator gave it (a
project group among them, see access_control.ensure_project_group) and, for an OIDC user, the
groups named by its groups claim at its last login.

The session token (see oidc.SessionSigner) carries the id of the user. At each request,
SessionVerifier reads the user again: a deleted user loses its sessions at once, a new role or
new projects apply at once, and a password change ends the sessions opened before it.
``WebUser.session_version`` is random (drawn at creation and at each password change) and the
session must name the same username, so that a session never opens another account that reuses
the id of a deleted one.

The first administrator is the local user ``SECREVIEW_ADMIN_USERNAME`` (``admin``), created on
the first start of the controller with a random password that only ``user reset-password`` sets,
member of the group ``administrators``. The last user that holds ``users.manage`` can be
neither deleted nor lose that permission, so that the web interface always keeps an
administrator.

Failed logins are throttled per username and address and per address, in the database
(rate_limit.LoginThrottle): every worker and replica of the controller shares the counts.
"""

import base64
import hashlib
import hmac
import logging
import re
import secrets
import string
from collections.abc import Iterable
from datetime import UTC, datetime
from functools import cache
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, and_, col, func, or_, select

from .. import audit
from ..audit import AuditAction
from ..config import Settings
from ..http_server import Role, TokenInfo
from ..reports.services import NotFoundError
from ..storage.database import session_scope
from ..storage.models import RevokedSsoUser, WebUser, utcnow
from . import access_control, token_store
from .oidc import MAX_LABEL_CHARS, OidcError, OidcIdentity, SessionSigner, same_value

Permission = access_control.Permission

logger = logging.getLogger("security_review_mcp.web")

MAX_USERS = 500
MAX_USERNAME_CHARS = 64
# Length of the sub claim of OpenID Connect (and of WebUser.oidc_subject)
MAX_SUBJECT_CHARS = 255
MIN_PASSWORD_CHARS = 12
# Bounded: the hash cost does not depend on the length, but the request body does
MAX_PASSWORD_CHARS = 256
# Length of a generated password (letters, digits and symbols: about 150 bits of entropy)
GENERATED_PASSWORD_CHARS = 24
# Random session versions fit in a signed 64-bit integer column
SESSION_VERSION_BITS = 62
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]*")
AUTH_LOCAL = "local"
# Themes of the web interface; auto follows the system preference
THEMES = ("light", "dark", "auto")
AUTH_OIDC = "oidc"
AUTH_SOURCES = (AUTH_LOCAL, AUTH_OIDC)

# scrypt with N=2^14, r=8, p=5: 16 MiB of memory, a setting recommended by OWASP
SCRYPT_PREFIX = "scrypt"
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 5
SCRYPT_SALT_BYTES = 16
SCRYPT_KEY_BYTES = 32
# Upper bounds accepted when reading a stored hash (a tampered row must not exhaust memory)
SCRYPT_MAX_N = 2**20
SCRYPT_MAX_P = 16
SCRYPT_MAXMEM = 256 * 1024 * 1024


# ── Passwords ────────────────────────────────────────────────────────────────


def _b64(data: bytes) -> str:
    """Base64 without padding."""
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    """Decode the base64 written by _b64."""
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


def hash_password(password: str) -> str:
    """Return ``scrypt$N$r$p$salt$key`` for a password (random salt)."""
    salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM,
        dklen=SCRYPT_KEY_BYTES,
    )
    return f"{SCRYPT_PREFIX}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(key)}"


def verify_password(password: str, stored: str) -> bool:
    """True when ``password`` matches a hash of hash_password (constant-time comparison).

    A malformed hash, or one whose parameters exceed the accepted bounds, never matches.
    """
    try:
        prefix, n, r, p, salt, key = stored.split("$")
        n_value, r_value, p_value = int(n), int(r), int(p)
        expected = _unb64(key)
        salt_bytes = _unb64(salt)
    except ValueError:
        return False
    if (
        prefix != SCRYPT_PREFIX
        or not 2 <= n_value <= SCRYPT_MAX_N
        or n_value & (n_value - 1)
        or not 1 <= r_value <= 32
        or not 1 <= p_value <= SCRYPT_MAX_P
        or not expected
    ):
        return False
    try:
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt_bytes,
            n=n_value,
            r=r_value,
            p=p_value,
            maxmem=SCRYPT_MAXMEM,
            dklen=len(expected),
        )
    except ValueError:
        return False
    return hmac.compare_digest(actual, expected)


@cache
def _dummy_hash() -> str:
    """Hash checked when the username is unknown, so that timing does not reveal it."""
    return hash_password(secrets.token_urlsafe(16))


def new_session_version() -> int:
    """Random session version of a user (see session_identity)."""
    return secrets.randbits(SESSION_VERSION_BITS)


# Characters of a generated password: one of each class at least (see password_problems)
_PASSWORD_CLASSES = (
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
    "-_.~!@#%^*+=",
)


def generate_password() -> str:
    """Return a random password of GENERATED_PASSWORD_CHARS characters that follows the
    password policy (one character of each class at least)."""
    alphabet = "".join(_PASSWORD_CLASSES)
    chosen = [secrets.choice(characters) for characters in _PASSWORD_CLASSES]
    chosen += [secrets.choice(alphabet) for _ in range(GENERATED_PASSWORD_CHARS - len(chosen))]
    secrets.SystemRandom().shuffle(chosen)
    return "".join(chosen)


def password_problems(password: str) -> list[str]:
    """Rules of the password policy that ``password`` breaks (empty: it follows them all)."""
    problems = []
    if not MIN_PASSWORD_CHARS <= len(password) <= MAX_PASSWORD_CHARS:
        problems.append(f"between {MIN_PASSWORD_CHARS} and {MAX_PASSWORD_CHARS} characters")
    if not any(character.islower() for character in password):
        problems.append("a lowercase letter")
    if not any(character.isupper() for character in password):
        problems.append("an uppercase letter")
    if not any(character.isdigit() for character in password):
        problems.append("a digit")
    if all(character.isalnum() for character in password):
        problems.append("a character that is neither a letter nor a digit")
    return problems


# ── Validation ───────────────────────────────────────────────────────────────


def clean_username(username: str) -> str:
    """Validate a username: letters, digits and ``. _ @ -``, 1 to 64 characters."""
    cleaned = username.strip()
    if not 1 <= len(cleaned) <= MAX_USERNAME_CHARS:
        raise ValueError(f"Username must contain between 1 and {MAX_USERNAME_CHARS} characters")
    if not USERNAME_PATTERN.fullmatch(cleaned):
        raise ValueError(
            "Username may only contain letters, digits and . _ @ -, and starts with a letter or "
            "a digit"
        )
    return cleaned


def clean_password(password: str) -> str:
    """Validate a new password against the policy (kept as typed: spaces are significant).

    The policy applies to new passwords only: a stored one keeps working.
    """
    problems = password_problems(password)
    if problems:
        raise ValueError("Password must contain " + ", ".join(problems))
    if not password.strip() or not password.isprintable():
        raise ValueError("Password must not be blank nor contain control characters")
    return password


def clean_auth_source(auth_source: str) -> str:
    """Validate the source of a user: ``local`` or ``oidc``."""
    if auth_source not in AUTH_SOURCES:
        raise ValueError("Source must be local or oidc")
    return auth_source


# ── Accounts ─────────────────────────────────────────────────────────────────


def _aware(value: datetime | None) -> datetime | None:
    """Read a stored time as UTC (SQLite drops the time zone)."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _iso(value: datetime | None) -> str | None:
    """ISO 8601 form of a stored time, or None."""
    aware = _aware(value)
    return aware.isoformat() if aware else None


def _label(row: WebUser) -> str:
    """Name of a user in the logs and the triage history (``oidc:<name>`` for an OIDC user)."""
    if row.auth_source == AUTH_OIDC:
        return f"oidc:{row.username}"[:MAX_LABEL_CHARS]
    return row.username


def _grants(session: Session, row: WebUser) -> dict[str, Any]:
    """Permissions of a user through its groups; empty when it has none (or too many projects)."""
    if row.id is None:
        return {}
    try:
        return access_control.user_grants(session, row.id)
    except ValueError as exc:
        logger.warning("Web user %s has no usable access: %s", row.username, exc)
        return {}


def _public(session: Session, row: WebUser) -> dict[str, Any]:
    """API view of a user, never its password hash nor its subject."""
    grants = _grants(session, row)
    return {
        "id": row.id,
        "username": row.username,
        "auth_source": row.auth_source,
        "groups": access_control.user_groups(session, row.id) if row.id is not None else [],
        "permissions": {
            name: None if projects is None else sorted(projects)
            for name, projects in sorted(grants.items())
        },
        "sso_linked": row.oidc_subject is not None,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "password_changed_at": _iso(row.password_changed_at),
        "must_change_password": row.must_change_password,
        "last_login_at": _iso(row.last_login_at),
        "created_by": row.created_by,
    }


def _get(session: Any, user_id: int) -> WebUser:
    """Return a user by id or raise NotFoundError."""
    row = session.get(WebUser, user_id)
    if row is None:
        raise NotFoundError(f"Web user {user_id} not found")
    return row


def _by_name(session: Any, username: str) -> WebUser | None:
    """Return the user with this exact username, or None."""
    return session.exec(select(WebUser).where(WebUser.username == username)).first()


def _by_identity(session: Any, issuer: str, subject: str) -> WebUser | None:
    """Return the OIDC user bound to this issuer and subject, or None."""
    query = select(WebUser).where(
        WebUser.auth_source == AUTH_OIDC,
        WebUser.oidc_issuer == issuer,
        WebUser.oidc_subject == subject,
    )
    return session.exec(query).first()


def _lift_revocation(session: Any, username: str) -> None:
    """Forget the revocation of a name: an administrator creates that user again."""
    revoked = session.exec(select(RevokedSsoUser).where(RevokedSsoUser.username == username))
    for row in revoked.all():
        session.delete(row)


def _is_revoked(session: Any, username: str, identity: OidcIdentity | None = None) -> bool:
    """True when an administrator deleted the OIDC user with this name or, given an
    ``identity``, the OIDC user bound to its issuer and subject (whatever its name now)."""
    revoked = RevokedSsoUser.username == username
    if identity is not None:
        revoked = or_(
            revoked,
            and_(
                RevokedSsoUser.oidc_issuer == identity.issuer,
                RevokedSsoUser.oidc_subject == identity.subject,
            ),
        )
    return session.exec(select(RevokedSsoUser.id).where(revoked)).first() is not None


def lift_revocation(username: str) -> dict[str, Any]:
    """Let a deleted OIDC user be created again by its next login; raise NotFoundError."""
    with session_scope() as session:
        row = session.exec(
            select(RevokedSsoUser).where(RevokedSsoUser.username == username.strip())
        ).first()
        if row is None:
            raise NotFoundError(f"No revoked OIDC user named '{username}'")
        lifted = {"username": row.username, "revoked_at": _iso(row.revoked_at)}
        session.delete(row)
        return lifted


def list_revoked_users() -> list[dict[str, Any]]:
    """Names of the deleted OIDC users, never created again by a login."""
    with session_scope() as session:
        rows = session.exec(select(RevokedSsoUser).order_by(col(RevokedSsoUser.username))).all()
        return [
            {
                "username": row.username,
                "revoked_at": _iso(row.revoked_at),
                "revoked_by": row.revoked_by,
            }
            for row in rows
        ]


def _check_capacity(session: Any) -> None:
    """Refuse one more user once MAX_USERS exist."""
    if session.exec(select(func.count()).select_from(WebUser)).one() >= MAX_USERS:
        raise ValueError(f"The limit of {MAX_USERS} web users has been reached")


def has_users() -> bool:
    """True when at least one web user exists."""
    with session_scope() as session:
        return session.exec(select(WebUser.id).limit(1)).first() is not None


def list_users() -> list[dict[str, Any]]:
    """Return every user, by username."""
    with session_scope() as session:
        rows = session.exec(select(WebUser).order_by(col(WebUser.username))).all()
        return [_public(session, row) for row in rows]


def find_user(reference: str) -> dict[str, Any]:
    """Return a user by username or id; raise NotFoundError."""
    with session_scope() as session:
        row = _by_name(session, reference.strip())
        if row is None and reference.strip().isdigit():
            row = session.get(WebUser, int(reference.strip()))
        if row is None:
            raise NotFoundError(f"Web user '{reference}' not found")
        return _public(session, row)


def create_user(
    username: str,
    password: str | None,
    groups: Iterable[int] | None = None,
    created_by: str | None = None,
    auth_source: str = AUTH_LOCAL,
    actor: str | None = None,
) -> dict[str, Any]:
    """Create a user, member of ``groups`` (ids); a local one without ``password`` gets a random
    one. ``actor`` is written to the audit log (default: ``created_by``).

    An OIDC user (``auth_source="oidc"``) has no password; its OIDC groups are added at each
    login. Returns the user and, when generated, its ``password`` (shown exactly once). Raises
    ValueError when invalid, duplicated or over the limit, NotFoundError for an unknown group.
    """
    source = clean_auth_source(auth_source)
    name = clean_username(username)
    secret: str | None = None
    if source == AUTH_OIDC:
        if password is not None:
            raise ValueError("An OIDC user has no password: it logs in with the identity provider")
    else:
        secret = generate_password() if password is None else clean_password(password)
    with session_scope() as session:
        _check_capacity(session)
    row = WebUser(
        username=name,
        auth_source=source,
        password_hash=hash_password(secret) if secret is not None else None,
        password_changed_at=utcnow() if secret is not None else None,
        # Chosen or generated by someone else: the user sets its own at its first login
        must_change_password=secret is not None,
        session_version=new_session_version(),
        created_by=created_by,
    )
    try:
        with session_scope() as session:
            _lift_revocation(session, name)
            session.add(row)
            session.flush()
            if groups:
                access_control.set_user_groups(session, row.id, groups, actor or created_by)  # type: ignore[arg-type]
            session.refresh(row)
            created = _public(session, row)
    except IntegrityError as exc:
        raise ValueError(f"A web user named '{name}' already exists") from exc
    generated = source == AUTH_LOCAL and password is None
    return created | {"password": secret} if generated else created


def update_user(
    user_id: int,
    groups: Iterable[int] | None,
    updated_by: str | None = None,
) -> dict[str, Any]:
    """Replace the groups an administrator gave to a user; applies to its sessions at once.

    ``None`` leaves the groups unchanged. Its OIDC groups are kept. The last user that holds
    ``users.manage`` cannot lose it.
    """
    with session_scope() as session:
        row = _get(session, user_id)
        before = access_control.managers(session)
        if groups is not None:
            access_control.set_user_groups(session, user_id, groups, updated_by)
        if before and not access_control.managers(session):
            raise ValueError("At least one user must keep the users.manage permission")
        row.updated_at = utcnow()
        session.add(row)
        session.flush()
        session.refresh(row)
        return _public(session, row)


def set_password(
    user_id: int, password: str | None = None, must_change: bool = True
) -> dict[str, Any]:
    """Replace the password of a local user and end its open sessions.

    Without ``password`` a random one is generated and returned in ``password``. An OIDC user has
    no password (ValueError). ``must_change`` (a password set by an administrator) makes the
    user change it at its next login.
    """
    generated = password is None
    secret = generate_password() if password is None else clean_password(password)
    password_hash = hash_password(secret)
    with session_scope() as session:
        row = _get(session, user_id)
        if row.auth_source != AUTH_LOCAL:
            raise ValueError("An OIDC user has no password: it logs in with the identity provider")
        row.password_hash = password_hash
        row.password_changed_at = row.updated_at = utcnow()
        row.must_change_password = must_change
        row.session_version = new_session_version()
        session.add(row)
        session.flush()
        session.refresh(row)
        updated = _public(session, row)
    return updated | {"password": secret} if generated else updated


def change_own_password(user_id: int, current: str, new: str) -> dict[str, Any]:
    """Replace the password of a local user who proves the current one (ValueError otherwise)."""
    with session_scope() as session:
        row = _get(session, user_id)
        stored = row.password_hash if row.auth_source == AUTH_LOCAL else None
    if stored is None:
        raise ValueError("An OIDC user has no password: it logs in with the identity provider")
    if not verify_password(current[:MAX_PASSWORD_CHARS], stored):
        raise ValueError("The current password is wrong")
    if current == new:
        raise ValueError("The new password must differ from the current one")
    return set_password(user_id, new, must_change=False)


def get_preferences(user_id: int) -> dict[str, str]:
    """Preferences of a web user in the web interface (its theme)."""
    with session_scope() as session:
        return {"theme": _get(session, user_id).theme}


def set_theme(user_id: int, theme: str) -> dict[str, str]:
    """Remember the theme of a web user; raise ValueError when it is not one of THEMES."""
    if theme not in THEMES:
        raise ValueError(f"theme must be one of: {', '.join(THEMES)}")
    with session_scope() as session:
        row = _get(session, user_id)
        row.theme = theme
        session.add(row)
    return {"theme": theme}


def delete_user(user_id: int, deleted_by: str | None = None) -> dict[str, Any]:
    """Delete a user (its sessions stop at once); the last administrator is kept.

    A deleted OIDC user is revoked, by its name and its identity (issuer and subject): a login
    never creates it again (even with ``SECREVIEW_OIDC_AUTO_CREATE_USERS``), under that name or
    another one, until an administrator creates it again.
    """
    with session_scope() as session:
        row = _get(session, user_id)
        if access_control.managers(session) == {user_id}:
            raise ValueError("The last holder of users.manage cannot be deleted")
        deleted = _public(session, row)
        if row.auth_source == AUTH_OIDC and not _is_revoked(session, row.username):
            # The identity too, so that a name changed at the provider is not created again
            bound = bool(row.oidc_subject) and row.oidc_issuer is not None
            session.add(
                RevokedSsoUser(
                    username=row.username,
                    oidc_issuer=row.oidc_issuer if bound else None,
                    oidc_subject=row.oidc_subject if bound else None,
                    revoked_by=deleted_by,
                )
            )
        access_control.forget_user(session, user_id)
        token_store.delete_user_tokens(session, user_id, deleted_by)
        session.delete(row)
    return deleted


def _valid_name(username: str | None) -> str | None:
    """A username as written to the audit log: only a valid one, never arbitrary input."""
    try:
        return clean_username(username or "")
    except ValueError:
        return None


def record_login_failure(username: str | None, method: str, address: str | None) -> None:
    """Write a failed login of the web interface to the audit log (never the password)."""
    with session_scope() as session:
        audit.record(
            session,
            AuditAction.USER_LOGIN_FAILED,
            audit.ANONYMOUS_ACTOR,
            "user",
            _valid_name(username),
            details={"method": method, "address": address},
        )


def _record_login(session: Session, row: WebUser, method: str, address: str | None) -> None:
    """Write a successful login of the web interface to the audit log."""
    audit.record(
        session,
        AuditAction.USER_LOGIN,
        audit.user_actor(_label(row)),
        "user",
        row.username,
        details={"method": method, "address": address},
    )


def record_logout(label: str, address: str | None) -> None:
    """Write the logout of a web user (``label``: its session label) to the audit log."""
    with session_scope() as session:
        audit.record(
            session,
            AuditAction.USER_LOGOUT,
            audit.user_actor(label),
            "user",
            label.removeprefix(f"{AUTH_OIDC}:"),
            details={"address": address},
        )


def authenticate(username: str, password: str, address: str | None = None) -> dict[str, Any] | None:
    """Return the local user whose username and password match, or None.

    An OIDC user never matches. The time spent does not depend on whether the username exists.
    The last login time is recorded, and the login or its failure (from ``address``) is written
    to the audit log.
    """
    with session_scope() as session:
        row = _by_name(session, username.strip())
        stored = row.password_hash if row is not None and row.auth_source == AUTH_LOCAL else None
        matches = verify_password(password[:MAX_PASSWORD_CHARS], stored or _dummy_hash())
        if row is not None and stored is not None and matches:
            row.last_login_at = utcnow()
            session.add(row)
            _record_login(session, row, "password", address)
            session.flush()
            session.refresh(row)
            return _public(session, row)
    record_login_failure(username.strip(), "password", address)
    return None


def ensure_bootstrap_admin(username: str = "admin") -> bool:
    """Create the local administrator ``username`` while no web user exists; True if created.

    The user joins the group ``administrators`` (created with the ``admin`` role when missing).
    Its random password is never returned nor logged: an operator sets one with
    ``security-review-controller user reset-password``, and the user changes it at its first
    login.

    Raises:
        ValueError: If the username is invalid.
    """
    name = clean_username(username)
    if has_users():
        return False
    with session_scope() as session:
        group_id = access_control.ensure_admin_group(session).id
    try:
        create_user(name, None, [group_id], created_by="bootstrap")  # type: ignore[list-item]
    except ValueError:
        # Another instance sharing the database created it first
        return False
    return True


# ── Sessions ─────────────────────────────────────────────────────────────────


def _session(signer: SessionSigner, row: WebUser, grants: access_control.Grants) -> dict[str, Any]:
    """Issue a session token for a web user, with its current access and version."""
    if not grants or row.id is None:
        raise ValueError(f"Web user {row.username} has no permission")
    token = signer.issue_session(
        _label(row),
        access_control.scope(grants, Permission.REPORTS_READ),
        user_id=row.id,
        user_version=row.session_version,
    )
    return {
        "session": token,
        "expires_in": signer.session_seconds,
        "username": row.username,
        "must_change_password": row.must_change_password,
    }


def new_session(signer: SessionSigner, user_id: int) -> dict[str, Any]:
    """Issue a session token for a web user, with its current permissions and version."""
    with session_scope() as session:
        row = _get(session, user_id)
        return _session(signer, row, _grants(session, row))


def oidc_login(
    signer: SessionSigner,
    identity: OidcIdentity,
    settings: Settings,
    address: str | None = None,
) -> dict[str, Any]:
    """Open the session of the OIDC user of a verified OIDC login; raise OidcError.

    The account is identified by the issuer and the subject, never by a name: the user bound to
    them opens, whatever its username claim says now (a name changed at the provider keeps the
    account and its username). Only an identity bound to no user is looked up by its username
    claim, to bind a user created beforehand (by an administrator, or bound before the issuer
    was recorded: it gets it). It is refused when the name belongs to a local account, when it
    is bound to another subject or to another identity provider, or when it does not exist and
    ``SECREVIEW_OIDC_AUTO_CREATE_USERS`` is off (``unknown_user``) or an administrator deleted it
    (``revoked``). Its OIDC groups are replaced by those its groups claim names (see
    access_control.sync_sso_groups); the login is refused (``forbidden``) when its groups give
    it no permission, and a missing user is then not created.
    """
    label = identity.label
    if not 1 <= len(identity.subject) <= MAX_SUBJECT_CHARS or not identity.subject.isascii():
        # OIDC Core 2: at most 255 ASCII characters; never truncated into another subject
        logger.warning("OIDC login of %s refused: invalid subject", label)
        raise OidcError("token", "Invalid subject claim")
    try:
        name = clean_username(identity.username or "")
    except ValueError:
        logger.warning("OIDC login of %s refused: missing or invalid username claim", label)
        raise OidcError("username", "Missing or invalid username claim") from None
    try:
        with session_scope() as session:
            row = _by_identity(session, identity.issuer, identity.subject)
            if row is not None:
                if row.username != name:
                    logger.info(
                        "OIDC login of %s opens user %s (username claim changed)",
                        label,
                        row.username,
                    )
                name = row.username
            else:
                row = _by_name(session, name)
            if row is not None and row.auth_source != AUTH_OIDC:
                logger.warning("OIDC login of %s refused: %s is a local account", label, name)
                raise OidcError("conflict", "This username belongs to a local account")
            if row is not None and row.oidc_subject is not None:
                if not same_value(row.oidc_subject, identity.subject):
                    logger.warning(
                        "OIDC login of %s refused: user %s is bound to another subject",
                        label,
                        name,
                    )
                    raise OidcError("conflict", "This user is bound to another account")
                if row.oidc_issuer is not None and not same_value(row.oidc_issuer, identity.issuer):
                    logger.warning(
                        "OIDC login of %s refused: user %s is bound to another provider",
                        label,
                        name,
                    )
                    raise OidcError("conflict", "This user is bound to another account")
            created = row is None
            if row is None:
                if not settings.oidc_auto_create_users:
                    logger.warning("OIDC login of %s refused: no web user %s", label, name)
                    raise OidcError("unknown_user", "No web user for this account")
                if _is_revoked(session, name, identity):
                    logger.warning("OIDC login of %s refused: web user %s was deleted", label, name)
                    raise OidcError("revoked", "This web user was deleted by an administrator")
                _check_capacity(session)
                row = WebUser(
                    username=name,
                    auth_source=AUTH_OIDC,
                    session_version=new_session_version(),
                    created_by="oidc",
                )
            row.oidc_subject = identity.subject
            row.oidc_issuer = identity.issuer
            row.last_login_at = utcnow()
            session.add(row)
            session.flush()
            joined = access_control.sync_sso_groups(
                session,
                row.id,  # type: ignore[arg-type]
                identity.groups,
                settings,
            )
            grants = _grants(session, row)
            if not grants and created:
                # Rolled back: the user is not created
                logger.warning("OIDC login of %s refused: no group gives it a permission", label)
                raise OidcError("forbidden", "No web role granted to this user")
            if created:
                logger.info("OIDC web user %s created at its first login", name)
            if grants:
                _record_login(session, row, "oidc", address)
            result = _session(signer, row, grants) if grants else None
    except IntegrityError:
        # The same user logged in twice at the same time
        raise OidcError("state", "Concurrent first login: try again") from None
    if result is None:
        # The OIDC groups it lost are committed, so that its other sessions lose them too
        logger.warning("OIDC login of %s refused: no group gives it a permission", label)
        raise OidcError("forbidden", "No web role granted to this user")
    logger.info("OIDC login of %s through %d OIDC group(s)", label, len(joined))
    return result


def session_identity(user_id: int, version: int, username: str) -> TokenInfo | None:
    """Current identity of the user of a session issued to ``username`` with ``version``.

    None when the user no longer exists (or its id now belongs to another account), has no
    permission any more, or its password changed after the session was issued.
    """
    with session_scope() as session:
        row = session.get(WebUser, user_id)
        if (
            row is None
            or row.session_version != version
            or not hmac.compare_digest(_label(row).encode(), username.encode())
        ):
            return None
        grants = _grants(session, row)
        if not grants:
            return None
        return TokenInfo(
            label=_label(row),
            role=Role.USER,
            projects=access_control.scope(grants, Permission.REPORTS_READ),
            user_id=row.id,
            auth_source=row.auth_source,
            grants=grants,
            must_change_password=row.must_change_password,
        )


class SessionVerifier:
    """Verifier of the controller sessions (http_server.SessionVerifier).

    Every session names a web user, checked against the database at each request (see
    session_identity).
    """

    def __init__(self, signer: SessionSigner) -> None:
        self.signer = signer

    def owns(self, credentials: str) -> bool:
        """True when the bearer value is a session token."""
        return self.signer.owns(credentials)

    def verify_session(self, credentials: str) -> TokenInfo | None:
        """Return the identity of a valid session, or None."""
        payload = self.signer.decode_session(credentials)
        if payload is None:
            return None
        return session_identity(payload["uid"], payload["uver"], payload["sub"])
