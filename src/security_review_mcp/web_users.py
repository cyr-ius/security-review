"""Web users: username and password accounts of the web interface of the controller.

A web user has a web role (``reader``, ``triager`` or ``admin``) and, for ``reader`` and
``triager``, an optional list of projects. Only a scrypt hash of the password is stored
(``WebUser``); the parameters are part of the hash, so that they can be raised later.

``POST /api/v1/auth/login`` checks the password and issues a session token (see
oidc.SessionSigner) that carries the id of the user. At each request, SessionVerifier reads the
user again: a deleted user loses its sessions at once, a new role or new projects apply at once,
and a password change ends the sessions opened before it. ``WebUser.session_version`` is random
(drawn at creation and at each password change) and the session must name the same username, so
that a session never opens another account that reuses the id of a deleted one.

The first administrator is the user ``admin``, created with a random password on the first
start of the controller (``SECREVIEW_AUTH_BOOTSTRAP_ADMIN``). The last administrator can be
neither deleted nor demoted, so that the web interface always keeps one.

Failed logins are throttled in memory (LoginThrottle), per username and address and per
address: each controller replica counts its own failures.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable
from datetime import UTC, datetime
from functools import cache
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlmodel import col, func, select

from .database import session_scope
from .http_server import WEB_ROLES, Role, TokenInfo
from .models import WebUser, utcnow
from .oidc import SessionSigner
from .services import NotFoundError
from .token_store import MAX_PROJECTS_PER_TOKEN, _clean_project

BOOTSTRAP_USERNAME = "admin"
MAX_USERS = 500
MAX_USERNAME_CHARS = 64
MIN_PASSWORD_CHARS = 12
# Bounded: the hash cost does not depend on the length, but the request body does
MAX_PASSWORD_CHARS = 256
GENERATED_PASSWORD_BYTES = 18
# Random session versions fit in a signed 64-bit integer column
SESSION_VERSION_BITS = 62
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]*")
USER_ROLES = (Role.READER, Role.TRIAGER, Role.ADMIN)

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


def generate_password() -> str:
    """Return a random password (24 URL-safe characters)."""
    return secrets.token_urlsafe(GENERATED_PASSWORD_BYTES)


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
    """Validate a new password (kept as typed: spaces are significant)."""
    if not MIN_PASSWORD_CHARS <= len(password) <= MAX_PASSWORD_CHARS:
        raise ValueError(
            f"Password must contain between {MIN_PASSWORD_CHARS} and {MAX_PASSWORD_CHARS} "
            "characters"
        )
    if not password.strip() or not password.isprintable():
        raise ValueError("Password must not be blank nor contain control characters")
    return password


def clean_role(role: Role | str) -> Role:
    """Validate the web role of a user."""
    try:
        parsed = Role(str(role).strip().lower())
    except ValueError:
        parsed = None
    if parsed not in USER_ROLES:
        raise ValueError("Role must be reader, triager or admin")
    return parsed


def clean_projects(role: Role, projects: Iterable[str] | None) -> list[str]:
    """Validate the projects of a user (empty: every project); none for ``admin``."""
    cleaned = list(dict.fromkeys(_clean_project(name) for name in projects or ()))
    if not all(name.isprintable() for name in cleaned):
        raise ValueError("Project must not contain control characters")
    if cleaned and role == Role.ADMIN:
        raise ValueError("An admin user reaches every project: it cannot list projects")
    if len(cleaned) > MAX_PROJECTS_PER_TOKEN:
        raise ValueError(f"A user may reach at most {MAX_PROJECTS_PER_TOKEN} projects")
    return cleaned


# ── Accounts ─────────────────────────────────────────────────────────────────


def _aware(value: datetime) -> datetime:
    """Read a stored time as UTC (SQLite drops the time zone)."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _projects(row: WebUser) -> list[str] | None:
    """Projects of a user; None for every project."""
    return json.loads(row.projects) or None


def _public(row: WebUser) -> dict[str, Any]:
    """API view of a user, never its password hash."""
    return {
        "id": row.id,
        "username": row.username,
        "role": row.role,
        "projects": _projects(row),
        "created_at": _aware(row.created_at).isoformat(),
        "updated_at": _aware(row.updated_at).isoformat(),
        "password_changed_at": _aware(row.password_changed_at).isoformat(),
        "last_login_at": _aware(row.last_login_at).isoformat() if row.last_login_at else None,
        "created_by": row.created_by,
    }


def _get(session: Any, user_id: int) -> WebUser:
    """Return a user by id or raise NotFoundError."""
    row = session.get(WebUser, user_id)
    if row is None:
        raise NotFoundError(f"Web user {user_id} not found")
    return row


def _admin_count(session: Any) -> int:
    """Number of users with the admin role."""
    return session.exec(
        select(func.count()).select_from(WebUser).where(WebUser.role == Role.ADMIN.value)
    ).one()


def has_users() -> bool:
    """True when at least one web user exists."""
    with session_scope() as session:
        return session.exec(select(WebUser.id).limit(1)).first() is not None


def list_users() -> list[dict[str, Any]]:
    """Return every user, by username."""
    with session_scope() as session:
        rows = session.exec(select(WebUser).order_by(col(WebUser.username))).all()
        return [_public(row) for row in rows]


def find_user(reference: str) -> dict[str, Any]:
    """Return a user by username or id; raise NotFoundError."""
    with session_scope() as session:
        row = session.exec(select(WebUser).where(WebUser.username == reference.strip())).first()
        if row is None and reference.strip().isdigit():
            row = session.get(WebUser, int(reference.strip()))
        if row is None:
            raise NotFoundError(f"Web user '{reference}' not found")
        return _public(row)


def create_user(
    username: str,
    password: str | None,
    role: Role | str,
    projects: Iterable[str] | None = None,
    created_by: str | None = None,
) -> dict[str, Any]:
    """Create a user; without ``password`` a random one is generated.

    Returns the user and, when generated, its ``password`` (shown exactly once). Raises
    ValueError when invalid, duplicated or over the limit.
    """
    name = clean_username(username)
    parsed = clean_role(role)
    names = clean_projects(parsed, projects)
    generated = password is None
    secret = generate_password() if password is None else clean_password(password)
    with session_scope() as session:
        if session.exec(select(func.count()).select_from(WebUser)).one() >= MAX_USERS:
            raise ValueError(f"The limit of {MAX_USERS} web users has been reached")
    row = WebUser(
        username=name,
        role=parsed.value,
        projects=json.dumps(names),
        password_hash=hash_password(secret),
        session_version=new_session_version(),
        created_by=created_by,
    )
    try:
        with session_scope() as session:
            session.add(row)
            session.flush()
            session.refresh(row)
            created = _public(row)
    except IntegrityError as exc:
        raise ValueError(f"A web user named '{name}' already exists") from exc
    return created | {"password": secret} if generated else created


def update_user(
    user_id: int, role: Role | str, projects: Iterable[str] | None = None
) -> dict[str, Any]:
    """Replace the role and projects of a user (applies to its open sessions at once).

    The last administrator cannot be demoted.
    """
    parsed = clean_role(role)
    names = clean_projects(parsed, projects)
    with session_scope() as session:
        row = _get(session, user_id)
        if row.role == Role.ADMIN.value and parsed != Role.ADMIN and _admin_count(session) <= 1:
            raise ValueError("The last administrator cannot lose the admin role")
        row.role = parsed.value
        row.projects = json.dumps(names)
        row.updated_at = utcnow()
        session.add(row)
        session.flush()
        session.refresh(row)
        return _public(row)


def set_password(user_id: int, password: str | None = None) -> dict[str, Any]:
    """Replace the password of a user and end its open sessions.

    Without ``password`` a random one is generated and returned in ``password``.
    """
    generated = password is None
    secret = generate_password() if password is None else clean_password(password)
    password_hash = hash_password(secret)
    with session_scope() as session:
        row = _get(session, user_id)
        row.password_hash = password_hash
        row.password_changed_at = row.updated_at = utcnow()
        row.session_version = new_session_version()
        session.add(row)
        session.flush()
        session.refresh(row)
        updated = _public(row)
    return updated | {"password": secret} if generated else updated


def change_own_password(user_id: int, current: str, new: str) -> dict[str, Any]:
    """Replace the password of a user who proves the current one (ValueError otherwise)."""
    with session_scope() as session:
        stored = _get(session, user_id).password_hash
    if not verify_password(current[:MAX_PASSWORD_CHARS], stored):
        raise ValueError("The current password is wrong")
    if current == new:
        raise ValueError("The new password must differ from the current one")
    return set_password(user_id, new)


def delete_user(user_id: int) -> dict[str, Any]:
    """Delete a user (its sessions stop at once); the last administrator is kept."""
    with session_scope() as session:
        row = _get(session, user_id)
        if row.role == Role.ADMIN.value and _admin_count(session) <= 1:
            raise ValueError("The last administrator cannot be deleted")
        deleted = _public(row)
        session.delete(row)
    return deleted


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Return the user whose username and password match, or None.

    The time spent does not depend on whether the username exists. The last login time is
    recorded.
    """
    with session_scope() as session:
        row = session.exec(select(WebUser).where(WebUser.username == username.strip())).first()
        stored = row.password_hash if row is not None else _dummy_hash()
        matches = verify_password(password[:MAX_PASSWORD_CHARS], stored)
        if row is None or not matches:
            return None
        row.last_login_at = utcnow()
        session.add(row)
        session.flush()
        session.refresh(row)
        return _public(row)


def ensure_bootstrap_admin() -> str | None:
    """Create the user ``admin`` with a random password while no web user exists.

    Return the password only when the user was created.
    """
    if has_users():
        return None
    try:
        created = create_user(BOOTSTRAP_USERNAME, None, Role.ADMIN, created_by="bootstrap")
    except ValueError:
        # Another instance sharing the database created it first
        return None
    return created["password"]


# ── Sessions ─────────────────────────────────────────────────────────────────


def new_session(signer: SessionSigner, user_id: int) -> dict[str, Any]:
    """Issue a session token for a web user, with its current role, projects and version."""
    with session_scope() as session:
        row = _get(session, user_id)
        role = Role(row.role)
        projects = _projects(row)
        token = signer.issue_session(
            row.username,
            role,
            None if projects is None else frozenset(projects),
            user_id=row.id,
            user_version=row.session_version,
        )
        return {
            "session": token,
            "expires_in": signer.session_seconds,
            "username": row.username,
            "role": role,
        }


def session_identity(user_id: int, version: int, username: str) -> TokenInfo | None:
    """Current identity of the user of a session issued to ``username`` with ``version``.

    None when the user no longer exists (or its id now belongs to another account), its role
    cannot use the web interface, or its password changed after the session was issued.
    """
    with session_scope() as session:
        row = session.get(WebUser, user_id)
        if (
            row is None
            or row.session_version != version
            or not hmac.compare_digest(row.username.encode(), username.encode())
        ):
            return None
        try:
            role = Role(row.role)
        except ValueError:
            return None
        if role not in WEB_ROLES:
            return None
        projects = _projects(row)
        return TokenInfo(
            label=row.username,
            role=role,
            projects=None if projects is None else frozenset(projects),
            user_id=row.id,
        )


class SessionVerifier:
    """Verifier of the controller sessions (http_server.SessionVerifier).

    An OIDC session is trusted as signed; the session of a web user is checked against the
    database at each request (see session_identity).
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
        if payload.get("uid") is None:
            return self.signer.verify_session(credentials)
        if not isinstance(payload["sub"], str):
            return None
        return session_identity(payload["uid"], payload["uver"], payload["sub"])


# ── Login throttling ─────────────────────────────────────────────────────────


class LoginThrottle:
    """Count the failed logins of the last ``window`` seconds, in memory.

    A username is locked for an address after ``max_per_user`` failures, an address after
    ``max_per_address`` failures on any username. At most ``max_keys`` keys are kept (the oldest
    are dropped), so that memory stays bounded.
    """

    def __init__(
        self,
        max_per_user: int = 5,
        max_per_address: int = 20,
        window: float = 15 * 60,
        max_keys: int = 10_000,
    ) -> None:
        self.max_per_user = max_per_user
        self.max_per_address = max_per_address
        self.window = window
        self.max_keys = max_keys
        self._failures: OrderedDict[tuple[str, ...], list[float]] = OrderedDict()
        self._lock = threading.Lock()

    def _recent(self, key: tuple[str, ...], now: float) -> list[float]:
        """Failures of a key still inside the window (expired ones are dropped)."""
        times = [t for t in self._failures.get(key, []) if now - t < self.window]
        if times:
            self._failures[key] = times
        else:
            self._failures.pop(key, None)
        return times

    def blocked(self, username: str, address: str) -> bool:
        """True when this login must be refused without checking the password."""
        now = time.monotonic()
        with self._lock:
            return (
                len(self._recent(("user", username.lower(), address), now)) >= self.max_per_user
                or len(self._recent(("address", address), now)) >= self.max_per_address
            )

    def failed(self, username: str, address: str) -> None:
        """Record a failed login."""
        now = time.monotonic()
        with self._lock:
            for key in (("user", username.lower(), address), ("address", address)):
                self._failures.setdefault(key, []).append(now)
                self._failures.move_to_end(key)
            while len(self._failures) > self.max_keys:
                self._failures.popitem(last=False)

    def succeeded(self, username: str, address: str) -> None:
        """Forget the failures of a username for an address after a successful login."""
        with self._lock:
            self._failures.pop(("user", username.lower(), address), None)
