"""Bearer tokens of the HTTP transport, stored in the database (SHA-256 digests only).

Every token lives in the ``ApiToken`` table: the bootstrap administrator password, the tokens
created with ``security-review-mcp token create`` and the project tokens created in the web
interface. Every server instance sharing the database sees a creation or a revocation
immediately.

An enrollment request is a token stored with the ``pending`` status: its secret is given to the
requester at once but authenticates nothing until an administrator approves the request.
"""

import hmac
import secrets
import uuid
from datetime import timedelta

from sqlalchemy import ColumnElement
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, or_, select

from .database import session_scope
from .http_server import Role, TokenInfo, hash_token
from .models import ApiToken, utcnow
from .scanner import redact_secrets

BOOTSTRAP_LABEL = "bootstrap-admin"
MAX_TOKENS = 500
MAX_LABEL_CHARS = 64
MAX_PROJECT_CHARS = 200

ACTIVE = "active"
PENDING = "pending"
# Anonymous requests are bounded: at most this many wait for a decision, and the requests
# nobody decided on are dropped after ENROLLMENT_TTL
MAX_PENDING_ENROLLMENTS = 20
ENROLLMENT_TTL = timedelta(days=7)
ENROLLMENT_ROLE = Role.MCP
MAX_REQUESTED_BY_CHARS = 200
MAX_ADDRESS_CHARS = 64


def _is_pending(row: ApiToken) -> bool:
    """True for an enrollment request that no administrator has approved yet."""
    return row.status == PENDING


def _active_clause() -> ColumnElement[bool]:
    """WHERE clause of the tokens that authenticate (rows without status are active)."""
    return or_(col(ApiToken.status).is_(None), col(ApiToken.status) != PENDING)


def _info(row: ApiToken) -> TokenInfo:
    """Convert a stored token into the identity used by the middleware."""
    return TokenInfo(
        row.label,
        Role(row.role),
        project=row.project,
        token_id=row.id,
        pending=_is_pending(row),
    )


def _public(row: ApiToken) -> dict[str, str | None]:
    """Metadata of a token, without its hash."""
    return {
        "id": row.id,
        "label": row.label,
        "role": row.role,
        "project": row.project,
        "status": PENDING if _is_pending(row) else ACTIVE,
        "created_at": row.created_at.isoformat(),
    }


def _request(row: ApiToken) -> dict[str, str | None]:
    """Metadata of an enrollment request, with who asked for it and from where."""
    return _public(row) | {"requested_by": row.requested_by, "requested_from": row.requested_from}


class DatabaseTokenStore:
    """Token lookup used by http_server.BearerAuthMiddleware (one query per request)."""

    def lookup(self, digest: bytes) -> TokenInfo | None:
        """Return the identity of the stored token with this SHA-256 digest, or None.

        The lookup key is the digest of the presented credential: its timing reveals nothing
        usable without a preimage of a stored hash. The final check is constant time.
        """
        with session_scope() as session:
            row = session.exec(select(ApiToken).where(ApiToken.token_hash == digest.hex())).first()
            if row is None or not hmac.compare_digest(bytes.fromhex(row.token_hash), digest):
                return None
            return _info(row)

    def has_tokens(self) -> bool:
        """True when at least one active token is stored.

        Pending enrollment requests do not count: anybody may create one, and doing so must
        not switch on authentication for a server that has none.
        """
        with session_scope() as session:
            return (
                session.exec(select(ApiToken.id).where(_active_clause()).limit(1)).first()
                is not None
            )


def _insert(
    label: str, role: Role, project: str | None = None, **fields: str | None
) -> tuple[ApiToken, str]:
    """Generate a token, store its digest and return (row, raw token).

    ``fields`` sets the enrollment columns (status, requested_by, requested_from). A duplicate
    label raises ValueError; the token limit is enforced here.
    """
    with session_scope() as session:
        count = session.exec(select(func.count()).select_from(ApiToken)).one()
    if count >= MAX_TOKENS:
        raise ValueError(f"The limit of {MAX_TOKENS} tokens has been reached")
    token = secrets.token_urlsafe(32)
    row = ApiToken(
        id=str(uuid.uuid4()),
        label=label,
        role=role.value,
        project=project,
        token_hash=hash_token(token).hex(),
        status=fields.get("status", ACTIVE),
        requested_by=fields.get("requested_by"),
        requested_from=fields.get("requested_from"),
    )
    try:
        with session_scope() as session:
            session.add(row)
            session.flush()
            session.refresh(row)
            session.expunge(row)
    except IntegrityError as exc:
        raise ValueError(f"A token named '{label}' already exists") from exc
    return row, token


# ── Tokens ───────────────────────────────────────────────────────────────────


def _clean_label(label: str) -> str:
    """Strip a token label and check its length."""
    label = label.strip()
    if not 1 <= len(label) <= MAX_LABEL_CHARS:
        raise ValueError(f"Token label must contain between 1 and {MAX_LABEL_CHARS} characters")
    return label


def _clean_project(project: str) -> str:
    """Strip a project name and check its length."""
    project = project.strip()
    if not 1 <= len(project) <= MAX_PROJECT_CHARS:
        raise ValueError(f"Project must contain between 1 and {MAX_PROJECT_CHARS} characters")
    return project


def create_token(label: str, role: Role | str, project: str | None = None) -> dict[str, str | None]:
    """Create a token and return its metadata with the raw secret, shown exactly once.

    ``project`` restricts the token to one project, for the MCP tools and the web interface.
    It is refused for ``admin``, whose rights (rules, every project) cannot be scoped.
    """
    label = _clean_label(label)
    try:
        role = Role(str(role).strip().lower())
    except ValueError:
        allowed = ", ".join(r.value for r in Role)
        raise ValueError(f"Unknown role '{role}' (allowed: {allowed})") from None
    if project is not None:
        project = _clean_project(project)
        if role == Role.ADMIN:
            raise ValueError("An admin token cannot be restricted to a project")
    row, token = _insert(label, role, project)
    return _public(row) | {"token": token}


def list_tokens(project: str | None = None, pending: bool = False) -> list[dict[str, str | None]]:
    """Return token metadata (never the hashes), optionally only one project's tokens.

    With ``pending`` only the enrollment requests waiting for approval are returned.
    """
    statement = select(ApiToken).order_by(col(ApiToken.created_at), col(ApiToken.label))
    if project is not None:
        statement = statement.where(ApiToken.project == project)
    if pending:
        statement = statement.where(ApiToken.status == PENDING)
    with session_scope() as session:
        return [
            _request(row) if _is_pending(row) else _public(row)
            for row in session.exec(statement).all()
        ]


def revoke_token(reference: str) -> dict[str, str | None]:
    """Delete a token by id or label and return its metadata.

    The next request presenting it is rejected.
    """
    with session_scope() as session:
        row = session.exec(
            select(ApiToken).where(or_(ApiToken.id == reference, ApiToken.label == reference))
        ).first()
        if row is None:
            raise ValueError(f"Token '{reference}' was not found")
        revoked = _public(row)
        session.delete(row)
    return revoked


# ── Project tokens (web interface) ───────────────────────────────────────────


def list_project_tokens() -> list[dict[str, str | None]]:
    """Return the metadata of the active project-scoped tokens."""
    return [
        token
        for token in list_tokens()
        if token["project"] is not None and token["status"] == ACTIVE
    ]


def create_project_token(label: str, project: str) -> dict[str, str | None]:
    """Create a read-only token restricted to one project."""
    return create_token(label, Role.READER, project)


def revoke_project_token(token_id: str) -> None:
    """Delete a project token by id; other tokens cannot be revoked this way."""
    with session_scope() as session:
        row = session.exec(
            select(ApiToken).where(ApiToken.id == token_id, col(ApiToken.project).is_not(None))
        ).first()
        if row is None:
            raise ValueError(f"Project token '{token_id}' was not found")
        session.delete(row)


# ── Enrollment requests ──────────────────────────────────────────────────────


def _purge_expired_requests() -> None:
    """Drop the enrollment requests that waited longer than ENROLLMENT_TTL."""
    cutoff = utcnow() - ENROLLMENT_TTL
    with session_scope() as session:
        for row in session.exec(
            select(ApiToken).where(ApiToken.status == PENDING, ApiToken.created_at < cutoff)
        ).all():
            session.delete(row)


def request_enrollment(
    project: str,
    label: str | None = None,
    requested_by: str | None = None,
    requested_from: str | None = None,
) -> dict[str, str | None]:
    """Store an enrollment request and return its metadata with the raw secret, shown once.

    ``label`` (default: the project name) gets a random suffix. The request is an ``mcp``
    token restricted to ``project`` and created ``pending``: it
    authenticates nothing until an administrator approves it. Anybody may call this, so the
    number of pending requests is bounded and ``requested_by`` (free text) is redacted.
    """
    project = _clean_project(project)
    # The requester never picks the exact label: a random suffix keeps labels unique without
    # telling an anonymous client which labels already exist
    base = label.strip() if label is not None and label.strip() else f"{project}-enroll"
    suffix = f"-{secrets.token_hex(3)}"
    label = _clean_label(base[: MAX_LABEL_CHARS - len(suffix)] + suffix)
    if requested_by is not None:
        requested_by = redact_secrets(requested_by.strip())[:MAX_REQUESTED_BY_CHARS] or None
    if requested_from is not None:
        requested_from = requested_from[:MAX_ADDRESS_CHARS]
    _purge_expired_requests()
    with session_scope() as session:
        pending = session.exec(
            select(func.count()).select_from(ApiToken).where(ApiToken.status == PENDING)
        ).one()
    if pending >= MAX_PENDING_ENROLLMENTS:
        raise ValueError(
            "Too many enrollment requests are waiting for approval; ask an administrator"
        )
    row, token = _insert(
        label,
        ENROLLMENT_ROLE,
        project,
        status=PENDING,
        requested_by=requested_by,
        requested_from=requested_from,
    )
    return _request(row) | {"token": token}


def _pending_row(session: Session, reference: str) -> ApiToken:
    """Return the pending request with this id or label, or raise ValueError."""
    row = session.exec(
        select(ApiToken).where(
            ApiToken.status == PENDING,
            or_(ApiToken.id == reference, ApiToken.label == reference),
        )
    ).first()
    if row is None:
        raise ValueError(f"Enrollment request '{reference}' was not found")
    return row


def approve_enrollment(reference: str) -> dict[str, str | None]:
    """Activate a pending request (by id or label): its token works from the next request."""
    with session_scope() as session:
        row = _pending_row(session, reference)
        row.status = ACTIVE
        session.add(row)
        session.flush()
        return _request(row)


def reject_enrollment(reference: str) -> dict[str, str | None]:
    """Delete a pending request (by id or label); active tokens cannot be removed this way."""
    with session_scope() as session:
        row = _pending_row(session, reference)
        rejected = _request(row)
        session.delete(row)
    return rejected


def enrollment_status(token_id: str | None) -> dict[str, str | None]:
    """Status of the enrollment request of a token id (as seen by its holder)."""
    if token_id is not None:
        with session_scope() as session:
            row = session.get(ApiToken, token_id)
            if row is not None:
                return {
                    "status": PENDING if _is_pending(row) else ACTIVE,
                    "label": row.label,
                    "project": row.project,
                    "requested_at": row.created_at.isoformat(),
                }
    return {"status": "not_enrolled"}


# ── Bootstrap administrator ──────────────────────────────────────────────────


def ensure_bootstrap_admin() -> str | None:
    """Create the bootstrap administrator password once; return it only when created."""
    with session_scope() as session:
        exists = session.exec(select(ApiToken.id).where(ApiToken.label == BOOTSTRAP_LABEL)).first()
    if exists is not None:
        return None
    try:
        _, password = _insert(BOOTSTRAP_LABEL, Role.ADMIN)
    except ValueError:
        # Another instance sharing the database created it first
        return None
    return password


def reset_bootstrap_admin() -> str:
    """Replace the bootstrap administrator password and return the new one."""
    with session_scope() as session:
        for row in session.exec(select(ApiToken).where(ApiToken.label == BOOTSTRAP_LABEL)).all():
            session.delete(row)
    _, password = _insert(BOOTSTRAP_LABEL, Role.ADMIN)
    return password
