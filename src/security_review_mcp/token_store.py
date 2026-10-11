"""Bearer tokens of the HTTP transport, stored in the database (SHA-256 digests only).

Every token lives in the ``ApiToken`` table: the bootstrap administrator password, the tokens
created with ``security-review-mcp token create`` and the project tokens created in the web
interface. Every server instance sharing the database sees a creation or a revocation
immediately.
"""

import hmac
import secrets
import uuid

from sqlalchemy.exc import IntegrityError
from sqlmodel import col, func, or_, select

from .database import session_scope
from .http_server import Role, TokenInfo, hash_token
from .models import ApiToken

BOOTSTRAP_LABEL = "bootstrap-admin"
MAX_TOKENS = 500
MAX_LABEL_CHARS = 64
MAX_PROJECT_CHARS = 200


def _info(row: ApiToken) -> TokenInfo:
    """Convert a stored token into the identity used by the middleware."""
    return TokenInfo(row.label, Role(row.role), project=row.project, token_id=row.id)


def _public(row: ApiToken) -> dict[str, str | None]:
    """Metadata of a token, without its hash."""
    return {
        "id": row.id,
        "label": row.label,
        "role": row.role,
        "project": row.project,
        "created_at": row.created_at.isoformat(),
    }


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
        """True when at least one token is stored."""
        with session_scope() as session:
            return session.exec(select(ApiToken.id).limit(1)).first() is not None


def _insert(label: str, role: Role, project: str | None = None) -> tuple[ApiToken, str]:
    """Generate a token, store its digest and return (row, raw token).

    A duplicate label raises ValueError; the token limit is enforced here.
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


def create_token(label: str, role: Role | str, project: str | None = None) -> dict[str, str | None]:
    """Create a token and return its metadata with the raw secret, shown exactly once.

    ``project`` restricts the token to one project, for the MCP tools and the web interface.
    It is refused for ``admin``, whose rights (rules, every project) cannot be scoped.
    """
    label = label.strip()
    if not 1 <= len(label) <= MAX_LABEL_CHARS:
        raise ValueError(f"Token label must contain between 1 and {MAX_LABEL_CHARS} characters")
    try:
        role = Role(str(role).strip().lower())
    except ValueError:
        allowed = ", ".join(r.value for r in Role)
        raise ValueError(f"Unknown role '{role}' (allowed: {allowed})") from None
    if project is not None:
        project = project.strip()
        if not 1 <= len(project) <= MAX_PROJECT_CHARS:
            raise ValueError(f"Project must contain between 1 and {MAX_PROJECT_CHARS} characters")
        if role == Role.ADMIN:
            raise ValueError("An admin token cannot be restricted to a project")
    row, token = _insert(label, role, project)
    return _public(row) | {"token": token}


def list_tokens(project: str | None = None) -> list[dict[str, str | None]]:
    """Return token metadata (never the hashes), optionally only one project's tokens."""
    statement = select(ApiToken).order_by(col(ApiToken.created_at), col(ApiToken.label))
    if project is not None:
        statement = statement.where(ApiToken.project == project)
    with session_scope() as session:
        return [_public(row) for row in session.exec(statement).all()]


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
    """Return the metadata of the project-scoped tokens."""
    return [token for token in list_tokens() if token["project"] is not None]


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
