"""Bearer tokens of the HTTP transport, stored in the database (SHA-256 digests only).

Every token lives in the ``ApiToken`` table: the tokens created with
``security-review-controller token create``, the project tokens created in the web interface and
the enrollment requests. Every server instance sharing the database sees a creation or a
revocation immediately. The web users, who log in with a password, are in web_users.

A token restricted to projects lists them in ``ApiTokenProject``; a token without project rows
(and without ``ApiToken.project``) reaches every project.

An enrollment request is a ``pending`` project row. When it creates the token (first
enrollment), the token is ``pending`` too: its secret is given to the requester at once but
authenticates nothing until an administrator approves the request. A complementary enrollment
adds a pending project to an active token, which keeps working for its other projects.
"""

import hmac
import secrets
import uuid
from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from sqlalchemy import ColumnElement
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, or_, select

from .database import session_scope
from .http_server import Role, TokenInfo, hash_token
from .models import ApiToken, ApiTokenProject, WebUser, utcnow
from .scanner import redact_secrets

MAX_TOKENS = 500
MAX_LABEL_CHARS = 64
MAX_PROJECT_CHARS = 200
# Projects one token may reach (granted or requested)
MAX_PROJECTS_PER_TOKEN = 50

ACTIVE = "active"
PENDING = "pending"
# Kinds of enrollment requests
NEW_TOKEN = "new"
ADDITIONAL_PROJECT = "additional"
# Anonymous requests are bounded: at most this many wait for a decision, and the requests
# nobody decided on are dropped after ENROLLMENT_TTL
MAX_PENDING_ENROLLMENTS = 20
# Pending requests of one client address, so that one client cannot fill the whole queue
MAX_PENDING_PER_ADDRESS = 3
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


def _links(session: Session, token_ids: Iterable[str]) -> dict[str, list[ApiTokenProject]]:
    """Project rows of the given tokens, grouped by token id (oldest first)."""
    ids = list(token_ids)
    grouped: dict[str, list[ApiTokenProject]] = {token_id: [] for token_id in ids}
    if ids:
        statement = (
            select(ApiTokenProject)
            .where(col(ApiTokenProject.token_id).in_(ids))
            .order_by(col(ApiTokenProject.created_at), col(ApiTokenProject.project))
        )
        for link in session.exec(statement).all():
            grouped[link.token_id].append(link)
    return grouped


def _active_projects(row: ApiToken, links: list[ApiTokenProject]) -> list[str] | None:
    """Projects a token reaches: None for an unrestricted token.

    A restricted token whose project rows are missing (database not migrated yet) keeps its
    legacy ``ApiToken.project``: a restriction is never lost.
    """
    if row.project is None and not links:
        return None
    if not links:
        return [row.project] if row.project is not None and not _is_pending(row) else []
    return [link.project for link in links if link.status == ACTIVE]


def _info(row: ApiToken, links: list[ApiTokenProject]) -> TokenInfo:
    """Convert a stored token into the identity used by the middleware."""
    projects = _active_projects(row, links)
    return TokenInfo(
        row.label,
        Role(row.role),
        projects=None if projects is None else frozenset(projects),
        token_id=row.id,
        pending=_is_pending(row),
    )


def _public(row: ApiToken, links: list[ApiTokenProject]) -> dict[str, Any]:
    """Metadata of a token, without its hash.

    ``projects`` is None for an unrestricted token; ``project`` is the first project.
    """
    return {
        "id": row.id,
        "label": row.label,
        "role": row.role,
        "project": row.project,
        "projects": _active_projects(row, links),
        "pending_projects": [link.project for link in links if link.status == PENDING],
        "status": PENDING if _is_pending(row) else ACTIVE,
        "created_at": row.created_at.isoformat(),
    }


def _request(link: ApiTokenProject, row: ApiToken) -> dict[str, Any]:
    """An enrollment request: the requested project, its token, who asked and from where."""
    return {
        "id": link.id,
        "token_id": row.id,
        "label": row.label,
        "role": row.role,
        "project": link.project,
        "kind": NEW_TOKEN if _is_pending(row) else ADDITIONAL_PROJECT,
        "status": link.status,
        "requested_by": link.requested_by,
        "requested_from": link.requested_from,
        "created_at": link.created_at.isoformat(),
    }


class DatabaseTokenStore:
    """Token lookup used by http_server.BearerAuthMiddleware (one or two queries a request).

    ``include_users`` (controller) counts the web users as credentials in has_tokens: the web
    API then requires a login as soon as a user exists, even without any token.
    """

    def __init__(self, include_users: bool = False) -> None:
        self.include_users = include_users

    def lookup(self, digest: bytes) -> TokenInfo | None:
        """Return the identity of the stored token with this SHA-256 digest, or None.

        The lookup key is the digest of the presented credential: its timing reveals nothing
        usable without a preimage of a stored hash. The final check is constant time.
        """
        with session_scope() as session:
            row = session.exec(select(ApiToken).where(ApiToken.token_hash == digest.hex())).first()
            if row is None or not hmac.compare_digest(bytes.fromhex(row.token_hash), digest):
                return None
            return _info(row, _links(session, [row.id])[row.id])

    def has_tokens(self) -> bool:
        """True when at least one active token is stored.

        Pending enrollment requests do not count: anybody may create one, and doing so must
        not switch on authentication for a server that has none.
        """
        with session_scope() as session:
            if session.exec(select(ApiToken.id).where(_active_clause()).limit(1)).first():
                return True
            return (
                self.include_users and session.exec(select(WebUser.id).limit(1)).first() is not None
            )


def _new_link(token_id: str, project: str, status: str, **fields: str | None) -> ApiTokenProject:
    """Build a project row (``fields``: requested_by, requested_from)."""
    return ApiTokenProject(
        id=str(uuid.uuid4()),
        token_id=token_id,
        project=project,
        status=status,
        requested_by=fields.get("requested_by"),
        requested_from=fields.get("requested_from"),
    )


def _insert(
    label: str, role: Role, projects: list[str] | None = None, **fields: str | None
) -> tuple[ApiToken, list[ApiTokenProject], str]:
    """Generate a token, store its digest and projects and return (row, project rows, token).

    ``fields`` sets the enrollment columns (status, requested_by, requested_from); the project
    rows get the status of the token. A duplicate label raises ValueError; the token limit is
    enforced here.
    """
    with session_scope() as session:
        count = session.exec(select(func.count()).select_from(ApiToken)).one()
    if count >= MAX_TOKENS:
        raise ValueError(f"The limit of {MAX_TOKENS} tokens has been reached")
    token = secrets.token_urlsafe(32)
    status = fields.get("status") or ACTIVE
    row = ApiToken(
        id=str(uuid.uuid4()),
        label=label,
        role=role.value,
        project=projects[0] if projects else None,
        token_hash=hash_token(token).hex(),
        status=status,
        requested_by=fields.get("requested_by"),
        requested_from=fields.get("requested_from"),
    )
    links = [
        _new_link(
            row.id,
            project,
            status,
            requested_by=fields.get("requested_by"),
            requested_from=fields.get("requested_from"),
        )
        for project in projects or []
    ]
    try:
        with session_scope() as session:
            session.add(row)
            session.flush()
            session.add_all(links)
            session.flush()
            for item in (row, *links):
                session.refresh(item)
                session.expunge(item)
    except IntegrityError as exc:
        raise ValueError(f"A token named '{label}' already exists") from exc
    return row, links, token


def _delete_token(session: Session, row: ApiToken) -> None:
    """Delete a token and its project rows (the rows first: they reference the token)."""
    for link in session.exec(
        select(ApiTokenProject).where(ApiTokenProject.token_id == row.id)
    ).all():
        session.delete(link)
    session.flush()
    session.delete(row)


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


def _clean_projects(projects: str | Iterable[str] | None) -> list[str] | None:
    """Validate a project or a list of projects; duplicates are dropped, order is kept."""
    if projects is None:
        return None
    names = [projects] if isinstance(projects, str) else list(projects)
    cleaned = list(dict.fromkeys(_clean_project(name) for name in names))
    if not cleaned:
        return None
    if len(cleaned) > MAX_PROJECTS_PER_TOKEN:
        raise ValueError(f"A token may reach at most {MAX_PROJECTS_PER_TOKEN} projects")
    return cleaned


def create_token(
    label: str, role: Role | str, projects: str | Iterable[str] | None = None
) -> dict[str, Any]:
    """Create a token and return its metadata with the raw secret, shown exactly once.

    ``projects`` (one name or several) restricts the token to these projects, for the MCP
    tools and the web interface. It is refused for ``admin``, whose rights (rules, every
    project) cannot be scoped.
    """
    label = _clean_label(label)
    try:
        role = Role(str(role).strip().lower())
    except ValueError:
        allowed = ", ".join(r.value for r in Role)
        raise ValueError(f"Unknown role '{role}' (allowed: {allowed})") from None
    cleaned = _clean_projects(projects)
    if cleaned is not None and role == Role.ADMIN:
        raise ValueError("An admin token cannot be restricted to a project")
    row, links, token = _insert(label, role, cleaned)
    return _public(row, links) | {"token": token}


def list_tokens(project: str | None = None) -> list[dict[str, Any]]:
    """Return token metadata (never the hashes), optionally only the tokens of one project.

    With ``project``, only the tokens that reach it (approved) are returned.
    """
    statement = select(ApiToken).order_by(col(ApiToken.created_at), col(ApiToken.label))
    if project is not None:
        granted = select(ApiTokenProject.token_id).where(
            ApiTokenProject.project == project, ApiTokenProject.status == ACTIVE
        )
        legacy = (ApiToken.project == project) & ~col(ApiToken.id).in_(
            select(ApiTokenProject.token_id)
        )
        statement = statement.where(or_(col(ApiToken.id).in_(granted), legacy))
    with session_scope() as session:
        rows = session.exec(statement).all()
        links = _links(session, [row.id for row in rows])
        return [_public(row, links[row.id]) for row in rows]


def revoke_token(reference: str) -> dict[str, Any]:
    """Delete a token by id or label and return its metadata.

    The next request presenting it is rejected.
    """
    with session_scope() as session:
        row = session.exec(
            select(ApiToken).where(or_(ApiToken.id == reference, ApiToken.label == reference))
        ).first()
        if row is None:
            raise ValueError(f"Token '{reference}' was not found")
        revoked = _public(row, _links(session, [row.id])[row.id])
        _delete_token(session, row)
    return revoked


# ── Project tokens (web interface) ───────────────────────────────────────────


def list_project_tokens() -> list[dict[str, Any]]:
    """Return the metadata of the active project-scoped tokens."""
    return [
        token
        for token in list_tokens()
        if token["projects"] is not None and token["status"] == ACTIVE
    ]


def create_project_token(
    label: str,
    projects: str | Iterable[str],
    role: Role | str = Role.READER,
) -> dict[str, Any]:
    """Create a role-specific token restricted to one or several projects."""
    if _clean_projects(projects) is None:
        raise ValueError("A project token needs at least one project")
    return create_token(label, role, projects)


def revoke_project_token(token_id: str) -> None:
    """Delete a project token by id; other tokens cannot be revoked this way."""
    with session_scope() as session:
        row = session.exec(
            select(ApiToken).where(ApiToken.id == token_id, col(ApiToken.project).is_not(None))
        ).first()
        if row is None:
            raise ValueError(f"Project token '{token_id}' was not found")
        _delete_token(session, row)


# ── Enrollment requests ──────────────────────────────────────────────────────


def _purge_expired_requests() -> None:
    """Drop the enrollment requests that waited longer than ENROLLMENT_TTL.

    An expired first enrollment deletes its token; an expired complementary request only
    drops the requested project.
    """
    cutoff = utcnow() - ENROLLMENT_TTL
    with session_scope() as session:
        for row in session.exec(
            select(ApiToken).where(ApiToken.status == PENDING, ApiToken.created_at < cutoff)
        ).all():
            _delete_token(session, row)
        for link in session.exec(
            select(ApiTokenProject).where(
                ApiTokenProject.status == PENDING, ApiTokenProject.created_at < cutoff
            )
        ).all():
            session.delete(link)


def _clean_requester(
    requested_by: str | None, requested_from: str | None
) -> tuple[str | None, str | None]:
    """Bound the requester fields; ``requested_by`` is free text, so secrets are masked."""
    if requested_by is not None:
        requested_by = redact_secrets(requested_by.strip())[:MAX_REQUESTED_BY_CHARS] or None
    if requested_from is not None:
        requested_from = requested_from[:MAX_ADDRESS_CHARS]
    return requested_by, requested_from


def _check_pending_capacity(requested_from: str | None = None) -> None:
    """Refuse a new request while MAX_PENDING_ENROLLMENTS requests wait for a decision, or
    MAX_PENDING_PER_ADDRESS requests of the client address ``requested_from`` (None: stdio)."""
    _purge_expired_requests()
    with session_scope() as session:
        pending = session.exec(
            select(func.count())
            .select_from(ApiTokenProject)
            .where(ApiTokenProject.status == PENDING)
        ).one()
        from_address = (
            session.exec(
                select(func.count())
                .select_from(ApiTokenProject)
                .where(
                    ApiTokenProject.status == PENDING,
                    ApiTokenProject.requested_from == requested_from,
                )
            ).one()
            if requested_from is not None
            else 0
        )
    if from_address >= MAX_PENDING_PER_ADDRESS:
        raise ValueError(
            "Too many enrollment requests from this address are waiting for approval; "
            "ask an administrator"
        )
    if pending >= MAX_PENDING_ENROLLMENTS:
        raise ValueError(
            "Too many enrollment requests are waiting for approval; ask an administrator"
        )


def request_enrollment(
    project: str,
    label: str | None = None,
    requested_by: str | None = None,
    requested_from: str | None = None,
) -> dict[str, Any]:
    """Store a first enrollment request and return the new token, shown once.

    ``label`` (default: the project name) gets a random suffix. The request is an ``mcp``
    token restricted to ``project`` and created ``pending``: it authenticates nothing until an
    administrator approves it. Anybody may call this, so the number of pending requests is
    bounded (in all and per client address) and ``requested_by`` (free text) is redacted.
    ``request_id`` identifies the request for the administrator.
    """
    project = _clean_project(project)
    # The requester never picks the exact label: a random suffix keeps labels unique without
    # telling an anonymous client which labels already exist
    base = label.strip() if label is not None and label.strip() else f"{project}-enroll"
    suffix = f"-{secrets.token_hex(3)}"
    label = _clean_label(base[: MAX_LABEL_CHARS - len(suffix)] + suffix)
    requested_by, requested_from = _clean_requester(requested_by, requested_from)
    _check_pending_capacity(requested_from)
    row, links, token = _insert(
        label,
        ENROLLMENT_ROLE,
        [project],
        status=PENDING,
        requested_by=requested_by,
        requested_from=requested_from,
    )
    return _public(row, links) | {
        "request_id": links[0].id,
        "kind": NEW_TOKEN,
        "requested_by": requested_by,
        "requested_from": requested_from,
        "token": token,
    }


def request_additional_project(
    token_id: str,
    project: str,
    requested_by: str | None = None,
    requested_from: str | None = None,
) -> dict[str, Any]:
    """Complementary enrollment: ask for one more project on an active restricted token.

    The token keeps working for its other projects and reaches ``project`` once an
    administrator approves the request. No new secret is created.

    Raises:
        ValueError: Unknown or pending token, unrestricted token, project already granted or
            requested, or too many pending requests.
    """
    project = _clean_project(project)
    requested_by, requested_from = _clean_requester(requested_by, requested_from)
    _check_pending_capacity(requested_from)
    with session_scope() as session:
        row = session.get(ApiToken, token_id)
        if row is None:
            raise ValueError("Token not found")
        if _is_pending(row):
            raise ValueError("This token is still waiting for the approval of its first request")
        links = _links(session, [row.id])[row.id]
        if _active_projects(row, links) is None:
            raise ValueError("This token is not restricted: it already reaches every project")
        existing = next((link for link in links if link.project == project), None)
        if existing is not None and existing.status == ACTIVE:
            raise ValueError(f"This token already reaches project '{project}'")
        if existing is not None:
            raise ValueError(f"A request for project '{project}' is already waiting for approval")
        if len(links) >= MAX_PROJECTS_PER_TOKEN:
            raise ValueError(f"A token may reach at most {MAX_PROJECTS_PER_TOKEN} projects")
        link = _new_link(
            row.id, project, PENDING, requested_by=requested_by, requested_from=requested_from
        )
        session.add(link)
        try:
            session.flush()
        except IntegrityError as exc:
            # Same request sent twice at the same time
            raise ValueError(
                f"A request for project '{project}' is already waiting for approval"
            ) from exc
        session.refresh(link)
        return _request(link, row) | {"projects": _active_projects(row, links)}


def list_enrollments() -> list[dict[str, Any]]:
    """Return the enrollment requests waiting for approval (never a secret), oldest first."""
    statement = (
        select(ApiTokenProject, ApiToken)
        .join(ApiToken, col(ApiToken.id) == col(ApiTokenProject.token_id))
        .where(ApiTokenProject.status == PENDING)
        .order_by(col(ApiTokenProject.created_at), col(ApiToken.label))
    )
    with session_scope() as session:
        return [_request(link, row) for link, row in session.exec(statement).all()]


def _pending_request(session: Session, reference: str) -> tuple[ApiTokenProject, ApiToken]:
    """Return the pending request with this id, or the only one of the token with this id or
    label; raise ValueError otherwise."""
    link = session.exec(
        select(ApiTokenProject).where(
            ApiTokenProject.id == reference, ApiTokenProject.status == PENDING
        )
    ).first()
    if link is None:
        links = session.exec(
            select(ApiTokenProject)
            .join(ApiToken, col(ApiToken.id) == col(ApiTokenProject.token_id))
            .where(
                ApiTokenProject.status == PENDING,
                or_(ApiToken.id == reference, ApiToken.label == reference),
            )
        ).all()
        if len(links) > 1:
            raise ValueError(
                f"Token '{reference}' has several pending requests; use the request id"
            )
        link = links[0] if links else None
    if link is None:
        raise ValueError(f"Enrollment request '{reference}' was not found")
    row = session.get(ApiToken, link.token_id)
    if row is None:
        raise ValueError(f"Enrollment request '{reference}' was not found")
    return link, row


def approve_enrollment(reference: str) -> dict[str, Any]:
    """Approve a pending request (request id, or token id or label when it has only one).

    A first enrollment activates the token; a complementary one adds the project to it. The
    change applies from the next request.
    """
    with session_scope() as session:
        link, row = _pending_request(session, reference)
        approved = _request(link, row) | {"status": ACTIVE}
        link.status = ACTIVE
        session.add(link)
        if _is_pending(row):
            row.status = ACTIVE
            session.add(row)
        session.flush()
        return approved | {"projects": _active_projects(row, _links(session, [row.id])[row.id])}


def reject_enrollment(reference: str) -> dict[str, Any]:
    """Reject a pending request (same references as approve_enrollment).

    A rejected first enrollment deletes its token; a rejected complementary request only drops
    the project, the token keeps its other projects.
    """
    with session_scope() as session:
        link, row = _pending_request(session, reference)
        rejected = _request(link, row)
        if _is_pending(row):
            _delete_token(session, row)
        else:
            session.delete(link)
    return rejected


def enrollment_status(token_id: str | None) -> dict[str, Any]:
    """Status of the enrollments of a token id (as seen by its holder).

    ``projects`` are the projects the token reaches, ``pending_projects`` those waiting for an
    administrator.
    """
    if token_id is not None:
        with session_scope() as session:
            row = session.get(ApiToken, token_id)
            if row is not None:
                public = _public(row, _links(session, [row.id])[row.id])
                return {
                    "status": public["status"],
                    "label": row.label,
                    "project": row.project,
                    "projects": public["projects"],
                    "pending_projects": public["pending_projects"],
                    "requested_at": row.created_at.isoformat(),
                }
    return {"status": "not_enrolled"}
