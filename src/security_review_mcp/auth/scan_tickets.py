"""Single-use tickets of the codebase scans started by an MCP agent (``ScanTicket``).

The MCP tool start_codebase_scan asks the controller for a ticket (``POST /api/v1/scan/tickets``,
see web_api.scan_routes), with the token of its caller relayed by the MCP server: an OAuth
access token, a personal or role ``mcp`` token or an ``admin`` token. The agent then runs
``security-review-ci scan-code`` (and ``scan-deps``) with the ticket on stdin: the files of the
workstation reach the controller without going through the model, and the developer needs no
``ci`` token.

A ticket is a bearer credential with these limits:

- only its SHA-256 digest is stored; it is shown once, to the agent that asked for it;
- it reaches the code scan and the dependency scan of its project only (http_server.TICKET_PATHS),
  each once (``consume``), until it expires (SECREVIEW_SCAN_TICKET_TTL_SECONDS); a ticket asked
  for one scan only (``scope``) is issued with the other one already used;
- it acts as a ``ci`` token of its project, with the rights of the token that asked for it read
  again at each use: the web user of a personal token or of an OAuth grant must still write to
  the project (``reports.write``), a token must still exist, be valid and reach the project;
- a caller may hold at most MAX_PENDING_PER_ISSUER tickets that are not expired; the expired ones
  are deleted when a new one is issued.

Every issue is written to the audit log. The ticket passes through the context of the model
(the agent copies it to the command): it is only worth one scan of each kind, for a short time.
"""

import hmac
import secrets
import uuid
from collections.abc import Mapping
from datetime import timedelta
from typing import Any, Literal

from sqlalchemy import delete, func, update
from sqlmodel import Session, col, select

from ..config import get_settings
from ..http_server import MCP_ROLES, Role, TokenInfo, hash_token
from ..observability import audit
from ..observability.audit import AuditAction
from ..storage.database import session_scope
from ..storage.models import ApiToken, ScanTicket, WebUser, as_utc, utcnow
from ..storage.project_names import normalize_project

# Prefix of a ticket, so that a leaked one is recognized (secret scanners, logs)
PREFIX = "secreview_scan_"
# Tickets of one caller that may be valid at the same time
MAX_PENDING_PER_ISSUER = 20

Kind = Literal["code", "deps"]
Scope = Literal["all", "code", "deps"]
_USED_COLUMNS = {"code": ScanTicket.code_used_at, "deps": ScanTicket.deps_used_at}


def issue(project: str, state: Mapping[str, Any], scope: Scope = "all") -> dict[str, Any]:
    """Issue a ticket for ``project`` to the caller described by the ASGI ``state`` of its
    request (set by http_server.BearerAuthMiddleware). With ``scope`` ``code`` or ``deps``, the
    other scan is marked as used at once: the ticket opens no scan the agent did not ask for.

    Returns:
        ``ticket`` (shown once), ``project`` and ``expires_at``.

    Raises:
        ValueError: If the project name is invalid, the caller may not save reports on it, is
            not tied to a user nor to a stored token, or holds too many tickets.
    """
    from ..http_server import write_scope

    project = normalize_project(project)
    projects = state.get("auth_projects")
    writable = write_scope(state)
    if (projects is not None and project not in projects) or (
        writable is not None and project not in writable
    ):
        raise ValueError(f"This token cannot save reports on project {project!r} (reports.write)")
    issued_to = str(state.get("auth_client") or "")[:200]
    token_id = state.get("auth_token_id")
    owner = state.get("auth_owner")
    now = utcnow()
    secret = PREFIX + secrets.token_urlsafe(32)
    with session_scope() as session:
        user_id = None
        if owner is not None:
            user_id = session.exec(select(WebUser.id).where(WebUser.username == owner)).first()
            if user_id is None:
                raise ValueError("The user of this token is gone")
        if user_id is None and token_id is None:
            raise ValueError("Only a stored token or the token of a web user may ask for a ticket")
        session.execute(delete(ScanTicket).where(col(ScanTicket.expires_at) <= now))
        pending = session.exec(
            select(func.count())
            .select_from(ScanTicket)
            .where(ScanTicket.issued_to == issued_to, col(ScanTicket.expires_at) > now)
        ).one()
        if pending >= MAX_PENDING_PER_ISSUER:
            raise ValueError(f"Too many pending scan tickets ({pending}): wait for them to expire")
        row = ScanTicket(
            id=uuid.uuid4().hex,
            ticket_hash=hash_token(secret).hex(),
            project=project,
            user_id=user_id,
            token_id=token_id,
            issued_to=issued_to,
            created_at=now,
            expires_at=now + timedelta(seconds=get_settings().scan_ticket_ttl_seconds),
            code_used_at=now if scope == "deps" else None,
            deps_used_at=now if scope == "code" else None,
        )
        session.add(row)
        audit.record(
            session,
            AuditAction.SCAN_TICKET_ISSUED,
            audit.token_actor(issued_to),
            "scan_ticket",
            row.id,
            project=project,
            details={"expires_at": row.expires_at.isoformat(), "scope": scope},
        )
        return {"ticket": secret, "project": project, "expires_at": row.expires_at.isoformat()}


def _token_reaches(session: Session, token_id: str, project: str) -> bool:
    """True when the stored token that asked for a ticket still exists, is valid, has an MCP
    role and reaches ``project``."""
    from .token_store import _info, _links  # token_store looks tickets up here

    row = session.get(ApiToken, token_id)
    if row is None or row.role not in MCP_ROLES:
        return False
    info = _info(row, _links(session, [row.id])[row.id])
    return not info.expired and (info.projects is None or project in info.projects)


def _user_writes(session: Session, user_id: int, project: str) -> str | None:
    """Username of the web user who asked for a ticket when it may still read and write to
    ``project``, None otherwise (gone, password to change, grants unreadable)."""
    from .. import app_settings
    from .token_store import _user_projects

    user = session.get(WebUser, user_id)
    if user is None or user.must_change_password:
        return None
    if not app_settings.personal_tokens_enabled(session):
        return None
    try:
        projects, writable = _user_projects(session, user_id)
    except ValueError:
        return None
    if any(scope is not None and project not in scope for scope in (projects, writable)):
        return None
    return user.username


def ticket_info(session: Session, digest: bytes) -> TokenInfo | None:
    """Identity of a scan ticket, or None when unknown, used for both scans or when the rights
    of the token or user that asked for it no longer reach its project (fail closed); an
    expired one is marked ``expired``."""
    row = session.exec(select(ScanTicket).where(ScanTicket.ticket_hash == digest.hex())).first()
    if row is None or not hmac.compare_digest(bytes.fromhex(row.ticket_hash), digest):
        return None
    if row.code_used_at is not None and row.deps_used_at is not None:
        return None
    if row.token_id is not None and not _token_reaches(session, row.token_id, row.project):
        return None
    owner = None
    if row.user_id is not None:
        owner = _user_writes(session, row.user_id, row.project)
        if owner is None:
            return None
    project = frozenset({row.project})
    return TokenInfo(
        f"{row.issued_to}:ticket"[:200],
        Role.CI,
        projects=project,
        write_projects=project,
        expired=as_utc(row.expires_at) <= utcnow(),
        owner=owner,
        ticket_id=row.id,
    )


def consume(ticket_id: str, kind: Kind) -> bool:
    """Mark the ticket as used for a scan of this ``kind``, atomically: False when it was
    already used for it or has expired (a second request with the same ticket is refused)."""
    column = _USED_COLUMNS[kind]
    now = utcnow()
    with session_scope() as session:
        result = session.execute(
            update(ScanTicket)
            .where(
                col(ScanTicket.id) == ticket_id,
                col(column).is_(None),
                col(ScanTicket.expires_at) > now,
            )
            .values({column.key: now})
        )
        return result.rowcount == 1


def release(ticket_id: str, kind: Kind) -> None:
    """Give back a ticket whose scan failed before it stored anything (invalid request, busy
    OpenGrep), so that the client may retry while it is valid."""
    column = _USED_COLUMNS[kind]
    with session_scope() as session:
        session.execute(
            update(ScanTicket).where(col(ScanTicket.id) == ticket_id).values({column.key: None})
        )


def delete_user_tickets(session: Session, user_id: int) -> None:
    """Delete the tickets of a web user (before the user)."""
    session.execute(delete(ScanTicket).where(col(ScanTicket.user_id) == user_id))
