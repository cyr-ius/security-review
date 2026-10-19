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

A token may expire (``expires_at``, bounded by SECREVIEW_TOKEN_MAX_DAYS): it then authenticates
nothing but stays listed, so that an administrator rotates or revokes it. A rotation replaces the
secret of a token (same id, label, role and projects); the previous secret may keep working
during a grace period, so that its clients are updated without an interruption.

A token has one of the roles of http_server.TOKEN_ROLES: tokens are for machines (MCP agent,
pipeline, Prometheus, administration). A person reaches the web API through a session, whose
rights come from its groups (see access_control). A stored token of another role (``reader`` or
``triager``, from an older version) authenticates nothing.

The web interface manages the ``mcp``, ``ci`` and ``api`` tokens (WEB_TOKEN_ROLES): an
administrator creates them for some projects or for every project, changes their projects,
rotates and revokes them. The ``admin`` and ``metrics`` tokens are managed with the CLI only.

An ``api`` token reaches the REST API (Swagger, scripts) with the rights of the access control
(see access_control), read at each request:

- a **role token** (``access_role_id``), created on the Tokens screen, holds the permissions of
  one role on its projects (every project, or a list for a role made of scoped permissions);
- a **personal token** (``user_id``), created by a web user for itself (label
  ``<username>:<label>``), holds the current rights of that user, and is deleted with it. Its
  projects and its secret cannot be changed; an administrator may revoke it.

A web user may also create a **personal** ``mcp`` token for its MCP agent: it reaches the
projects the user may read (``reports.read`` of its groups), read at each request, so that a
project granted to or removed from the user applies at once. It has no project rows and no
complementary enrollment: an administrator grants the project to the user instead. A web user
holds at most SECREVIEW_PERSONAL_TOKENS_PER_USER personal tokens of each role.

Like every token, an ``api`` token never accepts a risk nor marks a false positive.

Every creation, rotation, revocation, change of projects and enrollment decision is written to
the audit log.
"""

import hmac
import secrets
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, or_, select

from . import audit
from .audit import AuditAction
from .config import MAX_RETENTION_DAYS, get_settings
from .database import session_scope
from .http_server import TOKEN_ROLES, Role, TokenInfo, hash_token
from .models import ApiToken, ApiTokenProject, WebUser, as_utc, utcnow
from .project_names import normalize_project
from .scanner import redact_secrets

MAX_TOKENS = 500
MAX_LABEL_CHARS = 64
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
# Longest time the previous secret of a rotated token keeps working
MAX_ROTATION_GRACE_HOURS = 168
# Roles whose rights cannot be scoped to projects
UNSCOPED_ROLES = frozenset({Role.ADMIN, Role.METRICS})
# Roles of the tokens managed in the web interface (admin and metrics tokens: CLI only)
WEB_TOKEN_ROLES = frozenset({Role.MCP, Role.CI, Role.API})
# Roles of the personal tokens of a web user (REST API, MCP agent)
PERSONAL_TOKEN_ROLES = frozenset({Role.API, Role.MCP})


def _is_pending(row: ApiToken) -> bool:
    """True for an enrollment request that no administrator has approved yet."""
    return row.status == PENDING


def _is_expired(row: ApiToken, now: datetime | None = None) -> bool:
    """True for a token past its expiry date."""
    return row.expires_at is not None and as_utc(row.expires_at) <= (now or utcnow())


def _expiry(expires_in_days: int | None, now: datetime) -> datetime | None:
    """Expiry date of a token created or rotated now.

    Without ``expires_in_days`` the token gets the longest validity (SECREVIEW_TOKEN_MAX_DAYS),
    or none when that setting is 0.

    Raises:
        ValueError: If ``expires_in_days`` is out of bounds.
    """
    longest = get_settings().token_max_days
    if expires_in_days is None:
        return now + timedelta(days=longest) if longest else None
    limit = longest or MAX_RETENTION_DAYS
    if not 1 <= expires_in_days <= limit:
        raise ValueError(f"The validity of a token must be between 1 and {limit} days")
    return now + timedelta(days=expires_in_days)


def _iso(value: datetime | None) -> str | None:
    """ISO 8601 form of an optional date (UTC)."""
    return None if value is None else as_utc(value).isoformat()


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
    """Convert a stored token into the identity used by the middleware.

    A ``ci`` token is never unrestricted: without projects it reaches none (fail closed). An
    expired token is marked ``expired``: the middleware rejects it.
    """
    projects = _active_projects(row, links)
    if projects is None and row.role == Role.CI:
        projects = []
    return TokenInfo(
        row.label,
        Role(row.role),
        projects=None if projects is None else frozenset(projects),
        token_id=row.id,
        pending=_is_pending(row),
        expired=_is_expired(row),
    )


def _public(row: ApiToken, links: list[ApiTokenProject]) -> dict[str, Any]:
    """Metadata of a token, without its hash.

    ``projects`` is None for an unrestricted token; ``project`` is the first project.
    ``grace_until`` is the end of the grace period of the previous secret after a rotation.
    """
    now = utcnow()
    grace = row.previous_expires_at if row.previous_token_hash else None
    return {
        "id": row.id,
        "label": row.label,
        "role": row.role,
        "project": row.project,
        "projects": _active_projects(row, links),
        "pending_projects": [link.project for link in links if link.status == PENDING],
        "status": PENDING if _is_pending(row) else ACTIVE,
        "created_at": row.created_at.isoformat(),
        "expires_at": _iso(row.expires_at),
        "expired": _is_expired(row, now),
        "rotated_at": _iso(row.rotated_at),
        "grace_until": _iso(grace) if grace is not None and as_utc(grace) > now else None,
        "access_role_id": row.access_role_id,
        "personal": row.user_id is not None,
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
        usable without a preimage of a stored hash. The final check is constant time. The
        previous secret of a rotated token matches until the end of its grace period.
        """
        hexdigest = digest.hex()
        with session_scope() as session:
            row = session.exec(
                select(ApiToken).where(
                    or_(ApiToken.token_hash == hexdigest, ApiToken.previous_token_hash == hexdigest)
                )
            ).first()
            if row is None or row.role not in TOKEN_ROLES or not _matches(row, digest):
                return None
            info = _info(row, _links(session, [row.id])[row.id])
            if row.role == Role.API:
                return _api_info(session, row, info)
            if row.user_id is not None:
                return _personal_mcp_info(session, row, info)
            return info

    def has_tokens(self) -> bool:
        """True when at least one active token is stored.

        Pending enrollment requests do not count: anybody may create one, and doing so must
        not switch on authentication for a server that has none. Expired tokens do count: a
        server whose tokens have all expired stays closed (fail closed).
        """
        with session_scope() as session:
            if session.exec(select(ApiToken.id).where(_active_clause()).limit(1)).first():
                return True
            return (
                self.include_users and session.exec(select(WebUser.id).limit(1)).first() is not None
            )


def _api_info(session: Session, row: ApiToken, info: TokenInfo) -> TokenInfo | None:
    """Identity of an ``api`` token, with its grants read now: those of its user (personal
    token) or of its role on its projects (role token). None when the user or the role is gone,
    or when the token grants nothing (fail closed)."""
    from . import access_control  # access_control depends on this module

    must_change = False
    if row.user_id is not None:
        user = session.get(WebUser, row.user_id)
        if user is None:
            return None
        try:
            grants = access_control.user_grants(session, row.user_id)
        except ValueError:
            return None
        must_change = user.must_change_password
    elif row.access_role_id is not None and info.projects != frozenset():
        grants = access_control.role_token_grants(session, row.access_role_id, info.projects)
    else:
        return None
    if not grants:
        return None
    return TokenInfo(
        info.label,
        Role.API,
        projects=access_control.scope(grants, access_control.Permission.REPORTS_READ),
        token_id=info.token_id,
        pending=info.pending,
        expired=info.expired,
        grants=grants,
        must_change_password=must_change,
    )


def _user_projects(session: Session, user_id: int) -> frozenset[str] | None:
    """Projects a web user may read now (None: every project, empty: none).

    Raises:
        ValueError: If the user is gone or its grants are too large.
    """
    from . import access_control  # access_control depends on this module

    if session.get(WebUser, user_id) is None:
        raise ValueError(f"User {user_id} not found")
    grants = access_control.user_grants(session, user_id)
    return access_control.scope(grants, access_control.Permission.REPORTS_READ)


def _personal_mcp_info(session: Session, row: ApiToken, info: TokenInfo) -> TokenInfo | None:
    """Identity of a personal ``mcp`` token: the projects its user may read now. None when the
    user is gone, must change a password set by an administrator (as its api tokens, see
    web_api.deps) or its grants cannot be read (fail closed); a user without any project gets a
    token that reaches none."""
    user = session.get(WebUser, row.user_id)
    if user is None or user.must_change_password:
        return None
    try:
        projects = _user_projects(session, user.id)  # type: ignore[arg-type]
    except ValueError:
        return None
    return TokenInfo(
        info.label,
        Role.MCP,
        projects=projects,
        token_id=info.token_id,
        pending=info.pending,
        expired=info.expired,
    )


def _matches(row: ApiToken, digest: bytes) -> bool:
    """Constant-time check of a digest against the secret of a token, or its previous secret
    during the grace period of a rotation."""
    if hmac.compare_digest(bytes.fromhex(row.token_hash), digest):
        return True
    if row.previous_token_hash is None or row.previous_expires_at is None:
        return False
    return hmac.compare_digest(bytes.fromhex(row.previous_token_hash), digest) and (
        as_utc(row.previous_expires_at) > utcnow()
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
    label: str,
    role: Role,
    projects: list[str] | None = None,
    expires_in_days: int | None = None,
    event: tuple[AuditAction, str | None] = (AuditAction.TOKEN_CREATED, None),
    user_id: int | None = None,
    access_role_id: int | None = None,
    **fields: str | None,
) -> tuple[ApiToken, list[ApiTokenProject], str]:
    """Generate a token, store its digest and projects and return (row, project rows, token).

    ``user_id`` and ``access_role_id`` set the owner or the role of an ``api`` token.
    ``fields`` sets the enrollment columns (status, requested_by, requested_from); the project
    rows get the status of the token. ``event`` is the audit action and actor written with the
    token. A duplicate label raises ValueError; the token limit is enforced here.
    """
    expires_at = _expiry(expires_in_days, utcnow())
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
        expires_at=expires_at,
        user_id=user_id,
        access_role_id=access_role_id,
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
            action, actor = event
            audit.record(
                session,
                action,
                actor,
                "token",
                row.id,
                row.project,
                {
                    "label": label,
                    "role": role.value,
                    "projects": projects,
                    "expires_at": _iso(expires_at),
                    "requested_by": fields.get("requested_by"),
                    "requested_from": fields.get("requested_from"),
                    "access_role_id": access_role_id,
                    "personal": user_id is not None,
                },
            )
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
    """Strip a token label and check its length.

    ``:`` is refused: it separates the user from the label of a personal token
    (``<username>:<label>``), so that no other token passes for one in the logs and the audit.
    """
    label = label.strip()
    if not 1 <= len(label) <= MAX_LABEL_CHARS:
        raise ValueError(f"Token label must contain between 1 and {MAX_LABEL_CHARS} characters")
    if ":" in label:
        raise ValueError("Token label must not contain ':' (it names the user of a personal token)")
    return label


def _clean_project(project: str) -> str:
    """Normalize a project name (see project_names.normalize_project)."""
    return normalize_project(project)


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
    label: str,
    role: Role | str,
    projects: str | Iterable[str] | None = None,
    expires_in_days: int | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """Create a token and return its metadata with the raw secret, shown exactly once.

    ``role`` is one of TOKEN_ROLES. ``projects`` (one name or several) restricts the token to
    these projects, for the MCP tools and the pipeline routes. It is refused for ``admin``,
    whose rights (rules, every project) cannot be scoped, and for ``metrics`` (whole database),
    and required for ``ci``, the pipeline token. ``expires_in_days`` defaults to
    SECREVIEW_TOKEN_MAX_DAYS (0: no expiry). The creation is audited with ``actor`` (default
    ``cli``).
    """
    label = _clean_label(label)
    allowed = ", ".join(sorted(r.value for r in TOKEN_ROLES))
    try:
        role = Role(str(role).strip().lower())
    except ValueError:
        raise ValueError(f"Unknown role '{role}' (allowed: {allowed})") from None
    if role not in TOKEN_ROLES:
        raise ValueError(
            f"A token cannot have the role '{role.value}' (allowed: {allowed}): give a person "
            "web access through a group"
        )
    if role == Role.API:
        raise ValueError(
            "An api token is created with a role on the Tokens screen, or by a web user for "
            "itself in My account"
        )
    cleaned = _clean_projects(projects)
    if cleaned is not None and role in UNSCOPED_ROLES:
        raise ValueError(f"A {role.value} token cannot be restricted to a project")
    if cleaned is None and role == Role.CI:
        raise ValueError("A ci token must be restricted to at least one project")
    row, links, token = _insert(
        label, role, cleaned, expires_in_days, (AuditAction.TOKEN_CREATED, actor)
    )
    return _public(row, links) | {"token": token}


def list_tokens(project: str | None = None) -> list[dict[str, Any]]:
    """Return token metadata (never the hashes), optionally only the tokens of one project.

    With ``project``, only the tokens that reach it (approved) are returned.
    """
    statement = select(ApiToken).order_by(col(ApiToken.created_at), col(ApiToken.label))
    if project is not None:
        project = normalize_project(project)
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
        return [
            _personal_public(session, row)
            if row.user_id is not None
            else _public(row, links[row.id])
            for row in rows
        ]


def _audit_token(
    session: Session, action: AuditAction, actor: str | None, public: dict[str, Any], **extra: Any
) -> None:
    """Write an audit event about a token (its metadata, never its secret)."""
    audit.record(
        session,
        action,
        actor,
        "token",
        public["id"],
        public["project"],
        {"label": public["label"], "role": public["role"], "projects": public["projects"]} | extra,
    )


def revoke_token(reference: str, actor: str | None = None) -> dict[str, Any]:
    """Delete a token by id or label and return its metadata.

    The next request presenting it is rejected. The revocation is audited with ``actor``.
    """
    with session_scope() as session:
        row = session.exec(
            select(ApiToken).where(or_(ApiToken.id == reference, ApiToken.label == reference))
        ).first()
        if row is None:
            raise ValueError(f"Token '{reference}' was not found")
        revoked = _public(row, _links(session, [row.id])[row.id])
        _delete_token(session, row)
        _audit_token(session, AuditAction.TOKEN_REVOKED, actor, revoked)
    return revoked


def rotate_token(
    reference: str,
    grace_hours: int = 0,
    expires_in_days: int | None = None,
    actor: str | None = None,
    project_token: bool = False,
) -> dict[str, Any]:
    """Replace the secret of a token (by id or label) and return the new one, shown once.

    The token keeps its id, label, role and projects. During ``grace_hours`` (at most
    MAX_ROTATION_GRACE_HOURS) the previous secret keeps working, unless the token had expired:
    an expired secret never comes back. The new expiry date follows ``expires_in_days`` (same
    rules as create_token). ``project_token`` (web interface) only accepts a token of
    WEB_TOKEN_ROLES.

    Raises:
        ValueError: Unknown token, enrollment request still pending, or bounds exceeded.
    """
    if not 0 <= grace_hours <= MAX_ROTATION_GRACE_HOURS:
        raise ValueError(f"The grace period must be between 0 and {MAX_ROTATION_GRACE_HOURS} hours")
    now = utcnow()
    expires_at = _expiry(expires_in_days, now)
    token = secrets.token_urlsafe(32)
    statement = select(ApiToken).where(or_(ApiToken.id == reference, ApiToken.label == reference))
    if project_token:
        statement = _web_token_query(reference)
    with session_scope() as session:
        row = session.exec(statement).first()
        if row is None:
            kind = "Project token" if project_token else "Token"
            raise ValueError(f"{kind} '{reference}' was not found")
        if _is_pending(row):
            raise ValueError("An enrollment request waiting for approval cannot be rotated")
        if row.user_id is not None:
            # Its new secret would carry the rights of the user to whoever rotates it
            raise ValueError("A personal token cannot be rotated: its user creates a new one")
        grace = grace_hours if not _is_expired(row, now) else 0
        row.previous_token_hash = row.token_hash if grace else None
        row.previous_expires_at = now + timedelta(hours=grace) if grace else None
        row.token_hash = hash_token(token).hex()
        row.rotated_at = now
        row.expires_at = expires_at
        session.add(row)
        session.flush()
        rotated = _public(row, _links(session, [row.id])[row.id])
        _audit_token(
            session,
            AuditAction.TOKEN_ROTATED,
            actor,
            rotated,
            grace_hours=grace,
            expires_at=rotated["expires_at"],
        )
    return rotated | {"token": token}


def token_counts(expiring_within: timedelta = timedelta(days=14)) -> dict[str, Any]:
    """Count the tokens by role and state (``active``, ``expired``, ``pending``), the active
    ones that expire within ``expiring_within`` and the enrollment requests waiting."""
    now = utcnow()
    by_role: dict[tuple[str, str], int] = {}
    expiring = 0
    with session_scope() as session:
        for row in session.exec(select(ApiToken)).all():
            if _is_pending(row):
                state = PENDING
            elif _is_expired(row, now):
                state = "expired"
            else:
                state = ACTIVE
                if row.expires_at is not None and as_utc(row.expires_at) <= now + expiring_within:
                    expiring += 1
            by_role[(row.role, state)] = by_role.get((row.role, state), 0) + 1
        pending = session.exec(
            select(func.count())
            .select_from(ApiTokenProject)
            .where(ApiTokenProject.status == PENDING)
        ).one()
    return {"by_role_and_state": by_role, "expiring_soon": expiring, "pending_enrollments": pending}


# ── Project tokens (web interface) ───────────────────────────────────────────


def _web_token_query(token_id: str) -> Any:
    """SELECT of a token managed in the web interface (role in WEB_TOKEN_ROLES), by id."""
    return select(ApiToken).where(
        ApiToken.id == token_id, col(ApiToken.role).in_([role.value for role in WEB_TOKEN_ROLES])
    )


def list_project_tokens() -> list[dict[str, Any]]:
    """Return the metadata of the active tokens managed in the web interface.

    They are the ``mcp`` and ``ci`` tokens, restricted to projects
    (``projects`` lists them) or reaching every project (``projects`` None).
    """
    return [
        token
        for token in list_tokens()
        if token["role"] in WEB_TOKEN_ROLES and token["status"] == ACTIVE
    ]


def create_project_token(
    label: str,
    projects: str | Iterable[str] | None,
    role: Role | str = Role.MCP,
    expires_in_days: int | None = None,
    actor: str | None = None,
    access_role_id: int | None = None,
) -> dict[str, Any]:
    """Create a token of WEB_TOKEN_ROLES for one or several projects, or for every project
    (``projects`` None; refused for ``ci``, see create_token).

    An ``api`` token needs ``access_role_id``, the role whose permissions it holds: a list of
    projects is only accepted for a role made of scoped permissions.

    Raises:
        ValueError: Role refused, ``access_role_id`` missing or given to another role, invalid
            projects or label.
        NotFoundError: Unknown ``access_role_id``.
    """
    try:
        kind = Role(str(role).strip().lower())
        if kind not in WEB_TOKEN_ROLES:
            raise ValueError
    except ValueError:
        raise ValueError(f"A {role} token cannot be created in the web interface") from None
    if kind != Role.API:
        if access_role_id is not None:
            raise ValueError("Only an api token has a role of the access control")
        return create_token(label, kind, _scope(projects), expires_in_days, actor)
    if access_role_id is None:
        raise ValueError("An api token needs a role")
    # Import here: access_control depends on this module
    from . import access_control

    _, cleaned = access_control.role_token_scope(access_role_id, _scope(projects))
    row, links, token = _insert(
        _clean_label(label),
        Role.API,
        cleaned,
        expires_in_days,
        (AuditAction.TOKEN_CREATED, actor),
        access_role_id=access_role_id,
    )
    return _public(row, links) | {"token": token}


def _scope(projects: str | Iterable[str] | None) -> list[str] | None:
    """Validate the projects of a web token: None gives every project, an empty list is refused
    (never read as every project)."""
    cleaned = _clean_projects(projects)
    if projects is not None and cleaned is None:
        raise ValueError("A project token needs at least one project (None: every project)")
    return cleaned


def set_token_projects(
    token_id: str, projects: str | Iterable[str] | None, actor: str | None = None
) -> dict[str, Any]:
    """Change the projects of a token of WEB_TOKEN_ROLES and return its metadata.

    ``projects`` replaces the approved projects; None gives the token every project (refused
    for ``ci``). A pending enrollment request for a project now granted is approved with the
    change; with every project, the pending requests are dropped (the token reaches them). The
    other pending requests keep waiting. The change is audited with ``actor``.

    Raises:
        ValueError: Unknown token, enrollment request still pending, ``ci`` token for every
            project, or more than MAX_PROJECTS_PER_TOKEN projects granted or requested.
    """
    cleaned = _scope(projects)
    wanted = set(cleaned or [])
    with session_scope() as session:
        row = session.exec(_web_token_query(token_id)).first()
        if row is None:
            raise ValueError(f"Project token '{token_id}' was not found")
        if _is_pending(row):
            raise ValueError("An enrollment request waiting for approval cannot be changed")
        if cleaned is None and row.role == Role.CI:
            raise ValueError("A ci token must be restricted to at least one project")
        if row.user_id is not None:
            raise ValueError("A personal token holds the rights of its user: no projects")
        if row.access_role_id is not None and cleaned is not None:
            from . import access_control  # access_control depends on this module

            access_control.role_token_scope(row.access_role_id, cleaned)
        links = _links(session, [row.id])[row.id]
        previous = _active_projects(row, links)
        # Pending requests for other projects keep waiting (dropped with every project)
        waiting = {
            link.id
            for link in links
            if cleaned is not None and link.status == PENDING and link.project not in wanted
        }
        if len(wanted) + len(waiting) > MAX_PROJECTS_PER_TOKEN:
            raise ValueError(f"A token may reach at most {MAX_PROJECTS_PER_TOKEN} projects")
        for link in links:
            if link.project in wanted:
                link.status = ACTIVE
                session.add(link)
            elif link.id not in waiting:
                session.delete(link)
        known = {link.project for link in links}
        session.add_all(
            _new_link(row.id, name, ACTIVE) for name in cleaned or [] if name not in known
        )
        row.project = cleaned[0] if cleaned else None
        session.add(row)
        session.flush()
        updated = _public(row, _links(session, [row.id])[row.id])
        _audit_token(
            session,
            AuditAction.TOKEN_PROJECTS_CHANGED,
            actor,
            updated,
            previous_projects=previous,
        )
    return updated


def revoke_project_token(token_id: str, actor: str | None = None) -> None:
    """Delete a token of WEB_TOKEN_ROLES by id; other tokens cannot be revoked this way."""
    with session_scope() as session:
        row = session.exec(_web_token_query(token_id)).first()
        if row is None:
            raise ValueError(f"Project token '{token_id}' was not found")
        revoked = _public(row, _links(session, [row.id])[row.id])
        _delete_token(session, row)
        _audit_token(session, AuditAction.TOKEN_REVOKED, actor, revoked)


# ── Personal api tokens (web users) ──────────────────────────────────────────


def _personal_label(username: str, label: str) -> str:
    """Label of a personal token: ``<username>:<label>``, within MAX_LABEL_CHARS."""
    full = f"{username}:{_clean_label(label)}"
    if len(full) > MAX_LABEL_CHARS:
        room = MAX_LABEL_CHARS - len(username) - 1
        raise ValueError(f"The label of your token must contain at most {room} characters")
    return full


def _personal_role(role: Role | str) -> Role:
    """Role of a personal token (PERSONAL_TOKEN_ROLES).

    Raises:
        ValueError: For another role.
    """
    try:
        kind = Role(str(role).strip().lower())
    except ValueError:
        kind = None
    if kind not in PERSONAL_TOKEN_ROLES:
        raise ValueError(f"A web user cannot create a personal {role} token")
    return kind  # type: ignore[return-value]


def create_personal_token(
    user_id: int, label: str, expires_in_days: int | None = None, role: Role | str = Role.API
) -> dict[str, Any]:
    """Create a personal token of a web user for itself and return it with its secret, shown
    once: an ``api`` token holds the current rights of the user (see _api_info), an ``mcp``
    token reaches the projects the user may read (see _personal_mcp_info).

    Raises:
        ValueError: Unknown user, role other than ``api`` or ``mcp``, invalid label or
            validity, or SECREVIEW_PERSONAL_TOKENS_PER_USER tokens of this role held already.
    """
    kind = _personal_role(role)
    limit = get_settings().personal_tokens_per_user
    with session_scope() as session:
        user = session.get(WebUser, user_id)
        if user is None:
            raise ValueError(f"User {user_id} not found")
        username = user.username
        count = session.exec(
            select(func.count())
            .select_from(ApiToken)
            .where(ApiToken.user_id == user_id, ApiToken.role == kind.value)
        ).one()
    if count >= limit:
        raise ValueError(
            f"A user may hold at most {limit} personal {kind.value} token(s): revoke one first"
        )
    row, links, token = _insert(
        _personal_label(username, label),
        kind,
        None,
        expires_in_days,
        (AuditAction.TOKEN_CREATED, f"user:{username}"),
        user_id=user_id,
    )
    return _public(row, links) | {"token": token}


def _personal_public(session: Session, row: ApiToken) -> dict[str, Any]:
    """Metadata of a personal token; for an ``mcp`` token, ``projects`` are those its user may
    read now (empty when they cannot be read)."""
    public = _public(row, [])
    if row.role == Role.MCP and row.user_id is not None:
        try:
            projects = _user_projects(session, row.user_id)
        except ValueError:
            projects = frozenset()
        public["projects"] = None if projects is None else sorted(projects)
    return public


def list_personal_tokens(user_id: int) -> list[dict[str, Any]]:
    """Return the metadata of the personal tokens of a web user (never their secret)."""
    with session_scope() as session:
        rows = session.exec(
            select(ApiToken)
            .where(ApiToken.user_id == user_id)
            .order_by(col(ApiToken.created_at), col(ApiToken.label))
        ).all()
        return [_personal_public(session, row) for row in rows]


def revoke_personal_token(user_id: int, token_id: str, actor: str | None = None) -> None:
    """Delete an api token of a web user; the token of another user is not found."""
    with session_scope() as session:
        row = session.exec(
            select(ApiToken).where(ApiToken.id == token_id, ApiToken.user_id == user_id)
        ).first()
        if row is None:
            raise ValueError(f"Token '{token_id}' was not found")
        revoked = _public(row, [])
        _delete_token(session, row)
        _audit_token(session, AuditAction.TOKEN_REVOKED, actor, revoked)


def delete_user_tokens(session: Session, user_id: int, actor: str | None = None) -> None:
    """Delete the personal tokens of a web user (before the user), each one audited."""
    for row in session.exec(select(ApiToken).where(ApiToken.user_id == user_id)).all():
        revoked = _public(row, [])
        _delete_token(session, row)
        _audit_token(session, AuditAction.TOKEN_REVOKED, actor, revoked)
    session.flush()


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
    base = base.replace(":", "-")  # reserved for the personal tokens (see _clean_label)
    suffix = f"-{secrets.token_hex(3)}"
    label = _clean_label(base[: MAX_LABEL_CHARS - len(suffix)] + suffix)
    requested_by, requested_from = _clean_requester(requested_by, requested_from)
    _check_pending_capacity(requested_from)
    row, links, token = _insert(
        label,
        ENROLLMENT_ROLE,
        [project],
        None,
        (AuditAction.ENROLLMENT_REQUESTED, audit.ANONYMOUS_ACTOR),
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
        if _is_expired(row):
            raise ValueError("This token has expired")
        if row.user_id is not None:
            raise ValueError(
                "A personal token reaches the projects of its user: ask an administrator to "
                f"give your account access to project '{project}'"
            )
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
        audit.record(
            session,
            AuditAction.ENROLLMENT_REQUESTED,
            audit.token_actor(row.label),
            "enrollment",
            link.id,
            project,
            {
                "label": row.label,
                "kind": ADDITIONAL_PROJECT,
                "requested_by": requested_by,
                "requested_from": requested_from,
            },
        )
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


def _audit_request(
    session: Session, action: AuditAction, actor: str | None, request: dict[str, Any]
) -> None:
    """Write an audit event about an enrollment decision."""
    audit.record(
        session,
        action,
        actor,
        "enrollment",
        request["id"],
        request["project"],
        {
            "label": request["label"],
            "token_id": request["token_id"],
            "kind": request["kind"],
            "requested_by": request["requested_by"],
            "requested_from": request["requested_from"],
        },
    )


def approve_enrollment(reference: str, actor: str | None = None) -> dict[str, Any]:
    """Approve a pending request (request id, or token id or label when it has only one).

    A first enrollment activates the token; a complementary one adds the project to it. The
    change applies from the next request. The approval is audited with ``actor``.
    """
    with session_scope() as session:
        link, row = _pending_request(session, reference)
        approved = _request(link, row) | {"status": ACTIVE}
        link.status = ACTIVE
        session.add(link)
        if _is_pending(row):
            row.status = ACTIVE
            session.add(row)
        _audit_request(session, AuditAction.ENROLLMENT_APPROVED, actor, approved)
        session.flush()
        return approved | {"projects": _active_projects(row, _links(session, [row.id])[row.id])}


def reject_enrollment(reference: str, actor: str | None = None) -> dict[str, Any]:
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
        _audit_request(session, AuditAction.ENROLLMENT_REJECTED, actor, rejected)
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
                public = (
                    _personal_public(session, row)
                    if row.user_id is not None
                    else _public(row, _links(session, [row.id])[row.id])
                )
                return {
                    "status": public["status"],
                    "label": row.label,
                    "project": row.project,
                    "projects": public["projects"],
                    "pending_projects": public["pending_projects"],
                    "requested_at": row.created_at.isoformat(),
                }
    return {"status": "not_enrolled"}
