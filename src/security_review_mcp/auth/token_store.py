"""Bearer tokens of the HTTP transport, stored in the database (SHA-256 digests only).

Every token lives in the ``ApiToken`` table: the tokens created with
``security-review-controller token create`` and those created in the web interface. Every
server instance sharing the database sees a creation or a revocation immediately. The web
users, who log in with a password, are in web_users.

A token restricted to projects lists them in ``ApiTokenProject``; a token without project rows
(and without ``ApiToken.project``) reaches every project.

No token is ever created for an MCP client: the developer creates a personal ``mcp`` token in
the web interface, and its agent requests the projects it does not reach yet (see
access_control.request_project).

A token may expire (``expires_at``, bounded by SECREVIEW_TOKEN_MAX_DAYS): it then authenticates
nothing but stays listed, so that an administrator rotates or revokes it. A rotation replaces the
secret of a token (same id, label, role and projects); the previous secret may keep working
during a grace period, so that its clients are updated without an interruption.

A token has one of the roles of http_server.TOKEN_ROLES: tokens are for machines (MCP agent,
pipeline, Prometheus, administration). A person reaches the web API through a session, whose
rights come from its roles (see access_control). A stored token of another role (``reader`` or
``triager``, from an older version) authenticates nothing.

The web interface manages the ``mcp``, ``ci`` and ``api`` tokens (WEB_TOKEN_ROLES): an
administrator creates them for some projects or for every project, changes their projects,
rotates and revokes them. The ``admin`` and ``metrics`` tokens are managed with the CLI only.

An ``api`` token reaches the REST API (Swagger, scripts) with the rights of the access control
(see access_control), read at each request:

- a **role token** (``access_role_id``), created on the Tokens screen, holds the permissions of
  one role and its per-project permissions (``project_permissions``) on its projects (every
  project, or a list);
- a **personal token** (``user_id``), created by a web user for itself (label
  ``<username>:<label>``), holds the current rights of that user, and is deleted with it. Its
  projects and its secret cannot be changed; an administrator may revoke it.

A web user may also create a **personal** ``mcp`` token for its MCP agent, or a **personal**
``ci`` token for ``security-review-ci`` on its workstation (code and dependency scans, gate):
it reaches the projects the user may read (``reports.read`` of its roles), read at each
request, so that a project granted to or removed from the user applies at once. It has no
project rows and no change of projects: an administrator grants the project to the user
instead. Each personal token has one usage: an ``mcp`` token only reaches the MCP server, a
``ci`` token only the pipeline routes. A web user holds at most
SECREVIEW_PERSONAL_TOKENS_PER_USER personal tokens of each role. With
SECREVIEW_PERSONAL_MCP_TOKENS=false (MCP clients logged in with OAuth, see oauth_server), no
personal ``mcp`` token is created and the controller revokes those left at start. With
SECREVIEW_PERSONAL_TOKENS_ENABLED=false (see app_settings.personal_tokens_enabled), no personal
``mcp`` or ``ci`` token is created, and those already created are refused like the OAuth grants:
they authenticate nothing until it is true again.

Like every token, an ``api`` token never accepts a risk nor marks a false positive.

Every creation, rotation, revocation and change of projects is written to the audit log.

The access tokens of the OAuth login of the MCP clients (``OAuthGrant``, see oauth_server) are
checked here too, after the stored tokens: one acts as a personal ``mcp`` token of the user who
approved its client, on the MCP server only (not the pipeline routes). They are refused while the
OAuth login is off, and accepted again once it is turned on (the grants are kept).
"""

import hmac
import json
import secrets
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, func, or_, select

from .. import app_settings
from ..config import MAX_RETENTION_DAYS, get_settings
from ..http_server import TOKEN_ROLES, Role, TokenInfo, hash_token
from ..observability import audit
from ..observability.audit import AuditAction
from ..storage.database import session_scope
from ..storage.models import ApiToken, ApiTokenProject, OAuthGrant, WebUser, as_utc, utcnow
from ..storage.project_names import normalize_project
from ..storage.projects import ensure_project

MAX_TOKENS = 500
MAX_LABEL_CHARS = 64
# Projects one token may reach (granted or requested)
MAX_PROJECTS_PER_TOKEN = 50

ACTIVE = "active"
# Longest time the previous secret of a rotated token keeps working
MAX_ROTATION_GRACE_HOURS = 168
# Roles whose rights cannot be scoped to projects
UNSCOPED_ROLES = frozenset({Role.ADMIN, Role.METRICS})
# Roles of the tokens managed in the web interface (admin and metrics tokens: CLI only)
WEB_TOKEN_ROLES = frozenset({Role.MCP, Role.CI, Role.API})
# Roles of the personal tokens of a web user (REST API, MCP agent, workstation scans)
PERSONAL_TOKEN_ROLES = frozenset({Role.API, Role.MCP, Role.CI})
# Personal tokens that reach the projects their user may read (see _personal_scoped_info)
SCOPED_PERSONAL_ROLES = frozenset({Role.MCP, Role.CI})


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
        return [row.project] if row.project is not None else []
    return [link.project for link in links]


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
        "created_at": row.created_at.isoformat(),
        "expires_at": _iso(row.expires_at),
        "expired": _is_expired(row, now),
        "rotated_at": _iso(row.rotated_at),
        "grace_until": _iso(grace) if grace is not None and as_utc(grace) > now else None,
        "access_role_id": row.access_role_id,
        "project_permissions": json.loads(row.project_permissions),
        "personal": row.user_id is not None,
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
            if row is None:
                return _oauth_info(session, digest)
            if row.role not in TOKEN_ROLES or not _matches(row, digest):
                return None
            info = _info(row, _links(session, [row.id])[row.id])
            if row.role == Role.API:
                return _api_info(session, row, info)
            if row.user_id is not None:
                return _personal_scoped_info(session, row, info)
            return info

    def has_tokens(self) -> bool:
        """True when at least one token is stored.

        Expired tokens count: a server whose tokens have all expired stays closed (fail closed).
        """
        with session_scope() as session:
            if session.exec(select(ApiToken.id).limit(1)).first():
                return True
            return (
                self.include_users and session.exec(select(WebUser.id).limit(1)).first() is not None
            )


def _api_info(session: Session, row: ApiToken, info: TokenInfo) -> TokenInfo | None:
    """Identity of an ``api`` token, with its grants read now: those of its user (personal
    token) or of its role on its projects (role token). None when the user or the role is gone,
    or when the token grants nothing (fail closed)."""
    from . import access_control  # access_control depends on this module

    must_change, owner = False, None
    if row.user_id is not None:
        user = session.get(WebUser, row.user_id)
        if user is None:
            return None
        try:
            grants = access_control.user_grants(session, row.user_id)
        except ValueError:
            return None
        must_change, owner = user.must_change_password, user.username
    elif row.access_role_id is not None and info.projects != frozenset():
        grants = access_control.role_token_grants(
            session, row.access_role_id, info.projects, json.loads(row.project_permissions)
        )
    else:
        return None
    if not grants:
        return None
    return TokenInfo(
        info.label,
        Role.API,
        projects=access_control.scope(grants, access_control.Permission.REPORTS_READ),
        token_id=info.token_id,
        expired=info.expired,
        owner=owner,
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


def _personal_scoped_info(session: Session, row: ApiToken, info: TokenInfo) -> TokenInfo | None:
    """Identity of a personal ``mcp`` or ``ci`` token: the projects its user may read now. None
    when the user is gone, must change a password set by an administrator (as its api tokens,
    see web_api.deps), its grants cannot be read, the role is not a scoped personal one or
    SECREVIEW_PERSONAL_TOKENS_ENABLED is false (fail closed); a user without any project gets a
    token that reaches none."""
    if info.role not in SCOPED_PERSONAL_ROLES or not app_settings.personal_tokens_enabled(session):
        return None
    user = session.get(WebUser, row.user_id)
    if user is None or user.must_change_password:
        return None
    try:
        projects = _user_projects(session, user.id)  # type: ignore[arg-type]
    except ValueError:
        return None
    return TokenInfo(
        info.label,
        info.role,
        projects=projects,
        token_id=info.token_id,
        expired=info.expired,
        owner=user.username,
    )


# Writes of the last use of an OAuth grant are spaced by this much (not one per MCP request)
OAUTH_LAST_USED_RESOLUTION = timedelta(minutes=5)


def _oauth_info(session: Session, digest: bytes) -> TokenInfo | None:
    """Identity of an OAuth access token (see oauth_server): the projects the user who approved
    the client may read now, as a personal ``mcp`` token without the pipeline routes. None when
    unknown, when the user is gone or must change its password, while the OAuth login is off
    (the grant is kept for when it is turned on again) or while SECREVIEW_PERSONAL_TOKENS_ENABLED
    is false; an expired one is marked ``expired``."""
    grant = session.exec(
        select(OAuthGrant).where(OAuthGrant.access_token_hash == digest.hex())
    ).first()
    if grant is None or not hmac.compare_digest(bytes.fromhex(grant.access_token_hash), digest):
        return None
    if not app_settings.mcp_oauth_on(session) or not app_settings.personal_tokens_enabled(session):
        return None
    user = session.get(WebUser, grant.user_id)
    if user is None or user.must_change_password:
        return None
    try:
        projects = _user_projects(session, grant.user_id)
    except ValueError:
        return None
    now = utcnow()
    if grant.last_used_at is None or as_utc(grant.last_used_at) < now - OAUTH_LAST_USED_RESOLUTION:
        grant.last_used_at = now
        session.add(grant)
    return TokenInfo(
        f"{user.username}:oauth:{grant.client_id[:8]}",
        Role.MCP,
        projects=projects,
        expired=as_utc(grant.access_expires_at) <= now,
        owner=user.username,
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


def _new_link(token_id: str, project: str) -> ApiTokenProject:
    """Build a project row."""
    return ApiTokenProject(id=str(uuid.uuid4()), token_id=token_id, project=project)


def _insert(
    label: str,
    role: Role,
    projects: list[str] | None = None,
    expires_in_days: int | None = None,
    event: tuple[AuditAction, str | None] = (AuditAction.TOKEN_CREATED, None),
    user_id: int | None = None,
    access_role_id: int | None = None,
    project_permissions: list[str] | None = None,
) -> tuple[ApiToken, list[ApiTokenProject], str]:
    """Generate a token, store its digest and projects and return (row, project rows, token).

    ``user_id`` and ``access_role_id`` set the owner or the role of an ``api`` token.
    ``event`` is the audit action and actor written with the token. A duplicate label raises
    ValueError; the token limit is enforced here.
    """
    expires_at = _expiry(expires_in_days, utcnow())
    with session_scope() as session:
        count = session.exec(select(func.count()).select_from(ApiToken)).one()
    if count >= MAX_TOKENS:
        raise ValueError(f"The limit of {MAX_TOKENS} tokens has been reached")
    token = secrets.token_urlsafe(32)
    row = ApiToken(
        id=str(uuid.uuid4()),
        label=label,
        role=role.value,
        project=projects[0] if projects else None,
        token_hash=hash_token(token).hex(),
        expires_at=expires_at,
        user_id=user_id,
        access_role_id=access_role_id,
        project_permissions=json.dumps(project_permissions or []),
    )
    links = [_new_link(row.id, project) for project in projects or []]
    try:
        with session_scope() as session:
            session.add(row)
            session.flush()
            for project in projects or []:
                ensure_project(session, project, event[1])
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
                    "access_role_id": access_role_id,
                    "project_permissions": project_permissions or [],
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
            "web access through a web user and its roles"
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

    With ``project``, only the tokens that reach it are returned.
    """
    statement = select(ApiToken).order_by(col(ApiToken.created_at), col(ApiToken.label))
    if project is not None:
        project = normalize_project(project)
        granted = select(ApiTokenProject.token_id).where(ApiTokenProject.project == project)
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
        ValueError: Unknown token, personal token, or bounds exceeded.
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
    """Count the tokens by role and state (``active``, ``expired``) and the active ones that
    expire within ``expiring_within``."""
    now = utcnow()
    by_role: dict[tuple[str, str], int] = {}
    expiring = 0
    with session_scope() as session:
        for row in session.exec(select(ApiToken)).all():
            if _is_expired(row, now):
                state = "expired"
            else:
                state = ACTIVE
                if row.expires_at is not None and as_utc(row.expires_at) <= now + expiring_within:
                    expiring += 1
            by_role[(row.role, state)] = by_role.get((row.role, state), 0) + 1
    return {"by_role_and_state": by_role, "expiring_soon": expiring}


# ── Project tokens (web interface) ───────────────────────────────────────────


def _web_token_query(token_id: str) -> Any:
    """SELECT of a token managed in the web interface (role in WEB_TOKEN_ROLES), by id."""
    return select(ApiToken).where(
        ApiToken.id == token_id, col(ApiToken.role).in_([role.value for role in WEB_TOKEN_ROLES])
    )


def list_project_tokens() -> list[dict[str, Any]]:
    """Return the metadata of the tokens managed in the web interface.

    They are the ``mcp`` and ``ci`` tokens, restricted to projects
    (``projects`` lists them) or reaching every project (``projects`` None).
    """
    return [token for token in list_tokens() if token["role"] in WEB_TOKEN_ROLES]


def create_project_token(
    label: str,
    projects: str | Iterable[str] | None,
    role: Role | str = Role.MCP,
    expires_in_days: int | None = None,
    actor: str | None = None,
    access_role_id: int | None = None,
    project_permissions: Iterable[str] = (),
) -> dict[str, Any]:
    """Create a token of WEB_TOKEN_ROLES for one or several projects, or for every project
    (``projects`` None; refused for ``ci``, see create_token).

    An ``api`` token needs ``access_role_id``, the role whose permissions it holds, and holds the
    per-project permissions ``project_permissions`` on its projects.

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
        if access_role_id is not None or list(project_permissions):
            raise ValueError("Only an api token has a role and per-project permissions")
        return create_token(label, kind, _scope(projects), expires_in_days, actor)
    if access_role_id is None:
        raise ValueError("An api token needs a role")
    # Import here: access_control depends on this module
    from . import access_control

    _, cleaned, scoped = access_control.role_token_scope(
        access_role_id, _scope(projects), project_permissions
    )
    row, links, token = _insert(
        _clean_label(label),
        Role.API,
        cleaned,
        expires_in_days,
        (AuditAction.TOKEN_CREATED, actor),
        access_role_id=access_role_id,
        project_permissions=scoped,
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

    ``projects`` replaces the projects of the token; None gives the token every project
    (refused for ``ci``). The change is audited with ``actor``.

    Raises:
        ValueError: Unknown or personal token, ``ci`` token for every project, or more than
            MAX_PROJECTS_PER_TOKEN projects.
    """
    cleaned = _scope(projects)
    wanted = set(cleaned or [])
    with session_scope() as session:
        row = session.exec(_web_token_query(token_id)).first()
        if row is None:
            raise ValueError(f"Project token '{token_id}' was not found")
        if cleaned is None and row.role == Role.CI:
            raise ValueError("A ci token must be restricted to at least one project")
        if row.user_id is not None:
            raise ValueError("A personal token holds the rights of its user: no projects")
        if row.access_role_id is not None and cleaned is not None:
            from . import access_control  # access_control depends on this module

            access_control.role_token_scope(row.access_role_id, cleaned)
        links = _links(session, [row.id])[row.id]
        previous = _active_projects(row, links)
        for link in links:
            if link.project not in wanted:
                session.delete(link)
        known = {link.project for link in links}
        for name in cleaned or []:
            if name not in known:
                ensure_project(session, name, actor)
                session.add(_new_link(row.id, name))
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


def forget_project(session: Session, project: str, actor: str | None = None) -> dict[str, int]:
    """Remove a deleted ``project`` from every token in ``session`` and return the counts.

    A token that reaches no other project is revoked: it is never
    left without project rows, which would make it reach every project. Each change is audited.
    """
    ids = set(
        session.exec(select(ApiTokenProject.token_id).where(ApiTokenProject.project == project))
    ) | set(session.exec(select(ApiToken.id).where(ApiToken.project == project)))
    counts = {"tokens_revoked": 0, "tokens_changed": 0}
    if not ids:
        return counts
    rows = session.exec(select(ApiToken).where(col(ApiToken.id).in_(ids))).all()
    for row in rows:
        links = _links(session, [row.id])[row.id]
        before = _public(row, links)
        kept = [link for link in links if link.project != project]
        if not kept:
            _delete_token(session, row)
            _audit_token(session, AuditAction.TOKEN_REVOKED, actor, before)
            counts["tokens_revoked"] += 1
            continue
        for link in links:
            if link.project == project:
                session.delete(link)
        row.project = kept[0].project
        session.add(row)
        session.flush()
        _audit_token(
            session,
            AuditAction.TOKEN_PROJECTS_CHANGED,
            actor,
            _public(row, _links(session, [row.id])[row.id]),
            previous_projects=before["projects"],
        )
        counts["tokens_changed"] += 1
    session.flush()
    return counts


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
    once: an ``api`` token holds the current rights of the user (see _api_info), an ``mcp`` or
    ``ci`` token reaches the projects the user may read (see _personal_scoped_info).

    Raises:
        ValueError: Unknown user, role other than ``api``, ``mcp`` or ``ci``, an ``mcp`` or
            ``ci`` token while SECREVIEW_PERSONAL_TOKENS_ENABLED is false, an ``mcp`` token
            while SECREVIEW_PERSONAL_MCP_TOKENS is false, invalid label or validity, or
            SECREVIEW_PERSONAL_TOKENS_PER_USER tokens of this role held already.
    """
    kind = _personal_role(role)
    settings = get_settings()
    if kind in SCOPED_PERSONAL_ROLES and not settings.personal_tokens_enabled:
        raise ValueError("Personal MCP and CI tokens are disabled on this server")
    if kind == Role.MCP and not settings.personal_mcp_tokens:
        raise ValueError(
            "Personal MCP tokens are disabled on this server: connect the MCP client with its "
            "OAuth login instead"
        )
    limit = settings.personal_tokens_per_user
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
    """Metadata of a personal token; for an ``mcp`` or ``ci`` token, ``projects`` are those its
    user may read now (empty when they cannot be read)."""
    public = _public(row, [])
    if row.role in SCOPED_PERSONAL_ROLES and row.user_id is not None:
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


def revoke_personal_mcp_tokens(actor: str) -> int:
    """Revoke every personal ``mcp`` token (controller start with SECREVIEW_PERSONAL_MCP_TOKENS
    false), each one audited; return how many were revoked."""
    with session_scope() as session:
        rows = session.exec(
            select(ApiToken).where(
                col(ApiToken.user_id).is_not(None), ApiToken.role == Role.MCP.value
            )
        ).all()
        for row in rows:
            revoked = _public(row, [])
            _delete_token(session, row)
            _audit_token(session, AuditAction.TOKEN_REVOKED, actor, revoked)
    return len(rows)


def delete_user_tokens(session: Session, user_id: int, actor: str | None = None) -> None:
    """Delete the personal tokens of a web user (before the user), each one audited."""
    for row in session.exec(select(ApiToken).where(ApiToken.user_id == user_id)).all():
        revoked = _public(row, [])
        _delete_token(session, row)
        _audit_token(session, AuditAction.TOKEN_REVOKED, actor, revoked)
    session.flush()
