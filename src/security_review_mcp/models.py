"""SQLModel models: table models (stored) and data models (MCP tool schemas)."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import field_validator, model_validator
from sqlalchemy import BigInteger, String, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel


def utcnow() -> datetime:
    """Return the current UTC time (timezone aware)."""
    return datetime.now(UTC)


class Severity(StrEnum):
    """Finding severity, ordered from the most to the least critical."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Used to compute the overall risk level of a report
SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class FindingStatus(StrEnum):
    """Lifecycle status of a finding."""

    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


# Statuses that close a finding without a fix: a person decides them, with a reason and an
# expiry date after which the finding counts as open again
DISMISSED_STATUSES = frozenset({FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE})
# Statuses an agent may propose (never apply) through the MCP tool propose_finding_status
PROPOSABLE_STATUSES = frozenset(
    {FindingStatus.FIXED, FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE}
)
MAX_STATUS_REASON_CHARS = 1000
# Developer username declared with a report, and label of the token that saved it
MAX_AUTHOR_CHARS = 200


def as_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime (SQLite returns naive values)."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def effective_status(
    status: FindingStatus, expires_at: datetime | None, now: datetime | None = None
) -> FindingStatus:
    """Return ``open`` for an accepted or false-positive finding whose decision has expired."""
    if status in DISMISSED_STATUSES and expires_at is not None:
        if as_utc(expires_at) <= (now or utcnow()):
            return FindingStatus.OPEN
    return status


class ReviewType(StrEnum):
    """Kind of review that produced a report (the MCP prompt or the CLI command)."""

    SECURITY_REVIEW = "security-review"
    API_SECURITY_REVIEW = "api-security-review"
    CONFIGURATION_REVIEW = "configuration-review"
    DEPENDENCY_REVIEW = "dependency-review"
    CODEBASE_REVIEW = "codebase-review"
    CODE_SCAN = "code-scan"
    DEPENDENCY_SCAN = "dependency-scan"
    OTHER = "other"


# ── Findings ─────────────────────────────────────────────────────────────────


class FindingBase(SQLModel):
    """Fields shared by every Finding variant."""

    title: str = Field(min_length=3, max_length=200, description="Short name of the issue")
    severity: Severity = Field(index=True, description="critical, high, medium, low or info")
    rule_id: str | None = Field(
        default=None,
        max_length=60,
        description="Scanner rule or advisory id (example: PY-004, ACME-001, GHSA-xxxx)",
    )
    category: str = Field(
        default="code",
        max_length=50,
        description="code, configuration, dependency, secret, api, infrastructure...",
    )
    cwe: str | None = Field(default=None, max_length=20, description="Example: CWE-89")
    owasp: str | None = Field(default=None, max_length=60, description="Example: A03:2021")
    file_path: str | None = Field(default=None, max_length=500)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    description: str = Field(min_length=3, description="What is wrong and why it matters")
    evidence: str | None = Field(default=None, description="Relevant code excerpt (secrets masked)")
    recommendation: str | None = Field(default=None, description="How to fix it")

    @field_validator("cwe")
    @classmethod
    def normalize_cwe(cls, value: str | None) -> str | None:
        """Accept '89', 'cwe-89' or 'CWE-89' and store 'CWE-89'."""
        if value is None or not value.strip():
            return None
        digits = value.strip().upper().removeprefix("CWE").lstrip("-: ")
        if not digits.isdigit():
            raise ValueError("cwe must look like 'CWE-89'")
        return f"CWE-{digits}"


class Finding(FindingBase, table=True):
    """Finding table: one security issue attached to a report."""

    id: int | None = Field(default=None, primary_key=True)
    report_id: int = Field(foreign_key="securityreport.id", index=True)
    status: FindingStatus = Field(default=FindingStatus.OPEN, index=True)
    status_changed_at: datetime | None = Field(default=None)
    # Triage decision, made by a person in the web interface (never by an agent)
    status_reason: str | None = Field(default=None, max_length=MAX_STATUS_REASON_CHARS)
    status_approver: str | None = Field(default=None, max_length=200)
    status_expires_at: datetime | None = Field(default=None, index=True)
    # Status proposed by an agent (MCP propose_finding_status): stored, never applied
    proposed_status: FindingStatus | None = Field(default=None, sa_type=String(20))
    proposed_reason: str | None = Field(default=None, max_length=MAX_STATUS_REASON_CHARS)
    proposed_by: str | None = Field(default=None, max_length=200)
    proposed_at: datetime | None = Field(default=None)
    report: SecurityReport = Relationship(back_populates="findings")


class FindingCreate(FindingBase):
    """Finding as submitted by the host (no id, no status)."""


class FindingPublic(FindingBase):
    """Finding as returned to the host."""

    id: int
    report_id: int
    status: FindingStatus
    status_changed_at: datetime | None = None
    status_reason: str | None = None
    status_approver: str | None = None
    status_expires_at: datetime | None = None
    proposed_status: FindingStatus | None = None
    proposed_reason: str | None = None
    proposed_by: str | None = None
    proposed_at: datetime | None = None

    @model_validator(mode="after")
    def _expire_dismissal(self) -> FindingPublic:
        """Show an expired acceptance or false positive as open (its reason stays visible)."""
        self.status = effective_status(self.status, self.status_expires_at)
        return self


# ── Reports ──────────────────────────────────────────────────────────────────


class SecurityReportBase(SQLModel):
    """Fields shared by every SecurityReport variant."""

    project: str = Field(index=True, min_length=1, max_length=200)
    repository: str | None = Field(default=None, max_length=500)
    branch: str | None = Field(default=None, max_length=200)
    commit_sha: str | None = Field(default=None, max_length=64, index=True)
    reviewer: str | None = Field(default=None, max_length=200, description="Agent or person")
    # Declared by the client (not authenticated): one enrolled device may serve several people
    author: str | None = Field(
        default=None,
        index=True,
        max_length=MAX_AUTHOR_CHARS,
        description="Username of the developer whose work was reviewed (git user, login name)",
    )
    scope: str | None = Field(default=None, description="What was reviewed (files, MR, diff...)")
    # Stored as text, not as a database enum: a new review type needs no migration
    review_type: ReviewType | None = Field(
        default=None,
        index=True,
        sa_type=String(40),
        description="Kind of review: the prompt used (security-review...) or the CLI scan",
    )
    summary: str = Field(min_length=3, description="Executive summary of the review")


class SecurityReport(SecurityReportBase, table=True):
    """Report table: one security review."""

    id: int | None = Field(default=None, primary_key=True)
    risk_level: Severity = Field(index=True)
    created_at: datetime = Field(default_factory=utcnow, index=True)
    # Label of the bearer token (enrolled device) that saved the report, set by the server
    submitted_by: str | None = Field(default=None, max_length=MAX_AUTHOR_CHARS)
    findings: list[Finding] = Relationship(
        back_populates="report",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class SecurityReportPublic(SecurityReportBase):
    """Report as returned to the host (with its findings)."""

    id: int
    risk_level: Severity
    created_at: datetime
    submitted_by: str | None = None
    findings: list[FindingPublic] = []


# ── Vulnerability advisories (OSV format, imported offline) ──────────────────


class Advisory(SQLModel, table=True):
    """One advisory (OSV record). The packages it affects are in AdvisoryAffected."""

    id: str = Field(primary_key=True, max_length=100)
    summary: str = Field(default="")
    severity: str | None = Field(default=None, max_length=10)  # critical/high/medium/low or None
    aliases: str = Field(default="[]")  # JSON list (CVE ids...)
    modified: str | None = Field(default=None, max_length=40)
    imported_at: datetime = Field(default_factory=utcnow, index=True)


class AdvisoryAffected(SQLModel, table=True):
    """A package (and its affected versions) covered by an advisory."""

    id: int | None = Field(default=None, primary_key=True)
    advisory_id: str = Field(foreign_key="advisory.id", index=True, max_length=100)
    ecosystem: str = Field(index=True, max_length=30)
    package: str = Field(index=True, max_length=300)  # normalized name
    ranges: str = Field(default="[]")  # JSON: OSV ranges
    versions: str = Field(default="[]")  # JSON: explicit affected versions
    fixed: str = Field(default="[]")  # JSON: versions that fix the issue


# ── Bearer tokens ────────────────────────────────────────────────────────────


class ApiToken(SQLModel, table=True):
    """Bearer token of the HTTP transport (CLI, web project tokens, enrollment requests).

    Only the SHA-256 digest of the secret is stored. An enrollment request is a token whose
    status is ``pending``: it authenticates nothing until an administrator approves it.
    The projects a restricted token reaches are in ApiTokenProject.
    """

    id: str = Field(primary_key=True, max_length=64)
    label: str = Field(unique=True, index=True, max_length=64)
    role: str = Field(max_length=20)
    # First project of a restricted token (None: every project). The full list is in
    # ApiTokenProject; this column stays filled so that an older version reading the database
    # still sees the token as restricted.
    project: str | None = Field(default=None, index=True, max_length=200)
    token_hash: str = Field(unique=True, index=True, max_length=64)  # hex SHA-256
    created_at: datetime = Field(default_factory=utcnow)
    # "active" or "pending"; None (rows created before enrollment existed) means active
    status: str | None = Field(default=None, max_length=20)
    # Who asked for the token (free text given by the requester) and from which address
    requested_by: str | None = Field(default=None, max_length=200)
    requested_from: str | None = Field(default=None, max_length=64)
    # After this date the token authenticates nothing (None: no expiry)
    expires_at: datetime | None = Field(default=None, index=True)
    # Rotation: the secret replaced by the latest rotation keeps working until
    # previous_expires_at (grace period), then nothing but the new one authenticates
    rotated_at: datetime | None = Field(default=None)
    previous_token_hash: str | None = Field(default=None, index=True, max_length=64)
    previous_expires_at: datetime | None = Field(default=None)
    # ``api`` token: the web user of a personal token (it holds the current rights of the user),
    # or the role of a role token (it holds the permissions of the role on its projects)
    user_id: int | None = Field(default=None, foreign_key="webuser.id", index=True)
    access_role_id: int | None = Field(default=None, foreign_key="accessrole.id", index=True)


class ApiTokenProject(SQLModel, table=True):
    """A project reached by a restricted token.

    A ``pending`` row is an enrollment request for that project: the request that created the
    token, or a complementary request of an active token that needs one more project. Only
    ``active`` rows grant access.
    """

    __table_args__ = (UniqueConstraint("token_id", "project"),)

    id: str = Field(primary_key=True, max_length=64)
    token_id: str = Field(foreign_key="apitoken.id", index=True, max_length=64)
    project: str = Field(index=True, max_length=200)
    status: str = Field(default="active", index=True, max_length=20)  # "active" or "pending"
    created_at: datetime = Field(default_factory=utcnow)
    requested_by: str | None = Field(default=None, max_length=200)
    requested_from: str | None = Field(default=None, max_length=64)


# ── Audit log (see audit) ────────────────────────────────────────────────────


class AuditEvent(SQLModel, table=True):
    """One security-relevant change: triage decision, token or enrollment event.

    ``actor`` is ``user:<name>`` (web session), ``token:<label>`` (bearer token), ``cli``
    (operator command) or ``anonymous`` (public enrollment). ``details`` is a JSON object, with
    the secrets masked; it never holds a token or a password.
    """

    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=utcnow, index=True)
    action: str = Field(index=True, max_length=50)
    actor: str = Field(index=True, max_length=200)
    target_type: str = Field(max_length=30)
    target_id: str | None = Field(default=None, max_length=200)
    project: str | None = Field(default=None, index=True, max_length=200)
    details: str = Field(default="{}")


# ── Rules (managed with `security-review-controller rules` and the web interface) ──
# The tables keep their historical "custom" names: they also hold the default content seeded
# from default_rules.toml on the first run.


class CustomRule(SQLModel, table=True):
    """Stored scan rule: a default rule (seeded, possibly edited) or a custom one."""

    id: str = Field(primary_key=True, max_length=50)
    title: str = Field(max_length=300)
    severity: str = Field(max_length=10)
    cwe: str = Field(default="", max_length=20)
    languages: str = Field(default='["*"]')  # JSON list
    pattern: str = Field(max_length=500)
    advice: str = Field(default="")
    ignore_case: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class CustomCheckItem(SQLModel, table=True):
    """Stored checklist item; the ``company`` domain is added to every review prompt."""

    domain: str = Field(primary_key=True, max_length=31)
    id: str = Field(primary_key=True, max_length=50)
    title: str = Field(max_length=300)
    what_to_look_for: str
    cwe: str = Field(default="", max_length=20)


class DevStandard(SQLModel, table=True):
    """Development standard of a technology, served to the developer's AI (see standards).

    ``technologies`` (JSON list of lowercase names and aliases) and ``file_patterns`` (JSON list
    of file name globs) select the standard; ``content`` holds the guidance, in Markdown.
    """

    id: int | None = Field(default=None, primary_key=True)
    slug: str = Field(unique=True, index=True, max_length=50)
    title: str = Field(max_length=200)
    description: str = Field(default="", max_length=500)
    technologies: str = Field(default="[]")
    file_patterns: str = Field(default="[]")
    content: str = Field(default="")
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    updated_by: str | None = Field(default=None, max_length=64)


class DisabledRule(SQLModel, table=True):
    """A switched-off rule id (default or custom)."""

    rule_id: str = Field(primary_key=True, max_length=50)
    disabled_at: datetime = Field(default_factory=utcnow)


class RuleSetRevision(SQLModel, table=True):
    """Single-row counter bumped by every rule change, so that each server instance reloads."""

    id: int = Field(default=1, primary_key=True)
    revision: int = Field(default=0)


class DefaultSeed(SQLModel, table=True):
    """A default rule or checklist item already copied from default_rules.toml.

    ``digest`` fingerprints the default content that was seeded: a newer default replaces the
    stored entry only while it still has this fingerprint (not modified by an administrator),
    and a deleted default entry is not seeded again.
    """

    kind: str = Field(primary_key=True, max_length=10)  # "rule" or "checklist"
    key: str = Field(primary_key=True, max_length=90)  # rule id, or "domain/item id"
    digest: str = Field(max_length=64)  # hex SHA-256
    seeded_at: datetime = Field(default_factory=utcnow)


# ── Settings changed in the web interface and history of the OSV updates ─────


class AppSetting(SQLModel, table=True):
    """A setting changed by an administrator in the web interface.

    It overrides the matching ``SECREVIEW_*`` variable for both processes (see app_settings);
    a missing row means the variable applies.
    """

    key: str = Field(primary_key=True, max_length=50)
    value: str = Field(default="", max_length=500)
    updated_at: datetime = Field(default_factory=utcnow)
    updated_by: str | None = Field(default=None, max_length=64)


class AdvisoryUpdate(SQLModel, table=True):
    """One download of the OSV exports by the controller (scheduled, CLI or web)."""

    id: int | None = Field(default=None, primary_key=True)
    trigger: str = Field(max_length=20)  # "schedule", "cli" or "web"
    triggered_by: str | None = Field(default=None, max_length=64)
    # "running", "success", "partial" (some ecosystems failed) or "failed"
    status: str = Field(default="running", index=True, max_length=20)
    source: str = Field(default="", max_length=500)
    started_at: datetime = Field(default_factory=utcnow, index=True)
    finished_at: datetime | None = Field(default=None)
    results: str = Field(default="{}")  # JSON: counters or error of each ecosystem


# ── Web users (username and password login, see web_users) ───────────────────


class WebUser(SQLModel, table=True):
    """Account of the web interface: a local account (username and password) or an OIDC one.

    ``auth_source`` is ``local`` (password login, only a scrypt hash of the password is stored)
    or ``oidc`` (OpenID Connect login, no password). What a user may do comes only from the
    roles of its groups (``GroupMember``, see access_control). ``oidc_subject`` and
    ``oidc_issuer`` are the ``sub`` claim and the issuer bound at the first OIDC login: an
    account is identified by both, so that another identity provider cannot reuse a subject.
    ``session_version`` is drawn at random at creation and at each password change: the sessions
    issued with another version are refused.
    """

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True, max_length=64)
    auth_source: str = Field(default="local", max_length=20)
    password_hash: str | None = Field(default=None, max_length=255)
    oidc_subject: str | None = Field(default=None, max_length=255)
    oidc_issuer: str | None = Field(default=None, max_length=500)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    password_changed_at: datetime | None = Field(default=None)
    # Set by a password chosen or generated for the user (creation, reset, first administrator):
    # its sessions reach nothing but the change of its own password until it changes it
    must_change_password: bool = Field(default=False)
    session_version: int = Field(default=0, sa_type=BigInteger)
    last_login_at: datetime | None = Field(default=None)
    created_by: str | None = Field(default=None, max_length=64)
    # Theme of the web interface chosen by the user: light, dark or auto (system preference)
    theme: str = Field(default="auto", max_length=10)


# ── Rate limiting (see rate_limit) ───────────────────────────────────────────


class RateLimitCounter(SQLModel, table=True):
    """Events of a rate limit key in one fixed time window, shared by every process.

    ``key`` is a SHA-256 digest of the limit and of what it counts (address, username...),
    ``window_start`` the start of the window in seconds since the epoch.
    """

    key: str = Field(primary_key=True, max_length=64)
    window_start: int = Field(primary_key=True, sa_type=BigInteger, index=True)
    hits: int = Field(default=0)


# ── Access control: roles, groups and members (see access_control) ───────────


class AccessRole(SQLModel, table=True):
    """Role of the web interface: a named set of permissions, given to groups.

    ``permissions`` is the JSON list of the permission names (access_control.Permission). A
    ``system`` (built-in) role, ``reader`` or ``admin``, can be neither changed nor deleted: its
    permissions are those of the code, not of this column.
    """

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=64)
    description: str = Field(default="", max_length=500)
    permissions: str = Field(default="[]")
    system: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    created_by: str | None = Field(default=None, max_length=64)


class UserGroup(SQLModel, table=True):
    """Group of web users; its roles apply to every member.

    With ``sso``, the OIDC users whose groups claim holds ``name`` are members too: their
    membership is recomputed at each login. Without it, only the members an administrator added
    belong to the group.
    """

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=200)
    description: str = Field(default="", max_length=500)
    sso: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    created_by: str | None = Field(default=None, max_length=64)


class GroupRole(SQLModel, table=True):
    """Role given to a group, on every project or on the projects listed in ``projects``.

    ``projects`` is a JSON list; empty means every project. Only a role whose permissions are
    all scoped to projects (reading reports, triaging findings) may list projects.
    """

    __table_args__ = (UniqueConstraint("group_id", "role_id"),)

    id: int | None = Field(default=None, primary_key=True)
    group_id: int = Field(foreign_key="usergroup.id", index=True)
    role_id: int = Field(foreign_key="accessrole.id", index=True)
    projects: str = Field(default="[]")


class GroupMember(SQLModel, table=True):
    """Membership of a web user in a group.

    ``source`` is ``local`` (added by an administrator) or ``oidc`` (found in the groups claim
    at the last OIDC login, replaced at each login).
    """

    __table_args__ = (UniqueConstraint("group_id", "user_id", "source"),)

    id: int | None = Field(default=None, primary_key=True)
    group_id: int = Field(foreign_key="usergroup.id", index=True)
    user_id: int = Field(foreign_key="webuser.id", index=True)
    source: str = Field(default="local", max_length=20)
    created_at: datetime = Field(default_factory=utcnow)


class RevokedSsoUser(SQLModel, table=True):
    """Username of an OIDC web user deleted by an administrator (see web_users.delete_user).

    With ``SECREVIEW_OIDC_AUTO_CREATE_USERS``, an OIDC login never creates a web user with this
    name again; an administrator who creates the user again lifts the revocation.
    """

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True, max_length=64)
    revoked_at: datetime = Field(default_factory=utcnow)
    revoked_by: str | None = Field(default=None, max_length=64)
