"""SQLModel models: table models (stored) and data models (MCP tool schemas)."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import field_validator
from sqlalchemy import UniqueConstraint
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
    report: SecurityReport = Relationship(back_populates="findings")


class FindingCreate(FindingBase):
    """Finding as submitted by the host (no id, no status)."""


class FindingPublic(FindingBase):
    """Finding as returned to the host."""

    id: int
    report_id: int
    status: FindingStatus
    status_changed_at: datetime | None = None


# ── Reports ──────────────────────────────────────────────────────────────────


class SecurityReportBase(SQLModel):
    """Fields shared by every SecurityReport variant."""

    project: str = Field(index=True, min_length=1, max_length=200)
    repository: str | None = Field(default=None, max_length=500)
    branch: str | None = Field(default=None, max_length=200)
    commit_sha: str | None = Field(default=None, max_length=64, index=True)
    reviewer: str | None = Field(default=None, max_length=200, description="Agent or person")
    scope: str | None = Field(default=None, description="What was reviewed (files, MR, diff...)")
    summary: str = Field(min_length=3, description="Executive summary of the review")


class SecurityReport(SecurityReportBase, table=True):
    """Report table: one security review."""

    id: int | None = Field(default=None, primary_key=True)
    risk_level: Severity = Field(index=True)
    created_at: datetime = Field(default_factory=utcnow, index=True)
    findings: list[Finding] = Relationship(
        back_populates="report",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class SecurityReportPublic(SecurityReportBase):
    """Report as returned to the host (with its findings)."""

    id: int
    risk_level: Severity
    created_at: datetime
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
    """Bearer token of the HTTP transport (CLI, bootstrap admin, web project tokens).

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


# ── OIDC role mapping (web interface, see role_mapping) ──────────────────────


class OidcRoleMapping(SQLModel, table=True):
    """Web role granted to the OIDC users whose groups or roles claim holds ``claim_value``.

    ``projects`` is the JSON list of the projects a ``reader`` or ``triager`` mapping is limited
    to; an empty list means every project (always the case for ``admin``).
    """

    __table_args__ = (UniqueConstraint("claim_value", "role"),)

    id: int | None = Field(default=None, primary_key=True)
    claim_value: str = Field(index=True, max_length=200)
    role: str = Field(max_length=20)
    projects: str = Field(default="[]")
    created_at: datetime = Field(default_factory=utcnow)
    created_by: str | None = Field(default=None, max_length=64)


class OidcUserGrant(SQLModel, table=True):
    """Projects an OIDC user reads in the web interface, granted by name (``reader``).

    Usually created when an administrator approves an enrollment request: the developer who
    enrolled a project for the MCP tools reads its reports in the web interface. ``username`` is
    compared exactly with the ``SECREVIEW_OIDC_USERNAME_CLAIM`` claim of the login; ``projects``
    is the JSON list of the projects (never empty).
    """

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True, max_length=200)
    projects: str = Field(default="[]")
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    created_by: str | None = Field(default=None, max_length=64)
