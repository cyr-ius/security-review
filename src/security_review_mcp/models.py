"""SQLModel models: table models (stored) and data models (MCP tool schemas)."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import field_validator
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
    report: "SecurityReport" = Relationship(back_populates="findings")


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
