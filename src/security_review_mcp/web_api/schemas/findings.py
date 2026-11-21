"""Schemas of the projects, reports, findings, trends and gate."""

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from ...reports import services
from ...storage.models import (
    MAX_COMMENT_CHARS,
    MAX_STATUS_REASON_CHARS,
    FindingPublic,
    FindingStatus,
    ReviewType,
    Severity,
)
from ...storage.project_names import ProjectName
from .common import Granularity

# ── Projects, reports and findings ───────────────────────────────────────────


class ProjectSummary(BaseModel):
    """One project with its open findings."""

    project: str
    reports_total: int
    # None for a project without any report yet
    last_report_at: str | None
    open_findings_total: int
    open_findings_by_severity: dict[str, int]
    worst_open_severity: Severity | None
    # The holders of projects.autojoin may not join this project at once
    autojoin_blocked: bool = False


class ProjectAutojoin(BaseModel):
    """Whether the autojoin of a project is blocked (PUT /projects/{project}/autojoin)."""

    project: str
    autojoin_blocked: bool


class ProjectAutojoinUpdate(BaseModel):
    """Block (true) or allow again (false) the autojoin of a project."""

    blocked: bool


class ProjectCreate(BaseModel):
    """Name of a new project (POST /projects), normalized."""

    project: ProjectName


class ProjectDeleted(BaseModel):
    """What the deletion of a project removed (DELETE /projects/{project})."""

    project: str
    reports: int
    findings: int
    # Users who lost their roles on the project, and the claims of the OIDC mappings changed
    members_removed: int
    mappings_changed: list[str]
    tokens_revoked: int
    tokens_changed: int


class PendingProject(BaseModel):
    """A project requested by an enrollment, waiting for an approval (GET /projects/pending)."""

    id: int
    project: str
    # The project already exists: the request asks for an access to it
    existing: bool
    # Free text given by the client (not verified), its address and its token (or anonymous)
    requested_by: str | None
    requested_from: str | None
    requested_with: str | None
    created_at: str
    # The request is deleted at this date unless it is approved
    expires_at: str


class PendingProjectApproved(PendingProject):
    """An approved project (created when new): the requesting user, if any, got the ``reader``
    role on it."""

    granted_to: str | None


class ProjectPosture(BaseModel):
    """Open findings of a project across all its reports."""

    project: str
    reports_total: int
    open_findings_total: int
    open_findings_by_severity: dict[str, int]
    worst_open_severity: Severity | None


class ReportSummary(BaseModel):
    """One line of the report list."""

    report_id: int
    project: str
    branch: str | None
    commit_sha: str | None
    review_type: ReviewType | None
    risk_level: Severity
    reviewer: str | None
    author: str | None
    submitted_by: str | None
    created_at: str
    findings_total: int
    findings_open: int
    summary: str


class ProjectFinding(FindingPublic):
    """A finding of a project, with the context of its report."""

    project: str
    branch: str | None
    commit_sha: str | None
    review_type: ReviewType | None
    report_created_at: datetime


class ProjectFindingPage(BaseModel):
    """One page of the findings of a project, or of every project in the scope of the caller
    (``project`` None; ``total`` counts every matching finding)."""

    project: str | None
    total: int
    findings: list[ProjectFinding]


class RiskAcceptance(ProjectFinding):
    """An accepted risk: the finding, the context of its report, whether the acceptance has
    expired (the finding counts as open again) or expires soon, and its number of comments."""

    expired: bool
    expiring_soon: bool
    comments_total: int


class RiskAcceptancePage(BaseModel):
    """One page of the accepted risks of a project, or of every project in the scope of the
    caller (``project`` None; ``total`` counts every acceptance)."""

    project: str | None
    total: int
    acceptances: list[RiskAcceptance]


class FindingCommentCreate(BaseModel):
    """Body of POST /findings/{id}/comments: a comment, which can never be edited."""

    body: str = Field(min_length=1, max_length=MAX_COMMENT_CHARS)


# Hard cap of the ids of a bulk triage decision (the service counts distinct ids)
MAX_BULK_FINDINGS = services.MAX_BULK_FINDINGS


class FindingStatusUpdate(BaseModel):
    """Body of PATCH /findings/{id}: a triage decision.

    ``accepted`` needs a reason and an expiry date (the finding counts as open again from that
    day, 00:00 UTC), unless SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED is on for the date. A false
    positive needs no expiry date and its reason is optional. Reason
    and expiry are optional to accept a finding less severe than
    SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY.
    """

    status: FindingStatus
    reason: str | None = Field(default=None, max_length=MAX_STATUS_REASON_CHARS)
    expires_on: date | None = None


class FindingBulkStatusUpdate(FindingStatusUpdate):
    """Body of PATCH /findings: the same triage decision for several findings, all or nothing.

    At most MAX_BULK_FINDINGS ids in the body.
    """

    finding_ids: list[Annotated[int, Field(ge=1)]] = Field(
        min_length=1, max_length=MAX_BULK_FINDINGS
    )


class FindingSeverityUpdate(BaseModel):
    """Body of PATCH /findings/{id}/severity: a severity raised by a security analyst.

    The severity must be above the one given by the report, or equal to it to undo an
    escalation; the justification is required.
    """

    severity: Severity
    reason: str = Field(min_length=1, max_length=MAX_STATUS_REASON_CHARS)


class TrendPeriod(BaseModel):
    """One period of the trend of a project."""

    period: str
    reports: int
    worst_report_risk: Severity | None
    new: dict[str, int]
    new_total: int
    fixed_total: int
    dismissed_total: int
    open_at_end: dict[str, int]
    open_total: int
    risk_score: int


class CweCount(BaseModel):
    """A CWE among the open findings and its number of findings."""

    cwe: str
    count: int


class RemediationTime(BaseModel):
    """Time to remediate the findings of one severity, in days."""

    count: int
    mean_days: float
    median_days: float


class TrendSummary(BaseModel):
    """Totals of the trend window and the backlog open now."""

    reports_total: int
    reports_in_window: int
    new_findings: int
    fixed_findings: int
    dismissed_findings: int
    open_now: dict[str, int]
    open_now_total: int
    risk_score_now: int
    oldest_open_days: dict[str, float]
    top_open_cwes: list[CweCount]
    mttr_days: dict[str, RemediationTime]


class Trend(BaseModel):
    """Evolution of the security posture of a project (see trends.get_trend)."""

    project: str
    window_days: int
    granularity: Granularity
    generated_at: str
    direction: Literal["improving", "worsening", "stable", "insufficient_data"]
    summary: TrendSummary
    periods: list[TrendPeriod]
    notes: list[str]
    risk_score_weights: dict[str, int]


class GateResult(BaseModel):
    """Security gate of a project: ``passed`` is false while open findings reach ``fail_on``."""

    project: str
    report_id: int | None
    fail_on: Severity
    passed: bool
    blocking_findings: int
    open_findings_by_severity: dict[str, int]
    # Decisions at or above fail_on that expire within expiry_warning_days: they block again then
    expiring_soon: int
    expiry_warning_days: int
