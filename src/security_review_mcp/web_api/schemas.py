"""Request and response schemas of the controller REST API.

Every route declares its response model: FastAPI validates the answer and drops any field
that is not declared, so a value added to a service (a hash, a secret) never leaks by
accident, and the OpenAPI document describes each answer. Dates produced by the services are
already ISO 8601 strings and are kept as such.
"""

from datetime import date, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .. import access_control, app_settings, proxy, rules_loader, standards, token_store, web_users
from ..config import MAX_RETENTION_DAYS, REPORT_LANGUAGE_MAX_CHARS
from ..http_server import Role
from ..models import (
    MAX_AUTHOR_CHARS,
    MAX_STATUS_REASON_CHARS,
    FindingPublic,
    FindingStatus,
    ReviewType,
    Severity,
)

AuthSource = Literal["local", "oidc"]
Origin = Literal["builtin", "custom"]
Granularity = Literal["day", "week", "month"]

# ── Identity and login ───────────────────────────────────────────────────────


class Identity(BaseModel):
    """Who is calling and what they may do."""

    client: str
    # Role of a token; for a web user, the web role that sums up its permissions
    role: Role
    can_triage: bool
    # Always true: the API answers authenticated requests only (kept for API compatibility)
    auth_enabled: bool
    # Projects whose reports the caller reads; None: every project
    projects: list[str] | None = None
    # Each permission of the caller (see access_control.Permission) with its projects (None:
    # every project)
    permissions: dict[str, list[str] | None] = Field(default_factory=dict)
    # True for a local web user (logged in with a password, which it may change)
    local_account: bool = False
    # Source of the account of a web user ("local" or "oidc"); None for a bearer token
    auth_source: AuthSource | None = None
    # A web user whose password was set by someone else: it must change it before anything else
    must_change_password: bool = False
    version: str


Theme = Literal["light", "dark", "auto"]


class Preferences(BaseModel):
    """Preferences of a web user in the web interface; body of PUT /me/preferences."""

    # auto: the system preference (prefers-color-scheme)
    theme: Theme


class AuthConfig(BaseModel):
    """Login methods offered by the login page (web users only: tokens are for the API)."""

    # Username and password of a local web user (false with SECREVIEW_OIDC_ONLY and OIDC enabled)
    password: bool = True
    oidc: bool
    oidc_display_name: str | None = None


class PasswordLogin(BaseModel):
    """Body of POST /auth/login."""

    username: str = Field(min_length=1, max_length=web_users.MAX_USERNAME_CHARS)
    password: str = Field(min_length=1, max_length=web_users.MAX_PASSWORD_CHARS)


class LoginSession(BaseModel):
    """Session opened by a password login, sent back as a bearer token."""

    session: str
    expires_in: int
    username: str
    role: Role
    # True: only the change of the password is reachable until it is done
    must_change_password: bool = False


class PasswordChange(BaseModel):
    """Body of PUT /me/password: the current password and the new one."""

    current_password: str = Field(min_length=1, max_length=web_users.MAX_PASSWORD_CHARS)
    new_password: str = Field(
        min_length=web_users.MIN_PASSWORD_CHARS, max_length=web_users.MAX_PASSWORD_CHARS
    )


class HealthStatus(BaseModel):
    """Answer of the liveness probes."""

    status: Literal["ok"] = "ok"


class About(BaseModel):
    """What the About page shows: version, links, Swagger and backend status."""

    version: str
    documentation_url: str | None
    repository_url: str | None
    issues_url: str | None
    # The Swagger documentation is served (SECREVIEW_SWAGGER_ENABLED and its files built)
    swagger_url: str | None
    health_url: str


class UpdateStatus(BaseModel):
    """Latest release on GitHub against the running version (SECREVIEW_UPDATE_CHECK_ENABLED)."""

    enabled: bool
    current: str
    latest: str | None
    update_available: bool
    release_url: str | None
    checked_at: str | None
    # Why the latest release is unknown while enabled
    error: Literal["unreachable", "invalid"] | None


# ── Projects, reports and findings ───────────────────────────────────────────


class ProjectSummary(BaseModel):
    """One project with its open findings."""

    project: str
    reports_total: int
    last_report_at: str
    open_findings_total: int
    open_findings_by_severity: dict[str, int]
    worst_open_severity: Severity | None


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


class FindingStatusUpdate(BaseModel):
    """Body of PATCH /findings/{id}: a triage decision.

    ``accepted`` and ``false_positive`` need a reason and an expiry date (the finding counts as
    open again from that day, 00:00 UTC).
    """

    status: FindingStatus
    reason: str | None = Field(default=None, max_length=MAX_STATUS_REASON_CHARS)
    expires_on: date | None = None


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


# ── Pipeline scans (security-review-ci code-scan and deps-scan) ─────────────

# Bound of a file path: the file_path of a finding
MAX_SCAN_PATH_CHARS = 500
MAX_SKIP_REASON_CHARS = 200


class ScanFile(BaseModel):
    """A file sent for a scan: its path relative to the scanned directory (a label, never read
    on the controller) and its content."""

    path: str = Field(min_length=1, max_length=MAX_SCAN_PATH_CHARS)
    # Bounded by SECREVIEW_MAX_SCAN_REQUEST_MB (whole body) and, once received, by
    # SECREVIEW_MAX_SCAN_FILE_CHARS (code) or SECREVIEW_MAX_DEPENDENCY_CHARS (dependencies)
    content: str


class SkippedFile(BaseModel):
    """A file that was not scanned, with the reason."""

    file: str = Field(min_length=1, max_length=MAX_SCAN_PATH_CHARS)
    reason: str = Field(min_length=1, max_length=MAX_SKIP_REASON_CHARS)


class ScanRequest(BaseModel):
    """Fields shared by the scan requests: project, threshold and report to store."""

    project: str = Field(min_length=1, max_length=200)
    fail_on: Severity = Severity.HIGH
    # Store the result as a report of the project
    save: bool = False
    repository: str | None = Field(default=None, max_length=500)
    branch: str | None = Field(default=None, max_length=200)
    commit_sha: str | None = Field(default=None, max_length=64)
    # Username of the developer, declared by the client (not authenticated)
    author: str | None = Field(default=None, max_length=MAX_AUTHOR_CHARS)


class CodeScanRequest(ScanRequest):
    """Files of a codebase listed and read by ``security-review-ci code-scan``."""

    # Scanned directory as given to the client, only shown in the scope of the report
    root: str = Field(default=".", min_length=1, max_length=MAX_SCAN_PATH_CHARS)
    listing: Literal["git", "walk"] = "git"
    files: list[ScanFile]
    # Files the client did not send (binary, too large, symbolic link...)
    skipped: list[SkippedFile] = []
    # Files skipped by an exclusion glob, and files of an unsupported type (counted only)
    excluded: int = Field(default=0, ge=0)
    unsupported: int = Field(default=0, ge=0)
    # Also answer the matches as a SARIF 2.1.0 log
    sarif: bool = False


class DependencyScanRequest(ScanRequest):
    """Manifests and lockfiles read by ``security-review-ci deps-scan``."""

    files: list[ScanFile] = Field(min_length=1)
    # Refuse the scan (422) when the vulnerability check cannot run for a file
    require_database: bool = False


class SavedReport(BaseModel):
    """Report stored by a scan."""

    report_id: int
    project: str
    review_type: ReviewType | None
    author: str | None
    risk_level: Severity
    findings_count: int
    findings_by_severity: dict[str, int]


class CodeMatch(BaseModel):
    """A line matched by a scan rule (secrets masked in the excerpt)."""

    rule_id: str
    title: str
    severity: Severity
    cwe: str | None
    line: int
    excerpt: str
    advice: str


class CodeScanFile(BaseModel):
    """Matches of one scanned file."""

    file: str
    language: str
    lines: int
    matches: list[CodeMatch]
    # Matches hidden by a secreview:ignore marker, reported so that they can be audited
    suppressed: list[CodeMatch]
    # True when the file reached the number of matches kept per file
    truncated: bool


class ScanVerdict(BaseModel):
    """Verdict of a scan at the requested threshold, and the report stored with ``save``."""

    fail_on: Severity
    blocked: bool
    blocking_findings: int
    saved_report: SavedReport | None


class CodeScanResult(ScanVerdict):
    """Result of a code scan (leads to verify, not confirmed vulnerabilities)."""

    root: str
    listing: Literal["git", "walk"]
    files_scanned: int
    files_skipped: int
    files_unsupported: int
    lines_scanned: int
    matches_count: int
    suppressed_count: int
    by_severity: dict[str, int]
    files: list[CodeScanFile]
    skipped: list[SkippedFile]
    # SARIF 2.1.0 log of the matches, when asked for
    sarif: dict[str, Any] | None = None


class DependencyVulnerability(BaseModel):
    """A component version affected by an advisory."""

    advisory_id: str
    aliases: list[str]
    also_known_as: list[str]
    summary: str | None
    severity: Severity
    # False when the advisory has no severity (medium is assumed)
    severity_known: bool
    fixed_versions: list[str]
    recommended_upgrade: str | None
    ecosystem: str
    package: str
    version: str
    file: str
    line: int | None


class DependencyHygieneIssue(BaseModel):
    """A hygiene issue of a dependency file (unpinned version, insecure source...)."""

    rule_id: str
    title: str
    severity: Severity
    cwe: str | None
    message: str
    line: int | None
    file: str


class DependencyFileScan(BaseModel):
    """Scan of one dependency file (the list of components is not returned)."""

    file: str
    file_type: str
    ecosystem: str
    is_lockfile: bool
    components_total: int
    components_resolved: int
    components_unresolved: int
    # performed, skipped_no_advisory_database or skipped_no_advisories_for_ecosystem
    vulnerability_check: str
    vulnerabilities_count: int
    vulnerabilities: list[DependencyVulnerability]
    hygiene_count: int
    hygiene: list[DependencyHygieneIssue]
    advisory_database: AdvisoryDatabase
    notes: list[str]


class DependencyScanResult(ScanVerdict):
    """Result of a dependency scan."""

    files: list[DependencyFileScan]


# ── Rules, checklists and development standards ─────────────────────────────


class RuleWrite(BaseModel):
    """A custom scan rule sent to the web API."""

    id: str = Field(min_length=3, max_length=rules_loader.MAX_ID_CHARS)
    title: str = Field(min_length=1, max_length=rules_loader.MAX_TITLE_CHARS)
    severity: Severity
    cwe: str = Field(default="", max_length=20)
    languages: list[Annotated[str, Field(max_length=32)]] = Field(min_length=1, max_length=32)
    pattern: str = Field(min_length=1, max_length=rules_loader.MAX_PATTERN_CHARS)
    advice: str = Field(default="", max_length=rules_loader.MAX_TEXT_CHARS)
    ignore_case: bool = True


class RuleEnabledUpdate(BaseModel):
    """Enabled state of a custom scan rule."""

    enabled: bool


class StoredRule(BaseModel):
    """A scan rule stored in the database (default or custom)."""

    id: str
    title: str
    severity: Severity
    cwe: str
    languages: list[str]
    pattern: str
    advice: str
    ignore_case: bool
    origin: Origin
    # True for a default rule edited by an administrator
    modified: bool
    enabled: bool
    updated_at: str


class RuleCatalog(BaseModel):
    """The stored rules and the diagnostics of the active registry."""

    rules: list[StoredRule]
    load_errors: list[str]


class RuleReload(BaseModel):
    """Summary returned after a rule change or a reload."""

    loaded_rules: int
    load_errors: list[str]


class ChecklistItemWrite(BaseModel):
    """A checklist item sent to the web API."""

    domain: str = Field(min_length=1, max_length=31)
    id: str = Field(min_length=3, max_length=rules_loader.MAX_ID_CHARS)
    title: str = Field(min_length=1, max_length=rules_loader.MAX_TITLE_CHARS)
    what_to_look_for: str = Field(min_length=1, max_length=rules_loader.MAX_TEXT_CHARS)
    cwe: str = Field(default="", max_length=20)


class StoredChecklistItem(BaseModel):
    """A checklist item stored in the database."""

    domain: str
    id: str
    title: str
    what_to_look_for: str
    cwe: str
    origin: Origin
    modified: bool


class ChecklistCatalog(BaseModel):
    """The stored checklist items and the diagnostics of the active registry."""

    checklist_items: list[StoredChecklistItem]
    load_errors: list[str]


class ChecklistReload(BaseModel):
    """Summary returned after a checklist item change."""

    loaded_checklist_items: int
    load_errors: list[str]


class StandardWrite(BaseModel):
    """A development standard sent to the web API (validated again by standards.normalize)."""

    slug: str = Field(min_length=1, max_length=50)
    title: str = Field(min_length=1, max_length=standards.MAX_TITLE_CHARS)
    description: str = Field(default="", max_length=standards.MAX_DESCRIPTION_CHARS)
    technologies: list[Annotated[str, Field(max_length=standards.MAX_KEYWORD_CHARS)]] = Field(
        default_factory=list, max_length=standards.MAX_KEYWORDS
    )
    file_patterns: list[Annotated[str, Field(max_length=standards.MAX_PATTERN_CHARS)]] = Field(
        default_factory=list, max_length=standards.MAX_KEYWORDS
    )
    content: str = Field(min_length=1, max_length=standards.MAX_CONTENT_CHARS)
    enabled: bool = True


class PackUpload(BaseModel):
    """A TOML pack (rules and checklists, or development standards) uploaded for import."""

    # File name, only used in the error messages
    name: str = Field(default="pack.toml", min_length=1, max_length=200)
    # Bounded again (in bytes) by rule_store.import_packs and standards.import_pack
    content: str = Field(min_length=1, max_length=standards.MAX_PACK_BYTES)


class RulePackImport(BaseModel):
    """Outcome of a rule pack import and the diagnostics of the reloaded registry."""

    files: list[str]
    rules: int
    checklist_items: int
    disabled_rules: int
    replaced: bool
    loaded_rules: int
    loaded_checklist_items: int
    load_errors: list[str]


class StandardPackImport(BaseModel):
    """Outcome of a development standards import: slugs created and replaced."""

    file: str
    created: list[str]
    updated: list[str]


class StandardSummary(BaseModel):
    """A development standard without its content."""

    slug: str
    title: str
    description: str
    technologies: list[str]
    file_patterns: list[str]
    enabled: bool
    content_chars: int
    updated_at: str
    updated_by: str | None


class Standard(StandardSummary):
    """A development standard with its Markdown content."""

    content: str
    created_at: str


class StandardCatalog(BaseModel):
    """The development standards, disabled ones included."""

    standards: list[StandardSummary]


# ── Tokens and enrollments ───────────────────────────────────────────────────

_ProjectName = Annotated[str, Field(min_length=1, max_length=200)]


class ProjectTokenCreate(BaseModel):
    """A role-specific token scoped to one or several projects, or to every project."""

    label: str = Field(min_length=1, max_length=64)
    # mcp: MCP agent; ci: pipeline token (gate, SARIF, trend and scans of its projects only,
    # see ci_client); api: REST API (Swagger, scripts) with the permissions of access_role_id
    role: Literal["mcp", "ci", "api"] = "mcp"
    # null: every project (refused for a ci token); a list is refused for an api token whose
    # role holds a permission on the whole controller
    projects: list[_ProjectName] | None = Field(
        min_length=1, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )
    # Validity in days (null: SECREVIEW_TOKEN_MAX_DAYS, or no expiry when it is 0)
    expires_in_days: int | None = Field(default=None, ge=1, le=MAX_RETENTION_DAYS)
    # Role of an api token (required for it, refused for the others)
    access_role_id: int | None = Field(default=None, ge=1)


class TokenRoleChoice(BaseModel):
    """A role an api token may hold (GET /project-tokens/roles)."""

    id: int
    name: str
    permissions: list[access_control.Permission]
    # Only scoped permissions: the token may be limited to projects
    scoped: bool


class PersonalTokenCreate(BaseModel):
    """Body of POST /me/tokens: an api token of the logged-in user, with its rights."""

    label: str = Field(min_length=1, max_length=64)
    # Validity in days (null: SECREVIEW_TOKEN_MAX_DAYS, or no expiry when it is 0)
    expires_in_days: int | None = Field(default=None, ge=1, le=MAX_RETENTION_DAYS)


class ProjectTokenProjects(BaseModel):
    """Body of PUT /project-tokens/{id}/projects."""

    # null: every project (refused for a ci token)
    projects: list[_ProjectName] | None = Field(
        min_length=1, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )


class ProjectTokenRotation(BaseModel):
    """Body of POST /project-tokens/{id}/rotate."""

    # Hours during which the previous secret keeps working (0: it stops at once)
    grace_hours: int = Field(default=0, ge=0, le=token_store.MAX_ROTATION_GRACE_HOURS)
    # Validity of the new secret in days (null: SECREVIEW_TOKEN_MAX_DAYS, or no expiry)
    expires_in_days: int | None = Field(default=None, ge=1, le=MAX_RETENTION_DAYS)


class ProjectToken(BaseModel):
    """Metadata of a token managed in the web interface, never its hash."""

    id: str
    label: str
    role: Role
    # First project of the token (kept for API compatibility)
    project: str | None
    # None: every project
    projects: list[str] | None
    pending_projects: list[str]
    status: Literal["active", "pending"]
    created_at: str
    expires_at: str | None
    expired: bool
    rotated_at: str | None
    # End of the grace period of the previous secret after a rotation
    grace_until: str | None
    # api token: its role (role token), or personal (the rights of the user who created it)
    access_role_id: int | None
    personal: bool


class ProjectTokenSecret(ProjectToken):
    """A token just created or rotated: ``token`` is its secret, returned exactly once."""

    token: str


class EnrollmentApproval(BaseModel):
    """Optional body of an approval: the web user who also reads the project on the web (an
    unknown name becomes an OIDC user when OIDC is enabled)."""

    portal_user: str | None = Field(default=None, max_length=web_users.MAX_USERNAME_CHARS)


class EnrollmentRequest(BaseModel):
    """A project token requested by a client, waiting for an administrator (never a secret)."""

    id: str
    token_id: str
    label: str
    role: Role
    project: str
    # new: first enrollment (new token); additional: one more project for an active token
    kind: Literal["new", "additional"]
    status: Literal["pending", "active"]
    requested_by: str | None
    requested_from: str | None
    created_at: str


# ── Web users, roles and groups ──────────────────────────────────────────────


class UserGroupMembership(BaseModel):
    """Membership of a web user in a group."""

    group_id: int
    name: str
    # local: given by an administrator; oidc: named by the groups claim at the last login
    source: AuthSource


class WebUser(BaseModel):
    """A web user, local or OIDC; never its password hash nor its subject."""

    id: int
    username: str
    auth_source: AuthSource
    groups: list[UserGroupMembership]
    permissions: dict[str, list[str] | None]
    # Web role that sums up the permissions; None: no permission
    effective_role: Role | None
    # True once an OIDC user logged in (bound to its identity provider account)
    sso_linked: bool
    created_at: str | None
    updated_at: str | None
    # None for an OIDC user (no password)
    password_changed_at: str | None
    # Its password was set by someone else: it must change it at its next login
    must_change_password: bool = False
    last_login_at: str | None
    created_by: str | None


class WebUserWithPassword(WebUser):
    """A web user just created or reset: ``password`` is set when it was generated (once)."""

    password: str | None = None


class RevokedUser(BaseModel):
    """A deleted OIDC user: a login never creates it again until the revocation is lifted."""

    username: str
    revoked_at: str | None
    revoked_by: str | None


class EnrollmentApproved(EnrollmentRequest):
    """An approved request; ``portal_user`` is present when a web user got read access."""

    projects: list[str] | None
    portal_user: WebUser | None = None


class WebUserCreate(BaseModel):
    """A web user and its groups, the only source of its permissions. A local one without
    ``password`` gets a random one, returned once; an OIDC one (``auth_source="oidc"``) has no
    password and also joins its OIDC groups at each login."""

    # A user has no role of its own: an unknown field (such as "roles") is refused, not ignored
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=web_users.MAX_USERNAME_CHARS)
    auth_source: AuthSource = "local"
    password: str | None = Field(
        default=None,
        min_length=web_users.MIN_PASSWORD_CHARS,
        max_length=web_users.MAX_PASSWORD_CHARS,
    )
    group_ids: list[Annotated[int, Field(ge=1)]] = Field(
        default_factory=list, max_length=access_control.MAX_GROUPS
    )


class WebUserUpdate(BaseModel):
    """Groups an administrator gives to a web user (its OIDC groups are kept); a missing field
    is left unchanged."""

    # A user has no role of its own: an unknown field (such as "roles") is refused, not ignored
    model_config = ConfigDict(extra="forbid")

    group_ids: list[Annotated[int, Field(ge=1)]] | None = Field(
        default=None, max_length=access_control.MAX_GROUPS
    )


class PasswordReset(BaseModel):
    """New password of a web user, set by an administrator (null: generate one)."""

    password: str | None = Field(
        default=None,
        min_length=web_users.MIN_PASSWORD_CHARS,
        max_length=web_users.MAX_PASSWORD_CHARS,
    )


class PermissionInfo(BaseModel):
    """A permission a role may hold, and whether it can be limited to projects."""

    name: access_control.Permission
    scoped: bool


class RoleWrite(BaseModel):
    """A custom role: a name and the permissions it holds."""

    name: str = Field(min_length=1, max_length=access_control.MAX_ROLE_NAME_CHARS)
    description: str = Field(default="", max_length=access_control.MAX_DESCRIPTION_CHARS)
    permissions: list[access_control.Permission] = Field(
        min_length=1, max_length=len(access_control.Permission)
    )


class AccessRole(BaseModel):
    """A role: a named set of permissions, given to groups."""

    id: int
    name: str
    description: str
    permissions: list[access_control.Permission]
    # Built-in role (reader, admin): neither changed nor deleted
    system: bool
    # Only scoped permissions: the role may be limited to projects in a group
    scoped: bool
    # Number of groups that have the role
    groups: int
    created_at: str
    updated_at: str
    created_by: str | None


class GroupWrite(BaseModel):
    """A group of web users. With ``sso``, the OIDC users whose groups claim holds ``name`` are
    members too."""

    name: str = Field(min_length=1, max_length=access_control.MAX_GROUP_NAME_CHARS)
    description: str = Field(default="", max_length=access_control.MAX_DESCRIPTION_CHARS)
    sso: bool = True


class GroupRoleBinding(BaseModel):
    """A role given to a group, on every project (empty ``projects``) or on some projects."""

    role_id: int = Field(ge=1)
    projects: list[_ProjectName] = Field(
        default_factory=list, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )


class GroupRolesUpdate(BaseModel):
    """Body of PUT /groups/{id}/roles: every role of the group."""

    roles: list[GroupRoleBinding] = Field(max_length=access_control.MAX_ROLES_PER_GROUP)


class GroupMembersUpdate(BaseModel):
    """Body of PUT /groups/{id}/members: the members added by an administrator."""

    user_ids: list[Annotated[int, Field(ge=1)]] = Field(
        max_length=access_control.MAX_MEMBERS_PER_CHANGE
    )


class GroupRole(BaseModel):
    """A role of a group, on every project (None) or on some projects."""

    role_id: int
    name: str
    projects: list[str] | None


class GroupMember(BaseModel):
    """A member of a group."""

    user_id: int
    username: str
    source: AuthSource


class UserGroup(BaseModel):
    """A group of web users with its roles and members."""

    id: int
    name: str
    description: str
    # The OIDC users whose groups claim holds the name are members too
    sso: bool
    roles: list[GroupRole]
    members: list[GroupMember]
    created_at: str
    updated_at: str
    created_by: str | None


class GroupCatalog(BaseModel):
    """The groups and the OIDC settings that use them."""

    oidc_enabled: bool
    roles_claim: str
    # OIDC groups created with the admin role at the login of a member
    admin_groups: list[str]
    # Group every OIDC user joins at each login
    default_group: str | None
    groups: list[UserGroup]


# ── Audit log ────────────────────────────────────────────────────────────────


class AuditEvent(BaseModel):
    """One entry of the audit log (details never hold a secret)."""

    id: int
    created_at: str
    action: str
    # user:NAME, token:LABEL, cli, anonymous or stdio
    actor: str
    target_type: str
    target_id: str | None
    project: str | None
    details: dict[str, Any]


class AuditPage(BaseModel):
    """One page of the audit log (``total`` counts every matching event)."""

    total: int
    events: list[AuditEvent]


# ── Settings, advisories and OIDC ─────────────────────────────────────────────


class ReportLanguageUpdate(BaseModel):
    """Body of PUT /settings/report-language: "" lets the agent choose, null removes the stored
    value. Refused (422) when SECREVIEW_REPORT_LANGUAGE is set: the variable takes precedence."""

    value: str | None = Field(default=None, max_length=REPORT_LANGUAGE_MAX_CHARS)


class ProxyUpdate(BaseModel):
    """Body of PUT /settings/proxy: proxy of the outgoing connections of the controller.

    A field left out is unchanged, ``null`` removes the stored value. A value is refused (422)
    when its variable is set (HTTPS_PROXY or HTTP_PROXY, NO_PROXY): the variable takes
    precedence. ``url`` ``""`` connects directly; a password sent back as returned by the API
    (``***``) keeps the stored one.
    """

    model_config = ConfigDict(extra="forbid")

    url: str | None = Field(default=None, max_length=proxy.MAX_PROXY_URL_CHARS)
    no_proxy: str | None = Field(default=None, max_length=proxy.MAX_NO_PROXY_CHARS)


class ReportLanguageSetting(BaseModel):
    """Language of the reports: stored value, variable, whether the variable is set (it then
    takes precedence over the stored value), effective value."""

    value: str | None
    env: str
    env_set: bool
    effective: str


class ProxyValue(BaseModel):
    """A proxy setting: stored in the web interface, variable, and whether the variable is set
    (it then takes precedence over the stored value)."""

    value: str | None
    env: str | None
    env_set: bool


class ProxyEffective(BaseModel):
    """Proxy actually used and where it comes from."""

    url: str | None
    no_proxy: str | None
    # environment: HTTPS_PROXY (else HTTP_PROXY); none: direct connection
    source: Literal["web", "environment", "none"]


class ProxySettings(BaseModel):
    """Proxy of the outgoing connections of the controller (passwords replaced by ``***``)."""

    url: ProxyValue
    no_proxy: ProxyValue
    effective: ProxyEffective


class OsvSettings(BaseModel):
    """Download of the OSV advisories (variables only)."""

    download_enabled: bool
    update_interval_hours: int
    url: str
    ecosystems: str
    cafile: str | None
    max_download_mb: int


class AppSettings(BaseModel):
    """Settings of the web interface, their variables and their effective values."""

    report_language: ReportLanguageSetting
    proxy: ProxySettings
    osv: OsvSettings


class AdvisoryDatabase(BaseModel):
    """Size and freshness of the advisory database."""

    loaded: bool
    advisories: int
    by_ecosystem: dict[str, int]
    last_imported_at: str | None
    age_days: int | None
    stale: bool


class AdvisoryUpdate(BaseModel):
    """One OSV update of the history."""

    id: int
    trigger: str
    triggered_by: str | None
    status: str
    source: str
    started_at: str
    finished_at: str | None
    # Per ecosystem, or {"error": ...} when the whole update failed
    results: dict[str, Any]


class AdvisoryOverview(BaseModel):
    """State of the advisory database and history of its updates."""

    database: AdvisoryDatabase
    download_enabled: bool
    running: bool
    updates: list[AdvisoryUpdate]


class AdvisoryUpdateStarted(BaseModel):
    """Identifier of the OSV update started in the background."""

    id: int


_OidcText = Annotated[str, Field(max_length=app_settings.MAX_OIDC_VALUE_CHARS)]


class OidcSettingsUpdate(BaseModel):
    """Body of PUT /oidc/settings and POST /oidc/settings/test.

    A field left out is unchanged, ``null`` removes the stored value. A value is refused (422)
    when its ``SECREVIEW_OIDC_*`` variable is set: the variable takes precedence. A client
    secret sent back as returned by the API (``***``) keeps the stored one; ``""`` makes the
    client public.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    issuer: _OidcText | None = None
    client_id: _OidcText | None = None
    client_secret: _OidcText | None = None
    redirect_uri: _OidcText | None = None
    scope: _OidcText | None = None
    roles_claim: _OidcText | None = None
    username_claim: _OidcText | None = None
    admin_groups: _OidcText | None = None
    default_group: _OidcText | None = None
    auto_create_users: bool | None = None
    display_name: _OidcText | None = None


class OidcSettingValue(BaseModel):
    """One OIDC setting: stored value, variable, whether the variable is set (it then takes
    precedence over the stored value), effective value."""

    value: bool | str | None
    env: bool | str | None
    env_set: bool
    effective: bool | str | None


class OidcSettings(BaseModel):
    """OIDC settings of the controller (a set client secret is replaced by ``***``)."""

    fields: dict[str, OidcSettingValue]
    # SECREVIEW_OIDC_CAFILE, variable only
    cafile: str | None
    callback_path: str
    # The OIDC login is enabled and valid on this controller
    active: bool


class OidcTestStep(BaseModel):
    """One step of the test of an identity provider."""

    name: str
    ok: bool
    detail: str


class OidcTestResult(BaseModel):
    """Outcome of the test of an identity provider."""

    success: bool
    steps: list[OidcTestStep]


# Declared before AdvisoryDatabase, which it holds
DependencyFileScan.model_rebuild()
