"""Schemas of the scans (pipeline, content and scan tickets)."""

from typing import Any, Literal

from pydantic import BaseModel, Field

from ...storage.models import (
    MAX_AUTHOR_CHARS,
    ReviewType,
    Severity,
)
from ...storage.project_names import ProjectName
from .settings import AdvisoryDatabase

# ── Pipeline scans (security-review-ci scan-code and scan-deps) ─────────────

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

    project: ProjectName
    fail_on: Severity = Severity.HIGH
    # Store the result as a report of the project
    save: bool = False
    repository: str | None = Field(default=None, max_length=500)
    branch: str | None = Field(default=None, max_length=200)
    commit_sha: str | None = Field(default=None, max_length=64)
    # Username of the developer, declared by the client (not authenticated); the user of a
    # personal token is the author instead
    author: str | None = Field(default=None, max_length=MAX_AUTHOR_CHARS)


class CodeScanRequest(ScanRequest):
    """Files of a codebase listed and read by ``security-review-ci scan-code``."""

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
    """Manifests and lockfiles read by ``security-review-ci scan-deps``."""

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
    # Findings that a previous report of the project already raised, and the decisions of a
    # person (acceptance, false positive) carried to them
    recurring_findings: int = 0
    carried_decisions: int = 0


class CodeMatch(BaseModel):
    """A line matched by a scan rule (secrets masked in the excerpt)."""

    rule_id: str
    title: str
    severity: Severity
    cwe: str | None
    line: int
    excerpt: str
    advice: str


class ContentScanRequest(BaseModel):
    """Fragment sent by the scan_code tool of the MCP server (see
    app_settings.mcp_scan_controller_url)."""

    # Bounded by SECREVIEW_MAX_CONTENT_CHARS once received
    content: str
    language: str = Field(min_length=1, max_length=40)


class ScanTicketRequest(BaseModel):
    """Project of a codebase scan started by the MCP tool start_codebase_scan."""

    project: str = Field(min_length=1, max_length=200)
    # Scans the ticket opens: both, or the code or dependency scan only
    scope: Literal["all", "code", "deps"] = "all"


class ScanTicketResult(BaseModel):
    """Single-use ticket of a codebase scan (shown once), and where security-review-ci sends it."""

    ticket: str
    project: str
    expires_at: str
    # Public URL of the controller (None when unknown) and whether it serves the client
    controller_url: str | None
    client_download: bool


class ContentMatch(CodeMatch):
    """A match of a fragment; an OpenGrep match also gives its last line and its message."""

    line_end: int | None = None
    description: str | None = None


class ContentScanResult(BaseModel):
    """Matches of a fragment (leads to verify, secrets masked), and the engines that ran."""

    language: str
    lines_scanned: int
    matches: list[ContentMatch]
    # Matches hidden by a secreview:ignore marker, reported so that they can be audited
    suppressed: list[ContentMatch]
    engines: list[Literal["rules", "opengrep"]]


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
