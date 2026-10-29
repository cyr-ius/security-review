"""MCP server exposing security-review prompts, tools and stored reports."""

import argparse
import functools
import logging
import sys
import threading
import time
from collections.abc import Callable
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ResourceNotFoundError, ToolError
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, ToolAnnotations
from pydantic import Field, SecretStr
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from . import __version__, app_settings, http_server, prompts, standards
from .auth import access_control, token_store
from .ci_client import EXIT_ERROR
from .config import (
    Settings,
    check_report_language,
    configure_logging,
    default_database_url,
    get_settings,
)
from .deps import advisories, depscan
from .observability import audit
from .reports import sarif, services, trends
from .rules import registry, scanner
from .storage.database import SchemaError, check_db, init_db
from .storage.models import (
    MAX_AUTHOR_CHARS,
    MAX_BRANCH_CHARS,
    MAX_CHECKLIST_RESULTS,
    MAX_COMMIT_SHA_CHARS,
    MAX_ITEM_ID_CHARS,
    MAX_REPOSITORY_CHARS,
    MAX_REVIEWER_CHARS,
    MAX_SCAN_RULES,
    MAX_STATUS_REASON_CHARS,
    ChecklistResult,
    FindingCreate,
    FindingStatus,
    ReviewType,
    SecurityReportPublic,
    Severity,
)
from .storage.project_names import ProjectName

logger = logging.getLogger("security_review_mcp")

INSTRUCTIONS = """\
Security code-review server.
- Use the prompts `security-review`, `api-security-review` and `configuration-review` to \
start a structured review, and `codebase-review` to review a whole repository (not only a diff).
- Use `get_review_checklist` and `scan_code` while reviewing. When their results give a report \
language, write your reply and the free-text fields of the report in that language.
- At the end of a review, call `save_security_report` once to store the report in the \
database: the server records the user of the token as its author. Use \
`list_security_reports`, `get_security_report` and `get_project_security_posture` to read \
stored results.
- You never change the status of a finding: `propose_finding_status` only records a proposal \
(fixed, accepted, false_positive) with its reason, which a person approves or rejects in the \
web interface. The gate keeps blocking until then.
- Before a review, call `request_project` with the project name: when the token does not \
reach the project yet, a user allowed to create projects gets it at once, otherwise the \
project is requested for an administrator to approve (which gives the user access to it). \
If its `status` is `requested`, do not review: give the user its `next_steps`.
- Before writing code, use the prompt `development-standards` (or the tool \
`get_development_standards`) to get the development standards of the technologies you work on.
"""

ENROLLMENT_INSTRUCTIONS = """\
Security code-review server, enrollment mode: the client sends no bearer token, so no tool is \
available. Tell the user to sign in to the web interface{where}, to create a personal MCP token \
in My account and to add it to the MCP client configuration as \
`Authorization: Bearer <token>`, then to reconnect. The review prompts (`security-review`...) \
give the same steps.
"""


ENROLLMENT_INSTRUCTIONS_NO_PERSONAL_TOKEN = """\
Security code-review server, enrollment mode: the client sends no bearer token, so no tool is \
available. Personal MCP tokens are disabled on this server: tell the user to ask an \
administrator for an MCP token and to add it to the MCP client configuration as \
`Authorization: Bearer <token>`, then to reconnect.
"""


def enrollment_instructions(web_url: str | None, personal_tokens: bool = True) -> str:
    """Instructions of the enrollment server, with the address of the web interface if known
    (from an administrator when the controller offers no personal MCP token)."""
    if not personal_tokens:
        return ENROLLMENT_INSTRUCTIONS_NO_PERSONAL_TOKEN
    return ENROLLMENT_INSTRUCTIONS.replace("{where}", f" ({web_url})" if web_url else "")


mcp = MCPServer(
    "security-review",
    title="Security Review",
    instructions=INSTRUCTIONS,
    version=__version__,
)

# Served by the HTTP transport to the clients that send no token (see http_server)
enrollment_mcp = MCPServer(
    "security-review",
    title=http_server.ENROLLMENT_SERVER_TITLE,
    instructions=enrollment_instructions(None),
    version=__version__,
)


def set_enrollment_web_url(web_url: str | None, personal_tokens: bool = True) -> None:
    """Give the address of the web interface in the instructions of the enrollment server, and
    tell whether the controller offers personal MCP tokens.

    The address is read after the server is built (see EnrollmentWebUrl); the host shows these
    instructions at connection, before any prompt. MCPServer exposes them read-only, hence the
    low-level server.
    """
    enrollment_mcp._lowlevel_server.instructions = enrollment_instructions(web_url, personal_tokens)


# How long the address of the web interface read for the clients without a valid token is kept
WEB_URL_CACHE_SECONDS = 30.0


class EnrollmentWebUrl:
    """Address of the web interface for the clients without a valid token (enrollment server,
    401): derived from the URL stored by the controller (app_settings.web_url), None if none;
    personal_tokens tells whether the controller offers personal MCP tokens
    (app_settings.personal_mcp_tokens), read at the same time.

    Read again at most every ``ttl`` seconds, so that an anonymous client cannot make the server
    query the database at each request; each reading updates the instructions of the
    enrollment server. Called from the threads of the HTTP transport.
    """

    def __init__(self, ttl: float = WEB_URL_CACHE_SECONDS) -> None:
        self.ttl = ttl
        self._lock = threading.Lock()
        self._value: str | None = None
        self._personal = True
        self._read_at: float | None = None

    def _refresh(self) -> None:
        """Read the stored values again once ``ttl`` has passed (lock held)."""
        now = time.monotonic()
        if self._read_at is None or now - self._read_at >= self.ttl:
            self._value = app_settings.web_url()
            self._personal = app_settings.personal_mcp_tokens()
            self._read_at = now
            set_enrollment_web_url(self._value, self._personal)

    def __call__(self) -> str | None:
        with self._lock:
            self._refresh()
            return self._value

    def personal_tokens(self) -> bool:
        """True while the controller offers personal MCP tokens."""
        with self._lock:
            self._refresh()
            return self._personal


enrollment_web_url = EnrollmentWebUrl()


class StoredOAuthResource:
    """The OAuth login of the MCP clients, as the controller publishes it in the database (URL
    of the MCP endpoint and of the controller, see app_settings.sync_mcp_oauth), None while it
    is off. Read again at most every ``ttl`` seconds, like EnrollmentWebUrl."""

    def __init__(self, ttl: float = WEB_URL_CACHE_SECONDS) -> None:
        self.ttl = ttl
        self._lock = threading.Lock()
        self._value: http_server.OAuthResource | None = None
        self._read_at: float | None = None

    def __call__(self) -> http_server.OAuthResource | None:
        with self._lock:
            now = time.monotonic()
            if self._read_at is None or now - self._read_at >= self.ttl:
                resource, issuer = app_settings.mcp_oauth_resource(), app_settings.controller_url()
                self._value = (
                    http_server.OAuthResource(resource, issuer) if resource and issuer else None
                )
                self._read_at = now
            return self._value


oauth_resource = StoredOAuthResource()


READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)


def _tool_errors(func: Callable[..., Any]) -> Callable[..., Any]:
    """Expose anticipated errors (not found, invalid input) to the model.

    The SDK hides the message of unexpected exceptions on purpose; only ToolError messages
    reach the model, so our own validation errors are converted here.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except (services.NotFoundError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

    return wrapper


def _resource_errors(func: Callable[..., Any]) -> Callable[..., Any]:
    """Same as _tool_errors, for resources."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except services.NotFoundError as exc:
            raise ResourceNotFoundError(str(exc)) from exc
        except ValueError as exc:
            raise ResourceError(str(exc)) from exc

    return wrapper


def _auth_state(ctx: Context) -> dict:
    """Identity stored in the ASGI scope by the HTTP middleware (empty with stdio)."""
    request = ctx.request_context.request
    scope = getattr(request, "scope", None) or {}
    return scope.get("state") or {}


def _caller_projects(ctx: Context) -> frozenset[str] | None:
    """Projects the caller's token is restricted to, or None.

    With stdio, or without authentication, there is no restriction.
    """
    return _auth_state(ctx).get("auth_projects")


def _caller_address(ctx: Context) -> str | None:
    """Client address of the HTTP request (None with stdio), audited with the project requests."""
    request = ctx.request_context.request
    client = getattr(request, "client", None)
    return client.host if client else None


# ── Prompts ──────────────────────────────────────────────────────────────────


def _report_language(requested: str) -> str:
    """Resolve the report language: prompt argument, web interface, SECREVIEW_REPORT_LANGUAGE."""
    try:
        return check_report_language(requested) or app_settings.report_language()
    except ValueError as exc:
        raise MCPError(code=INVALID_PARAMS, message=str(exc)) from exc


@mcp.prompt(
    name="security-review",
    title="Security code review",
    description=(
        "Review Python, Java, Go, C#, Rust, TypeScript/Node.js or Angular code for "
        "vulnerabilities and insecure settings."
    ),
)
def security_review(
    language: str = "",
    code: str = "",
    context: str = "",
    focus: str = "",
    report_language: str = "",
) -> str:
    """Build the general security-review prompt.

    Args:
        language: Languages of the code, for example "python" or "python, angular" (selects
            the checklists; aliases such as py or ts are accepted).
        code: Code or diff to review (leave empty to review the workspace files).
        context: Optional context (exposure, data sensitivity, authentication model...).
        focus: Optional areas to emphasize (for example "authentication, file upload").
        report_language: Language of the reply and of the stored report, for example French
            (default: SECREVIEW_REPORT_LANGUAGE).
    """
    return prompts.build_security_review_prompt(
        language, code, context, focus, _report_language(report_language)
    )


@mcp.prompt(
    name="api-security-review",
    title="REST API security review",
    description="Review REST API code against the OWASP API Security Top 10.",
)
def api_security_review(
    framework: str = "",
    code: str = "",
    context: str = "",
    focus: str = "",
    report_language: str = "",
) -> str:
    """Build the REST API review prompt.

    Args:
        framework: For example FastAPI, Spring Boot, Express.
        code: Controllers, routes, DTOs or diff to review.
        context: Optional context (public API, internal, consumers...).
        focus: Optional areas to emphasize.
        report_language: Language of the reply and of the stored report.
    """
    return prompts.build_api_review_prompt(
        framework, code, context, focus, _report_language(report_language)
    )


@mcp.prompt(
    name="configuration-review",
    title="Configuration security review",
    description="Review Docker, CI/CD, Spring, YAML or properties files for misconfiguration.",
)
def configuration_review(
    config_type: str = "",
    content: str = "",
    context: str = "",
    focus: str = "",
    report_language: str = "",
) -> str:
    """Build the configuration review prompt.

    Args:
        config_type: For example Dockerfile, GitLab CI, Jenkinsfile, Spring properties.
        content: Configuration content to review.
        context: Optional context (environment, exposure...).
        focus: Optional areas to emphasize.
        report_language: Language of the reply and of the stored report.
    """
    return prompts.build_config_review_prompt(
        config_type, content, context, focus, _report_language(report_language)
    )


@mcp.prompt(
    name="codebase-review",
    title="Whole codebase security review",
    description="Review a whole repository, not only a diff, starting from codebase scan results.",
)
def codebase_review(
    languages: str = "",
    scan_results: str = "",
    context: str = "",
    focus: str = "",
    report_language: str = "",
) -> str:
    """Build the whole-codebase review prompt.

    Args:
        languages: Main languages, for example "python, angular" (selects the checklists).
        scan_results: Optional output of
            `security-review-ci scan-code . --project <name> --format json`.
        context: Optional context (exposure, data sensitivity, authentication model...).
        focus: Optional areas to emphasize.
        report_language: Language of the reply and of the stored report.
    """
    language = _report_language(report_language)
    limit = get_settings().max_content_chars
    if len(scan_results) > limit:
        raise MCPError(
            code=INVALID_PARAMS,
            message=f"scan_results too large ({len(scan_results)} chars); the limit is {limit}. "
            "Filter it, for example with --exclude or --fail-on, or use --save and triage-report.",
        )
    return prompts.build_codebase_review_prompt(languages, scan_results, context, focus, language)


@mcp.prompt(
    name="dependency-review",
    title="Dependency and supply-chain review",
    description="Check manifests and lockfiles for vulnerable versions and risky practices.",
)
def dependency_review(
    ecosystem: str = "", files: str = "", context: str = "", report_language: str = ""
) -> str:
    """Build the dependency review prompt.

    Args:
        ecosystem: PyPI, npm, Maven, Go, crates.io or NuGet (leave empty for all).
        files: Dependency files with their names (leave empty to read the workspace files).
        context: Optional context (exposure, runtime vs dev usage...).
        report_language: Language of the reply and of the stored report.
    """
    return prompts.build_dependency_review_prompt(
        ecosystem, files, context, _report_language(report_language)
    )


@mcp.prompt(
    name="triage-report",
    title="Triage a security report",
    description="Re-assess the findings of a stored report and update their status.",
)
def triage_report(
    ctx: Context, report_id: int, context: str = "", report_language: str = ""
) -> str:
    """Build a triage prompt from a stored report.

    Args:
        report_id: Identifier returned by save_security_report.
        context: Optional deployment context to re-assess severity.
        report_language: Language of the reply.
    """
    language = _report_language(report_language)
    try:
        report = _visible_report(ctx, report_id)
    except services.NotFoundError as exc:
        raise MCPError(code=INVALID_PARAMS, message=str(exc)) from exc
    return prompts.build_triage_prompt(services.render_report_markdown(report), context, language)


def _visible_report(ctx: Context, report_id: int) -> SecurityReportPublic:
    """A report of the caller's scope, without its author.

    The author is often an e-mail address: as in the REST API, only a manager of the users or
    tokens sees it, in the web interface, and an MCP token is never one.
    """
    services.check_report_scope(_caller_projects(ctx), report_id)
    return services.get_report(report_id).model_copy(update={"author": None})


def _split_list(value: str) -> list[str]:
    """Split a prompt argument given as a comma or newline separated list."""
    return [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]


@mcp.prompt(
    name="development-standards",
    title="Development standards",
    description="Get the development standards of the technologies you work on before coding.",
)
def development_standards(
    technologies: str = "", files: str = "", task: str = "", context: str = ""
) -> str:
    """Build the prompt that applies the development standards to a coding task.

    Args:
        technologies: Technologies of the code, for example "python, fastapi, angular" (leave
            empty to let the assistant detect them from the workspace).
        files: Optional file names that reveal the stack, comma or newline separated (for
            example "pyproject.toml, angular.json").
        task: Optional description of what is to be written or changed.
        context: Optional context (project, constraints...).
    """
    wanted, paths = _split_list(technologies), _split_list(files)
    limit = get_settings().max_content_chars
    if len(task) + len(context) > limit:
        raise MCPError(
            code=INVALID_PARAMS, message=f"task and context too large; the limit is {limit}"
        )
    try:
        if wanted or paths:
            markdown = standards.render_lookup_markdown(standards.find_standards(wanted, paths))
        else:
            markdown = standards.render_catalog_markdown(standards.list_standards())
    except ValueError as exc:
        raise MCPError(code=INVALID_PARAMS, message=str(exc)) from exc
    return prompts.build_development_standards_prompt(markdown, wanted, task, context)


# ── Tools: knowledge and scanning ────────────────────────────────────────────


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def list_checklists() -> dict[str, int]:
    """List the available review checklists (built-in and internal) with their item count."""
    return {domain: len(registry.get_checklist(domain)) for domain in registry.domains()}


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def get_review_checklist(
    domain: Annotated[str, Field(description="A domain from list_checklists")],
) -> str:
    """Return the security checklist of a domain, in Markdown, with the report language."""
    checklist = registry.render_checklist_markdown(domain)
    language_block = prompts.report_language_block(app_settings.report_language())
    return "\n\n".join(x for x in (checklist, language_block) if x)


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def scan_code(
    content: Annotated[str, Field(description="Source or configuration text to scan")],
    language: Annotated[
        str, Field(description=f"One of: {', '.join(scanner.SUPPORTED_LANGUAGES)}")
    ],
) -> dict:
    """Quick pattern scan that returns suspicious lines to verify (not a full SAST).

    The scan is a first pass: every match must be confirmed by reading the code, and an
    empty result does not mean the code is safe. Excerpts have their secrets masked.
    """
    limit = get_settings().max_content_chars
    if len(content) > limit:
        raise ValueError(f"Content too large ({len(content)} chars); the limit is {limit}")
    matches, suppressed = registry.scan(content, language)
    return {
        "language": scanner.normalize_language(language),
        "lines_scanned": len(content.splitlines()),
        "matches_count": len(matches),
        "matches": matches,
        "suppressed_count": len(suppressed),
        "suppressed": suppressed,
        # Reviews made without a prompt only learn the configured language here
        "report_language": app_settings.report_language() or None,
        "note": (
            "Leads only: verify each one in context. No match does not mean safe. "
            "Suppressed lines carry an inline secreview:ignore marker: review them too."
        ),
    }


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def list_rules(
    language: Annotated[str | None, Field(description="Only rules for this language")] = None,
) -> dict:
    """List the active scan rules (built-in and internal) and any internal rule loading problem."""
    current = registry.snapshot()
    return {
        "rules": registry.describe_rules(language),
        "disabled_rules": sorted(current.disabled_rule_ids),
        "load_errors": list(current.errors),
    }


@mcp.tool(annotations=WRITE)
@_tool_errors
def reload_rules(ctx: Context) -> dict:
    """Re-read the internal rules from the database now (changes are otherwise seen within
    a few seconds)."""
    if _caller_projects(ctx) is not None:
        raise ValueError("A token restricted to projects cannot reload the rules")
    current = registry.reload()
    return {
        "rules_active": len(current.rules),
        "custom_rules": len(current.custom_rule_ids),
        "load_errors": list(current.errors),
    }


# ── Tools: development standards ─────────────────────────────────────────────


# Fields of a standard listed to the model (no content, no audit fields)
_STANDARD_FIELDS = ("slug", "title", "description", "technologies", "file_patterns")


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def list_development_standards() -> list[dict]:
    """List the development standards defined by the administrators (without their content).

    Each entry gives the slug, the title, the technologies it applies to and the file name
    patterns that reveal them. Read one with get_development_standards.
    """
    return [{key: item[key] for key in _STANDARD_FIELDS} for item in standards.list_standards()]


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def get_development_standards(
    technologies: Annotated[
        list[Annotated[str, Field(max_length=standards.MAX_KEYWORD_CHARS)]],
        Field(
            description="Technologies, frameworks or standard slugs, e.g. ['python', 'angular']",
            max_length=standards.MAX_QUERY_TECHNOLOGIES,
        ),
    ] = [],  # noqa: B006  (the SDK copies the default)
    files: Annotated[
        list[Annotated[str, Field(max_length=standards.MAX_QUERY_FILE_CHARS)]],
        Field(
            description="File names or paths of the workspace that reveal the stack, "
            "e.g. ['pyproject.toml', 'src/app/app.ts']",
            max_length=standards.MAX_QUERY_FILES,
        ),
    ] = [],  # noqa: B006
    format: Literal["markdown", "json"] = "markdown",
) -> dict | str:
    """Return the development standards to follow for technologies or files, before coding.

    A standard is selected by its technologies or by a file matching its patterns. The answer
    also names the technologies no standard covers.
    """
    if not technologies and not files:
        raise ValueError("Give at least one technology or file name")
    found = standards.find_standards(technologies, files)
    return standards.render_lookup_markdown(found) if format == "markdown" else found


# ── Tools: reports ───────────────────────────────────────────────────────────


@mcp.tool(annotations=WRITE)
@_tool_errors
def save_security_report(
    ctx: Context,
    project: Annotated[
        ProjectName,
        Field(
            description="Project name, used to group reports: the repository name (the server "
            "normalizes it: lowercase, last segment of a remote URL, '-' as separator)"
        ),
    ],
    summary: Annotated[str, Field(description="Executive summary of the review")],
    findings: Annotated[
        list[FindingCreate], Field(description="Confirmed findings (empty list if none)")
    ],
    repository: Annotated[str | None, Field(max_length=MAX_REPOSITORY_CHARS)] = None,
    branch: Annotated[str | None, Field(max_length=MAX_BRANCH_CHARS)] = None,
    commit_sha: Annotated[str | None, Field(max_length=MAX_COMMIT_SHA_CHARS)] = None,
    reviewer: Annotated[
        str | None,
        Field(max_length=MAX_REVIEWER_CHARS, description="Agent or person who reviewed"),
    ] = None,
    scope: Annotated[str | None, Field(description="What was reviewed")] = None,
    risk_level: Annotated[
        Severity | None,
        Field(description="Optional override; can only raise the risk computed from findings"),
    ] = None,
    review_type: Annotated[
        ReviewType | None,
        Field(
            description="Kind of review: the name of the review prompt used (security-review, "
            "api-security-review, configuration-review, dependency-review, codebase-review), "
            "or other"
        ),
    ] = None,
    author: Annotated[
        str | None,
        Field(
            max_length=MAX_AUTHOR_CHARS,
            description="Not needed: the server records the user of a personal token as the "
            "author, whatever is passed here. Only kept for a token without a user (created by "
            "an administrator), when the developer's username is known; never guess it",
        ),
    ] = None,
    checklist_results: Annotated[
        list[ChecklistResult] | None,
        Field(
            max_length=MAX_CHECKLIST_RESULTS,
            description="Every checklist item you walked through (the checklists of the prompt "
            "and those you fetched), with its outcome: ok (verified, nothing found), issue "
            "(reported as a finding), not_applicable, not_verifiable (not_covered is set by the "
            "server for the items you skipped)",
        ),
    ] = None,
    scan_rules: Annotated[
        list[Annotated[str, Field(max_length=MAX_ITEM_ID_CHARS)]] | None,
        Field(
            max_length=MAX_SCAN_RULES,
            description="Rule ids of every lead returned by scan_code, confirmed or dismissed",
        ),
    ] = None,
) -> dict:
    """Store a security report and its findings in the database.

    Call this once at the end of a review, with the free-text fields written in the report
    language given by the review prompt, scan_code or get_review_checklist, if any, the
    review_type given by the review prompt. The server records the user of a personal token
    as the author and the label of the token that saved the report. Secrets in
    free-text fields are masked before storage. Each text (summary, scope, and description,
    evidence and recommendation of a finding) is limited to SECREVIEW_MAX_CONTENT_CHARS.
    Returns the report id, the overall risk level, the finding counts and the review
    coverage: checklist items of the domains you used that got no result (not_covered) and
    warnings about unknown ids, which are not stored.
    """
    allowed = _caller_projects(ctx)
    if allowed is not None and project not in allowed:
        reachable = ", ".join(f"'{name}'" for name in sorted(allowed)) or "no project yet"
        raise ValueError(
            f"This token can only save reports for {reachable}; call request_project to "
            "create or request the project"
        )
    return services.save_report(
        project=project,
        summary=summary,
        findings=findings,
        repository=repository,
        branch=branch,
        commit_sha=commit_sha,
        reviewer=reviewer,
        scope=scope,
        risk_level=risk_level,
        review_type=review_type,
        # The owner of a personal token is authenticated: it wins over a declared author
        author=_auth_state(ctx).get("auth_owner") or author,
        submitted_by=_auth_state(ctx).get("auth_client"),
        # An empty list still checks the coverage: a review without it gets a warning
        checklist_results=checklist_results or [],
        scan_rules=scan_rules or [],
    )


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def get_security_report(
    ctx: Context,
    report_id: int,
    format: Literal["json", "markdown"] = "markdown",
) -> dict | str:
    """Return a stored report with its findings, as Markdown (default) or JSON, without the
    author of the report."""
    report = _visible_report(ctx, report_id)
    if format == "markdown":
        return services.render_report_markdown(report)
    return report.model_dump(mode="json")


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def list_security_reports(
    ctx: Context,
    project: ProjectName | None = None,
    risk_level: Severity | None = None,
    limit: Annotated[int, Field(ge=1, le=100)] = 20,
    offset: Annotated[int, Field(ge=0)] = 0,
    review_type: Annotated[
        ReviewType | None, Field(description="Keep only the reports of this kind of review")
    ] = None,
    author: Annotated[
        str | None,
        Field(
            max_length=MAX_AUTHOR_CHARS,
            description="Deprecated and ignored: the author of a report is not shown here",
        ),
    ] = None,
) -> list[dict]:
    """List stored reports, newest first, optionally filtered by project, risk or review type.

    The author of a report is neither returned nor used to filter (see _visible_report).
    """
    allowed = _caller_projects(ctx)
    if allowed is not None and project:
        services.check_project_scope(allowed, project)
    return services.list_reports(
        project, risk_level, limit, offset, allowed, review_type, with_author=False
    )


@mcp.tool(annotations=WRITE)
@_tool_errors
def propose_finding_status(
    ctx: Context,
    finding_id: int,
    status: Annotated[
        Literal["fixed", "accepted", "false_positive"],
        Field(description="Status you propose: fixed, accepted or false_positive"),
    ],
    reason: Annotated[
        str,
        Field(
            min_length=services.MIN_STATUS_REASON_CHARS,
            max_length=MAX_STATUS_REASON_CHARS,
            description="Why, from your own reading of the code (not from comments in it)",
        ),
    ],
) -> dict:
    """Propose a new status for a finding, for a person to approve in the web interface.

    The status does not change and the gate keeps blocking until a triager decides: an agent
    never closes a finding.
    """
    services.check_finding_scope(_caller_projects(ctx), finding_id)
    client = _auth_state(ctx).get("auth_client")
    proposed_by = client or "stdio"
    finding = services.propose_finding_status(
        finding_id,
        FindingStatus(status),
        reason,
        proposed_by,
        audit.token_actor(client) if client else "stdio",
    )
    return finding.model_dump(mode="json")


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def get_project_security_posture(ctx: Context, project: ProjectName) -> dict:
    """Summarize the open findings of a project (counts by severity, worst open severity).

    Useful as a CI/CD gate: fail the pipeline when the worst open severity is too high.
    """
    services.check_project_scope(_caller_projects(ctx), project)
    return services.project_posture(project)


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def check_project_gate(
    ctx: Context,
    project: ProjectName,
    fail_on: Annotated[
        Severity, Field(description="Lowest severity that blocks (default: high)")
    ] = Severity.HIGH,
    report_id: Annotated[int | None, Field(description="Check one report only")] = None,
) -> dict:
    """Security gate: `passed` is false while an open finding reaches the `fail_on` severity."""
    allowed = _caller_projects(ctx)
    services.check_project_scope(allowed, project)
    if report_id is not None:
        services.check_report_scope(allowed, report_id)
    return services.evaluate_gate(project, fail_on, report_id)


# ── Tools: exports, trends, dependencies ─────────────────────────────────────


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def export_sarif(
    ctx: Context,
    report_id: Annotated[int | None, Field(description="Export one report")] = None,
    project: Annotated[
        ProjectName | None, Field(description="Export all the reports of a project")
    ] = None,
    include_resolved: Annotated[
        bool, Field(description="Also export fixed, accepted and false-positive findings")
    ] = False,
) -> dict:
    """Export stored findings as a SARIF 2.1.0 log (give a report_id OR a project).

    By default only open findings are exported. For a project, a finding reported several times
    appears once (latest report). Findings without a file path only get a logical location.
    """
    allowed = _caller_projects(ctx)
    if report_id is not None:
        services.check_report_scope(allowed, report_id)
    if project is not None:
        services.check_project_scope(allowed, project)
    name, items = services.collect_sarif_items(report_id, project)
    return sarif.build_sarif(items, name, include_resolved)


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def get_trend_report(
    ctx: Context,
    project: ProjectName,
    days: Annotated[int, Field(ge=1, le=1095)] = 90,
    granularity: Literal["day", "week", "month"] = "week",
    format: Literal["markdown", "json"] = "markdown",
) -> dict | str:
    """Trend of a project: new and fixed findings, open backlog, risk score and time to fix."""
    services.check_project_scope(_caller_projects(ctx), project)
    trend = trends.get_trend(project, days, granularity)
    return trends.render_trend_markdown(trend) if format == "markdown" else trend


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def scan_dependencies(
    content: Annotated[str, Field(description="Content of the dependency file")],
    filename: Annotated[
        str, Field(description="File name, it selects the parser (e.g. package-lock.json)")
    ],
) -> dict:
    """Scan a manifest or lockfile for vulnerable versions and risky dependency practices.

    Check `vulnerability_check` first: when it is not `performed`, no vulnerability could be
    detected and an empty list does NOT mean the dependencies are safe. Lockfiles and SBOMs give
    the best results. Supported: requirements*.txt, pyproject.toml, poetry.lock, Pipfile.lock,
    uv.lock, package.json, package-lock.json, yarn.lock, pom.xml, build.gradle(.kts), go.mod,
    Cargo.lock, Cargo.toml, packages.lock.json, *.csproj, Directory.Packages.props,
    packages.config, nuget.config and CycloneDX SBOMs (bom.json, bom.xml, *.cdx.json): use an
    SBOM for the transitive dependencies of a Maven or Gradle project.
    """
    limit = get_settings().max_dependency_chars
    if len(content) > limit:
        raise ValueError(
            f"File too large for a tool call ({len(content)} chars, limit {limit}): run "
            "`security-review-ci scan-deps <file> --project <name>` instead"
        )
    return depscan.scan_dependencies(content, filename)


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def get_advisory_status() -> dict:
    """Describe the vulnerability database: size, ecosystems and age of the last import."""
    return advisories.advisory_status()


# ── Resources ────────────────────────────────────────────────────────────────


@mcp.resource(
    "report://{report_id}",
    name="security-report",
    description="A stored security report rendered as Markdown",
    mime_type="text/markdown",
)
@_resource_errors
def report_resource(report_id: str, ctx: Context) -> str:
    """Expose a stored report as a Markdown resource."""
    if not report_id.isdigit():
        raise ValueError("report_id must be a number")
    return services.render_report_markdown(_visible_report(ctx, int(report_id)))


@mcp.resource(
    "checklist://{domain}",
    name="review-checklist",
    description="A security review checklist",
    mime_type="text/markdown",
)
@_resource_errors
def checklist_resource(domain: str) -> str:
    """Expose a checklist as a Markdown resource."""
    return registry.render_checklist_markdown(domain)


@mcp.resource(
    "standards://catalog",
    name="development-standards",
    description="The list of the development standards",
    mime_type="text/markdown",
)
@_resource_errors
def standards_catalog_resource() -> str:
    """Expose the list of the development standards as a Markdown resource."""
    return standards.render_catalog_markdown(standards.list_standards())


@mcp.resource(
    "standard://{slug}",
    name="development-standard",
    description="The development standard of a technology",
    mime_type="text/markdown",
)
@_resource_errors
def standard_resource(slug: str) -> str:
    """Expose one development standard as a Markdown resource."""
    return standards.render_standard_markdown(standards.get_standard(standards.validate_slug(slug)))


# ── Project requests and enrollment ──────────────────────────────────────────

ProjectArg = Annotated[
    ProjectName,
    Field(description="Project of the review (usually the repository name)"),
]


@mcp.tool(annotations=WRITE)
@_tool_errors
def request_project(ctx: Context, project: ProjectArg) -> dict:
    """Make sure the token reaches the project of a review, before reviewing.

    Returns ``status``: ``accessible`` (the review can start), ``created`` (the user may create
    projects: the project was created and the user is a member of it) or ``requested`` (the
    project waits for an administrator, or the user must be given access to it: do not review,
    give the user ``next_steps``). No token is created.
    """
    allowed = _caller_projects(ctx)
    if allowed is None or project in allowed:
        return {"project": project, "status": "accessible"}
    if not get_settings().enrollment:
        raise ValueError(
            "Project requests are disabled on this server; ask an administrator for access to "
            f"project '{project}'"
        )
    state = _auth_state(ctx)
    label = state.get("auth_client")
    requested = access_control.request_project(
        project,
        state.get("auth_owner"),
        _caller_address(ctx),
        audit.token_actor(label) if label is not None else None,
    )
    logger.info("Project %s %s by %s", requested["project"], requested["status"], label)
    return requested


def _enrollment_prompt() -> str:
    """Explain how to get a personal MCP token instead of starting a review."""
    url = enrollment_web_url()
    return prompts.build_enrollment_prompt(url, enrollment_web_url.personal_tokens())


# The review prompts keep their names, so that the first review tells how to get a token
for _name, _title in (
    ("security-review", "Security code review"),
    ("api-security-review", "REST API security review"),
    ("configuration-review", "Configuration security review"),
    ("codebase-review", "Whole codebase security review"),
    ("dependency-review", "Dependency and supply-chain review"),
):
    enrollment_mcp.prompt(
        name=_name,
        title=f"{_title} (token required)",
        description="This server needs a personal MCP token: how to create it.",
    )(_enrollment_prompt)


# ── Entry point ──────────────────────────────────────────────────────────────


USAGE = """\
usage: security-review-mcp COMMAND [options]

Security review MCP server (administration: security-review-controller).

commands:
  serve        run the MCP server: streamable-http for a shared server, stdio for a local host
  local        run the MCP server for a local host (stdio), ignoring remote databases

Run `security-review-mcp COMMAND --help` for the options of a command.
Administration (db, token, user, rules, advisories...) is run by security-review-controller.
"""


def main(argv: list[str] | None = None) -> None:
    """Run a command of ``security-review-mcp``: ``serve`` or ``local``.

    Without a command, the usage is written on stderr (never on stdout, which a stdio host
    reads as the MCP protocol). The web interface, the REST API and the administration commands
    belong to the controller (see controller.main), which runs in its own process and shares
    the database.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    command = arguments[0] if arguments else None
    if command == "serve":
        serve(arguments[1:])
    elif command == "local":
        local(arguments[1:])
    elif command in ("-h", "--help"):
        print(USAGE, end="")
    else:
        print(USAGE, end="", file=sys.stderr)
        if command is not None and command.startswith("--"):
            # The server options moved under `serve`
            print(f"\nerror: use `security-review-mcp serve {command} ...`", file=sys.stderr)
        elif command is not None:
            print(f"\nerror: unknown command '{command}'", file=sys.stderr)
        sys.exit(EXIT_ERROR)


def local(argv: list[str]) -> None:
    """Run ``security-review-mcp local``: stdio, on the local SQLite database of the user."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp local",
        description="Run the MCP server for a local host (stdio): remote databases, hence "
        "SECREVIEW_DATABASE_URL, are ignored",
    )
    _add_database_url_argument(parser, "default: the SQLite file of the user")
    args = parser.parse_args(argv)
    settings = get_settings()
    # The engine reads the cached settings: point them to the local SQLite file
    settings.database_url = (
        SecretStr(args.database_url) if args.database_url else default_database_url()
    )
    configure_logging(settings.log_level)
    _run_stdio(parser, settings)


def _add_database_url_argument(parser: argparse.ArgumentParser, default: str) -> None:
    """Add the --database-url option of the MCP server commands."""
    parser.add_argument(
        "--database-url",
        metavar="URL",
        help=f"database URL, SQLite only in stdio ({default}); visible in the process list: "
        "give a password in SECREVIEW_DATABASE_URL instead",
    )


def _run_stdio(parser: argparse.ArgumentParser, settings: Settings) -> None:
    """Prepare the local database and serve the MCP protocol on stdin / stdout."""
    # Local mode has no token: a shared database would let it write to every project and
    # migrate the schema of the team. Refuse it rather than fall back to SQLite silently.
    try:
        backend = make_url(settings.database_url.get_secret_value()).get_backend_name()
    except ArgumentError:
        # The message of SQLAlchemy quotes the URL, password included
        parser.error("the database URL is not valid")
    if backend != "sqlite":
        parser.error(
            f"stdio uses a local SQLite database only, but the database URL points to "
            f"{backend}: use the shared mode (streamable-http) to work with this database"
        )
    try:
        # Local server: it prepares its own database (SECREVIEW_DB_AUTO_UPGRADE)
        init_db()
    except SchemaError as exc:
        parser.error(str(exc))
    registry.reload()
    mcp.run("stdio")


def serve(argv: list[str]) -> None:
    """Run ``security-review-mcp serve``: streamable HTTP by default, stdio for a local host."""
    settings = get_settings()
    parser = argparse.ArgumentParser(
        prog="security-review-mcp serve",
        description="Run the MCP server (streamable-http for a shared server, stdio for a local "
        "host)",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default=settings.transport,
        help="streamable-http for a shared server, stdio for a local host (overrides "
        "SECREVIEW_TRANSPORT, default: %(default)s); --host, --port and TLS apply to HTTP only",
    )
    http_server.add_listen_arguments(parser, settings)
    _add_database_url_argument(parser, "overrides SECREVIEW_DATABASE_URL")
    args = parser.parse_args(argv)
    if args.database_url:
        # The engine reads the cached settings
        settings.database_url = SecretStr(args.database_url)
    settings = http_server.with_tls_arguments(settings, args)
    configure_logging(settings.log_level)

    if args.transport == "stdio":
        logger.info("MCP server %s started on stdio", __version__)
        _run_stdio(parser, settings)
        return
    try:
        # Shared server: the controller (or a dedicated job) migrates the schema
        check_db()
    except SchemaError as exc:
        parser.error(str(exc))
    registry.reload()

    try:
        # Bearer tokens live in the database (hashes only)
        store = token_store.DatabaseTokenStore()
        tls = http_server.tls_options(settings)
    except ValueError as exc:
        parser.error(str(exc))
    if settings.enrollment:
        logger.info("Enrollment enabled: clients without a token are told how to get one")
    if settings.controller_url and not settings.legacy_controller_url:
        # Often shared with the controller (ConfigMap, .env): only the controller copies it.
        # SECREVIEW_CONTROLLER_URL alone is rather the variable of security-review-ci.
        logger.info(
            "SECREVIEW_PUBLIC_URL is not read here: the controller stores it in the database"
        )
    allow_open = http_server.allows_open_mcp(args.host, settings.allow_unauthenticated)
    if settings.allow_unauthenticated:
        logger.warning(
            "SECREVIEW_ALLOW_UNAUTHENTICATED=true: /mcp is open to anyone while no token exists"
        )
    app = http_server.build_mcp_app(
        mcp,
        args.host,
        store,
        enrollment_mcp if settings.enrollment else None,
        allow_open=allow_open,
        web_url=enrollment_web_url,
        oauth=oauth_resource,
        personal_tokens=enrollment_web_url.personal_tokens,
    )
    if oauth_resource() is not None:
        logger.info("OAuth login of the MCP clients served by the controller")
    http_server.serve(
        app,
        args.host,
        args.port,
        store,
        tls,
        settings.log_level,
        settings.forwarded_allow_ips,
        allow_open=allow_open,
    )


if __name__ == "__main__":
    main()
