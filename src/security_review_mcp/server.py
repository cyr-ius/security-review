"""MCP server exposing security-review prompts, tools and stored reports."""

import argparse
import functools
import logging
import sys
from collections.abc import Callable
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ResourceNotFoundError, ToolError
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, ToolAnnotations
from pydantic import Field

from . import (
    __version__,
    advisories,
    app_settings,
    cli,
    depscan,
    enrollment_api,
    http_server,
    prompts,
    registry,
    sarif,
    scanner,
    services,
    standards,
    token_store,
    trends,
)
from .config import check_report_language, configure_logging, get_settings
from .database import SchemaError, check_db, init_db
from .models import FindingCreate, FindingStatus, Severity

logger = logging.getLogger("security_review_mcp")

INSTRUCTIONS = """\
Security code-review server.
- Use the prompts `security-review`, `api-security-review` and `configuration-review` to \
start a structured review, and `codebase-review` to review a whole repository (not only a diff).
- Use `get_review_checklist` and `scan_code` while reviewing. When their results give a report \
language, write your reply and the free-text fields of the report in that language.
- At the end of a review, call `save_security_report` once to store the report in the \
database. Use `list_security_reports`, `get_security_report` and \
`get_project_security_posture` to read stored results.
- If `save_security_report` refuses the project because the token is restricted to other \
projects, call `request_enrollment` to ask an administrator to add this project to the token \
(complementary enrollment: the token keeps working for its other projects), then \
`get_enrollment_status` to know whether it was approved.
- Before writing code, use the prompt `development-standards` (or the tool \
`get_development_standards`) to get the development standards of the technologies you work on.
"""

ENROLLMENT_INSTRUCTIONS = """\
Security code-review server, enrollment mode: the client has no approved bearer token yet, so \
the review tools are not available.
- Call `get_enrollment_status` to know whether a request is already waiting for approval.
- Otherwise call `request_enrollment` once with the project name (usually the repository \
name). Give the returned token to the user: they add it to the MCP client configuration as \
`Authorization: Bearer <token>`. It works once an administrator approves the request.
- The review prompts (`security-review`...) explain these steps.
"""

mcp = MCPServer(
    "security-review",
    title="Security Review",
    instructions=INSTRUCTIONS,
    version=__version__,
)

# Served by the HTTP transport to the clients that have no approved token (see http_server)
enrollment_mcp = MCPServer(
    "security-review",
    title="Security Review (enrollment)",
    instructions=ENROLLMENT_INSTRUCTIONS,
    version=__version__,
)

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
    """Client address of the HTTP request (None with stdio), stored with enrollment requests."""
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
    description="Review Python, Java or Angular code for vulnerabilities and insecure settings.",
)
def security_review(
    language: str = "python",
    code: str = "",
    context: str = "",
    focus: str = "",
    report_language: str = "",
) -> str:
    """Build the general security-review prompt.

    Args:
        language: python, java or angular.
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
        scan_results: Optional output of `security-review-controller code scan . --format json`.
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
        ecosystem: PyPI, npm or Maven (leave empty for all).
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
        services.check_report_scope(_caller_projects(ctx), report_id)
        report = services.get_report(report_id)
    except services.NotFoundError as exc:
        raise MCPError(code=INVALID_PARAMS, message=str(exc)) from exc
    return prompts.build_triage_prompt(services.render_report_markdown(report), context, language)


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
    project: Annotated[str, Field(description="Project name, used to group reports")],
    summary: Annotated[str, Field(description="Executive summary of the review")],
    findings: Annotated[
        list[FindingCreate], Field(description="Confirmed findings (empty list if none)")
    ],
    repository: str | None = None,
    branch: str | None = None,
    commit_sha: str | None = None,
    reviewer: Annotated[str | None, Field(description="Agent or person who reviewed")] = None,
    scope: Annotated[str | None, Field(description="What was reviewed")] = None,
    risk_level: Annotated[
        Severity | None,
        Field(description="Optional override; can only raise the risk computed from findings"),
    ] = None,
) -> dict:
    """Store a security report and its findings in the database.

    Call this once at the end of a review, with the free-text fields written in the report
    language given by the review prompt, scan_code or get_review_checklist, if any. Secrets in
    free-text fields are masked before storage. Returns the report id, the overall risk level
    and the finding counts.
    """
    allowed = _caller_projects(ctx)
    if allowed is not None and project not in allowed:
        reachable = ", ".join(f"'{name}'" for name in sorted(allowed)) or "no project yet"
        raise ValueError(
            f"This token can only save reports for {reachable}; call request_enrollment to "
            "ask an administrator to add this project to the token"
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
    )


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def get_security_report(
    ctx: Context,
    report_id: int,
    format: Literal["json", "markdown"] = "markdown",
) -> dict | str:
    """Return a stored report with its findings, as Markdown (default) or JSON."""
    services.check_report_scope(_caller_projects(ctx), report_id)
    report = services.get_report(report_id)
    if format == "markdown":
        return services.render_report_markdown(report)
    return report.model_dump(mode="json")


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def list_security_reports(
    ctx: Context,
    project: str | None = None,
    risk_level: Severity | None = None,
    limit: Annotated[int, Field(ge=1, le=100)] = 20,
    offset: Annotated[int, Field(ge=0)] = 0,
) -> list[dict]:
    """List stored reports, newest first, optionally filtered by project or risk level."""
    allowed = _caller_projects(ctx)
    if allowed is not None and project:
        services.check_project_scope(allowed, project)
    return services.list_reports(project, risk_level, limit, offset, allowed)


@mcp.tool(annotations=WRITE)
@_tool_errors
def update_finding_status(
    ctx: Context,
    finding_id: int,
    status: Annotated[FindingStatus, Field(description="open, fixed, accepted, false_positive")],
) -> dict:
    """Change the status of a finding after triage or a fix."""
    services.check_finding_scope(_caller_projects(ctx), finding_id)
    return services.update_finding_status(finding_id, status).model_dump(mode="json")


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def get_project_security_posture(ctx: Context, project: str) -> dict:
    """Summarize the open findings of a project (counts by severity, worst open severity).

    Useful as a CI/CD gate: fail the pipeline when the worst open severity is too high.
    """
    services.check_project_scope(_caller_projects(ctx), project)
    return services.project_posture(project)


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def check_project_gate(
    ctx: Context,
    project: str,
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
    project: Annotated[str | None, Field(description="Export all the reports of a project")] = None,
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
    project: str,
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
    detected and an empty list does NOT mean the dependencies are safe. Lockfiles give the best
    results. Supported: requirements*.txt, pyproject.toml, poetry.lock, Pipfile.lock,
    package.json, package-lock.json, yarn.lock, pom.xml, build.gradle(.kts).
    """
    limit = get_settings().max_dependency_chars
    if len(content) > limit:
        raise ValueError(
            f"File too large for a tool call ({len(content)} chars, limit {limit}): run "
            "`security-review-controller deps scan <file>` in the pipeline instead"
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
    services.check_report_scope(_caller_projects(ctx), int(report_id))
    return services.render_report_markdown(services.get_report(int(report_id)))


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


# ── Enrollment ───────────────────────────────────────────────────────────────

ProjectArg = Annotated[
    str, Field(description="Project the token is requested for (usually the repository name)")
]
LabelArg = Annotated[
    str | None,
    Field(description="Optional token name (default: the project); a random suffix is added"),
]
RequestedByArg = Annotated[
    str | None,
    Field(description="Who asks for access (name, email or team), shown to the administrator"),
]


def _request_enrollment(
    ctx: Context, project: str, label: str | None, requested_by: str | None
) -> dict:
    """Store a first enrollment request and explain to the model what the user must do next."""
    if not get_settings().enrollment:
        raise ValueError("Enrollment is disabled on this server; ask an administrator for a token")
    created = token_store.request_enrollment(project, label, requested_by, _caller_address(ctx))
    logger.info(
        "Enrollment requested for project %s (%s) from %s",
        created["project"],
        created["label"],
        created["requested_from"] or "stdio",
    )
    return created | {
        "next_steps": (
            "Show the token to the user once: it is not displayed again. They add it to the MCP "
            "client configuration as 'Authorization: Bearer <token>'. It works after an "
            "administrator approves the request (web interface, Jetons screen, or "
            f"`security-review-controller token approve {created['request_id']}`)."
        )
    }


def _request_additional_project(
    ctx: Context, token_id: str, project: str, requested_by: str | None
) -> dict:
    """Store a complementary enrollment request for the caller's token."""
    if not get_settings().enrollment:
        raise ValueError(
            "Enrollment is disabled on this server; ask an administrator to add the project"
        )
    created = token_store.request_additional_project(
        token_id, project, requested_by, _caller_address(ctx)
    )
    logger.info(
        "Complementary enrollment requested for project %s (%s) from %s",
        created["project"],
        created["label"],
        created["requested_from"] or "unknown",
    )
    return created | {
        "next_steps": (
            "No new token: the current token keeps working for its other projects and reaches "
            "this project once an administrator approves the request (web interface, Jetons "
            f"screen, or `security-review-controller token approve {created['id']}`). Call "
            "get_enrollment_status to check."
        )
    }


@mcp.tool(annotations=WRITE)
@_tool_errors
def request_enrollment(
    ctx: Context,
    project: ProjectArg,
    label: LabelArg = None,
    requested_by: RequestedByArg = None,
) -> dict:
    """Request access to a project, to be approved by an administrator.

    Use it when the current token cannot save reports for this project. With a token already
    restricted to other projects, this is a complementary enrollment: the project is added to
    the same token once approved (no new token, ``label`` is ignored). Without a token, a new
    token is returned once and works only after approval.
    """
    state = _auth_state(ctx)
    token_id = state.get("auth_token_id")
    if token_id is not None:
        if state.get("auth_projects") is None:
            raise ValueError("This token is not restricted: it already reaches every project")
        return _request_additional_project(ctx, token_id, project, requested_by)
    return _request_enrollment(ctx, project, label, requested_by)


@mcp.tool(name="get_enrollment_status", annotations=READ_ONLY)
@_tool_errors
def token_enrollment_status(ctx: Context) -> dict:
    """Projects the current token reaches and those waiting for an administrator's approval.

    ``not_enrolled`` means the client sends no token (stdio, or no authentication).
    """
    return token_store.enrollment_status(_auth_state(ctx).get("auth_token_id"))


@enrollment_mcp.tool(name="request_enrollment", annotations=WRITE)
@_tool_errors
def enrollment_request(
    ctx: Context,
    project: ProjectArg,
    label: LabelArg = None,
    requested_by: RequestedByArg = None,
) -> dict:
    """Request a bearer token for one project; it works once an administrator approves it.

    The returned token is shown once: give it to the user for the MCP client configuration.
    """
    if _enrollment_token_id(ctx) is not None:
        raise ValueError(
            "This client already uses a token waiting for approval; call get_enrollment_status"
        )
    return _request_enrollment(ctx, project, label, requested_by)


def _enrollment_token_id(ctx: Context) -> str | None:
    """Id of the pending token presented by the client of the enrollment server, or None."""
    return _auth_state(ctx).get("enrollment_token_id")


@enrollment_mcp.tool(name="get_enrollment_status", annotations=READ_ONLY)
@_tool_errors
def enrollment_status(ctx: Context) -> dict:
    """Tell whether the token presented by this client is waiting for approval.

    ``not_enrolled`` means the client sends no token: call request_enrollment.
    """
    return token_store.enrollment_status(_enrollment_token_id(ctx))


def _enrollment_prompt(project: str = "") -> str:
    """Explain the enrollment steps instead of starting a review.

    Args:
        project: Optional project name (usually the repository name).
    """
    return prompts.build_enrollment_prompt(project)


# The review prompts keep their names, so that the first review starts the enrollment
for _name, _title in (
    ("security-review", "Security code review"),
    ("api-security-review", "REST API security review"),
    ("configuration-review", "Configuration security review"),
    ("codebase-review", "Whole codebase security review"),
    ("dependency-review", "Dependency and supply-chain review"),
):
    enrollment_mcp.prompt(
        name=_name,
        title=f"{_title} (enrollment required)",
        description="This server needs an approved token: request one before reviewing.",
    )(_enrollment_prompt)


# ── Entry point ──────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> None:
    """Run the MCP server (stdio by default, streamable HTTP for a shared server).

    The web interface, the REST API and the administration commands belong to the controller
    (see controller.main), which runs in its own process and shares the database.
    """
    settings = get_settings()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] and arguments[0] in cli.MCP_COMMANDS:
        sys.exit(cli.run(arguments))
    if arguments[:1] and arguments[0] in cli.CONTROLLER_COMMANDS:
        # Kept for one major version: these commands moved to the controller CLI
        print(
            f"warning: `security-review-mcp {arguments[0]}` is deprecated, "
            f"use `security-review-controller {arguments[0]}`",
            file=sys.stderr,
        )
        sys.exit(cli.run(arguments))

    parser = argparse.ArgumentParser(
        prog="security-review-mcp",
        description="Security review MCP server (administration: security-review-controller)",
    )
    parser.add_argument(
        "--transport", choices=["stdio", "streamable-http"], default=settings.transport
    )
    http_server.add_listen_arguments(parser, settings)
    args = parser.parse_args(arguments)
    settings = http_server.with_tls_arguments(settings, args)
    configure_logging(settings.log_level)

    try:
        if args.transport == "stdio":
            # Local server: it prepares its own database (SECREVIEW_DB_AUTO_UPGRADE)
            init_db()
        else:
            # Shared server: the controller (or a dedicated job) migrates the schema
            check_db()
    except SchemaError as exc:
        parser.error(str(exc))
    registry.reload()

    if args.transport == "stdio":
        mcp.run("stdio")
        return
    try:
        # Bearer tokens live in the database (hashes only)
        store = token_store.DatabaseTokenStore()
        tls = http_server.tls_options(settings, args.host)
    except ValueError as exc:
        parser.error(str(exc))
    if settings.enrollment:
        logger.info("Enrollment enabled: clients without a token may request one")
    app = http_server.build_mcp_app(
        mcp,
        args.host,
        store,
        enrollment_mcp if settings.enrollment else None,
        enrollment_api.create_app(args.host) if settings.enrollment else None,
    )
    http_server.serve(app, args.host, args.port, store, tls, settings.log_level)


if __name__ == "__main__":
    main()
