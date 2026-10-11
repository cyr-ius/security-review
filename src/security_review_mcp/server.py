"""MCP server exposing security-review prompts, tools and stored reports."""

import argparse
import functools
import logging
import sys
from collections.abc import Callable
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ResourceNotFoundError, ToolError
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, ToolAnnotations
from pydantic import Field

from . import (
    __version__,
    advisories,
    cli,
    depscan,
    http_server,
    prompts,
    registry,
    sarif,
    scanner,
    services,
    trends,
    web_api,
)
from .config import get_settings
from .database import init_db
from .models import FindingCreate, FindingStatus, Severity

logger = logging.getLogger("security_review_mcp")

INSTRUCTIONS = """\
Security code-review server.
- Use the prompts `security-review`, `api-security-review` and `configuration-review` to \
start a structured review, and `codebase-review` to review a whole repository (not only a diff).
- Use `get_review_checklist` and `scan_code` while reviewing.
- At the end of a review, call `save_security_report` once to store the report in the \
database. Use `list_security_reports`, `get_security_report` and \
`get_project_security_posture` to read stored results.
"""

mcp = MCPServer(
    "security-review",
    title="Security Review",
    instructions=INSTRUCTIONS,
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


# ── Prompts ──────────────────────────────────────────────────────────────────


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
) -> str:
    """Build the general security-review prompt.

    Args:
        language: python, java or angular.
        code: Code or diff to review (leave empty to review the workspace files).
        context: Optional context (exposure, data sensitivity, authentication model...).
        focus: Optional areas to emphasize (for example "authentication, file upload").
    """
    return prompts.build_security_review_prompt(language, code, context, focus)


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
) -> str:
    """Build the REST API review prompt.

    Args:
        framework: For example FastAPI, Spring Boot, Express.
        code: Controllers, routes, DTOs or diff to review.
        context: Optional context (public API, internal, consumers...).
        focus: Optional areas to emphasize.
    """
    return prompts.build_api_review_prompt(framework, code, context, focus)


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
) -> str:
    """Build the configuration review prompt.

    Args:
        config_type: For example Dockerfile, GitLab CI, Jenkinsfile, Spring properties.
        content: Configuration content to review.
        context: Optional context (environment, exposure...).
        focus: Optional areas to emphasize.
    """
    return prompts.build_config_review_prompt(config_type, content, context, focus)


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
) -> str:
    """Build the whole-codebase review prompt.

    Args:
        languages: Main languages, for example "python, angular" (selects the checklists).
        scan_results: Optional output of `security-review-mcp code scan . --format json`.
        context: Optional context (exposure, data sensitivity, authentication model...).
        focus: Optional areas to emphasize.
    """
    limit = get_settings().max_content_chars
    if len(scan_results) > limit:
        raise MCPError(
            code=INVALID_PARAMS,
            message=f"scan_results too large ({len(scan_results)} chars); the limit is {limit}. "
            "Filter it, for example with --exclude or --fail-on, or use --save and triage-report.",
        )
    return prompts.build_codebase_review_prompt(languages, scan_results, context, focus)


@mcp.prompt(
    name="dependency-review",
    title="Dependency and supply-chain review",
    description="Check manifests and lockfiles for vulnerable versions and risky practices.",
)
def dependency_review(ecosystem: str = "", files: str = "", context: str = "") -> str:
    """Build the dependency review prompt.

    Args:
        ecosystem: PyPI, npm or Maven (leave empty for all).
        files: Dependency files with their names (leave empty to read the workspace files).
        context: Optional context (exposure, runtime vs dev usage...).
    """
    return prompts.build_dependency_review_prompt(ecosystem, files, context)


@mcp.prompt(
    name="triage-report",
    title="Triage a security report",
    description="Re-assess the findings of a stored report and update their status.",
)
def triage_report(report_id: int, context: str = "") -> str:
    """Build a triage prompt from a stored report.

    Args:
        report_id: Identifier returned by save_security_report.
        context: Optional deployment context to re-assess severity.
    """
    try:
        report = services.get_report(report_id)
    except services.NotFoundError as exc:
        raise MCPError(code=INVALID_PARAMS, message=str(exc)) from exc
    return prompts.build_triage_prompt(services.render_report_markdown(report), context)


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
    """Return the security checklist of a domain, in Markdown."""
    return registry.render_checklist_markdown(domain)


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
    """List the active scan rules (built-in and internal) and any rule pack loading problem."""
    current = registry.snapshot()
    return {
        "rules": registry.describe_rules(language),
        "disabled_rules": sorted(current.disabled_rule_ids),
        "rule_packs": list(current.sources),
        "load_errors": list(current.errors),
    }


@mcp.tool(annotations=WRITE)
@_tool_errors
def reload_rules() -> dict:
    """Re-read the internal rule packs from disk (after an administrator edited them)."""
    current = registry.reload()
    return {
        "rules_active": len(current.rules),
        "custom_rules": len(current.custom_rule_ids),
        "rule_packs": list(current.sources),
        "load_errors": list(current.errors),
    }


# ── Tools: reports ───────────────────────────────────────────────────────────


@mcp.tool(annotations=WRITE)
@_tool_errors
def save_security_report(
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

    Call this once at the end of a review. Secrets in free-text fields are masked before
    storage. Returns the report id, the overall risk level and the finding counts.
    """
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
    report_id: int,
    format: Literal["json", "markdown"] = "markdown",
) -> dict | str:
    """Return a stored report with its findings, as Markdown (default) or JSON."""
    report = services.get_report(report_id)
    if format == "markdown":
        return services.render_report_markdown(report)
    return report.model_dump(mode="json")


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def list_security_reports(
    project: str | None = None,
    risk_level: Severity | None = None,
    limit: Annotated[int, Field(ge=1, le=100)] = 20,
    offset: Annotated[int, Field(ge=0)] = 0,
) -> list[dict]:
    """List stored reports, newest first, optionally filtered by project or risk level."""
    return services.list_reports(project, risk_level, limit, offset)


@mcp.tool(annotations=WRITE)
@_tool_errors
def update_finding_status(
    finding_id: int,
    status: Annotated[FindingStatus, Field(description="open, fixed, accepted, false_positive")],
) -> dict:
    """Change the status of a finding after triage or a fix."""
    return services.update_finding_status(finding_id, status).model_dump(mode="json")


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def get_project_security_posture(project: str) -> dict:
    """Summarize the open findings of a project (counts by severity, worst open severity).

    Useful as a CI/CD gate: fail the pipeline when the worst open severity is too high.
    """
    return services.project_posture(project)


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def check_project_gate(
    project: str,
    fail_on: Annotated[
        Severity, Field(description="Lowest severity that blocks (default: high)")
    ] = Severity.HIGH,
    report_id: Annotated[int | None, Field(description="Check one report only")] = None,
) -> dict:
    """Security gate: `passed` is false while an open finding reaches the `fail_on` severity."""
    return services.evaluate_gate(project, fail_on, report_id)


# ── Tools: exports, trends, dependencies ─────────────────────────────────────


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def export_sarif(
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
    name, items = services.collect_sarif_items(report_id, project)
    return sarif.build_sarif(items, name, include_resolved)


@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def get_trend_report(
    project: str,
    days: Annotated[int, Field(ge=1, le=1095)] = 90,
    granularity: Literal["day", "week", "month"] = "week",
    format: Literal["markdown", "json"] = "markdown",
) -> dict | str:
    """Trend of a project: new and fixed findings, open backlog, risk score and time to fix."""
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
            "`security-review-mcp deps scan <file>` in the pipeline instead"
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
def report_resource(report_id: str) -> str:
    """Expose a stored report as a Markdown resource."""
    if not report_id.isdigit():
        raise ValueError("report_id must be a number")
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


# ── Entry point ──────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> None:
    """Run the server (stdio by default, streamable HTTP for shared/CI usage)."""
    settings = get_settings()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] and arguments[0] in cli.COMMANDS:
        sys.exit(cli.run(arguments))

    parser = argparse.ArgumentParser(description="Security review MCP server")
    parser.add_argument(
        "--transport", choices=["stdio", "streamable-http"], default=settings.transport
    )
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--tls-certfile", help="enable TLS (overrides SECREVIEW_TLS_CERTFILE)")
    parser.add_argument("--tls-keyfile", help="private key (overrides SECREVIEW_TLS_KEYFILE)")
    args = parser.parse_args(arguments)
    if args.tls_certfile or args.tls_keyfile:
        settings = settings.model_copy(
            update={
                "tls_certfile": args.tls_certfile or settings.tls_certfile,
                "tls_keyfile": args.tls_keyfile or settings.tls_keyfile,
            }
        )

    # Logs go to stderr: stdout is reserved for the MCP protocol with the stdio transport
    logging.basicConfig(
        level=settings.log_level.upper(),
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    init_db()
    registry.reload()

    if args.transport == "streamable-http":
        try:
            tokens = http_server.load_tokens(settings)
            bootstrap_password = None
            if settings.auth_bootstrap_file and settings.web_ui:
                bootstrap_tokens, bootstrap_password = http_server.ensure_bootstrap_admin_token(
                    settings.auth_bootstrap_file
                )
                tokens.update(bootstrap_tokens)
            managed_tokens = (
                http_server.load_project_tokens(settings.auth_managed_tokens_file)
                if settings.web_ui
                else {}
            )
            if tokens.keys() & managed_tokens.keys():
                raise ValueError("Project token hash conflicts with an existing auth token")
            tokens.update(managed_tokens)
            tls = http_server.tls_options(settings)
            web_app = web_api.create_app(args.host) if settings.web_ui else None
        except ValueError as exc:
            parser.error(str(exc))
        if bootstrap_password:
            logger.warning(
                "Initial Web UI administrator password (shown once): %s", bootstrap_password
            )
        http_server.run(mcp, args.host, args.port, tokens, tls, settings.log_level, web_app)
    else:
        mcp.run("stdio")


if __name__ == "__main__":
    main()
