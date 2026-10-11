"""Web interface: REST API (``/api/v1``) and the bundled Angular application (``/ui``).

Served next to the MCP endpoint by the streamable HTTP transport (see http_server). The bearer
middleware authenticates the requests and stores the token label and role in the ASGI scope;
this module only checks the permission to change a finding status.

The services are synchronous (SQLModel sessions), so every call runs in the thread pool.
"""

import json
import logging
import re
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi import Path as APIPath
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.security import HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import Scope

from . import __version__, registry, rules_loader, services, token_store, trends
from .config import get_settings
from .http_server import LOOPBACK_HOSTS, TRIAGE_ROLES, Role
from .models import FindingPublic, FindingStatus, SecurityReportPublic, Severity
from .sarif import build_sarif

logger = logging.getLogger("security_review_mcp.web")

BUNDLED_UI_DIR = Path(__file__).parent / "webui"
ANONYMOUS = "anonymous"

# The Angular build loads no inline script and no external resource. Component styles are
# injected as <style> elements at runtime, hence 'unsafe-inline' for styles only.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


# ── Schemas ──────────────────────────────────────────────────────────────────


class Identity(BaseModel):
    """Who is calling and what they may do."""

    client: str
    role: Role
    can_triage: bool
    auth_enabled: bool
    project: str | None = None
    version: str


class FindingStatusUpdate(BaseModel):
    """Body of PATCH /findings/{id}."""

    status: FindingStatus


class RuleWrite(BaseModel):
    """A custom scan rule sent to the web API."""

    id: str = Field(min_length=3, max_length=50)
    title: str = Field(min_length=1, max_length=300)
    severity: Severity
    cwe: str = Field(default="", max_length=20)
    languages: list[Annotated[str, Field(max_length=32)]] = Field(min_length=1, max_length=32)
    pattern: str = Field(min_length=1, max_length=rules_loader.MAX_PATTERN_CHARS)
    advice: str = Field(default="", max_length=5000)
    ignore_case: bool = True


class RuleEnabledUpdate(BaseModel):
    """Enabled state of a custom scan rule."""

    enabled: bool


class ProjectTokenCreate(BaseModel):
    """A read-only token scoped to one project."""

    label: str = Field(min_length=1, max_length=64)
    project: str = Field(min_length=1, max_length=200)


class ProjectSummary(BaseModel):
    """One project with its open findings."""

    project: str
    reports_total: int
    last_report_at: str
    open_findings_total: int
    open_findings_by_severity: dict[str, int]
    worst_open_severity: Severity | None


class ReportSummary(BaseModel):
    """One line of the report list."""

    report_id: int
    project: str
    branch: str | None
    commit_sha: str | None
    risk_level: Severity
    reviewer: str | None
    created_at: str
    findings_total: int
    findings_open: int
    summary: str


# ── Dependencies ─────────────────────────────────────────────────────────────


def current_identity(request: Request) -> Identity:
    """Identity set by the bearer middleware; without configured tokens everyone is admin."""
    state = request.scope.get("state") or {}
    auth_enabled = "auth_role" in state
    role = Role(state["auth_role"]) if auth_enabled else Role.ADMIN
    return Identity(
        client=state.get("auth_client", ANONYMOUS),
        role=role,
        can_triage=role in TRIAGE_ROLES,
        auth_enabled=auth_enabled,
        project=state.get("auth_project"),
        version=__version__,
    )


CurrentIdentity = Annotated[Identity, Depends(current_identity)]


def require_triage(identity: CurrentIdentity) -> Identity:
    """Only triagers and administrators may change a finding status."""
    if not identity.can_triage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{identity.role}' cannot change finding status",
        )
    return identity


def require_admin(identity: CurrentIdentity) -> Identity:
    """Only web administrators may change rule packs."""
    if identity.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{identity.role}' cannot manage rules",
        )
    return identity


def _scoped_project(identity: Identity, requested: str | None = None) -> str | None:
    """Restrict project tokens to their assigned project without disclosing other projects."""
    if identity.project is not None:
        if requested is not None and requested != identity.project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return identity.project
    return requested


def _ensure_report_scope(identity: Identity, report: SecurityReportPublic) -> None:
    """Hide reports outside a project token's scope."""
    if identity.project is not None and report.project != identity.project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


def _rule_catalog() -> dict:
    """Return valid custom rules and pack load diagnostics for the management screen."""
    directory = get_settings().rules_dir
    if not directory:
        return {
            "available": False,
            "sources": [],
            "load_errors": ["SECREVIEW_RULES_DIR is not configured"],
            "rules": [],
        }
    loaded = rules_loader.load_rules_dir(directory)
    rules = []
    for rule in loaded.rules:
        rules.append(
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity.value,
                "cwe": rule.cwe,
                "languages": sorted(rule.languages),
                "pattern": rule.pattern.pattern,
                "advice": rule.advice,
                "ignore_case": bool(rule.pattern.flags & re.IGNORECASE),
                "enabled": rule.id not in loaded.disabled_rules,
                "source": loaded.rule_sources[rule.id],
            }
        )
    return {
        "available": True,
        "sources": loaded.sources,
        "load_errors": loaded.errors,
        "rules": rules,
    }


async def _refresh_rules() -> dict:
    """Reload the active registry and return its diagnostics."""
    snapshot = await run_in_threadpool(registry.reload)
    return {"loaded_rules": len(snapshot.custom_rule_ids), "load_errors": list(snapshot.errors)}


# ── Routes ───────────────────────────────────────────────────────────────────


router = APIRouter(prefix="/api/v1", dependencies=[Depends(HTTPBearer(auto_error=False))])


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@router.get("/me")
async def me(identity: CurrentIdentity) -> Identity:
    """Return the identity and permissions of the caller."""
    return identity


@router.get("/projects")
async def projects(identity: CurrentIdentity) -> list[ProjectSummary]:
    """List the projects with their open findings, latest activity first."""
    projects = await run_in_threadpool(services.list_projects)
    return [
        item for item in projects if identity.project is None or item["project"] == identity.project
    ]


@router.get("/posture")
async def posture(
    project: Annotated[str, Query(min_length=1, max_length=200)], identity: CurrentIdentity
) -> dict:
    """Open findings of a project across all its reports."""
    return await run_in_threadpool(services.project_posture, _scoped_project(identity, project))


@router.get("/trend")
async def trend(
    project: Annotated[str, Query(min_length=1, max_length=200)],
    identity: CurrentIdentity,
    days: Annotated[int, Query(ge=1, le=1095)] = 90,
    granularity: Literal["day", "week", "month"] = "week",
) -> dict:
    """Evolution of the security posture of a project."""
    try:
        return await run_in_threadpool(
            trends.get_trend, _scoped_project(identity, project), days, granularity
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


@router.get("/sarif")
async def sarif(
    identity: CurrentIdentity,
    project: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    report_id: Annotated[int | None, Query(ge=1)] = None,
    include_resolved: bool = False,
) -> Response:
    """Download the findings of a project or of a report as SARIF 2.1.0."""
    try:
        if identity.project is not None:
            if project is not None and project != identity.project:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
            if report_id is not None:
                scoped_report = await run_in_threadpool(services.get_report, report_id)
                _ensure_report_scope(identity, scoped_report)
            else:
                project = identity.project
        name, items = await run_in_threadpool(services.collect_sarif_items, report_id, project)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    document = build_sarif(items, name, include_resolved)
    filename = f"report-{report_id}.sarif" if report_id else "project.sarif"
    return Response(
        content=json.dumps(document, indent=2),
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports")
async def reports(
    identity: CurrentIdentity,
    project: Annotated[str | None, Query(max_length=200)] = None,
    risk_level: Severity | None = None,
    limit: Annotated[int, Query(ge=1)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ReportSummary]:
    """List reports, newest first (limit is capped by SECREVIEW_MAX_LIST_LIMIT)."""
    return await run_in_threadpool(
        services.list_reports, _scoped_project(identity, project or None), risk_level, limit, offset
    )


@router.get("/reports/{report_id}")
async def report(report_id: int, identity: CurrentIdentity) -> SecurityReportPublic:
    """Return a report with its findings."""
    stored = await run_in_threadpool(services.get_report, report_id)
    _ensure_report_scope(identity, stored)
    return stored


@router.get("/reports/{report_id}/markdown", response_class=PlainTextResponse)
async def report_markdown(report_id: int, identity: CurrentIdentity) -> PlainTextResponse:
    """Download a report as Markdown."""
    stored = await run_in_threadpool(services.get_report, report_id)
    _ensure_report_scope(identity, stored)
    return PlainTextResponse(
        services.render_report_markdown(stored),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report-{report_id}.md"'},
    )


@router.patch("/findings/{finding_id}")
async def update_finding(
    finding_id: int,
    body: FindingStatusUpdate,
    identity: Annotated[Identity, Depends(require_triage)],
) -> FindingPublic:
    """Change the status of a finding (triage). The change is logged with the caller."""
    await run_in_threadpool(services.check_finding_scope, identity.project, finding_id)
    finding = await run_in_threadpool(services.update_finding_status, finding_id, body.status)
    logger.info("Finding %s set to %s by %s", finding_id, body.status, identity.client)
    return finding


@router.get("/rules")
async def list_custom_rules(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """List the valid rules loaded from TOML packs."""
    return await run_in_threadpool(_rule_catalog)


@router.post("/rules/reload")
async def reload_custom_rules(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """Reload TOML packs after changes made outside the web interface."""
    logger.info("Rule packs reloaded by %s", identity.client)
    return await _refresh_rules()


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_custom_rule(
    body: RuleWrite, identity: Annotated[Identity, Depends(require_admin)]
) -> dict:
    """Create a rule in the web-managed TOML pack."""
    try:
        await run_in_threadpool(
            rules_loader.create_rule, get_settings().rules_dir, body.model_dump(mode="json")
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Rule %s created by %s", body.id, identity.client)
    return await _refresh_rules()


@router.put("/rules/{rule_id}")
async def update_custom_rule(
    rule_id: Annotated[str, APIPath(min_length=3, max_length=50)],
    body: RuleWrite,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict:
    """Update a custom rule while keeping its stable id."""
    try:
        await run_in_threadpool(
            rules_loader.update_rule,
            get_settings().rules_dir,
            rule_id,
            body.model_dump(mode="json"),
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Rule %s updated by %s", rule_id, identity.client)
    return await _refresh_rules()


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_custom_rule(
    rule_id: Annotated[str, APIPath(min_length=3, max_length=50)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """Delete a custom rule from its TOML packs."""
    try:
        await run_in_threadpool(rules_loader.delete_rule, get_settings().rules_dir, rule_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await _refresh_rules()
    logger.info("Rule %s deleted by %s", rule_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.patch("/rules/{rule_id}/enabled")
async def set_custom_rule_enabled(
    rule_id: Annotated[str, APIPath(min_length=3, max_length=50)],
    body: RuleEnabledUpdate,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict:
    """Enable or disable a custom rule through the pack's disabled_rules list."""
    try:
        await run_in_threadpool(
            rules_loader.set_rule_enabled, get_settings().rules_dir, rule_id, body.enabled
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Rule %s enabled=%s by %s", rule_id, body.enabled, identity.client)
    return await _refresh_rules()


@router.get("/project-tokens")
async def project_tokens(
    identity: Annotated[Identity, Depends(require_admin)],
) -> list[dict[str, str | None]]:
    """List project-token metadata without returning hashes or token values."""
    return await run_in_threadpool(token_store.list_project_tokens)


@router.post("/project-tokens", status_code=status.HTTP_201_CREATED)
async def create_project_token(
    body: ProjectTokenCreate,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict[str, str | None]:
    """Create a project-scoped reader token and return its secret exactly once."""
    projects = await run_in_threadpool(services.list_projects)
    if not any(project["project"] == body.project for project in projects):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    try:
        created = await run_in_threadpool(
            token_store.create_project_token, body.label, body.project
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Project token %s created for %s by %s", body.label, body.project, identity.client)
    return created


@router.delete("/project-tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project_token(
    token_id: Annotated[str, APIPath(min_length=1, max_length=64)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """Revoke a project token: the next request presenting it is rejected."""
    try:
        await run_in_threadpool(token_store.revoke_project_token, token_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info("Project token %s revoked by %s", token_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Static files ─────────────────────────────────────────────────────────────


class SinglePageApp(StaticFiles):
    """Static files with a fallback on index.html for the client-side routes."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND:
                raise
            response = await super().get_response("index.html", scope)
        response.headers.update(SECURITY_HEADERS)
        if path in ("", ".", "index.html") or response.media_type == "text/html":
            # The page references hashed bundles: always revalidate it after an upgrade
            response.headers["Cache-Control"] = "no-cache"
        return response


def resolve_ui_dir(configured: str | None) -> Path | None:
    """Directory of the built Angular application, or None when it is not available."""
    directory = Path(configured) if configured else BUNDLED_UI_DIR
    if (directory / "index.html").is_file():
        return directory
    if configured:
        raise ValueError(f"SECREVIEW_WEB_UI_DIR: no index.html in {directory}")
    return None


# ── Application ──────────────────────────────────────────────────────────────


def create_app(host: str = "127.0.0.1", ui_dir: str | None = None) -> FastAPI:
    """Build the web application (REST API and, when it is built, the Angular application).

    Raises:
        ValueError: If ``ui_dir`` (SECREVIEW_WEB_UI_DIR) is set but holds no application.
    """
    settings = get_settings()
    app = FastAPI(
        title="security-review-mcp",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.include_router(router)

    @app.exception_handler(services.NotFoundError)
    async def not_found(_: Request, exc: services.NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    directory = resolve_ui_dir(ui_dir if ui_dir is not None else settings.web_ui_dir)
    if directory is not None:
        app.mount("/ui", SinglePageApp(directory=directory, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        async def root() -> RedirectResponse:
            return RedirectResponse("/ui/")
    else:
        logger.warning("Web interface not built: only the REST API is served (/api/v1)")

    if host in LOOPBACK_HOSTS:
        # Same protection as the MCP endpoint against DNS rebinding on a local server
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])
    return app
