"""Web interface: REST API (``/api/v1``) and the bundled Angular application (``/ui``).

Served next to the MCP endpoint by the streamable HTTP transport (see http_server). The bearer
middleware authenticates the requests and stores the token label and role in the ASGI scope;
this module only checks the permission to change a finding status.

The services are synchronous (SQLModel sessions), so every call runs in the thread pool.
"""

import json
import logging
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import Scope

from . import __version__, services, trends
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
    version: str


class FindingStatusUpdate(BaseModel):
    """Body of PATCH /findings/{id}."""

    status: FindingStatus


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


# ── Routes ───────────────────────────────────────────────────────────────────


router = APIRouter(prefix="/api/v1")


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@router.get("/me")
async def me(identity: CurrentIdentity) -> Identity:
    """Return the identity and permissions of the caller."""
    return identity


@router.get("/projects")
async def projects() -> list[ProjectSummary]:
    """List the projects with their open findings, latest activity first."""
    return await run_in_threadpool(services.list_projects)


@router.get("/posture")
async def posture(project: Annotated[str, Query(min_length=1, max_length=200)]) -> dict:
    """Open findings of a project across all its reports."""
    return await run_in_threadpool(services.project_posture, project)


@router.get("/trend")
async def trend(
    project: Annotated[str, Query(min_length=1, max_length=200)],
    days: Annotated[int, Query(ge=1, le=1095)] = 90,
    granularity: Literal["day", "week", "month"] = "week",
) -> dict:
    """Evolution of the security posture of a project."""
    try:
        return await run_in_threadpool(trends.get_trend, project, days, granularity)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


@router.get("/sarif")
async def sarif(
    project: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    report_id: Annotated[int | None, Query(ge=1)] = None,
    include_resolved: bool = False,
) -> Response:
    """Download the findings of a project or of a report as SARIF 2.1.0."""
    try:
        name, items = await run_in_threadpool(services.collect_sarif_items, report_id, project)
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
    project: Annotated[str | None, Query(max_length=200)] = None,
    risk_level: Severity | None = None,
    limit: Annotated[int, Query(ge=1)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ReportSummary]:
    """List reports, newest first (limit is capped by SECREVIEW_MAX_LIST_LIMIT)."""
    return await run_in_threadpool(
        services.list_reports, project or None, risk_level, limit, offset
    )


@router.get("/reports/{report_id}")
async def report(report_id: int) -> SecurityReportPublic:
    """Return a report with its findings."""
    return await run_in_threadpool(services.get_report, report_id)


@router.get("/reports/{report_id}/markdown", response_class=PlainTextResponse)
async def report_markdown(report_id: int) -> PlainTextResponse:
    """Download a report as Markdown."""
    stored = await run_in_threadpool(services.get_report, report_id)
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
    finding = await run_in_threadpool(services.update_finding_status, finding_id, body.status)
    logger.info("Finding %s set to %s by %s", finding_id, body.status, identity.client)
    return finding


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
