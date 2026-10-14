"""Controller: REST API (``/api/v1``) and the bundled Angular application (``/ui``).

Served by ``security-review-controller serve``, in its own process, apart from the MCP server
(see http_server). The bearer middleware authenticates the requests and stores the token label
and role in the ASGI scope; this module checks the permissions of each route. The public
enrollment endpoint is served by the MCP server (see enrollment_api); approving or rejecting
the requests is done here.

The services are synchronous (SQLModel sessions), so every call runs in the thread pool.
"""

import json
import logging
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi import Path as APIPath
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import Scope

from . import __version__, registry, rule_store, rules_loader, services, token_store, trends
from .config import get_settings
from .http_server import BEARER_CHALLENGE, HEALTH_PATH, LOOPBACK_HOSTS, TRIAGE_ROLES, Role
from .models import FindingPublic, FindingStatus, SecurityReportPublic, Severity
from .sarif import build_sarif

logger = logging.getLogger("security_review_mcp.web")

BUNDLED_UI_DIR = Path(__file__).parent / "webui"

# Declares the bearer scheme in the OpenAPI document (Swagger "Authorize" button). The token
# itself is validated by the bearer middleware: auto_error=False leaves the 401 to
# current_identity, which also covers an app served without that middleware.
bearer_scheme = HTTPBearer(
    auto_error=False, description="API token (`security-review-controller token create`)"
)

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
    # Always true: the API answers authenticated requests only (kept for API compatibility)
    auth_enabled: bool
    # Projects a restricted token reaches; None: every project
    projects: list[str] | None = None
    version: str


class FindingStatusUpdate(BaseModel):
    """Body of PATCH /findings/{id}."""

    status: FindingStatus


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


class ChecklistItemWrite(BaseModel):
    """A checklist item sent to the web API."""

    domain: str = Field(min_length=1, max_length=31)
    id: str = Field(min_length=3, max_length=rules_loader.MAX_ID_CHARS)
    title: str = Field(min_length=1, max_length=rules_loader.MAX_TITLE_CHARS)
    what_to_look_for: str = Field(min_length=1, max_length=rules_loader.MAX_TEXT_CHARS)
    cwe: str = Field(default="", max_length=20)


class ProjectTokenCreate(BaseModel):
    """A role-specific token scoped to one or several projects."""

    label: str = Field(min_length=1, max_length=64)
    role: Literal["mcp", "reader", "triager"] = "reader"
    projects: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        min_length=1, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )


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


def current_identity(
    request: Request,
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> Identity:
    """Identity set by the bearer middleware once it has validated the token.

    Fails closed: a request that reaches a route without an identity in its scope (app served
    without BearerAuthMiddleware, or a public path mistakenly routed here) gets 401, never an
    implicit administrator.
    """
    state = request.scope.get("state") or {}
    if "auth_role" not in state:
        logger.warning(
            "Rejected API request without an authenticated identity: %s", request.url.path
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid bearer token",
            headers={"WWW-Authenticate": BEARER_CHALLENGE},
        )
    role = Role(state["auth_role"])
    return Identity(
        client=state["auth_client"],
        role=role,
        can_triage=role in TRIAGE_ROLES,
        auth_enabled=True,
        projects=None if state.get("auth_projects") is None else sorted(state["auth_projects"]),
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


def _in_scope(identity: Identity, project: str) -> bool:
    """True when the caller may see this project (always for an unrestricted token)."""
    return identity.projects is None or project in identity.projects


def _scoped_project(identity: Identity, requested: str) -> str:
    """Refuse a project outside a project token's scope without disclosing other projects."""
    if not _in_scope(identity, requested):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return requested


def _ensure_report_scope(identity: Identity, report: SecurityReportPublic) -> None:
    """Hide reports outside a project token's scope."""
    if not _in_scope(identity, report.project):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


def _rule_catalog() -> dict:
    """Return the rules stored in the database (default and custom) and the diagnostics."""
    return {
        "rules": rule_store.list_rules(),
        "load_errors": list(registry.snapshot().errors),
    }


async def _refresh_rules() -> dict:
    """Reload the active registry and return its diagnostics."""
    snapshot = await run_in_threadpool(registry.reload)
    return {"loaded_rules": len(snapshot.custom_rule_ids), "load_errors": list(snapshot.errors)}


async def _refresh_checklists() -> dict:
    """Reload the active registry and return checklist-specific diagnostics."""
    snapshot = await run_in_threadpool(registry.reload)
    count = sum(len(items) for items in snapshot.checklists.values())
    return {"loaded_checklist_items": count, "load_errors": list(snapshot.errors)}


# ── Routes ───────────────────────────────────────────────────────────────────


# Every route needs an authenticated identity, even those that do not use it (health)
router = APIRouter(prefix="/api/v1", dependencies=[Depends(current_identity)])


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
    return [item for item in projects if _in_scope(identity, item["project"])]


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
        if identity.projects is not None:
            if project is not None:
                _scoped_project(identity, project)
            if report_id is not None:
                scoped_report = await run_in_threadpool(services.get_report, report_id)
                _ensure_report_scope(identity, scoped_report)
            elif project is None and len(identity.projects) == 1:
                project = identity.projects[0]
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
    if project:
        _scoped_project(identity, project)
    return await run_in_threadpool(
        services.list_reports, project or None, risk_level, limit, offset, identity.projects
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
    await run_in_threadpool(services.check_finding_scope, identity.projects, finding_id)
    finding = await run_in_threadpool(services.update_finding_status, finding_id, body.status)
    logger.info("Finding %s set to %s by %s", finding_id, body.status, identity.client)
    return finding


@router.get("/rules")
async def list_custom_rules(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """List the rules stored in the database (default and custom)."""
    return await run_in_threadpool(_rule_catalog)


@router.get("/checklists")
async def list_checklist_items(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """List the checklist items stored in the database (default and custom)."""
    return {
        "checklist_items": await run_in_threadpool(rule_store.list_checklist_items),
        "load_errors": list(registry.snapshot().errors),
    }


@router.post("/checklists", status_code=status.HTTP_201_CREATED)
async def create_checklist_item(
    body: ChecklistItemWrite, identity: Annotated[Identity, Depends(require_admin)]
) -> dict:
    """Create a custom checklist item."""
    try:
        await run_in_threadpool(rule_store.create_check_item, body.model_dump(mode="json"))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Checklist item %s/%s created by %s", body.domain, body.id, identity.client)
    return await _refresh_checklists()


@router.put("/checklists/{domain}/{item_id}")
async def update_checklist_item(
    domain: Annotated[str, APIPath(min_length=1, max_length=31)],
    item_id: Annotated[str, APIPath(min_length=3, max_length=rules_loader.MAX_ID_CHARS)],
    body: ChecklistItemWrite,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict:
    """Update a checklist item without changing its domain or id."""
    try:
        await run_in_threadpool(
            rule_store.update_check_item, domain, item_id, body.model_dump(mode="json")
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Checklist item %s/%s updated by %s", domain, item_id, identity.client)
    return await _refresh_checklists()


@router.delete("/checklists/{domain}/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_checklist_item(
    domain: Annotated[str, APIPath(min_length=1, max_length=31)],
    item_id: Annotated[str, APIPath(min_length=3, max_length=rules_loader.MAX_ID_CHARS)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """Delete one custom checklist item."""
    try:
        await run_in_threadpool(rule_store.delete_check_item, domain, item_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await _refresh_checklists()
    logger.info("Checklist item %s/%s deleted by %s", domain, item_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/rules/reload")
async def reload_custom_rules(identity: Annotated[Identity, Depends(require_admin)]) -> dict:
    """Reload the internal rules now (after a change made with the CLI)."""
    logger.info("Internal rules reloaded by %s", identity.client)
    return await _refresh_rules()


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_custom_rule(
    body: RuleWrite, identity: Annotated[Identity, Depends(require_admin)]
) -> dict:
    """Create a custom rule in the database."""
    try:
        await run_in_threadpool(rule_store.create_rule, body.model_dump(mode="json"))
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
    """Update a stored rule (default or custom) while keeping its stable id."""
    try:
        await run_in_threadpool(rule_store.update_rule, rule_id, body.model_dump(mode="json"))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Rule %s updated by %s", rule_id, identity.client)
    return await _refresh_rules()


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_custom_rule(
    rule_id: Annotated[str, APIPath(min_length=3, max_length=50)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """Delete a custom rule from the database (default rules can only be disabled)."""
    try:
        await run_in_threadpool(rule_store.delete_entries, [rule_id], False)
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
    """Enable or disable a default or custom rule."""
    try:
        await run_in_threadpool(rule_store.set_enabled, [rule_id], body.enabled)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info("Rule %s enabled=%s by %s", rule_id, body.enabled, identity.client)
    return await _refresh_rules()


@router.get("/project-tokens")
async def project_tokens(
    identity: Annotated[Identity, Depends(require_admin)],
) -> list[dict[str, Any]]:
    """List project-token metadata without returning hashes or token values."""
    return await run_in_threadpool(token_store.list_project_tokens)


@router.post("/project-tokens", status_code=status.HTTP_201_CREATED)
async def create_project_token(
    body: ProjectTokenCreate,
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict[str, Any]:
    """Create a scoped token for existing projects and return its secret exactly once."""
    known = {item["project"] for item in await run_in_threadpool(services.list_projects)}
    if not set(body.projects) <= known:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    try:
        created = await run_in_threadpool(
            token_store.create_project_token, body.label, body.projects, body.role
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    logger.info(
        "Project token %s (%s) created for %s by %s",
        body.label,
        body.role,
        ", ".join(created["projects"]),
        identity.client,
    )
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


@router.get("/enrollments")
async def enrollments(
    identity: Annotated[Identity, Depends(require_admin)],
) -> list[dict[str, Any]]:
    """List the enrollment requests waiting for approval (never a secret).

    ``kind`` is ``new`` for a first enrollment (new token) and ``additional`` for a
    complementary one (one more project for an active token).
    """
    return await run_in_threadpool(token_store.list_enrollments)


@router.post("/enrollments/{request_id}/approve")
async def approve_enrollment(
    request_id: Annotated[str, APIPath(min_length=1, max_length=64)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> dict[str, Any]:
    """Approve an enrollment request: the project is reachable from the next request."""
    try:
        approved = await run_in_threadpool(token_store.approve_enrollment, request_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info(
        "Enrollment %s for %s approved by %s",
        approved["label"],
        approved["project"],
        identity.client,
    )
    return approved


@router.delete("/enrollments/{request_id}", status_code=status.HTTP_204_NO_CONTENT)
async def reject_enrollment(
    request_id: Annotated[str, APIPath(min_length=1, max_length=64)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """Reject an enrollment request: a new token is deleted, an additional project dropped."""
    try:
        rejected = await run_in_threadpool(token_store.reject_enrollment, request_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info(
        "Enrollment %s for %s rejected by %s",
        rejected["label"],
        rejected["project"],
        identity.client,
    )
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


def create_app(host: str = "127.0.0.1", ui_dir: str | None = None, ui: bool = True) -> FastAPI:
    """Build the controller app (REST API and, when it is built, the Angular application).

    ``ui=False`` (SECREVIEW_WEB_UI=false) serves the REST API only.

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

    @app.get(HEALTH_PATH, include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Public liveness probe (containers, Kubernetes)."""
        return {"status": "ok"}

    @app.exception_handler(services.NotFoundError)
    async def not_found(_: Request, exc: services.NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    configured = ui_dir if ui_dir is not None else settings.web_ui_dir
    directory = resolve_ui_dir(configured) if ui else None
    if directory is not None:
        app.mount("/ui", SinglePageApp(directory=directory, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        async def root() -> RedirectResponse:
            return RedirectResponse("/ui/")
    elif ui:
        logger.warning("Web interface not built: only the REST API is served (/api/v1)")

    if host in LOOPBACK_HOSTS:
        # Same protection as the MCP endpoint against DNS rebinding on a local server
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])
    return app
