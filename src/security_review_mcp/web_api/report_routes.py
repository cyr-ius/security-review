"""Routes of the projects, reports and findings: posture, trend, SARIF export and triage."""

import json
import logging
from datetime import UTC, datetime, time
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse, Response

from .. import services, trends
from ..models import (
    DISMISSED_STATUSES,
    MAX_AUTHOR_CHARS,
    FindingPublic,
    FindingStatus,
    ReviewType,
    SecurityReportPublic,
    Severity,
)
from ..sarif import build_sarif
from .deps import (
    CurrentIdentity,
    Permission,
    Triager,
    actor_of,
    check_report_scope,
    ensure_report_scope,
    in_scope,
    permission_scope,
    scoped_project,
    unprocessable,
)
from .schemas import (
    FindingStatusUpdate,
    Granularity,
    ProjectFindingPage,
    ProjectPosture,
    ProjectSummary,
    ReportSummary,
    Trend,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["reports"])

ProjectQuery = Annotated[str, Query(min_length=1, max_length=200)]
TrendDays = Annotated[int, Query(ge=1, le=1095)]


def sarif_response(name: str, items: list, include_resolved: bool, filename: str) -> Response:
    """SARIF 2.1.0 download of collected findings."""
    document = build_sarif(items, name, include_resolved)
    return Response(
        content=json.dumps(document, indent=2),
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def project_trend(project: str, days: int, granularity: Granularity) -> dict:
    """Trend of a project in the scope of the caller (422 for invalid bounds)."""
    try:
        return await run_in_threadpool(trends.get_trend, project, days, granularity)
    except ValueError as exc:
        raise unprocessable(exc) from exc


@router.get("/projects")
async def projects(identity: CurrentIdentity) -> list[ProjectSummary]:
    """List the projects with their open findings, latest activity first."""
    projects = await run_in_threadpool(services.list_projects)
    return [item for item in projects if in_scope(identity, item["project"])]


@router.get("/posture")
async def posture(project: ProjectQuery, identity: CurrentIdentity) -> ProjectPosture:
    """Open findings of a project across all its reports."""
    return await run_in_threadpool(services.project_posture, scoped_project(identity, project))


@router.get("/findings")
async def project_findings(
    project: ProjectQuery,
    identity: CurrentIdentity,
    finding_status: Annotated[FindingStatus, Query(alias="status")] = FindingStatus.OPEN,
    severity: Severity | None = None,
    review_type: ReviewType | None = None,
    limit: Annotated[int, Query(ge=1)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ProjectFindingPage:
    """Findings of a project across all its reports (open by default), worst first.

    Gives an expert the whole list to review; limit is capped by SECREVIEW_MAX_LIST_LIMIT.
    """
    return await run_in_threadpool(
        services.list_project_findings,
        scoped_project(identity, project),
        finding_status,
        severity,
        limit,
        offset,
        review_type,
    )


@router.get("/trend")
async def trend(
    project: ProjectQuery,
    identity: CurrentIdentity,
    days: TrendDays = 90,
    granularity: Granularity = "week",
) -> Trend:
    """Evolution of the security posture of a project."""
    return await project_trend(scoped_project(identity, project), days, granularity)


@router.get("/sarif", response_class=Response)
async def sarif(
    identity: CurrentIdentity,
    project: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    report_id: Annotated[int | None, Query(ge=1)] = None,
    include_resolved: bool = False,
) -> Response:
    """Download the findings of a project or of a report as SARIF 2.1.0."""
    if identity.projects is not None:
        if project is not None:
            scoped_project(identity, project)
        if report_id is not None:
            await check_report_scope(identity, report_id)
        elif project is None and len(identity.projects) == 1:
            project = identity.projects[0]
    try:
        name, items = await run_in_threadpool(services.collect_sarif_items, report_id, project)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    filename = f"report-{report_id}.sarif" if report_id else "project.sarif"
    return sarif_response(name, items, include_resolved, filename)


@router.get("/reports")
async def reports(
    identity: CurrentIdentity,
    project: Annotated[str | None, Query(max_length=200)] = None,
    risk_level: Severity | None = None,
    review_type: ReviewType | None = None,
    author: Annotated[str | None, Query(max_length=MAX_AUTHOR_CHARS)] = None,
    limit: Annotated[int, Query(ge=1)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ReportSummary]:
    """List reports, newest first (limit is capped by SECREVIEW_MAX_LIST_LIMIT)."""
    if project:
        scoped_project(identity, project)
    return await run_in_threadpool(
        services.list_reports,
        project or None,
        risk_level,
        limit,
        offset,
        identity.projects,
        review_type,
        author or None,
    )


@router.get("/reports/{report_id}")
async def report(report_id: int, identity: CurrentIdentity) -> SecurityReportPublic:
    """Return a report with its findings."""
    stored = await run_in_threadpool(services.get_report, report_id)
    ensure_report_scope(identity, stored)
    return stored


@router.get("/reports/{report_id}/markdown", response_class=PlainTextResponse)
async def report_markdown(report_id: int, identity: CurrentIdentity) -> PlainTextResponse:
    """Download a report as Markdown."""
    stored = await run_in_threadpool(services.get_report, report_id)
    ensure_report_scope(identity, stored)
    return PlainTextResponse(
        services.render_report_markdown(stored),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report-{report_id}.md"'},
    )


@router.patch("/findings/{finding_id}")
async def update_finding(
    finding_id: int,
    body: FindingStatusUpdate,
    identity: Triager,
) -> FindingPublic:
    """Record a triage decision; the caller is stored as its approver and logged.

    Only a person logged in to the web interface may accept a risk or mark a false positive:
    a bearer token, which an agent may hold, is refused.
    """
    if body.status in DISMISSED_STATUSES and identity.auth_source is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only a person logged in to the web interface can accept a risk or mark a "
            "false positive",
        )
    await run_in_threadpool(
        services.check_finding_scope,
        permission_scope(identity, Permission.FINDINGS_TRIAGE),
        finding_id,
    )
    expires_at = (
        None if body.expires_on is None else datetime.combine(body.expires_on, time.min, UTC)
    )
    try:
        finding = await run_in_threadpool(
            services.update_finding_status,
            finding_id,
            body.status,
            identity.client,
            body.reason,
            expires_at,
            actor_of(identity),
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Finding %s set to %s by %s", finding_id, body.status, identity.client)
    return finding


@router.delete("/findings/{finding_id}/proposal")
async def reject_finding_proposal(finding_id: int, identity: Triager) -> FindingPublic:
    """Reject the status proposed by an agent; the status of the finding does not change."""
    await run_in_threadpool(
        services.check_finding_scope,
        permission_scope(identity, Permission.FINDINGS_TRIAGE),
        finding_id,
    )
    finding = await run_in_threadpool(
        services.clear_finding_proposal, finding_id, actor_of(identity)
    )
    logger.info("Proposal for finding %s rejected by %s", finding_id, identity.client)
    return finding
