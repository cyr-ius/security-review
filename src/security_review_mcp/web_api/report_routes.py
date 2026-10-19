"""Routes of the projects, reports and findings: posture, trend, SARIF export and triage."""

import json
import logging
from datetime import UTC, datetime, time
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Path, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse, Response

from .. import access_control, services, trends
from ..database import session_scope
from ..models import (
    DISMISSED_STATUSES,
    MAX_AUTHOR_CHARS,
    FindingCommentPublic,
    FindingPublic,
    FindingStatus,
    ReviewType,
    SecurityReportPublic,
    Severity,
)
from ..project_names import MAX_RAW_PROJECT_CHARS, ProjectName
from ..sarif import build_sarif
from .deps import (
    CurrentIdentity,
    Permission,
    ProjectCreator,
    ProjectDeleter,
    Triager,
    actor_of,
    check_report_scope,
    ensure_report_scope,
    in_scope,
    permission_scope,
    scoped_project,
    unprocessable,
    web_user_id,
)
from .schemas import (
    FindingCommentCreate,
    FindingStatusUpdate,
    Granularity,
    PendingProject,
    PendingProjectApproved,
    ProjectCreate,
    ProjectDeleted,
    ProjectFindingPage,
    ProjectPosture,
    ProjectSummary,
    ReportSummary,
    RiskAcceptancePage,
    Trend,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["reports"])

ProjectQuery = Annotated[ProjectName, Query()]
TrendDays = Annotated[int, Query(ge=1, le=1095)]
EnrollmentIdPath = Annotated[int, Path(ge=1)]


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


def _known_projects() -> list[dict]:
    """Projects with reports, then those without any report that a role of a group names."""
    with session_scope() as session:
        bound = access_control.bound_projects(session)
    return services.list_projects(bound)


@router.get("/projects")
async def projects(identity: CurrentIdentity) -> list[ProjectSummary]:
    """List the projects with their open findings, latest activity first (then the projects
    without any report yet)."""
    projects = await run_in_threadpool(_known_projects)
    return [item for item in projects if in_scope(identity, item["project"])]


@router.post("/projects", status_code=status.HTTP_201_CREATED)
async def create_project(
    request: Request, body: ProjectCreate, identity: ProjectCreator
) -> ProjectSummary:
    """Create a new project (``projects.create``, logged-in web user only): the controller
    creates its project group and adds the caller to it, so that the caller reads the project
    and its personal ``mcp`` token reaches it. A project already known is refused (409): the
    permission never opens an existing project."""
    user_id = web_user_id(request)
    try:
        created = await run_in_threadpool(
            access_control.create_project, user_id, body.project, actor_of(identity)
        )
    except services.NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ValueError as exc:
        if "already exists" in str(exc):
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        raise unprocessable(exc) from exc
    logger.info("Project %s created by %s", created["project"], identity.client)
    return ProjectSummary(
        project=created["project"],
        reports_total=0,
        last_report_at=None,
        open_findings_total=0,
        open_findings_by_severity={severity.value: 0 for severity in Severity},
        worst_open_severity=None,
    )


@router.get("/projects/pending")
async def pending_projects(identity: ProjectCreator) -> list[PendingProject]:
    """List the projects requested by an enrollment, oldest first (``projects.create``)."""
    return await run_in_threadpool(access_control.list_enrollments)


@router.post("/projects/pending/{enrollment_id}/approve")
async def approve_pending_project(
    enrollment_id: EnrollmentIdPath, identity: ProjectCreator
) -> PendingProjectApproved:
    """Approve a requested project (``projects.create``): its project group is created without
    any member, so that the project exists; the caller gains no access."""
    try:
        approved = await run_in_threadpool(
            access_control.approve_enrollment, enrollment_id, actor_of(identity)
        )
    except services.NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Project %s approved by %s", approved["project"], identity.client)
    return PendingProjectApproved.model_validate(approved)


@router.delete("/projects/pending/{enrollment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def reject_pending_project(
    enrollment_id: EnrollmentIdPath, identity: ProjectCreator
) -> Response:
    """Reject a requested project (``projects.create``): the request is deleted."""
    try:
        rejected = await run_in_threadpool(
            access_control.reject_enrollment, enrollment_id, actor_of(identity)
        )
    except services.NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info("Project %s rejected by %s", rejected["project"], identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/projects/{project}")
async def delete_project(
    request: Request, project: Annotated[ProjectName, Path()], identity: ProjectDeleter
) -> ProjectDeleted:
    """Delete a project and everything that refers to it (``projects.delete``, logged-in web
    user only): its reports, findings and comments, its project group, the project in the
    roles of the other groups and in the tokens (a token left without project is revoked)."""
    web_user_id(request)
    try:
        deleted = await run_in_threadpool(
            access_control.delete_project, project, actor_of(identity)
        )
    except services.NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Project %s deleted by %s", deleted["project"], identity.client)
    return ProjectDeleted(**deleted)


@router.get("/posture")
async def posture(project: ProjectQuery, identity: CurrentIdentity) -> ProjectPosture:
    """Open findings of a project across all its reports."""
    return await run_in_threadpool(services.project_posture, scoped_project(identity, project))


@router.get("/findings")
async def project_findings(
    identity: CurrentIdentity,
    project: Annotated[ProjectName | None, Query()] = None,
    finding_status: Annotated[FindingStatus, Query(alias="status")] = FindingStatus.OPEN,
    severity: Severity | None = None,
    review_type: ReviewType | None = None,
    limit: Annotated[int, Query(ge=1)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ProjectFindingPage:
    """Findings of a project across all its reports (open by default), worst first.

    Gives an expert the whole list to review; without ``project``, lists the findings of every
    project in the scope of the caller. limit is capped by SECREVIEW_MAX_LIST_LIMIT.
    """
    if project is not None:
        scoped_project(identity, project)
    return await run_in_threadpool(
        services.list_project_findings,
        project,
        finding_status,
        severity,
        limit,
        offset,
        review_type,
        identity.projects,
    )


@router.get("/risk-acceptances")
async def risk_acceptances(
    identity: CurrentIdentity,
    project: Annotated[ProjectName | None, Query()] = None,
    limit: Annotated[int, Query(ge=1)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> RiskAcceptancePage:
    """Accepted risks of a project (or of every project in the scope of the caller), expired
    ones included, nearest expiry first. limit is capped by SECREVIEW_MAX_LIST_LIMIT."""
    if project is not None:
        scoped_project(identity, project)
    return await run_in_threadpool(
        services.list_risk_acceptances, project, identity.projects, limit, offset
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
    project: Annotated[ProjectName | None, Query()] = None,
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
    project: Annotated[str | None, Query(max_length=MAX_RAW_PROJECT_CHARS)] = None,
    risk_level: Severity | None = None,
    review_type: ReviewType | None = None,
    author: Annotated[str | None, Query(max_length=MAX_AUTHOR_CHARS)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    sort_by: Literal[
        "created_at", "project", "risk_level", "review_type", "branch", "author", "summary"
    ] = "created_at",
    sort_direction: Literal["asc", "desc"] = "desc",
    limit: Annotated[int, Query(ge=1)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ReportSummary]:
    """List reports, newest first (limit is capped by SECREVIEW_MAX_LIST_LIMIT)."""
    if project:
        project = scoped_project(identity, project)
    return await run_in_threadpool(
        services.list_reports,
        project or None,
        risk_level,
        limit,
        offset,
        identity.projects,
        review_type,
        author or None,
        search,
        sort_by,
        sort_direction,
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


@router.get("/findings/{finding_id}/comments")
async def finding_comments(
    finding_id: int, identity: CurrentIdentity
) -> list[FindingCommentPublic]:
    """Comments of a finding, oldest first."""
    await run_in_threadpool(services.check_finding_scope, identity.projects, finding_id)
    return await run_in_threadpool(services.list_finding_comments, finding_id)


@router.post("/findings/{finding_id}/comments", status_code=status.HTTP_201_CREATED)
async def add_finding_comment(
    finding_id: int, body: FindingCommentCreate, identity: Triager
) -> FindingCommentPublic:
    """Comment a finding (its risk acceptance); the caller is stored as its author and logged.

    Only a person logged in to the web interface may comment: a bearer token is refused. A
    comment is never edited nor deleted (no route does it).
    """
    if identity.auth_source is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only a person logged in to the web interface can comment a finding",
        )
    await run_in_threadpool(
        services.check_finding_scope,
        permission_scope(identity, Permission.FINDINGS_TRIAGE),
        finding_id,
    )
    try:
        comment = await run_in_threadpool(
            services.add_finding_comment,
            finding_id,
            identity.client,
            body.body,
            actor_of(identity),
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Finding %s commented by %s", finding_id, identity.client)
    return comment
