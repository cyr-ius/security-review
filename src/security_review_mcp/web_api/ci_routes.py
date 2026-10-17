"""Pipeline routes (``/api/v1/ci``, ci tokens, see ci_client): gate, SARIF and trend.

Read only, scoped to the projects of the token; a ci token reaches nothing else.
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from .. import services, trends
from ..models import Severity
from .deps import (
    PipelineIdentity,
    check_report_scope,
    pipeline_identity,
    scoped_project,
    unprocessable,
)
from .report_routes import ProjectQuery, TrendDays, project_trend, sarif_response
from .schemas import GateResult, Granularity, Trend

router = APIRouter(prefix="/api/v1/ci", tags=["ci"], dependencies=[Depends(pipeline_identity)])


@router.get("/gate")
async def ci_gate(
    project: ProjectQuery,
    identity: PipelineIdentity,
    fail_on: Severity = Severity.HIGH,
    report_id: Annotated[int | None, Query(ge=1)] = None,
) -> GateResult:
    """Security gate of a project: ``passed`` is false while open findings reach ``fail_on``.

    ``report_id`` judges one report of the project only.
    """
    project = scoped_project(identity, project)
    if report_id is not None:
        await check_report_scope(identity, report_id)
    try:
        return await run_in_threadpool(services.evaluate_gate, project, fail_on, report_id)
    except ValueError as exc:
        raise unprocessable(exc) from exc


@router.get("/sarif", response_class=Response)
async def ci_sarif(
    project: ProjectQuery, identity: PipelineIdentity, include_resolved: bool = False
) -> Response:
    """Findings of a project as SARIF 2.1.0 (open ones only by default)."""
    project = scoped_project(identity, project)
    name, items = await run_in_threadpool(services.collect_sarif_items, None, project)
    return sarif_response(name, items, include_resolved, "project.sarif")


@router.get(
    "/trend",
    response_model=Trend,
    responses={200: {"content": {"text/markdown": {}}}},
)
async def ci_trend(
    project: ProjectQuery,
    identity: PipelineIdentity,
    days: TrendDays = 90,
    granularity: Granularity = "week",
    output: Annotated[Literal["json", "markdown"], Query(alias="format")] = "json",
) -> Response:
    """Evolution of the security posture of a project, as JSON or Markdown."""
    result = await project_trend(scoped_project(identity, project), days, granularity)
    if output == "markdown":
        return PlainTextResponse(
            trends.render_trend_markdown(result), media_type="text/markdown; charset=utf-8"
        )
    return JSONResponse(Trend.model_validate(result).model_dump(mode="json"))
