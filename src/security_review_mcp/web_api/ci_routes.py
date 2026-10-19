"""Pipeline routes (``/api/v1/ci``, ci tokens, see ci_client): gate, SARIF, trend and scans.

Scoped to the projects of the token; a ci token reaches nothing else. The gate, SARIF and trend
only read. The scans (``/scan/code``, ``/scan/deps``) receive the content of the files of a
pipeline, scan it with the rules or the advisory database of the controller and, with ``save``,
store the result as a report: they need a ``ci`` or ``admin`` token (see deps.scan_identity),
and their body is bounded by body_limit.BodyLimit before it is parsed.
"""

import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from .. import codescan, depscan, services, trends
from ..models import Severity
from .deps import (
    PipelineIdentity,
    ScanIdentity,
    check_report_scope,
    pipeline_identity,
    scoped_project,
    unprocessable,
)
from .report_routes import ProjectQuery, TrendDays, project_trend, sarif_response
from .schemas import (
    CodeScanRequest,
    CodeScanResult,
    DependencyScanRequest,
    DependencyScanResult,
    GateResult,
    Granularity,
    Trend,
)

logger = logging.getLogger("security_review_mcp.web")

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


# ── Scans (security-review-ci scan-code and scan-deps) ───────────────────────


def _verdict(blocking: int, request: CodeScanRequest | DependencyScanRequest) -> dict:
    """Verdict fields of a scan answer."""
    return {"fail_on": request.fail_on, "blocked": blocking > 0, "blocking_findings": blocking}


def _code_scan(request: CodeScanRequest, client: str) -> dict:
    """Scan the files of a code scan request, store the report with ``save``."""
    result = codescan.scan_files(
        [codescan.SourceFile(f.path, f.content) for f in request.files],
        [(s.file, s.reason) for s in request.skipped],
        request.listing,
        request.root,
        request.excluded,
        request.unsupported,
    )
    fields = {
        "repository": request.repository,
        "branch": request.branch,
        "commit_sha": request.commit_sha,
    }
    saved = None
    if request.save:
        saved = codescan.save(
            result, request.project, author=request.author, submitted_by=client, **fields
        )
    log = codescan.to_sarif(result, request.project, saved, **fields) if request.sarif else None
    blocking = codescan.blocking_count(result, request.fail_on)
    return result | _verdict(blocking, request) | {"saved_report": saved, "sarif": log}


def _dependency_scan(request: DependencyScanRequest, client: str) -> dict:
    """Scan the files of a dependency scan request, store the report with ``save``."""
    results = depscan.scan_files(
        [(f.path, f.content) for f in request.files], request.require_database
    )
    saved = None
    if request.save:
        saved = depscan.save(
            results,
            request.project,
            repository=request.repository,
            branch=request.branch,
            commit_sha=request.commit_sha,
            author=request.author,
            submitted_by=client,
        )
    blocking = depscan.blocking_count(results, request.fail_on)
    slim = [{k: v for k, v in r.items() if k != "components"} for r in results]
    return _verdict(blocking, request) | {"saved_report": saved, "files": slim}


@router.post("/scan/code")
async def ci_code_scan(request: CodeScanRequest, identity: ScanIdentity) -> CodeScanResult:
    """Pattern-scan the files of a codebase sent by ``security-review-ci scan-code``.

    The matches are leads to verify. With ``save``, they are stored as a ``code-scan`` report of
    the project (the most severe ones, up to SECREVIEW_MAX_FINDINGS_PER_REPORT); ``sarif`` also
    returns them as a SARIF 2.1.0 log. Files above SECREVIEW_MAX_SCAN_FILE_CHARS are skipped.
    """
    project = scoped_project(identity, request.project)
    try:
        result = await run_in_threadpool(_code_scan, request, identity.client)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info(
        "Code scan of %r by %s: %d file(s), %d match(es), report %s",
        project,
        identity.client,
        result["files_scanned"],
        result["matches_count"],
        result["saved_report"]["report_id"] if result["saved_report"] else "not saved",
    )
    return CodeScanResult.model_validate(result)


@router.post("/scan/deps")
async def ci_dependency_scan(
    request: DependencyScanRequest, identity: ScanIdentity
) -> DependencyScanResult:
    """Scan the manifests and lockfiles sent by ``security-review-ci scan-deps``.

    Vulnerable versions are found with the advisory database of the controller, hygiene issues
    without it. With ``save``, they are stored as a ``dependency-scan`` report of the project;
    ``require_database`` refuses the scan (422) when the vulnerability check cannot run.
    """
    project = scoped_project(identity, request.project)
    try:
        result = await run_in_threadpool(_dependency_scan, request, identity.client)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info(
        "Dependency scan of %r by %s: %d file(s), report %s",
        project,
        identity.client,
        len(result["files"]),
        result["saved_report"]["report_id"] if result["saved_report"] else "not saved",
    )
    return DependencyScanResult.model_validate(result)
