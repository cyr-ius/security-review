"""Administration routes: audit log, settings of the web interface and OSV advisories."""

import logging
from datetime import UTC, date, datetime, time
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool

from .. import advisories, advisory_sync, app_settings, audit
from ..config import get_settings
from .deps import AuditReader, SettingsManager, unprocessable
from .schemas import (
    AdvisoryOverview,
    AdvisoryUpdateStarted,
    AppSettings,
    AuditPage,
    ProxyUpdate,
    ReportLanguageUpdate,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["administration"])


@router.get("/audit")
async def audit_events(
    identity: AuditReader,
    action: Annotated[audit.AuditAction | None, Query()] = None,
    project: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    actor: Annotated[str | None, Query(min_length=1, max_length=audit.MAX_ACTOR_CHARS)] = None,
    since: date | None = None,
    limit: Annotated[int, Query(ge=1)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditPage:
    """Audit log, newest first: triage decisions, agent proposals, tokens and enrollments.

    ``since`` keeps the events from that day (00:00 UTC); limit is capped by
    SECREVIEW_MAX_LIST_LIMIT.
    """
    start = None if since is None else datetime.combine(since, time.min, UTC)
    return await run_in_threadpool(
        audit.list_events,
        action.value if action else None,
        project,
        actor,
        start,
        limit,
        offset,
    )


@router.get("/settings")
async def get_app_settings(identity: SettingsManager) -> AppSettings:
    """Return the settings of the web interface, the variables and the effective values.

    Passwords of proxy URLs are replaced by ``***``.
    """
    return await run_in_threadpool(app_settings.describe)


@router.put("/settings/report-language")
async def set_report_language(body: ReportLanguageUpdate, identity: SettingsManager) -> AppSettings:
    """Set the language of the review reports (used by the MCP server for the next prompts)."""
    try:
        await run_in_threadpool(app_settings.set_report_language, body.value, identity.client)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Report language set to %r by %s", body.value, identity.client)
    return await run_in_threadpool(app_settings.describe)


@router.put("/settings/proxy")
async def set_proxy(body: ProxyUpdate, identity: SettingsManager) -> AppSettings:
    """Set the proxy of the OSV download and of the OIDC provider (applied at the next download
    or login; the URL is never logged)."""
    values = body.model_dump(exclude_unset=True)
    try:
        await run_in_threadpool(app_settings.set_proxy, values, identity.client)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    # Names only: the URL may hold credentials
    logger.info("Proxy settings %s changed by %s", ", ".join(sorted(values)), identity.client)
    return await run_in_threadpool(app_settings.describe)


def _advisory_overview(limit: int) -> dict:
    """State of the advisory database and history of its updates."""
    settings = get_settings()
    return {
        "database": advisories.advisory_status(),
        "download_enabled": settings.osv_auto_update,
        "running": advisory_sync.running_update() is not None,
        "updates": advisory_sync.list_updates(limit),
    }


@router.get("/advisories")
async def advisory_overview(
    identity: SettingsManager,
    limit: Annotated[int, Query(ge=1, le=advisory_sync.HISTORY_SIZE)] = 20,
) -> AdvisoryOverview:
    """Return the state of the advisory database and the latest OSV updates."""
    return await run_in_threadpool(_advisory_overview, limit)


@router.post("/advisories/update", status_code=status.HTTP_202_ACCEPTED)
async def start_advisory_update(identity: SettingsManager) -> AdvisoryUpdateStarted:
    """Start downloading the OSV exports in the background; follow it with GET /advisories.

    Refused (409) when the download is disabled (SECREVIEW_OSV_AUTO_UPDATE=false) or an update
    is already running.
    """
    try:
        update_id = await run_in_threadpool(
            advisory_sync.start_web_update, get_settings(), identity.client
        )
    except (advisory_sync.DownloadDisabled, advisory_sync.UpdateInProgress) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("OSV update %d started by %s", update_id, identity.client)
    return AdvisoryUpdateStarted(id=update_id)
