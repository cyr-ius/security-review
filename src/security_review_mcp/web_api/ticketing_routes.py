"""Routes of the ticketing systems: connections, destinations of the projects and sending of a
finding (see ticketing). A system is named by the ``kind`` of its connector (``jira``,
``servicenow`` or a third-party one): an unknown kind answers 404."""

import logging
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, Response, status
from fastapi.concurrency import run_in_threadpool

from .. import app_settings, services
from ..config import get_settings
from ..models import FindingTicketPublic
from ..project_names import ProjectName
from ..ticketing import TicketingError, connections, core, registry
from ..ticketing.api import TicketConnector
from .deps import (
    CurrentIdentity,
    Permission,
    SettingsManager,
    Triager,
    actor_of,
    permission_scope,
    unprocessable,
)
from .schemas import (
    TicketDestination,
    TicketingSettings,
    TicketingSwitch,
    TicketingTestResult,
    TicketingValues,
    TicketSystem,
    TicketTarget,
    TicketTargetUpdate,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["ticketing"])

ProjectPath = Annotated[ProjectName, Path()]
KindPath = Annotated[str, Path(pattern=r"^[a-z][a-z0-9_]{1,19}$")]
# Refused before any request: the configuration, not the remote system, is at fault
_CONFLICT_CODES = frozenset({"disabled", "not_configured", "no_target", "in_progress"})


def _connector(kind: str) -> TicketConnector:
    """The connector of ``kind`` (404 when unknown)."""
    try:
        return registry.get(kind)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


def _describe() -> dict:
    """Ticketing settings and every connection."""
    settings = get_settings()
    return {
        "enabled": settings.ticketing_enabled,
        "interval_seconds": settings.ticketing_interval_seconds,
        "cafile": settings.ticketing_cafile,
        "plugins": registry.plugin_names(settings.ticketing_plugins),
        "connectors": [
            connections.describe(connector, registry.is_builtin(connector), settings)
            for connector in registry.connectors(settings).values()
        ],
    }


@router.get("/ticketing/systems")
async def ticket_systems(identity: CurrentIdentity) -> list[TicketSystem]:
    """Available ticketing systems (kind and name), to label the tickets of the findings."""
    found = await run_in_threadpool(registry.connectors)
    return [TicketSystem(kind=kind, name=connector.name) for kind, connector in found.items()]


@router.get("/settings/ticketing")
async def get_ticketing(identity: SettingsManager) -> TicketingSettings:
    """Return the connections of the ticketing systems (secrets replaced by ``***``)."""
    return await run_in_threadpool(_describe)


@router.put("/settings/ticketing/{kind}")
async def set_ticketing(
    kind: KindPath, body: Annotated[TicketingValues, Body()], identity: SettingsManager
) -> TicketingSettings:
    """Set fields of a connection (applied to the next ticket). A field left out is unchanged,
    ``null`` or ``""`` deletes the stored value, a secret sent back as ``***`` is kept. Refused
    (422) for a value whose variable is set, or a new host without its secrets entered again.
    The change is recorded in the audit log, secrets masked."""
    connector = _connector(kind)
    try:
        await run_in_threadpool(connections.set_connection, connector, body, actor_of(identity))
    except ValueError as exc:
        raise unprocessable(exc) from exc
    # Names only: the values may be secrets
    logger.info("%s settings %s changed by %s", kind, ", ".join(sorted(body)), identity.client)
    return await run_in_threadpool(_describe)


@router.put("/settings/ticketing/{kind}/enabled")
async def switch_ticketing(
    kind: KindPath, body: TicketingSwitch, identity: SettingsManager
) -> TicketingSettings:
    """Switch a connector on or off: nothing is sent through a connector switched off. Refused
    (422) when SECREVIEW_TICKETING_ENABLED is false, or to switch on a connection that is not
    configured. The change is recorded in the audit log."""
    connector = _connector(kind)
    try:
        await run_in_threadpool(
            connections.set_enabled, connector, body.enabled, actor_of(identity), get_settings()
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    state = "on" if body.enabled else "off"
    logger.info("%s connector switched %s by %s", kind, state, identity.client)
    return await run_in_threadpool(_describe)


@router.post("/settings/ticketing/{kind}/test")
async def test_ticketing(
    kind: KindPath, body: Annotated[TicketingValues, Body()], identity: SettingsManager
) -> TicketingTestResult:
    """Test the connection with the stored values and those of the body (not stored), with a
    read-only request to the system, the connector switched on or not. The same checks as a
    change apply."""
    connector = _connector(kind)
    try:
        state = await run_in_threadpool(connections.candidate, connector, body)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    settings = await run_in_threadpool(app_settings.effective_settings, get_settings())
    try:
        await run_in_threadpool(core.test_connection, settings, state)
    except TicketingError as exc:
        logger.info("%s connection test failed (%s)", kind, exc.code)
        return TicketingTestResult(ok=False, error=exc.code, message=str(exc))
    return TicketingTestResult(ok=True)


@router.get("/ticketing/targets")
async def ticket_targets(
    identity: SettingsManager, project: Annotated[ProjectName | None, Query()] = None
) -> list[TicketTarget]:
    """Destinations of the projects (of ``project`` only when given)."""
    found = await run_in_threadpool(core.list_targets, None if project is None else [project])
    return [TicketTarget.model_validate(item) for item in found]


@router.put("/projects/{project}/ticket-targets/{kind}")
async def set_ticket_target(
    project: ProjectPath, kind: KindPath, body: TicketTargetUpdate, identity: SettingsManager
) -> TicketTarget:
    """Set where the findings of a project go in a ticketing system, and its automatic
    sending (a threshold set now only applies to the reports saved from now)."""
    connector = _connector(kind)
    try:
        target = await run_in_threadpool(
            core.set_target,
            project,
            connector,
            body.destination,
            body.auto_min_severity,
            actor_of(identity),
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("%s destination of %s set by %s", kind, project, identity.client)
    return TicketTarget.model_validate(target)


@router.delete("/projects/{project}/ticket-targets/{kind}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ticket_target(
    project: ProjectPath, kind: KindPath, identity: SettingsManager
) -> Response:
    """Delete the destination of a project in a ticketing system (its tickets are kept)."""
    try:
        await run_in_threadpool(core.delete_target, project, kind, actor_of(identity))
    except services.NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info("%s destination of %s deleted by %s", kind, project, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/ticketing/destinations")
async def ticket_destinations(identity: CurrentIdentity) -> list[TicketDestination]:
    """Projects and systems the caller may send findings to now: connector switched on,
    connection configured, project with a destination and triaged by the caller."""
    scope = permission_scope(identity, Permission.FINDINGS_TRIAGE)
    if scope == []:
        return []
    settings = await run_in_threadpool(app_settings.effective_settings, get_settings())
    found = await run_in_threadpool(core.destinations, settings, scope)
    return [TicketDestination.model_validate(item) for item in found]


@router.post("/findings/{finding_id}/tickets/{kind}", status_code=status.HTTP_201_CREATED)
async def send_finding_ticket(
    finding_id: int, kind: KindPath, identity: Triager
) -> FindingTicketPublic:
    """Create the ticket of a finding in a ticketing system, at the destination of its project
    (the ticket of the same issue found earlier in the project is reused; a finding that
    already has its ticket returns it).

    409 when the connector is switched off, the connection or the destination of the project is
    missing, or the ticket is being created; 502 when the system refuses it or cannot be
    reached (``detail`` gives the reason).
    """
    await run_in_threadpool(
        services.check_finding_scope,
        permission_scope(identity, Permission.FINDINGS_TRIAGE),
        finding_id,
    )
    connector = _connector(kind)
    settings = await run_in_threadpool(app_settings.effective_settings, get_settings())
    try:
        ticket = await run_in_threadpool(
            core.send_finding, finding_id, connector, actor_of(identity), settings
        )
    except services.NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except TicketingError as exc:
        code = (
            status.HTTP_409_CONFLICT if exc.code in _CONFLICT_CODES else status.HTTP_502_BAD_GATEWAY
        )
        raise HTTPException(code, f"{exc.code}: {exc}") from exc
    logger.info("Finding %s sent to %s by %s", finding_id, kind, identity.client)
    return ticket
