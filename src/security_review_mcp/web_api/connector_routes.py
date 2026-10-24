"""Routes of the connectors: connections, destinations of the projects and sending of a
finding (see connectors). A system is named by the ``kind`` of its connector (``jira``,
``servicenow`` or a third-party one): an unknown kind answers 404."""

import logging
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, Response, status
from fastapi.concurrency import run_in_threadpool

from .. import app_settings
from ..config import get_settings
from ..connectors import ConnectorError, connections, core, registry
from ..connectors.api import Connector
from ..reports import services
from ..storage.models import FindingExportPublic
from ..storage.project_names import ProjectName
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
    ConnectorDestination,
    ConnectorSettings,
    ConnectorSwitch,
    ConnectorSystem,
    ConnectorTarget,
    ConnectorTargetUpdate,
    ConnectorTestResult,
    ConnectorValues,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["connectors"])

ProjectPath = Annotated[ProjectName, Path()]
KindPath = Annotated[str, Path(pattern=r"^[a-z][a-z0-9_]{1,19}$")]
# Refused before any request: the configuration, not the remote system, is at fault
_CONFLICT_CODES = frozenset(
    {"disabled", "not_configured", "no_target", "in_progress", "superseded"}
)


def _connector(kind: str) -> Connector:
    """The connector of ``kind`` (404 when unknown)."""
    try:
        return registry.get(kind)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


def _describe() -> dict:
    """Connector settings and every connection."""
    settings = get_settings()
    return {
        "enabled": settings.connectors_enabled,
        "interval_seconds": settings.connectors_interval_seconds,
        "cafile": settings.connectors_cafile,
        "plugins": registry.plugin_names(settings.connectors_plugins),
        "connectors": [
            connections.describe(connector, registry.is_builtin(connector), settings)
            for connector in registry.connectors(settings).values()
        ],
    }


@router.get("/connectors")
async def connector_systems(identity: CurrentIdentity) -> list[ConnectorSystem]:
    """Available connectors (kind and name), to label the exports of the findings."""
    found = await run_in_threadpool(registry.connectors)
    return [ConnectorSystem(kind=kind, name=connector.name) for kind, connector in found.items()]


@router.get("/settings/connectors")
async def get_connectors(identity: SettingsManager) -> ConnectorSettings:
    """Return the connections of the connectors (secrets replaced by ``***``)."""
    return await run_in_threadpool(_describe)


@router.put("/settings/connectors/{kind}")
async def set_connector(
    kind: KindPath, body: Annotated[ConnectorValues, Body()], identity: SettingsManager
) -> ConnectorSettings:
    """Set fields of a connection (applied to the next export). A field left out is unchanged,
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


@router.put("/settings/connectors/{kind}/enabled")
async def switch_connector(
    kind: KindPath, body: ConnectorSwitch, identity: SettingsManager
) -> ConnectorSettings:
    """Switch a connector on or off: nothing is sent through a connector switched off. Refused
    (422) when SECREVIEW_CONNECTORS_ENABLED is false, or to switch on a connection that is not
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


@router.post("/settings/connectors/{kind}/test")
async def test_connector(
    kind: KindPath, body: Annotated[ConnectorValues, Body()], identity: SettingsManager
) -> ConnectorTestResult:
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
    except ConnectorError as exc:
        logger.info("%s connection test failed (%s)", kind, exc.code)
        return ConnectorTestResult(ok=False, error=exc.code, message=str(exc))
    return ConnectorTestResult(ok=True)


@router.get("/connectors/targets")
async def connector_targets(
    identity: SettingsManager, project: Annotated[ProjectName | None, Query()] = None
) -> list[ConnectorTarget]:
    """Destinations of the projects (of ``project`` only when given)."""
    found = await run_in_threadpool(core.list_targets, None if project is None else [project])
    return [ConnectorTarget.model_validate(item) for item in found]


@router.put("/projects/{project}/connector-targets/{kind}")
async def set_connector_target(
    project: ProjectPath, kind: KindPath, body: ConnectorTargetUpdate, identity: SettingsManager
) -> ConnectorTarget:
    """Set where the findings of a project go through a connector, and its automatic
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
    return ConnectorTarget.model_validate(target)


@router.delete(
    "/projects/{project}/connector-targets/{kind}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_connector_target(
    project: ProjectPath, kind: KindPath, identity: SettingsManager
) -> Response:
    """Delete the destination of a project for a connector (its exports are kept)."""
    try:
        await run_in_threadpool(core.delete_target, project, kind, actor_of(identity))
    except services.NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    logger.info("%s destination of %s deleted by %s", kind, project, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/connectors/destinations")
async def connector_destinations(identity: CurrentIdentity) -> list[ConnectorDestination]:
    """Projects and systems the caller may send findings to now: connector switched on,
    connection configured, project with a destination and triaged by the caller."""
    scope = permission_scope(identity, Permission.FINDINGS_TRIAGE)
    if scope == []:
        return []
    settings = await run_in_threadpool(app_settings.effective_settings, get_settings())
    found = await run_in_threadpool(core.destinations, settings, scope)
    return [ConnectorDestination.model_validate(item) for item in found]


@router.post("/findings/{finding_id}/exports/{kind}", status_code=status.HTTP_201_CREATED)
async def export_finding(finding_id: int, kind: KindPath, identity: Triager) -> FindingExportPublic:
    """Create the record of a finding in an external system through a connector, at the
    destination of its project (the record of the same issue found earlier in the project is
    reused; a finding already exported returns its record).

    409 when the connector is switched off, the connection or the destination of the project is
    missing, or the finding is being exported; 502 when the system refuses it or cannot be
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
        export = await run_in_threadpool(
            core.send_finding, finding_id, connector, actor_of(identity), settings
        )
    except services.NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ConnectorError as exc:
        code = (
            status.HTTP_409_CONFLICT if exc.code in _CONFLICT_CODES else status.HTTP_502_BAD_GATEWAY
        )
        raise HTTPException(code, f"{exc.code}: {exc}") from exc
    logger.info("Finding %s sent to %s by %s", finding_id, kind, identity.client)
    return export
