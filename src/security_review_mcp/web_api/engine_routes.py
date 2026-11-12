"""Scan engines: the rules they read, and their list for the administrators.

``engine_router`` (``/api/v1/engine``): read by the enrolled scan engines with their OAuth access
token (``engine`` role, see auth.engine_clients), which reaches nothing else; no other
credential reaches these routes (see http_server.BearerAuthMiddleware.role_allowed). Each answer
carries an ``ETag``: an engine that already has the rules gets ``304``.

``engine_router`` also receives the heartbeat of each engine (its free OpenGrep slots, its
capacity and its counters), and the departure of an engine that stops (``DELETE /self``).

``router`` (``/api/v1/scan-engines``): the enrolled engines, listed and revoked by the holders of
``settings.manage`` (Scan engines page).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from ..auth import engine_clients
from ..config import get_settings, secret_value
from ..engines.protocol import manifest_digest, rule_digest
from ..rules import opengrep_rule_store, registry, rules_loader
from ..storage import controller_instances
from .deps import Permission, actor_of, engine_identity, require
from .schemas import (
    ControllerInstancePublic,
    EngineHeartbeat,
    EngineOpenGrepContents,
    EngineOpenGrepFetch,
    EngineOpenGrepManifest,
    EngineRuleSet,
    Identity,
    ScanEngineList,
    ScanEnginePublic,
)

engine_router = APIRouter(
    prefix="/api/v1/engine", tags=["scan-engines"], dependencies=[Depends(engine_identity)]
)
router = APIRouter(prefix="/scan-engines", tags=["scan-engines"])
EngineManager = Annotated[Identity, Depends(require(Permission.SETTINGS_MANAGE))]


def _conditional(request: Request, payload: dict, digest: str) -> Response:
    """The JSON answer with its ``ETag``, or ``304`` when the engine already has it."""
    etag = f'"{digest}"'
    headers = {"ETag": etag, "Cache-Control": "no-store"}
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    return JSONResponse(payload, headers=headers)


def _rule_set() -> dict:
    """The active internal rules, as in a TOML pack."""
    rules = [rules_loader.rule_entry(rule) for rule in registry.snapshot().rules]
    return EngineRuleSet.model_validate({"rules": rules}).model_dump(mode="json")


def _opengrep_manifest() -> dict:
    """The SHA-256 of each installed OpenGrep rule."""
    rules = {
        rule_id: rule_digest(content)
        for rule_id, content in opengrep_rule_store.installed_rules().items()
    }
    return EngineOpenGrepManifest(rules=rules).model_dump()


@engine_router.get("/rules", response_model=EngineRuleSet)
async def engine_rules(request: Request) -> Response:
    """The active internal rules (disabled rules left out); 304 when unchanged."""
    payload = await run_in_threadpool(_rule_set)
    return _conditional(request, payload, manifest_digest(payload["rules"]))


@engine_router.get("/opengrep-rules", response_model=EngineOpenGrepManifest)
async def engine_opengrep_manifest(request: Request) -> Response:
    """The SHA-256 of each installed OpenGrep rule; 304 when unchanged."""
    payload = await run_in_threadpool(_opengrep_manifest)
    return _conditional(request, payload, manifest_digest(payload["rules"]))


@engine_router.post("/opengrep-rules")
def engine_opengrep_contents(fetch: EngineOpenGrepFetch) -> EngineOpenGrepContents:
    """Content of the OpenGrep rules asked for; a rule deleted meanwhile is left out."""
    installed = opengrep_rule_store.installed_rules()
    return EngineOpenGrepContents(
        rules={rule_id: installed[rule_id] for rule_id in fetch.ids if rule_id in installed}
    )


@engine_router.post("/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
def engine_heartbeat(beat: EngineHeartbeat, request: Request) -> None:
    """Record that the engine is alive, with its free OpenGrep slots and its counters."""
    engine_id = (request.scope.get("state") or {}).get("auth_token_id") or ""
    try:
        engine_clients.heartbeat(engine_id, beat)
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or revoked scan engine") from exc


@engine_router.delete("/self", status_code=status.HTTP_204_NO_CONTENT)
def engine_leave(request: Request) -> None:
    """Forget the calling engine, which stops: it enrolls again at its next start (audited)."""
    engine_id = (request.scope.get("state") or {}).get("auth_token_id") or ""
    try:
        engine_clients.leave(engine_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or revoked scan engine") from exc


@router.get("")
def list_scan_engines(_identity: EngineManager) -> ScanEngineList:
    """The enrolled scan engines, the most recently seen first."""
    settings = get_settings()
    return ScanEngineList(
        enabled=secret_value(settings.scan_engine_token) is not None,
        fallback=settings.scan_engine_fallback,
        networks=settings.scan_engine_networks.split(","),
        access_token_minutes=settings.scan_engine_access_token_minutes,
        retention_days=settings.scan_engine_retention_days,
        controllers=[
            ControllerInstancePublic(**row) for row in controller_instances.active_instances()
        ],
        engines=[ScanEnginePublic(**row) for row in engine_clients.list_engines()],
    )


@router.delete("/{engine_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_scan_engine(engine_id: str, identity: EngineManager) -> None:
    """Revoke an enrolled engine: its access token stops working at once (audited)."""
    try:
        engine_clients.revoke_engine(engine_id, actor_of(identity))
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
