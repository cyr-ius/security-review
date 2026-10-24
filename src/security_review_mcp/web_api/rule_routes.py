"""Routes of the scan rules, checklist items and development standards (administrators)."""

import logging
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Response, status
from fastapi import Path as APIPath
from fastapi.concurrency import run_in_threadpool

from .. import standards
from ..rules import registry, rule_store, rules_loader
from .deps import RulesManager, StandardsManager, unprocessable
from .schemas import (
    ChecklistCatalog,
    ChecklistItemWrite,
    ChecklistReload,
    PackUpload,
    RuleCatalog,
    RuleEnabledUpdate,
    RulePackImport,
    RuleReload,
    RuleWrite,
    Standard,
    StandardCatalog,
    StandardPackImport,
    StandardWrite,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["rules"])

RuleIdPath = Annotated[str, APIPath(min_length=3, max_length=50)]
DomainPath = Annotated[str, APIPath(min_length=1, max_length=31)]
ItemIdPath = Annotated[str, APIPath(min_length=3, max_length=rules_loader.MAX_ID_CHARS)]
SlugPath = Annotated[str, APIPath(min_length=1, max_length=50)]


def _rule_catalog() -> dict:
    """Return the rules stored in the database (default and custom) and the diagnostics."""
    return {
        "rules": rule_store.list_rules(),
        "load_errors": list(registry.snapshot().errors),
    }


async def _refresh_rules() -> RuleReload:
    """Reload the active registry and return its diagnostics."""
    snapshot = await run_in_threadpool(registry.reload)
    return RuleReload(loaded_rules=len(snapshot.custom_rule_ids), load_errors=list(snapshot.errors))


async def _refresh_checklists() -> ChecklistReload:
    """Reload the active registry and return checklist-specific diagnostics."""
    snapshot = await run_in_threadpool(registry.reload)
    count = sum(len(items) for items in snapshot.checklists.values())
    return ChecklistReload(loaded_checklist_items=count, load_errors=list(snapshot.errors))


# ── Scan rules ───────────────────────────────────────────────────────────────


@router.get("/rules")
async def list_custom_rules(identity: RulesManager) -> RuleCatalog:
    """List the rules stored in the database (default and custom)."""
    return await run_in_threadpool(_rule_catalog)


@router.post("/rules/reload")
async def reload_custom_rules(identity: RulesManager) -> RuleReload:
    """Reload the internal rules now (after a change made with the CLI)."""
    logger.info("Internal rules reloaded by %s", identity.client)
    return await _refresh_rules()


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_custom_rule(body: RuleWrite, identity: RulesManager) -> RuleReload:
    """Create a custom rule in the database."""
    try:
        await run_in_threadpool(rule_store.create_rule, body.model_dump(mode="json"))
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Rule %s created by %s", body.id, identity.client)
    return await _refresh_rules()


@router.put("/rules/{rule_id}")
async def update_custom_rule(
    rule_id: RuleIdPath, body: RuleWrite, identity: RulesManager
) -> RuleReload:
    """Update a stored rule (default or custom) while keeping its stable id."""
    try:
        await run_in_threadpool(rule_store.update_rule, rule_id, body.model_dump(mode="json"))
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Rule %s updated by %s", rule_id, identity.client)
    return await _refresh_rules()


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_custom_rule(rule_id: RuleIdPath, identity: RulesManager) -> Response:
    """Delete a custom rule from the database (default rules can only be disabled)."""
    try:
        await run_in_threadpool(rule_store.delete_entries, [rule_id], False)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    await _refresh_rules()
    logger.info("Rule %s deleted by %s", rule_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.patch("/rules/{rule_id}/enabled")
async def set_custom_rule_enabled(
    rule_id: RuleIdPath, body: RuleEnabledUpdate, identity: RulesManager
) -> RuleReload:
    """Enable or disable a default or custom rule."""
    try:
        await run_in_threadpool(rule_store.set_enabled, [rule_id], body.enabled)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Rule %s enabled=%s by %s", rule_id, body.enabled, identity.client)
    return await _refresh_rules()


# ── Checklist items ──────────────────────────────────────────────────────────


@router.get("/checklists")
async def list_checklist_items(identity: RulesManager) -> ChecklistCatalog:
    """List the checklist items stored in the database (default and custom)."""
    return ChecklistCatalog.model_validate(
        {
            "checklist_items": await run_in_threadpool(rule_store.list_checklist_items),
            "load_errors": list(registry.snapshot().errors),
        }
    )


@router.post("/checklists", status_code=status.HTTP_201_CREATED)
async def create_checklist_item(
    body: ChecklistItemWrite, identity: RulesManager
) -> ChecklistReload:
    """Create a custom checklist item."""
    try:
        await run_in_threadpool(rule_store.create_check_item, body.model_dump(mode="json"))
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Checklist item %s/%s created by %s", body.domain, body.id, identity.client)
    return await _refresh_checklists()


@router.put("/checklists/{domain}/{item_id}")
async def update_checklist_item(
    domain: DomainPath, item_id: ItemIdPath, body: ChecklistItemWrite, identity: RulesManager
) -> ChecklistReload:
    """Update a checklist item without changing its domain or id."""
    try:
        await run_in_threadpool(
            rule_store.update_check_item, domain, item_id, body.model_dump(mode="json")
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Checklist item %s/%s updated by %s", domain, item_id, identity.client)
    return await _refresh_checklists()


@router.delete("/checklists/{domain}/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_checklist_item(
    domain: DomainPath, item_id: ItemIdPath, identity: RulesManager
) -> Response:
    """Delete one custom checklist item."""
    try:
        await run_in_threadpool(rule_store.delete_check_item, domain, item_id)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    await _refresh_checklists()
    logger.info("Checklist item %s/%s deleted by %s", domain, item_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Development standards ────────────────────────────────────────────────────


@router.get("/standards", tags=["standards"])
async def list_standards(identity: StandardsManager) -> StandardCatalog:
    """List the development standards (without content), disabled ones included.

    Administrators only, like the rules and checklists; the MCP tools serve the enabled
    standards to the assistants.
    """
    listed = await run_in_threadpool(standards.list_standards, True)
    return StandardCatalog.model_validate({"standards": listed})


@router.get("/standards/{slug}", tags=["standards"])
async def get_standard(slug: SlugPath, identity: StandardsManager) -> Standard:
    """Return one development standard with its content (administrators only)."""
    return await run_in_threadpool(standards.get_standard, slug, True)


@router.post("/standards", status_code=status.HTTP_201_CREATED, tags=["standards"])
async def create_standard(body: StandardWrite, identity: StandardsManager) -> Standard:
    """Create a development standard."""
    try:
        created = await run_in_threadpool(
            standards.create_standard, body.model_dump(), identity.client
        )
    except ValueError as exc:
        if "already exists" in str(exc):
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        raise unprocessable(exc) from exc
    logger.info("Development standard %s created by %s", created["slug"], identity.client)
    return created


@router.put("/standards/{slug}", tags=["standards"])
async def update_standard(
    slug: SlugPath, body: StandardWrite, identity: StandardsManager
) -> Standard:
    """Replace a development standard without changing its slug."""
    try:
        updated = await run_in_threadpool(
            standards.update_standard, slug, body.model_dump(), identity.client
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info("Development standard %s updated by %s", updated["slug"], identity.client)
    return updated


@router.delete("/standards/{slug}", status_code=status.HTTP_204_NO_CONTENT, tags=["standards"])
async def delete_standard(slug: SlugPath, identity: StandardsManager) -> Response:
    """Delete a development standard."""
    await run_in_threadpool(standards.delete_standard, slug)
    logger.info("Development standard %s deleted by %s", slug, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── TOML packs ───────────────────────────────────────────────────────────────

# Answer of the exports: a TOML file to save, not a JSON document
TOML_FILE = {200: {"content": {"application/toml": {}}, "description": "TOML pack"}}


def _toml_download(text: str, filename: str) -> Response:
    """Return a TOML pack as a file to save."""
    return Response(
        text,
        media_type="application/toml; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/packs/rules", response_class=Response, responses=TOML_FILE, tags=["packs"])
async def export_rule_pack(
    identity: RulesManager,
    sections: Annotated[list[Literal["rules", "checklist"]] | None, Query(max_length=2)] = None,
) -> Response:
    """Export the rules and checklist items that differ from the defaults as a TOML pack.

    ``sections`` limits the pack to the rules (with the disabled rule ids) or the checklist.
    """
    selected = frozenset(sections or rule_store.PACK_SECTIONS)
    text = await run_in_threadpool(rule_store.export_pack, selected)
    logger.info("Rule pack (%s) exported by %s", ", ".join(sorted(selected)), identity.client)
    name = "checklists" if selected == {"checklist"} else "rules"
    return _toml_download(text, f"security-review-{name}.toml")


@router.post("/packs/rules", tags=["packs"])
async def import_rule_pack(body: PackUpload, identity: RulesManager) -> RulePackImport:
    """Import a TOML rule pack (rules, checklist items, disabled ids), all or nothing.

    Entries are added or replaced by id; the other stored entries are kept.
    """
    try:
        result = await run_in_threadpool(
            rule_store.import_packs, [(body.name, body.content)], False
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info(
        "Rule pack imported by %s: %d rule(s), %d checklist item(s), %d disabled id(s)",
        identity.client,
        result["rules"],
        result["checklist_items"],
        result["disabled_rules"],
    )
    snapshot = await run_in_threadpool(registry.reload)
    return RulePackImport.model_validate(
        result
        | {
            "loaded_rules": len(snapshot.custom_rule_ids),
            "loaded_checklist_items": sum(len(items) for items in snapshot.checklists.values()),
            "load_errors": list(snapshot.errors),
        }
    )


@router.get("/packs/standards", response_class=Response, responses=TOML_FILE, tags=["packs"])
async def export_standard_pack(identity: StandardsManager) -> Response:
    """Export every development standard (disabled ones included) as a TOML pack."""
    text = await run_in_threadpool(standards.export_pack)
    logger.info("Development standards exported by %s", identity.client)
    return _toml_download(text, "security-review-standards.toml")


@router.post("/packs/standards", tags=["packs"])
async def import_standard_pack(body: PackUpload, identity: StandardsManager) -> StandardPackImport:
    """Import a TOML pack of development standards, all or nothing (created or replaced by
    slug; the other standards are kept)."""
    try:
        result = await run_in_threadpool(
            standards.import_pack, body.content, body.name, identity.client
        )
    except ValueError as exc:
        raise unprocessable(exc) from exc
    logger.info(
        "Development standards imported by %s: %d created, %d updated",
        identity.client,
        len(result["created"]),
        len(result["updated"]),
    )
    return result
