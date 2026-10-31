"""REST API for administrator-managed OpenGrep YAML rules."""
import logging
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Response, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from ..rules import opengrep_rule_store
from .deps import RulesManager, RulesReader

logger = logging.getLogger("security_review_mcp.web")
router = APIRouter(prefix="/opengrep", tags=["opengrep"])

RuleId = Annotated[str, Path(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]+$")]


class RuleWrite(BaseModel):
    """One YAML rule file submitted by an administrator."""
    id: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]+$")
    content: str = Field(min_length=1, max_length=262144)


class RuleFile(BaseModel):
    """A stored YAML rule file."""
    id: str
    content: str
    updated_at: str


class RuleCatalog(BaseModel):
    """The YAML rules available to OpenGrep."""
    rules: list[RuleFile]


class RuleValidation(BaseModel):
    """Validation result from the OpenGrep CLI."""
    valid: bool
    message: str


def _error(exc: Exception) -> HTTPException:
    """Map storage and validation errors to safe HTTP responses."""
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, str(exc))
    if isinstance(exc, FileExistsError):
        return HTTPException(status.HTTP_409_CONFLICT, str(exc))
    if isinstance(exc, RuntimeError):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))


@router.get("/rules", response_model=RuleCatalog)
async def list_rules(identity: RulesReader) -> RuleCatalog:
    """List managed OpenGrep YAML rules."""
    rules = await run_in_threadpool(opengrep_rule_store.list_rules)
    return RuleCatalog(rules=[RuleFile.model_validate(rule) for rule in rules])


@router.get("/rules/{rule_id}", response_model=RuleFile)
async def get_rule(rule_id: RuleId, identity: RulesReader) -> RuleFile:
    """Read one managed OpenGrep YAML rule."""
    try:
        result = await run_in_threadpool(opengrep_rule_store.get_rule, rule_id)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        raise _error(exc) from exc
    return RuleFile.model_validate(result)


@router.post("/rules/validate", response_model=RuleValidation)
async def validate_rule(body: RuleWrite, identity: RulesManager) -> RuleValidation:
    """Validate a YAML rule using the OpenGrep CLI."""
    try:
        message = await run_in_threadpool(opengrep_rule_store.validate_rule, body.id, body.content)
    except (ValueError, RuntimeError) as exc:
        raise _error(exc) from exc
    return RuleValidation(valid=True, message=message)


@router.post("/rules", response_model=RuleFile, status_code=status.HTTP_201_CREATED)
async def create_rule(body: RuleWrite, identity: RulesManager) -> RuleFile:
    """Create a validated OpenGrep YAML rule."""
    try:
        result = await run_in_threadpool(
            opengrep_rule_store.save_rule, body.id, body.content, create=True
        )
    except (ValueError, FileExistsError, RuntimeError) as exc:
        raise _error(exc) from exc
    logger.info("OpenGrep rule %s created by %s", body.id, identity.client)
    return RuleFile.model_validate(result)


@router.put("/rules/{rule_id}", response_model=RuleFile)
async def update_rule(rule_id: RuleId, body: RuleWrite, identity: RulesManager) -> RuleFile:
    """Update one validated OpenGrep YAML rule without changing its id."""
    if body.id != rule_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "The rule id cannot be changed")
    try:
        result = await run_in_threadpool(
            opengrep_rule_store.save_rule, rule_id, body.content, create=False
        )
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        raise _error(exc) from exc
    logger.info("OpenGrep rule %s updated by %s", rule_id, identity.client)
    return RuleFile.model_validate(result)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: RuleId, identity: RulesManager) -> Response:
    """Delete one managed OpenGrep YAML rule."""
    try:
        await run_in_threadpool(opengrep_rule_store.delete_rule, rule_id)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        raise _error(exc) from exc
    logger.info("OpenGrep rule %s deleted by %s", rule_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
