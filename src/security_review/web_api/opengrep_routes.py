"""REST API for administrator-managed OpenGrep YAML rules and the rules proposed by agents."""

import logging
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, Response, status
from fastapi.concurrency import run_in_threadpool

from ..rules import opengrep_proposals, opengrep_rule_store
from ..storage.models import RuleProposalStatus
from .deps import RulesManager, RulesReader, actor_of
from .schemas import (
    Identity,
    OpenGrepRuleApproval,
    OpenGrepRuleCatalog,
    OpenGrepRuleFile,
    OpenGrepRuleProposalList,
    OpenGrepRuleProposalPublic,
    OpenGrepRuleRejection,
    OpenGrepRuleValidation,
    OpenGrepRuleWrite,
)

logger = logging.getLogger("security_review.web")
router = APIRouter(prefix="/opengrep", tags=["opengrep"])
RuleId = Annotated[str, Path(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]+$")]


def _error(exc: Exception) -> HTTPException:
    """Map storage and validation errors to safe HTTP responses."""
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, str(exc))
    if isinstance(exc, FileExistsError):
        return HTTPException(status.HTTP_409_CONFLICT, str(exc))
    if isinstance(exc, RuntimeError):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))


@router.get("/rules", response_model=OpenGrepRuleCatalog)
async def list_rules(identity: RulesReader) -> OpenGrepRuleCatalog:
    """List managed OpenGrep YAML rules."""
    rules = await run_in_threadpool(opengrep_rule_store.list_rules)
    return OpenGrepRuleCatalog(rules=[OpenGrepRuleFile.model_validate(rule) for rule in rules])


@router.get("/rules/{rule_id}", response_model=OpenGrepRuleFile)
async def get_rule(rule_id: RuleId, identity: RulesReader) -> OpenGrepRuleFile:
    """Read one managed OpenGrep YAML rule."""
    try:
        result = await run_in_threadpool(opengrep_rule_store.get_rule, rule_id)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        raise _error(exc) from exc
    return OpenGrepRuleFile.model_validate(result)


@router.post("/rules/validate", response_model=OpenGrepRuleValidation)
async def validate_rule(body: OpenGrepRuleWrite, identity: RulesManager) -> OpenGrepRuleValidation:
    """Validate a YAML rule using the OpenGrep CLI."""
    try:
        message = await run_in_threadpool(opengrep_rule_store.validate_rule, body.id, body.content)
    except (ValueError, RuntimeError) as exc:
        raise _error(exc) from exc
    return OpenGrepRuleValidation(valid=True, message=message)


@router.post("/rules", response_model=OpenGrepRuleFile, status_code=status.HTTP_201_CREATED)
async def create_rule(body: OpenGrepRuleWrite, identity: RulesManager) -> OpenGrepRuleFile:
    """Create a validated OpenGrep YAML rule."""
    try:
        result = await run_in_threadpool(
            opengrep_rule_store.save_rule, body.id, body.content, create=True
        )
    except (ValueError, FileExistsError, RuntimeError) as exc:
        raise _error(exc) from exc
    logger.info("OpenGrep rule %s created by %s", body.id, identity.client)
    return OpenGrepRuleFile.model_validate(result)


@router.put("/rules/{rule_id}", response_model=OpenGrepRuleFile)
async def update_rule(
    rule_id: RuleId, body: OpenGrepRuleWrite, identity: RulesManager
) -> OpenGrepRuleFile:
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
    return OpenGrepRuleFile.model_validate(result)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: RuleId, identity: RulesManager) -> Response:
    """Delete one managed OpenGrep YAML rule."""
    try:
        await run_in_threadpool(opengrep_rule_store.delete_rule, rule_id)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        raise _error(exc) from exc
    logger.info("OpenGrep rule %s deleted by %s", rule_id, identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _person(identity: Identity) -> None:
    """Refuse a bearer token: only a person logged in to the web interface decides on a rule
    proposed by an agent (an agent may hold a token with rules.manage)."""
    if identity.auth_source is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only a person logged in to the web interface can decide on a proposed rule",
        )


@router.get("/proposals", response_model=OpenGrepRuleProposalList)
async def list_proposals(
    identity: RulesManager,
    proposal_status: Annotated[RuleProposalStatus | None, Query(alias="status")] = (
        RuleProposalStatus.PENDING
    ),
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> OpenGrepRuleProposalList:
    """List the OpenGrep rules proposed by agents (pending ones by default), newest first."""
    proposals = await run_in_threadpool(
        opengrep_proposals.list_proposals, proposal_status, limit, offset
    )
    total = await run_in_threadpool(opengrep_proposals.count_proposals, proposal_status)
    return OpenGrepRuleProposalList.model_validate({"proposals": proposals, "total": total})


@router.post("/proposals/{proposal_id}/approve", response_model=OpenGrepRuleProposalPublic)
async def approve_proposal(
    proposal_id: int, body: OpenGrepRuleApproval, identity: RulesManager
) -> OpenGrepRuleProposalPublic:
    """Validate a proposed rule with OpenGrep and install it (never over an existing rule)."""
    _person(identity)
    try:
        result = await run_in_threadpool(
            opengrep_proposals.approve_proposal,
            proposal_id,
            identity.client,
            actor_of(identity),
            body.content,
        )
    except (ValueError, FileExistsError, RuntimeError) as exc:
        raise _error(exc) from exc
    logger.info("OpenGrep rule proposal %s approved by %s", proposal_id, identity.client)
    return OpenGrepRuleProposalPublic.model_validate(result)


@router.post("/proposals/{proposal_id}/reject", response_model=OpenGrepRuleProposalPublic)
async def reject_proposal(
    proposal_id: int, body: OpenGrepRuleRejection, identity: RulesManager
) -> OpenGrepRuleProposalPublic:
    """Reject a proposed rule: it is not installed."""
    _person(identity)
    try:
        result = await run_in_threadpool(
            opengrep_proposals.reject_proposal,
            proposal_id,
            identity.client,
            actor_of(identity),
            body.reason,
        )
    except ValueError as exc:
        raise _error(exc) from exc
    logger.info("OpenGrep rule proposal %s rejected by %s", proposal_id, identity.client)
    return OpenGrepRuleProposalPublic.model_validate(result)
