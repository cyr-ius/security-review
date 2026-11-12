"""OpenGrep rules proposed by agents during a review, approved or rejected by a person.

An agent never installs a rule: ``propose_rule`` (MCP tool propose_opengrep_rule) stores the
YAML rule in the database shared by both processes. A person logged in to the web interface
then approves it, which validates it with OpenGrep and creates the rule file (only the
controller writes the rules directory, see opengrep_rule_store), or rejects it. An approval
never replaces an installed rule.
"""

import logging
from typing import Any

from sqlmodel import col, func, select

from ..config import get_settings
from ..observability import audit
from ..reports.services import MIN_STATUS_REASON_CHARS, NotFoundError
from ..storage.database import session_scope
from ..storage.models import (
    MAX_STATUS_REASON_CHARS,
    OpenGrepRuleProposal,
    RuleProposalStatus,
    as_utc,
    utcnow,
)
from ..storage.project_names import normalize_project
from . import opengrep_rule_store
from .scanner import redact_secrets, reveal_hidden_characters

logger = logging.getLogger(__name__)

# Prefix of the default rules shipped with the package: an agent may not propose one
RESERVED_PREFIX = "secreview."
_TARGET = "opengrep_rule"


def _public(row: OpenGrepRuleProposal) -> dict[str, Any]:
    """A proposal as returned by the MCP tool, the REST API and the web interface."""
    return {
        "id": row.id,
        "rule_id": row.rule_id,
        "content": row.content,
        "reason": row.reason,
        "test_code": row.test_code,
        "project": row.project,
        "status": RuleProposalStatus(row.status).value,
        "proposed_by": row.proposed_by,
        "proposed_at": as_utc(row.proposed_at).isoformat(),
        "decided_by": row.decided_by,
        "decided_at": as_utc(row.decided_at).isoformat() if row.decided_at else None,
        "decision_reason": row.decision_reason,
    }


def _check_text(value: str | None, name: str, minimum: int, maximum: int) -> str | None:
    """Strip, bound and mask a free text (None or blank stays None when ``minimum`` is 0)."""
    value = (value or "").strip()
    if not value and minimum == 0:
        return None
    if not minimum <= len(value) <= maximum:
        raise ValueError(f"The {name} must have {max(minimum, 1)} to {maximum} characters")
    return redact_secrets(value)


def _check_rule(rule_id: str, content: str) -> None:
    """Refuse a rule an agent may not propose: invalid id, reserved prefix, several rules, a
    secret or hidden characters (the rule is shown to a person, then run by OpenGrep).

    Raises:
        ValueError: With the reason of the refusal.
    """
    if not opengrep_rule_store.RULE_ID.fullmatch(rule_id):
        raise ValueError("Use a rule id of 3 to 80 letters, digits, dots, underscores or hyphens")
    if rule_id.startswith(RESERVED_PREFIX):
        raise ValueError(f"Rule ids starting with '{RESERVED_PREFIX}' are reserved")
    opengrep_rule_store.check_rule_file(rule_id, content)
    if redact_secrets(content) != content:
        raise ValueError("The rule looks like it holds a secret: remove it")
    if reveal_hidden_characters(content) != content:
        raise ValueError("The rule holds invisible characters: remove them")


def _check_duplicate(session: Any, project: str, rule_id: str, content: str) -> None:
    """Refuse a rule already installed, or that detects the same code as an installed or
    default rule or as another pending proposal (see opengrep_rule_store.detection_signature).
    A proposal of another project is not named.

    Raises:
        ValueError: Naming the rule or the proposal it duplicates.
    """
    signature = opengrep_rule_store.detection_signature(content)
    for known_id, known in opengrep_rule_store.known_rules().items():
        if known_id == rule_id:
            raise ValueError(f"The OpenGrep rule '{rule_id}' is already installed")
        if opengrep_rule_store.detection_signature(known) == signature:
            raise ValueError(f"This rule detects the same code as the OpenGrep rule '{known_id}'")
    pending = session.exec(
        select(OpenGrepRuleProposal).where(
            OpenGrepRuleProposal.status == RuleProposalStatus.PENDING,
            OpenGrepRuleProposal.rule_id != rule_id,
        )
    ).all()
    for row in pending:
        if opengrep_rule_store.detection_signature(row.content) != signature:
            continue
        if row.project != project:  # never named to a token that may not reach its project
            raise ValueError("This rule detects the same code as another pending proposal")
        raise ValueError(
            f"This rule detects the same code as the pending proposal {row.id} "
            f"('{row.rule_id}'): propose it again with that id to replace it"
        )


def propose_rule(
    project: str,
    rule_id: str,
    content: str,
    reason: str,
    test_code: str | None,
    proposed_by: str,
    actor: str | None = None,
) -> dict[str, Any]:
    """Store an OpenGrep rule proposed by an agent, without installing it.

    A proposal with the id of a pending one of the same project replaces it. It is written to
    the audit log (``actor``, default the token ``proposed_by``).

    Raises:
        ValueError: If the rule, the reason or the test code is invalid, if the rule duplicates
            an installed rule or another pending proposal, if a pending proposal of another
            project has the same id, or if too many proposals are
            pending (SECREVIEW_OPENGREP_MAX_PENDING_PROPOSALS).
    """
    settings = get_settings()
    project = normalize_project(project)
    _check_rule(rule_id, content)
    checked_reason = _check_text(reason, "reason", MIN_STATUS_REASON_CHARS, MAX_STATUS_REASON_CHARS)
    checked_test = _check_text(test_code, "test code", 0, settings.max_content_chars)
    proposed_by = (proposed_by.strip() or "unknown")[:200]
    with session_scope() as session:
        _check_duplicate(session, project, rule_id, content)
        row = session.exec(
            select(OpenGrepRuleProposal).where(
                OpenGrepRuleProposal.rule_id == rule_id,
                OpenGrepRuleProposal.status == RuleProposalStatus.PENDING,
            )
        ).first()
        replaced = row is not None
        if row is not None and row.project != project:
            # Only the project of a pending proposal replaces it, never named to the others
            raise ValueError("A pending proposal already has this id: choose another id")
        if row is None:
            pending = session.exec(
                select(func.count())
                .select_from(OpenGrepRuleProposal)
                .where(OpenGrepRuleProposal.status == RuleProposalStatus.PENDING)
            ).one()
            if pending >= settings.opengrep_max_pending_proposals:
                raise ValueError(
                    "Too many OpenGrep rule proposals are waiting for a decision; retry later"
                )
            row = OpenGrepRuleProposal(rule_id=rule_id, content=content, reason="", project="")
        row.content = content
        row.reason = checked_reason or ""
        row.test_code = checked_test
        row.project = project
        row.proposed_by = proposed_by
        row.proposed_at = utcnow()
        session.add(row)
        session.flush()
        audit.record(
            session,
            audit.AuditAction.OPENGREP_RULE_PROPOSED,
            actor or audit.token_actor(proposed_by),
            _TARGET,
            rule_id,
            project,
            {"proposal_id": row.id, "replaced": replaced},
        )
        logger.info("OpenGrep rule %s proposed for project %s", rule_id, project)
        return _public(row)


def list_proposals(
    status: RuleProposalStatus | None = RuleProposalStatus.PENDING,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Proposals, newest first, optionally of one status."""
    limit = max(1, min(limit, get_settings().max_list_limit))
    query = select(OpenGrepRuleProposal)
    if status is not None:
        query = query.where(OpenGrepRuleProposal.status == status)
    query = query.order_by(
        col(OpenGrepRuleProposal.proposed_at).desc(), col(OpenGrepRuleProposal.id).desc()
    )
    with session_scope() as session:
        rows = session.exec(query.offset(max(0, offset)).limit(limit)).all()
        return [_public(row) for row in rows]


def count_proposals(status: RuleProposalStatus | None = RuleProposalStatus.PENDING) -> int:
    """Number of proposals, optionally of one status (the badge of the sidebar)."""
    query = select(func.count()).select_from(OpenGrepRuleProposal)
    if status is not None:
        query = query.where(OpenGrepRuleProposal.status == status)
    with session_scope() as session:
        return session.exec(query).one()


def _pending(session: Any, proposal_id: int) -> OpenGrepRuleProposal:
    """The pending proposal ``proposal_id``.

    Raises:
        NotFoundError: If it does not exist.
        ValueError: If it was already approved or rejected.
    """
    row = session.get(OpenGrepRuleProposal, proposal_id)
    if row is None:
        raise NotFoundError(f"OpenGrep rule proposal {proposal_id} not found")
    if row.status != RuleProposalStatus.PENDING:
        raise ValueError(f"OpenGrep rule proposal {proposal_id} was already decided")
    return row


def approve_proposal(
    proposal_id: int, decided_by: str, actor: str, content: str | None = None
) -> dict[str, Any]:
    """Approve a proposal: validate the rule with OpenGrep and create its file.

    ``content`` replaces the proposed YAML (a rule corrected by the approver); the rule id
    does not change. Nothing is recorded when the file cannot be created.

    Raises:
        NotFoundError: If the proposal does not exist.
        ValueError: If it was already decided or OpenGrep rejects the rule.
        FileExistsError: If a rule with this id is already installed.
        RuntimeError: If OpenGrep is unavailable.
    """
    with session_scope() as session:
        row = _pending(session, proposal_id)
        final = row.content if content is None else content
        opengrep_rule_store.save_rule(row.rule_id, final, create=True)
        edited = final != row.content
        row.content = final
        row.status = RuleProposalStatus.APPROVED
        row.decided_by = decided_by[:200]
        row.decided_at = utcnow()
        session.add(row)
        audit.record(
            session,
            audit.AuditAction.OPENGREP_RULE_APPROVED,
            actor,
            _TARGET,
            row.rule_id,
            row.project,
            {"proposal_id": row.id, "edited": edited, "proposed_by": row.proposed_by},
        )
        logger.info("OpenGrep rule proposal %s approved", proposal_id)
        return _public(row)


def reject_proposal(
    proposal_id: int, decided_by: str, actor: str, reason: str | None = None
) -> dict[str, Any]:
    """Reject a proposal: the rule is not installed; the reason is optional.

    Raises:
        NotFoundError: If the proposal does not exist.
        ValueError: If it was already decided or the reason is too long.
    """
    checked = _check_text(reason, "reason", 0, MAX_STATUS_REASON_CHARS)
    with session_scope() as session:
        row = _pending(session, proposal_id)
        row.status = RuleProposalStatus.REJECTED
        row.decided_by = decided_by[:200]
        row.decided_at = utcnow()
        row.decision_reason = checked
        session.add(row)
        audit.record(
            session,
            audit.AuditAction.OPENGREP_RULE_REJECTED,
            actor,
            _TARGET,
            row.rule_id,
            row.project,
            {"proposal_id": row.id, "proposed_by": row.proposed_by},
        )
        logger.info("OpenGrep rule proposal %s rejected", proposal_id)
        return _public(row)
