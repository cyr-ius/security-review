"""Triage of the findings: status decisions, severity, agent proposals."""

import logging
from collections.abc import Collection
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlmodel import Session, col, select

from ...config import get_settings
from ...observability import audit
from ...rules.scanner import redact_secrets
from ...storage.database import session_scope
from ...storage.models import (
    DISMISSED_STATUSES,
    MAX_STATUS_REASON_CHARS,
    PROPOSABLE_STATUSES,
    SEVERITY_RANK,
    Finding,
    FindingComment,
    FindingPublic,
    FindingStatus,
    Severity,
    as_utc,
    effective_status,
    utcnow,
)
from .core import (
    MIN_STATUS_REASON_CHARS,
    NotFoundError,
    _check_current,
    _current,
    _expiring_dismissal,
    _status_is,
)

logger = logging.getLogger("security_review_mcp.services")


def _check_reason(reason: str | None, required: bool) -> str | None:
    """Strip, bound and mask a triage reason.

    Raises:
        ValueError: If a required reason is missing, too short or too long.
    """
    reason = (reason or "").strip()
    if not reason:
        if required:
            raise ValueError("A reason is required")
        return None
    if not MIN_STATUS_REASON_CHARS <= len(reason) <= MAX_STATUS_REASON_CHARS:
        raise ValueError(
            f"The reason must have {MIN_STATUS_REASON_CHARS} to {MAX_STATUS_REASON_CHARS} "
            "characters"
        )
    return redact_secrets(reason)


def _check_expiry(expires_at: datetime, now: datetime, longest: int) -> datetime:
    """Return the expiry date of a dismissal, in the future and at most ``longest`` days away.

    Raises:
        ValueError: If the date is past or too far.
    """
    if expires_at <= now:
        raise ValueError("The expiry date must be in the future")
    if expires_at > now + timedelta(days=longest):
        raise ValueError(f"The expiry date must be at most {longest} days away")
    return expires_at


def _check_fits_severity(severity: Severity | str, status: FindingStatus) -> None:
    """Check that ``status`` suits a finding of this severity.

    An ``info`` finding is an observation, not a risk: it is never ``accepted`` (it is
    ``acknowledged``, ``fixed`` or ``false_positive``, or its severity is raised first), and
    only an ``info`` finding is ``acknowledged``.

    Raises:
        ValueError: For ``accepted`` on an ``info`` finding, or ``acknowledged`` on a risk.
    """
    info = Severity(severity) == Severity.INFO
    if status == FindingStatus.ACCEPTED and info:
        raise ValueError(
            "An info finding is an observation, not a risk: it cannot be accepted. Mark it "
            "acknowledged, fixed or false_positive, or raise its severity first"
        )
    if status == FindingStatus.ACKNOWLEDGED and not info:
        raise ValueError(
            "Only an info finding (an observation) can be acknowledged: accept the risk, or "
            "mark it fixed or false_positive"
        )


def needs_formal_acceptance(severity: Severity | str) -> bool:
    """Whether accepting the risk of a finding of this severity needs a reason and an expiry.

    True from SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY up, and for every severity when it is
    empty; a less severe finding is accepted by a plain validation.
    """
    threshold = get_settings().risk_acceptance_min_severity
    return threshold is None or SEVERITY_RANK[Severity(severity)] >= SEVERITY_RANK[threshold]


def update_finding_status(
    finding_id: int,
    status: FindingStatus,
    approver: str,
    reason: str | None = None,
    expires_at: datetime | None = None,
    actor: str | None = None,
) -> FindingPublic:
    """Record a triage decision made by a person (web interface), never by an agent.

    ``accepted`` needs a reason; the reason of a ``false_positive`` is optional. Their expiry
    date, when given, is in the future and at most SECREVIEW_MAX_DISMISSAL_DAYS days away: once
    expired, the finding counts as open again. A false positive needs no expiry date; an
    acceptance needs one unless SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED is on.
    A finding less severe than SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY is accepted by a plain
    validation: its reason and its expiry date are optional.
    The reason of an acceptance is also its first comment (see ``add_finding_comment``).
    ``fixed`` takes an optional reason; ``open`` clears the decision. Any decision clears the
    status proposed by an agent. The decision is written to the audit log (``actor``, default
    the approver).

    Raises:
        NotFoundError: If the finding does not exist.
        ValueError: If the approver, the reason or the expiry date is missing or invalid.
    """
    approver = approver.strip()
    if not approver:
        raise ValueError("An approver is required")
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        _apply_status(session, finding, status, approver, reason, expires_at, actor, utcnow())
        session.flush()
        logger.info("Finding %s set to %s", finding_id, status)
        return FindingPublic.model_validate(finding, from_attributes=True)


# Findings of one bulk triage decision, independent of the page size (SECREVIEW_MAX_LIST_LIMIT):
# the web interface selects every loaded finding of a project
MAX_BULK_FINDINGS = 1000


def update_findings_status(
    finding_ids: Collection[int],
    status: FindingStatus,
    approver: str,
    reason: str | None = None,
    expires_at: datetime | None = None,
    actor: str | None = None,
    allowed: Collection[str] | None = None,
) -> list[FindingPublic]:
    """Record the same triage decision on several findings at once, all or nothing.

    Each finding is checked like by ``update_finding_status`` (an acceptance needs a reason and
    an expiry date when one of the findings is at or above
    SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY) and gets its own audit event. At most
    MAX_BULK_FINDINGS findings per call; repeated ids count once. A finding outside
    ``allowed`` (the projects of a restricted caller, None: every project) counts as missing.
    Nothing is saved when one finding is refused.

    Raises:
        NotFoundError: If a finding does not exist or is out of ``allowed``.
        ValueError: If there are no findings or too many, or a decision is invalid for one of
            them (the message names it).
    """
    approver = approver.strip()
    if not approver:
        raise ValueError("An approver is required")
    ids = list(dict.fromkeys(finding_ids))
    if not ids:
        raise ValueError("At least one finding is required")
    if len(ids) > MAX_BULK_FINDINGS:
        raise ValueError(f"At most {MAX_BULK_FINDINGS} findings can be triaged at once")
    now = utcnow()
    with session_scope() as session:
        rows = session.exec(select(Finding).where(col(Finding.id).in_(ids))).all()
        by_id = {row.id: row for row in rows}
        for finding_id in ids:
            finding = by_id.get(finding_id)
            if finding is None or (allowed is not None and finding.report.project not in allowed):
                raise NotFoundError(f"Finding {finding_id} not found")
            try:
                _apply_status(session, finding, status, approver, reason, expires_at, actor, now)
            except ValueError as exc:
                raise ValueError(f"Finding {finding_id}: {exc}") from exc
        session.flush()
        logger.info("%s findings set to %s", len(ids), status)
        return [FindingPublic.model_validate(by_id[i], from_attributes=True) for i in ids]


def _apply_status(
    session: Session,
    finding: Finding,
    status: FindingStatus,
    approver: str,
    reason: str | None,
    expires_at: datetime | None,
    actor: str | None,
    now: datetime,
) -> None:
    """Check and apply a triage decision to ``finding``, with its audit event (no commit).

    Raises:
        ValueError: If the reason or the expiry date is missing or invalid for this finding.
    """
    _check_current(finding)
    _check_fits_severity(finding.severity, status)
    if status in DISMISSED_STATUSES:
        settings = get_settings()
        plain = status == FindingStatus.ACCEPTED and not needs_formal_acceptance(finding.severity)
        # A false positive states a fact about the code: it needs no reason nor expiry date
        formal = status == FindingStatus.ACCEPTED and not plain
        reason = _check_reason(reason, required=formal)
        if expires_at is None:
            if formal and not settings.permanent_acceptance_enabled:
                raise ValueError(f"An expiry date is required for the status '{status.value}'")
        else:
            expires_at = _check_expiry(as_utc(expires_at), now, settings.max_dismissal_days)
    else:
        if expires_at is not None:
            raise ValueError(f"The status '{status.value}' takes no expiry date")
        reason = _check_reason(reason, required=False) if status != FindingStatus.OPEN else None
    previous = effective_status(finding.status, finding.status_expires_at, now)
    if previous != status:
        finding.status_changed_at = now
    # The reason of an acceptance opens its comments: a new one is added when the risk is
    # accepted or its reason changes, not when only the expiry date does
    if (
        status == FindingStatus.ACCEPTED
        and reason
        and (finding.status != status or finding.status_reason != reason)
    ):
        session.add(
            FindingComment(
                finding_id=finding.id, author=approver[:200], body=reason, created_at=now
            )
        )
    proposal = finding.proposed_status
    finding.status = status
    reopened = status == FindingStatus.OPEN
    finding.status_reason = reason
    finding.status_approver = None if reopened else approver[:200]
    finding.status_expires_at = expires_at
    finding.proposed_status = None
    finding.proposed_reason = None
    finding.proposed_by = None
    finding.proposed_at = None
    session.add(finding)
    audit.record(
        session,
        audit.AuditAction.FINDING_STATUS_CHANGED,
        actor or approver,
        "finding",
        finding.id,
        finding.report.project,
        {
            "previous_status": FindingStatus(previous).value,
            "status": status.value,
            "reason": reason,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "proposal": FindingStatus(proposal).value if proposal else None,
        },
    )


def update_finding_severity(
    finding_id: int,
    severity: Severity,
    analyst: str,
    reason: str,
    actor: str | None = None,
) -> FindingPublic:
    """Raise the severity of a finding, decided by a security analyst (web interface).

    The new severity must be above the one given by the report, or equal to it to undo an
    escalation: a finding is never made less severe than its report says (accepting a risk is
    the way to close it). The justification is required. An ``acknowledged`` observation
    becomes a risk: it is open again. The severity of the report is kept
    in ``original_severity`` and its risk level is raised with the finding. The change is
    written to the audit log (``actor``, default the analyst).

    Raises:
        NotFoundError: If the finding does not exist.
        ValueError: If the analyst or the justification is missing or invalid, or the
            severity is unchanged or below the one of the report.
    """
    analyst = analyst.strip()
    if not analyst:
        raise ValueError("An analyst is required")
    severity = Severity(severity)
    checked = _check_reason(reason, required=True)
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        _check_current(finding)
        previous = Severity(finding.severity)
        original = Severity(finding.original_severity or previous)
        if severity == previous:
            raise ValueError(f"The finding is already {severity.value}")
        if SEVERITY_RANK[severity] < SEVERITY_RANK[original]:
            raise ValueError(
                f"The severity cannot go below the one of the report ({original.value})"
            )
        now = utcnow()
        restored = severity == original
        finding.severity = severity
        finding.original_severity = None if restored else original
        finding.severity_reason = checked
        finding.severity_changed_by = analyst[:200]
        finding.severity_changed_at = now
        # An acknowledged observation raised to a risk is open again: seen is not accepted
        reopened = finding.status == FindingStatus.ACKNOWLEDGED
        if reopened:
            finding.status = FindingStatus.OPEN
            finding.status_changed_at = now
            finding.status_reason = None
            finding.status_approver = None
        report = finding.report
        if SEVERITY_RANK[severity] > SEVERITY_RANK[Severity(report.risk_level)]:
            report.risk_level = severity
            session.add(report)
        session.add(finding)
        audit.record(
            session,
            audit.AuditAction.FINDING_SEVERITY_CHANGED,
            actor or analyst,
            "finding",
            finding_id,
            report.project,
            {
                "previous_severity": previous.value,
                "severity": severity.value,
                "original_severity": original.value,
                "reason": checked,
                "reopened": reopened,
            },
        )
        session.flush()
        logger.info("Finding %s severity set to %s", finding_id, severity)
        return FindingPublic.model_validate(finding, from_attributes=True)


def propose_finding_status(
    finding_id: int,
    status: FindingStatus,
    reason: str,
    proposed_by: str,
    actor: str | None = None,
) -> FindingPublic:
    """Store the status an agent proposes for a finding, without applying it.

    The status, the gate and the posture do not change: a triager decides in the web
    interface. A new proposal replaces the previous one. It is written to the audit log
    (``actor``, default the token ``proposed_by``).

    Raises:
        NotFoundError: If the finding does not exist.
        ValueError: If the status cannot be proposed or the reason is missing or invalid.
    """
    if status not in PROPOSABLE_STATUSES:
        allowed = ", ".join(sorted(s.value for s in PROPOSABLE_STATUSES))
        raise ValueError(f"Only these statuses can be proposed: {allowed}")
    checked = _check_reason(reason, required=True)
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        _check_current(finding)
        _check_fits_severity(finding.severity, status)
        finding.proposed_status = status
        finding.proposed_reason = checked
        finding.proposed_by = (proposed_by.strip() or "unknown")[:200]
        finding.proposed_at = utcnow()
        session.add(finding)
        audit.record(
            session,
            audit.AuditAction.FINDING_STATUS_PROPOSED,
            actor or audit.token_actor(finding.proposed_by),
            "finding",
            finding_id,
            finding.report.project,
            {"status": status.value, "reason": checked},
        )
        session.flush()
        logger.info("Status %s proposed for finding %s", status, finding_id)
        return FindingPublic.model_validate(finding, from_attributes=True)


def clear_finding_proposal(finding_id: int, actor: str | None = None) -> FindingPublic:
    """Reject the status proposed by an agent for a finding (the status does not change).

    The rejection is written to the audit log when a proposal existed.

    Raises:
        NotFoundError: If the finding does not exist.
    """
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        if finding.proposed_status is not None:
            audit.record(
                session,
                audit.AuditAction.FINDING_PROPOSAL_REJECTED,
                actor,
                "finding",
                finding_id,
                finding.report.project,
                {
                    "status": FindingStatus(finding.proposed_status).value,
                    "proposed_by": finding.proposed_by,
                },
            )
        finding.proposed_status = None
        finding.proposed_reason = None
        finding.proposed_by = None
        finding.proposed_at = None
        session.add(finding)
        session.flush()
        logger.info("Proposal rejected for finding %s", finding_id)
        return FindingPublic.model_validate(finding, from_attributes=True)


def expiring_dismissal_count() -> int:
    """Count the decisions (acceptances, false positives) in force that expire within
    DISMISSAL_EXPIRY_WARNING, over every project."""
    with session_scope() as session:
        return session.exec(
            select(func.count())
            .select_from(Finding)
            .where(_expiring_dismissal(utcnow()), _current())
        ).one()


def finding_status_counts() -> dict[str, int]:
    """Count the findings by effective status (an expired dismissal counts as ``open``), plus
    ``proposed``: the findings with an agent proposal waiting for a person."""
    now = utcnow()
    with session_scope() as session:
        counts = {
            status.value: session.exec(
                select(func.count()).select_from(Finding).where(_status_is(status, now), _current())
            ).one()
            for status in FindingStatus
        }
        counts["proposed"] = session.exec(
            select(func.count())
            .select_from(Finding)
            .where(col(Finding.proposed_status).is_not(None), _current())
        ).one()
    return counts
