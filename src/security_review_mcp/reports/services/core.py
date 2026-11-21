"""Shared helpers of the report services: errors, risk level, status filters and checks."""

import re
from collections.abc import Collection
from datetime import datetime, timedelta

from sqlalchemy import ColumnElement, and_, or_
from sqlmodel import col

from ...storage.models import (
    DISMISSED_STATUSES,
    MAX_AUTHOR_CHARS,
    SEVERITY_RANK,
    Finding,
    FindingStatus,
    Severity,
    utcnow,
)

# Characters of a developer username or email (Unicode letters and digits included): no
# Markdown or HTML syntax, as the author is copied as is into the Markdown export of a report
_AUTHOR_RE = re.compile(r"[\w .@+'’,-]+")


# Shortest reason of a triage decision or of a proposal (a word or two is not a reason)
MIN_STATUS_REASON_CHARS = 10


class NotFoundError(LookupError):
    """Raised when a report or a finding does not exist."""


def compute_risk_level(severities: list[Severity], override: Severity | None = None) -> Severity:
    """Return the overall risk: the highest finding severity (an override can only raise it)."""
    computed = max(severities, key=lambda s: SEVERITY_RANK[s], default=Severity.INFO)
    if override is not None and SEVERITY_RANK[override] > SEVERITY_RANK[computed]:
        return override
    return computed


def _expired_dismissal(now: datetime) -> ColumnElement[bool]:
    """SQL condition: an accepted or false-positive finding whose decision has expired."""
    return and_(
        col(Finding.status).in_(DISMISSED_STATUSES),
        col(Finding.status_expires_at).is_not(None),
        col(Finding.status_expires_at) <= now,
    )


# A decision (acceptance, false positive) that expires within this delay is "expiring soon": the
# gate, the accepted risks and the metrics warn before the finding blocks again
DISMISSAL_EXPIRY_WARNING = timedelta(days=14)


def _expiring_dismissal(now: datetime) -> ColumnElement[bool]:
    """SQL condition: an accepted or false-positive finding whose decision is still in force but
    expires within DISMISSAL_EXPIRY_WARNING."""
    return and_(
        col(Finding.status).in_(DISMISSED_STATUSES),
        col(Finding.status_expires_at).is_not(None),
        col(Finding.status_expires_at) > now,
        col(Finding.status_expires_at) <= now + DISMISSAL_EXPIRY_WARNING,
    )


def _status_is(status: FindingStatus, now: datetime | None = None) -> ColumnElement[bool]:
    """SQL condition on the effective status (an expired dismissal counts as ``open``)."""
    now = now or utcnow()
    if status == FindingStatus.OPEN:
        return or_(Finding.status == FindingStatus.OPEN, _expired_dismissal(now))
    if status in DISMISSED_STATUSES:
        return and_(Finding.status == status, ~_expired_dismissal(now))
    return Finding.status == status


def _values[T: str](value: T | Collection[T] | None) -> list[T]:
    """Values of a filter given as one value or several (None or empty: no filter)."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]  # type: ignore[list-item]
    return list(dict.fromkeys(value))


def _check_author(author: str | None) -> str | None:
    """Strip and bound the developer username of a report (None when empty).

    Raises:
        ValueError: Longer than MAX_AUTHOR_CHARS, or with characters other than letters,
            digits, spaces and . @ _ + - ' , (no control character nor Markdown or HTML
            syntax: the name is shown as is in the web interface and the Markdown export).
    """
    author = (author or "").strip()
    if not author:
        return None
    if len(author) > MAX_AUTHOR_CHARS:
        raise ValueError(f"author must contain at most {MAX_AUTHOR_CHARS} characters")
    if not author.isprintable() or not _AUTHOR_RE.fullmatch(author):
        raise ValueError(
            "author may only contain letters, digits, spaces and . @ _ + - ' , characters"
        )
    return author


def _current() -> ColumnElement[bool]:
    """SQL condition: a finding not replaced by a later occurrence of the same issue."""
    return col(Finding.superseded_by).is_(None)


def _check_current(finding: Finding) -> None:
    """Refuse to act on a finding replaced by a later occurrence of the same issue.

    Raises:
        ValueError: Naming the occurrence to act on.
    """
    if finding.superseded_by is not None:
        raise ValueError(
            f"Finding {finding.id} was reported again: act on finding {finding.superseded_by}"
        )


def _check_lengths(*fields: tuple[str, str | None, int]) -> None:
    """Refuse a field (name, value, limit) longer than its limit, before it is masked or stored.

    The table models do not validate their max_length: a longer value would be stored and
    break the reading of the report.

    Raises:
        ValueError: Naming the first field that is too long.
    """
    for name, value, limit in fields:
        if value is not None and len(value) > limit:
            raise ValueError(f"{name} too long ({len(value)} chars); the limit is {limit}")
