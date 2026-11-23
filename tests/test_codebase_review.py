"""Review of the whole repository asked of the MCP agent (reports.codebase_review)."""

from datetime import datetime, timedelta

import pytest
from sqlmodel import select

from security_review.auth import access_control
from security_review.observability import audit
from security_review.reports import codebase_review, services
from security_review.storage.database import session_scope
from security_review.storage.models import Project, ReviewType
from security_review.storage.projects import ensure_project

GROUP = "0123456789abcdef0123456789abcdef"


def _state(project: str) -> dict:
    with session_scope() as session:
        return codebase_review.project_state(session, project)


def _save(project: str, review_type: ReviewType, group: str, from_scan: bool = False) -> None:
    services.save_report(
        project,
        "Review of the repository",
        [],
        review_type=review_type,
        review_group=group,
        from_scan=from_scan,
    )


def test_only_a_codebase_review_linked_to_a_code_scan_meets_a_request():
    """A request stays due until a codebase-review report of a review group with a code scan
    is saved after it: a report alone, without a new scan of the Controller server, never meets
    it. The change is audited once, a repeated one is not."""
    with session_scope() as session:
        ensure_project(session, "shop-api")
    assert _state("shop-api")["due"] is False

    access_control.set_codebase_review("shop-api", True, None, "user:alice")
    access_control.set_codebase_review("shop-api", True, None, "user:alice")
    assert len(audit.list_events(action="project.codebase_review_changed")["events"]) == 1
    assert _state("shop-api")["reasons"] == ["requested"]

    # A report that only claims to be a codebase review leaves the request pending
    _save("shop-api", ReviewType.CODEBASE_REVIEW, GROUP)
    assert _state("shop-api")["due"] is True

    _save("shop-api", ReviewType.CODE_SCAN, GROUP, from_scan=True)
    _save("shop-api", ReviewType.CODEBASE_REVIEW, GROUP)
    state = _state("shop-api")
    assert state["due"] is False and state["requested"] is False
    assert state["last_review_at"] is not None

    # A new request is not met by a report that reuses the review group of the older review
    access_control.set_codebase_review("shop-api", True, None, "user:alice")
    _save("shop-api", ReviewType.CODEBASE_REVIEW, GROUP)
    assert _state("shop-api")["reasons"] == ["requested"]


def test_the_periodic_review_falls_due_after_the_interval():
    """Without any codebase review, a periodic review is due at once; after one, it falls due
    when the interval has passed."""
    with session_scope() as session:
        ensure_project(session, "billing")
    access_control.set_codebase_review("billing", False, 30, "user:alice")
    assert _state("billing")["reasons"] == ["interval"]

    _save("billing", ReviewType.CODE_SCAN, GROUP, from_scan=True)
    _save("billing", ReviewType.CODEBASE_REVIEW, GROUP)
    state = _state("billing")
    assert state["due"] is False
    last = datetime.fromisoformat(state["last_review_at"])
    assert datetime.fromisoformat(state["next_due_at"]) == last + timedelta(days=30)
    with session_scope() as session:
        row = session.exec(select(Project).where(Project.name == "billing")).one()
        later = codebase_review.review_state(row, last, now=last + timedelta(days=31))
    assert later["reasons"] == ["interval"]

    with pytest.raises(ValueError, match="interval_days"):
        access_control.set_codebase_review("billing", False, 0, "user:alice")
