"""Shared fixtures: an isolated in-memory database (with the default rules) and a clean registry."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import SQLModel, StaticPool, create_engine

from security_review_mcp import models, registry, rule_store  # noqa: F401  (register the tables)
from security_review_mcp.database import set_engine
from security_review_mcp.models import DISMISSED_STATUSES, FindingPublic, FindingStatus
from security_review_mcp.services import update_finding_status


@pytest.fixture(autouse=True)
def database():
    """Provide a fresh in-memory SQLite database, seeded with the default rules, to each test."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    set_engine(engine)
    rule_store.seed_defaults()
    yield engine
    set_engine(None)
    engine.dispose()


@pytest.fixture(autouse=True)
def clean_registry():
    """Start every test with an unloaded registry and drop what it loaded."""
    registry.reset()
    yield
    registry.reset()


@pytest.fixture
def import_pack():
    """Return a function that imports a TOML rule pack into the test database and reloads."""

    def _import(text: str, name: str = "pack.toml", replace: bool = False) -> dict:
        stats = rule_store.import_packs([(name, text)], replace)
        registry.reload()
        return stats

    return _import


@pytest.fixture
def triage():
    """Return a function that records a triage decision as a person would (web interface).

    ``accepted`` and ``false_positive`` get a reason and an expiry date 30 days away.
    """

    def _triage(finding_id: int, status: str) -> FindingPublic:
        status = FindingStatus(status)
        if status in DISMISSED_STATUSES:
            expires_at = datetime.now(UTC) + timedelta(days=30)
            return update_finding_status(
                finding_id, status, "alice", "Reviewed by the security team", expires_at
            )
        return update_finding_status(finding_id, status, "alice")

    return _triage


@pytest.fixture
def anyio_backend():
    """Run every async test with asyncio only."""
    return "asyncio"
