"""Shared fixtures: an isolated in-memory database and a clean rule registry per test."""

import pytest
from sqlmodel import SQLModel, StaticPool, create_engine

from security_review_mcp import models, registry, rule_store  # noqa: F401  (register the tables)
from security_review_mcp.database import set_engine


@pytest.fixture(autouse=True)
def database():
    """Provide a fresh in-memory SQLite database to each test."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    set_engine(engine)
    yield engine
    set_engine(None)
    engine.dispose()


@pytest.fixture(autouse=True)
def clean_registry():
    """Start every test without internal rules and drop what it loaded."""
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
def anyio_backend():
    """Run every async test with asyncio only."""
    return "asyncio"
