"""Shared fixtures: an isolated in-memory database and a clean rule registry per test."""

import pytest
from sqlmodel import SQLModel, StaticPool, create_engine

from security_review_mcp import models, registry  # noqa: F401  (register the tables)
from security_review_mcp.config import get_settings
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
def clean_registry(monkeypatch):
    """Start every test without internal rule packs and drop what it loaded."""
    monkeypatch.setattr(get_settings(), "rules_dir", None)
    registry.reset()
    yield
    registry.reset()


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    """Point the server at an empty temporary rules directory."""
    monkeypatch.setattr(get_settings(), "rules_dir", str(tmp_path))
    registry.reset()
    return tmp_path


@pytest.fixture
def anyio_backend():
    """Run every async test with asyncio only."""
    return "asyncio"
