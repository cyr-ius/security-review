"""Database engine and session management."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

from .config import get_settings

logger = logging.getLogger(__name__)

_engine: Engine | None = None


def get_engine() -> Engine:
    """Create the engine lazily so that settings can be overridden in tests."""
    global _engine
    if _engine is None:
        settings = get_settings()
        connect_args = {}
        if settings.database_url.startswith("sqlite"):
            # The MCP server may serve requests from several threads
            connect_args["check_same_thread"] = False
        _engine = create_engine(
            settings.database_url,
            echo=settings.database_echo,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
    return _engine


def set_engine(engine: Engine | None) -> None:
    """Replace the global engine (used by tests)."""
    global _engine
    _engine = engine


def add_missing_columns(engine: Engine) -> list[str]:
    """Add columns introduced by newer versions to tables that already exist.

    ``create_all`` creates missing tables but never alters existing ones, so a database
    created by an older version would miss the new columns. Only nullable columns can be
    added safely; the list of ``table.column`` names that were added is returned.
    """
    inspector = inspect(engine)
    preparer = engine.dialect.identifier_preparer
    added: list[str] = []
    for table in SQLModel.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {column["name"] for column in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            if not column.nullable:
                raise RuntimeError(
                    f"Cannot add required column {table.name}.{column.name} automatically; "
                    "migrate the database manually."
                )
            ddl = (
                f"ALTER TABLE {preparer.quote(table.name)} "
                f"ADD COLUMN {preparer.quote(column.name)} {column.type.compile(engine.dialect)}"
            )
            with engine.begin() as connection:
                connection.execute(text(ddl))
            added.append(f"{table.name}.{column.name}")
    return added


def init_db() -> None:
    """Create the tables, upgrade older schemas and seed the default rules.

    On the first run the default rules and checklists (``default_rules.toml``) are copied into
    the database; later runs add the new defaults (see ``rule_store.seed_defaults``).
    """
    # Import here so that the table models are registered on the metadata
    # (and because rule_store depends on this module)
    from . import models, rule_store  # noqa: F401

    engine = get_engine()
    SQLModel.metadata.create_all(engine)
    for name in add_missing_columns(engine):
        logger.info("Schema upgraded: added column %s", name)
    written = rule_store.seed_defaults()
    if written:
        logger.info("Default rules seeded: %d rule(s) or checklist item(s) written", written)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Provide a transactional session: commit on success, rollback on error."""
    with Session(get_engine()) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
