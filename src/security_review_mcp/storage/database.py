"""Database engine, session management and schema migrations (Alembic)."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Connection, Engine, make_url
from sqlmodel import Session, create_engine

from ..config import get_settings

logger = logging.getLogger("security_review_mcp.database")

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
# Default database of version 1.0, relative to the working directory
LEGACY_DATABASE = Path("security_reports.db")

_engine: Engine | None = None


def get_engine() -> Engine:
    """Create the engine lazily so that settings can be overridden in tests."""
    global _engine
    if _engine is None:
        settings = get_settings()
        url = make_url(settings.database_url.get_secret_value())
        connect_args = {}
        if url.get_backend_name() == "sqlite":
            # The MCP server may serve requests from several threads
            connect_args["check_same_thread"] = False
            if url.database and url.database != ":memory:":
                # SQLite creates the file but not its directory, kept private: the reports
                # quote the reviewed code
                Path(url.database).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if "database_url" not in settings.model_fields_set and LEGACY_DATABASE.is_file():
            logger.warning(
                "%s is no longer the default database: set "
                "SECREVIEW_DATABASE_URL=sqlite:///%s to keep using it",
                LEGACY_DATABASE.resolve(),
                LEGACY_DATABASE.resolve(),
            )
        _engine = create_engine(
            url,
            echo=settings.database_echo,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
    return _engine


def set_engine(engine: Engine | None) -> None:
    """Replace the global engine (used by tests)."""
    global _engine
    _engine = engine


class SchemaError(RuntimeError):
    """The database schema is missing or older than this version expects."""


def alembic_config(connection: Connection | None = None) -> Config:
    """Alembic configuration built in code (the package ships no alembic.ini).

    ``connection`` is the connection the migrations run on (see migrations/env.py).
    """
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.attributes["connection"] = connection
    return config


def head_revision() -> str:
    """Revision of the schema this version of the package expects."""
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    if head is None:
        raise RuntimeError("No database migration found")
    return head


def current_revision() -> str | None:
    """Revision of the schema stored in the database, or None before the first migration."""
    with get_engine().connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def schema_status() -> dict[str, str | bool | None]:
    """Compare the revision of the database with the one this version expects."""
    current, head = current_revision(), head_revision()
    return {"current": current, "head": head, "up_to_date": current == head}


def upgrade_db() -> None:
    """Migrate the schema to the latest revision, then seed the default rules.

    An empty database is created and a database created by version 1.x (no revision yet) is
    completed by the baseline revision. On the first run the default rules and checklists
    (``default_rules.toml``) are copied into the database; later runs add the new defaults
    (see ``rule_store.seed_defaults``). The built-in roles are created when missing (see
    ``access_control.ensure_system_roles``).
    """
    # Import here because rule_store and access_control depend on this module
    from .. import access_control, rule_store

    before = current_revision()
    with get_engine().begin() as connection:
        command.upgrade(alembic_config(connection), "head")
    after = current_revision()
    if after != before:
        logger.info("Database schema migrated from %s to %s", before or "nothing", after)
    written = rule_store.seed_defaults()
    if written:
        logger.info("Default rules seeded: %d rule(s) or checklist item(s) written", written)
    access_control.ensure_system_roles()


def check_db() -> None:
    """Refuse to serve a database whose schema is not at the expected revision.

    Raises:
        SchemaError: If the database was not migrated (or was migrated by a newer version).
    """
    status = schema_status()
    if not status["up_to_date"]:
        raise SchemaError(
            f"Database schema is at revision {status['current'] or 'none'}, this version needs "
            f"{status['head']}: run `security-review-controller db upgrade` first"
        )


def init_db() -> None:
    """Prepare the database for a command: migrate it (SECREVIEW_DB_AUTO_UPGRADE) or check it.

    Raises:
        SchemaError: If automatic upgrades are disabled and the schema is not up to date.
    """
    if get_settings().db_auto_upgrade:
        upgrade_db()
    else:
        check_db()


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
