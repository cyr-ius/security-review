"""Tests of the schema migrations (Alembic) and of the schema checks done at start."""

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect
from sqlmodel import SQLModel, StaticPool, create_engine

from security_review_mcp import config, database, rule_store, web_users


@pytest.fixture
def empty_engine():
    """Replace the test database by an empty one (no table, no revision)."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    database.set_engine(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def no_auto_upgrade(monkeypatch):
    """Disable the automatic schema upgrade (SECREVIEW_DB_AUTO_UPGRADE=false)."""
    monkeypatch.setenv("SECREVIEW_DB_AUTO_UPGRADE", "false")
    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()


def test_upgrade_creates_the_schema_of_the_models(empty_engine):
    database.upgrade_db()

    assert database.schema_status() == {
        "current": database.head_revision(),
        "head": database.head_revision(),
        "up_to_date": True,
    }
    # A model changed without a migration would show up here
    with empty_engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), SQLModel.metadata) == []
    assert rule_store.list_rules()  # the default rules are seeded


def test_upgrade_is_idempotent(empty_engine):
    database.upgrade_db()
    revision = rule_store.revision()

    database.upgrade_db()

    assert database.current_revision() == database.head_revision()
    assert rule_store.revision() == revision


def test_check_refuses_a_database_that_was_not_migrated(empty_engine):
    with pytest.raises(database.SchemaError, match="security-review-controller db upgrade"):
        database.check_db()

    database.upgrade_db()
    database.check_db()


def test_check_refuses_a_legacy_database_until_it_is_upgraded():
    # The test database has the tables (as created by version 1.x) but no revision
    assert inspect(database.get_engine()).has_table("securityreport")
    with pytest.raises(database.SchemaError, match="revision none"):
        database.check_db()

    database.upgrade_db()
    database.check_db()


def test_init_db_only_checks_without_auto_upgrade(empty_engine, no_auto_upgrade):
    with pytest.raises(database.SchemaError):
        database.init_db()
    assert not inspect(empty_engine).has_table("securityreport")


def test_init_db_upgrades_by_default(empty_engine):
    database.init_db()

    assert database.current_revision() == database.head_revision()


def test_user_grants_become_sso_web_users(empty_engine):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0005")
        now = "2026-10-01 10:00:00"
        connection.execute(
            text(
                "INSERT INTO webuser (username, role, projects, password_hash, created_at, "
                "updated_at, password_changed_at, session_version) "
                "VALUES ('bob', 'admin', '[]', 'scrypt$x', :now, :now, :now, 1)"
            ),
            {"now": now},
        )
        for username, projects in (
            ("alice", '["shop-api", "billing"]'),
            ("bob", '["crm"]'),  # a local account: never turned into an SSO user
            ("not a username", '["crm"]'),
        ):
            connection.execute(
                text(
                    "INSERT INTO oidcusergrant (username, projects, created_at, updated_at, "
                    "created_by) VALUES (:username, :projects, :now, :now, 'admin')"
                ),
                {"username": username, "projects": projects, "now": now},
            )
        command.upgrade(database.alembic_config(connection), "head")

    assert not inspect(empty_engine).has_table("oidcusergrant")
    users = {user["username"]: user for user in web_users.list_users()}
    assert set(users) == {"alice", "bob"}
    alice = users["alice"]
    assert (alice["auth_source"], alice["role"], alice["projects"], alice["created_by"]) == (
        "oidc",
        "reader",
        ["shop-api", "billing"],
        "admin",
    )
    assert (users["bob"]["auth_source"], users["bob"]["role"]) == ("local", "admin")


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        ({"osv_proxy_mode": "custom", "osv_proxy_url": "http://proxy:3128"}, "http://proxy:3128"),
        ({"osv_proxy_mode": "none"}, ""),
        ({"osv_proxy_mode": "custom"}, None),  # no URL: the variable applies
    ],
)
def test_the_osv_proxy_becomes_the_general_proxy(empty_engine, stored, expected):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0007")
        for key, value in stored.items():
            connection.execute(
                text(
                    "INSERT INTO appsetting (key, value, updated_at, updated_by) "
                    "VALUES (:key, :value, '2026-10-01 10:00:00', 'admin')"
                ),
                {"key": key, "value": value},
            )
        command.upgrade(database.alembic_config(connection), "head")
        rows = dict(connection.execute(text("SELECT key, value FROM appsetting")).all())
    assert rows == ({} if expected is None else {"proxy": expected})

    # Downgrading gives the OSV proxy back
    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0007")
        rows = dict(connection.execute(text("SELECT key, value FROM appsetting")).all())
    assert rows == {key: value for key, value in stored.items() if expected is not None}
