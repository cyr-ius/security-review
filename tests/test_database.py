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
    assert (alice["auth_source"], alice["effective_role"], alice["created_by"]) == (
        "oidc",
        "reader",
        "admin",
    )
    # Revision 0013 moved the role of the user into its personal group, 0014 into a direct role
    assert alice["permissions"] == {"reports.read": ["billing", "shop-api"]}
    assert alice["groups"] == []
    assert [(role["name"], role["projects"]) for role in alice["roles"]] == [
        ("reader", ["shop-api", "billing"])
    ]
    assert (users["bob"]["auth_source"], users["bob"]["effective_role"]) == ("local", "admin")


def test_roles_and_mappings_become_groups(empty_engine):
    from alembic import command
    from sqlalchemy import text

    from security_review_mcp import access_control

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0012")
        now = "2026-10-01 10:00:00"
        for name, role, projects, sso_role in (
            ("root", "admin", "[]", None),
            ("tess", "triager", "[]", None),
            ("rita", "reader", '["shop"]', None),
            ("sam", None, "[]", "triager"),
        ):
            connection.execute(
                text(
                    "INSERT INTO webuser (username, auth_source, role, projects, sso_role, "
                    "sso_projects, created_at, updated_at, session_version) VALUES (:name, "
                    "'local', :role, :projects, :sso_role, '[]', :now, :now, 1)"
                ),
                {
                    "name": name,
                    "role": role,
                    "projects": projects,
                    "sso_role": sso_role,
                    "now": now,
                },
            )
        for claim, role, projects in (
            ("sec-team", "admin", "[]"),
            ("devs", "reader", '["shop", "crm"]'),
            ("devs", "triager", '["shop"]'),
        ):
            connection.execute(
                text(
                    "INSERT INTO oidcrolemapping (claim_value, role, projects, created_at) "
                    "VALUES (:claim, :role, :projects, :now)"
                ),
                {"claim": claim, "role": role, "projects": projects, "now": now},
            )
        command.upgrade(database.alembic_config(connection), "head")

    assert not inspect(empty_engine).has_table("oidcrolemapping")
    columns = {column["name"] for column in inspect(empty_engine).get_columns("webuser")}
    assert not columns & {"role", "projects", "sso_role", "sso_projects"}
    groups = {group["name"]: group for group in access_control.list_groups()}
    # The personal group user:rita of revision 0013 became a direct role in revision 0014
    assert set(groups) == {"administrators", "triagers", "sec-team", "devs"}
    assert [m["username"] for m in groups["administrators"]["members"]] == ["root"]
    assert groups["administrators"]["sso"] is False
    assert groups["sec-team"]["sso"] is True and groups["sec-team"]["members"] == []
    assert {(r["name"], tuple(r["projects"] or ())) for r in groups["devs"]["roles"]} == {
        ("reader", ("shop", "crm")),
        ("triager", ("shop",)),
    }
    users = {user["username"]: user for user in web_users.list_users()}
    assert users["rita"]["permissions"] == {"reports.read": ["shop"]}
    assert [(role["name"], role["projects"]) for role in users["rita"]["roles"]] == [
        ("reader", ["shop"])
    ]
    assert users["tess"]["effective_role"] == "triager"
    # The access given by the SSO groups at the last login is computed again at the next one
    assert users["sam"]["permissions"] == {}
    roles = {role["name"]: role for role in access_control.list_roles()}
    assert all(roles[name]["system"] for name in ("reader", "triager", "admin"))

    # Downgrading drops the access control tables
    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0012")
    assert not inspect(empty_engine).has_table("usergroup")
    assert inspect(empty_engine).has_table("oidcrolemapping")


def test_personal_groups_become_direct_roles(empty_engine):
    from alembic import command
    from sqlalchemy import text

    from security_review_mcp import access_control

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0013")
        now = "2026-10-01 10:00:00"
        for user_id, name in ((1, "rita"), (2, "sam"), (3, "tess")):
            connection.execute(
                text(
                    "INSERT INTO webuser (id, username, auth_source, created_at, updated_at, "
                    "session_version) VALUES (:id, :name, 'local', :now, :now, 1)"
                ),
                {"id": user_id, "name": name, "now": now},
            )
        reader = connection.execute(
            text("SELECT id FROM accessrole WHERE name = 'reader'")
        ).scalar_one()
        # user:rita is personal; user:sam also has tess, user:nobody names no user
        for group_id, name in ((10, "user:rita"), (11, "user:sam"), (12, "user:nobody")):
            connection.execute(
                text(
                    "INSERT INTO usergroup (id, name, description, sso, created_at, updated_at) "
                    "VALUES (:id, :name, '', 0, :now, :now)"
                ),
                {"id": group_id, "name": name, "now": now},
            )
            connection.execute(
                text(
                    "INSERT INTO grouprole (group_id, role_id, projects) "
                    'VALUES (:id, :role, \'["shop", "crm"]\')'
                ),
                {"id": group_id, "role": reader},
            )
        for group_id, user_id in ((10, 1), (11, 2), (11, 3)):
            connection.execute(
                text(
                    "INSERT INTO groupmember (group_id, user_id, source, created_at) "
                    "VALUES (:group, :user, 'local', :now)"
                ),
                {"group": group_id, "user": user_id, "now": now},
            )
        command.upgrade(database.alembic_config(connection), "head")

    groups = {group["name"] for group in access_control.list_groups()}
    assert groups == {"administrators", "user:sam", "user:nobody"}
    users = {user["username"]: user for user in web_users.list_users()}
    assert users["rita"]["groups"] == []
    assert [(r["name"], r["projects"]) for r in users["rita"]["roles"]] == [
        ("reader", ["shop", "crm"])
    ]
    assert users["rita"]["permissions"] == {"reports.read": ["crm", "shop"]}
    assert users["sam"]["roles"] == []

    # Downgrading moves the direct roles back into personal groups
    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0013")
        rows = connection.execute(
            text(
                "SELECT g.name, r.projects FROM usergroup g "
                "JOIN grouprole r ON r.group_id = g.id "
                "JOIN groupmember m ON m.group_id = g.id WHERE m.user_id = 1"
            )
        ).all()
    assert [tuple(row) for row in rows] == [("user:rita", '["shop", "crm"]')]
    assert not inspect(empty_engine).has_table("userrole")


def test_old_dismissals_expire_after_a_grace_period(empty_engine):
    from datetime import UTC, datetime, timedelta

    from alembic import command
    from sqlalchemy import text

    from security_review_mcp import services

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0009")
        connection.execute(
            text(
                "INSERT INTO securityreport (id, project, summary, risk_level, created_at) "
                "VALUES (1, 'shop', 'Old review', 'CRITICAL', '2026-10-01 10:00:00')"
            )
        )
        for number, status in enumerate(("OPEN", "FIXED", "ACCEPTED", "FALSE_POSITIVE"), 1):
            connection.execute(
                text(
                    "INSERT INTO finding (id, report_id, title, severity, category, "
                    "description, status) VALUES (:id, 1, 'Issue', 'CRITICAL', 'code', "
                    "'Something', :status)"
                ),
                {"id": number, "status": status},
            )
        command.upgrade(database.alembic_config(connection), "head")

    findings = {f.id: f for f in services.get_report(1).findings}
    soon = datetime.now(UTC) + timedelta(days=30)
    for dismissed in (3, 4):
        expires = findings[dismissed].status_expires_at.replace(tzinfo=UTC)
        assert soon - timedelta(minutes=5) < expires <= soon
        assert "confirm it" in findings[dismissed].status_reason
        assert findings[dismissed].status_approver is None
    for kept in (1, 2):
        assert findings[kept].status_expires_at is None and findings[kept].status_reason is None
    assert services.evaluate_gate("shop")["blocking_findings"] == 1  # only the open one, for now


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


def test_the_reports_of_the_cli_scans_get_their_review_type(empty_engine):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0008")
        for reviewer in (
            "security-review-controller code scan",
            "security-review-controller deps scan",
            "claude",
        ):
            connection.execute(
                text(
                    "INSERT INTO securityreport (project, reviewer, summary, risk_level, "
                    "created_at) VALUES ('shop', :reviewer, 'Summary', 'LOW', "
                    "'2026-10-01 10:00:00')"
                ),
                {"reviewer": reviewer},
            )
        command.upgrade(database.alembic_config(connection), "head")
        rows = connection.execute(
            text("SELECT reviewer, review_type FROM securityreport ORDER BY id")
        ).all()
    assert [tuple(row) for row in rows] == [
        ("security-review-controller code scan", "code-scan"),
        ("security-review-controller deps scan", "dependency-scan"),
        ("claude", None),
    ]

    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0008")
        columns = {c["name"] for c in inspect(connection).get_columns("securityreport")}
    assert "review_type" not in columns
