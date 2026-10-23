"""Tests of the schema migrations (Alembic) and of the schema checks done at start."""

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from conftest import ADMIN_GRANTS, TRIAGER_GRANTS
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


def test_the_default_database_is_a_private_file_of_the_user(tmp_path, monkeypatch, caplog):
    # Whatever directory the host starts the server from, one file in the data directory of the
    # user; the old default in the working directory is reported, not used
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "security_reports.db").touch()
    config.get_settings.cache_clear()
    database.set_engine(None)
    try:
        engine = database.get_engine()
    finally:
        config.get_settings.cache_clear()

    directory = tmp_path / "data" / "security-review-mcp"
    assert engine.url.database == str(directory / "security_reports.db")
    assert directory.stat().st_mode & 0o777 == 0o700
    assert "no longer the default database" in caplog.text
    engine.dispose()


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
            ("bob", '["crm"]'),  # a local account: never turned into an OIDC user
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
    assert (alice["auth_source"], alice["created_by"]) == ("oidc", "admin")
    # Revision 0013 moved the role of the user into its personal group, 0014 into a direct role
    # and 0018 into the groups of its projects
    assert alice["permissions"] == {"reports.read": ["billing", "shop-api"]}
    assert [group["name"] for group in alice["groups"]] == ["project:billing", "project:shop-api"]
    assert (users["bob"]["auth_source"], users["bob"]["permissions"]) == ("local", ADMIN_GRANTS)


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
    # The personal group user:rita of revision 0013 became a direct role in revision 0014, then
    # the group of its project in revision 0018
    assert set(groups) == {"administrators", "triagers", "sec-team", "devs", "project:shop"}
    assert [m["username"] for m in groups["administrators"]["members"]] == ["root"]
    assert groups["administrators"]["sso"] is False
    assert groups["sec-team"]["sso"] is True and groups["sec-team"]["members"] == []
    assert {(r["name"], tuple(r["projects"] or ())) for r in groups["devs"]["roles"]} == {
        ("reader", ("shop", "crm")),
        ("triager", ("shop",)),
    }
    users = {user["username"]: user for user in web_users.list_users()}
    assert users["rita"]["permissions"] == {"reports.read": ["shop"]}
    assert [group["name"] for group in users["rita"]["groups"]] == ["project:shop"]
    assert users["tess"]["permissions"] == TRIAGER_GRANTS
    # The access given by the OIDC groups at the last login is computed again at the next one
    assert users["sam"]["permissions"] == {}
    roles = {role["name"]: role for role in access_control.list_roles()}
    assert all(roles[name]["system"] for name in ("reader", "admin"))
    # Revision 0021: triager is an ordinary role, with the permissions it had
    assert not roles["triager"]["system"]
    assert roles["triager"]["permissions"] == ["findings.triage", "reports.read"]

    # Downgrading drops the access control tables
    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0012")
    assert not inspect(empty_engine).has_table("usergroup")
    assert inspect(empty_engine).has_table("oidcrolemapping")


def test_personal_groups_become_direct_roles(empty_engine):
    from alembic import command
    from sqlalchemy import text

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
        command.upgrade(database.alembic_config(connection), "0014")
        groups = set(connection.execute(text("SELECT name FROM usergroup")).scalars())
        direct = connection.execute(text("SELECT user_id, projects FROM userrole")).all()
    assert groups == {"administrators", "user:sam", "user:nobody"}
    assert [tuple(row) for row in direct] == [(1, '["shop", "crm"]')]

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


def test_direct_roles_become_groups(empty_engine):
    from alembic import command
    from sqlalchemy import text

    from security_review_mcp import access_control

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0017")
        now = "2026-10-01 10:00:00"
        for user_id, name in ((1, "root"), (2, "rita"), (3, "tess"), (4, "sam")):
            connection.execute(
                text(
                    "INSERT INTO webuser (id, username, auth_source, created_at, updated_at, "
                    "session_version, must_change_password) "
                    "VALUES (:id, :name, 'local', :now, :now, 1, 0)"
                ),
                {"id": user_id, "name": name, "now": now},
            )
        roles = dict(connection.execute(text("SELECT name, id FROM accessrole")).all())
        # A group made by an administrator with reader on shop alone is reused; the name
        # project:crm is taken by a group with another role
        for group_id, name, role, projects in (
            (10, "Shop team", "reader", '["shop"]'),
            (11, "project:crm", "triager", '["crm"]'),
        ):
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
                    "VALUES (:id, :role, :projects)"
                ),
                {"id": group_id, "role": roles[role], "projects": projects},
            )
        for user_id, role, projects in (
            (1, "admin", "[]"),
            (2, "reader", '["shop", "crm"]'),
            (3, "triager", '["shop"]'),
            (3, "reader", '["crm"]'),
            (4, "reader", '["crm"]'),
            (4, "triager", "[]"),
        ):
            connection.execute(
                text("INSERT INTO userrole (user_id, role_id, projects) VALUES (:u, :r, :p)"),
                {"u": user_id, "r": roles[role], "p": projects},
            )
        command.upgrade(database.alembic_config(connection), "head")

    assert not inspect(empty_engine).has_table("userrole")
    groups = {group["name"]: group for group in access_control.list_groups()}
    # administrators (created by revision 0013) holds admin alone on every project: reused
    assert set(groups) == {
        "Shop team",
        "administrators",
        "project:crm",
        "project:crm (2)",
        "project:shop:triager",
        "role:triager",
    }
    assert all(group["sso"] is False for group in groups.values())
    assert [(r["name"], r["projects"]) for r in groups["project:crm (2)"]["roles"]] == [
        ("reader", ["crm"])
    ]
    members = {name: [m["username"] for m in group["members"]] for name, group in groups.items()}
    assert members == {
        "Shop team": ["rita"],
        "project:crm": [],
        "project:crm (2)": ["rita", "sam", "tess"],
        "project:shop:triager": ["tess"],
        "administrators": ["root"],
        "role:triager": ["sam"],
    }
    # Nobody loses or gains any access, the last administrator included
    users = {user["username"]: user for user in web_users.list_users()}
    assert users["root"]["permissions"] == ADMIN_GRANTS
    assert users["rita"]["permissions"] == {"reports.read": ["crm", "shop"]}
    assert users["tess"]["permissions"] == {
        "findings.triage": ["shop"],
        "reports.read": ["crm", "shop"],
    }
    assert users["sam"]["permissions"] == {"findings.triage": None, "reports.read": None}

    # Downgrading creates the table again, empty, and keeps the groups
    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0017")
        assert connection.execute(text("SELECT count(*) FROM userrole")).scalar_one() == 0
        assert connection.execute(text("SELECT count(*) FROM usergroup")).scalar_one() == 6


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


def test_the_stored_oidc_scope_follows_the_renamed_variable(empty_engine):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0018")
        for key, value in (
            ("proxy", "http://proxy:3128"),
            ("no_proxy", "internal"),
            ("oidc_scopes", "openid email"),
        ):
            connection.execute(
                text(
                    "INSERT INTO appsetting (key, value, updated_at, updated_by) "
                    "VALUES (:key, :value, '2026-10-01 10:00:00', 'admin')"
                ),
                {"key": key, "value": value},
            )
        command.upgrade(database.alembic_config(connection), "0019")
        rows = dict(connection.execute(text("SELECT key, value FROM appsetting")).all())
    assert rows == {
        "proxy": "http://proxy:3128",
        "no_proxy": "internal",
        "oidc_scope": "openid email",
    }

    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0018")
        rows = dict(connection.execute(text("SELECT key, value FROM appsetting")).all())
    assert set(rows) == {"proxy", "no_proxy", "oidc_scopes"}


def test_person_tokens_are_revoked_and_triager_becomes_ordinary(empty_engine):
    from alembic import command
    from sqlalchemy import text

    from security_review_mcp import access_control, audit, token_store

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0020")
        # A built-in role took its permissions from the code, not from its row
        connection.execute(
            text("UPDATE accessrole SET permissions = '[]' WHERE name = 'triager' AND system")
        )
        for token_id, role, project in (
            ("t1", "reader", "shop"),
            ("t2", "triager", None),
            ("t3", "mcp", "shop"),
            ("t4", "ci", "shop"),
        ):
            connection.execute(
                text(
                    "INSERT INTO apitoken (id, label, role, project, token_hash, created_at) "
                    "VALUES (:id, :label, :role, :project, :digest, '2026-10-01')"
                ),
                {
                    "id": token_id,
                    "label": f"{role}-token",
                    "role": role,
                    "project": project,
                    "digest": token_id * 32,
                },
            )
            if project:
                connection.execute(
                    text(
                        "INSERT INTO apitokenproject (id, token_id, project, status, created_at) "
                        "VALUES (:id, :token, :project, 'active', '2026-10-01')"
                    ),
                    {"id": f"p{token_id}", "token": token_id, "project": project},
                )
        command.upgrade(database.alembic_config(connection), "head")
        links = connection.execute(text("SELECT token_id FROM apitokenproject")).scalars().all()

    assert sorted(token["label"] for token in token_store.list_tokens()) == [
        "ci-token",
        "mcp-token",
    ]
    assert sorted(links) == ["t3", "t4"]
    events = audit.list_events(action="token.revoked")["events"]
    assert sorted((e["actor"], e["target_id"], e["details"]["role"]) for e in events) == [
        ("migration", "t1", "reader"),
        ("migration", "t2", "triager"),
    ]
    assert events[0]["details"]["projects"] in (["shop"], None)
    roles = {role["name"]: role for role in access_control.list_roles()}
    assert not roles["triager"]["system"]
    assert roles["triager"]["permissions"] == ["findings.triage", "reports.read"]

    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0020")
        system = connection.execute(
            text("SELECT system FROM accessrole WHERE name = 'triager'")
        ).scalar_one()
    assert system


def test_a_new_database_gets_an_ordinary_triager_role(empty_engine):
    from security_review_mcp import access_control

    database.upgrade_db()

    roles = {role["name"]: role for role in access_control.list_roles()}
    assert [name for name, role in roles.items() if role["system"]] == ["admin", "reader"]
    assert roles["triager"]["permissions"] == ["findings.triage", "reports.read"]
    assert not roles["mcp-user"]["system"]
    assert roles["mcp-user"]["permissions"] == ["mcp_tokens.create"]


def test_the_mcp_user_role_is_kept_on_downgrade_while_a_group_holds_it(empty_engine):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        config = database.alembic_config(connection)
        command.upgrade(config, "head")
        command.downgrade(config, "0023")
        assert not connection.execute(
            text("SELECT id FROM accessrole WHERE name = 'mcp-user'")
        ).first()
        command.upgrade(config, "head")
        role_id = connection.execute(
            text("SELECT id FROM accessrole WHERE name = 'mcp-user'")
        ).scalar_one()
        group_id = connection.execute(
            text(
                "INSERT INTO usergroup (name, description, sso, created_at, updated_at) "
                "VALUES ('agents', '', 0, '2026-10-01', '2026-10-01') RETURNING id"
            )
        ).scalar_one()
        connection.execute(
            text(
                "INSERT INTO grouprole (group_id, role_id, projects) VALUES (:group, :role, '[]')"
            ),
            {"group": group_id, "role": role_id},
        )
        command.downgrade(config, "0023")
        kept = connection.execute(
            text("SELECT id FROM accessrole WHERE name = 'mcp-user'")
        ).scalar_one()
        # Upgrading again keeps the role of that name
        command.upgrade(config, "head")
        count = connection.execute(
            text("SELECT COUNT(*) FROM accessrole WHERE name = 'mcp-user'")
        ).scalar_one()

    assert (kept, count) == (role_id, 1)


def test_downgrading_the_api_tokens_deletes_them(empty_engine):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "head")
        for token_id, role in (("t1", "api"), ("t2", "mcp")):
            connection.execute(
                text(
                    "INSERT INTO apitoken (id, label, role, token_hash, created_at) "
                    "VALUES (:id, :id, :role, :digest, '2026-10-01')"
                ),
                {"id": token_id, "role": role, "digest": token_id * 32},
            )
        command.downgrade(database.alembic_config(connection), "0021")
        rows = connection.execute(text("SELECT id FROM apitoken")).scalars().all()
        columns = {column["name"] for column in inspect(connection).get_columns("apitoken")}

    assert rows == ["t2"]
    assert not columns & {"user_id", "access_role_id"}


def test_users_sharing_an_oidc_identity_keep_it_on_the_last_one(empty_engine):
    from alembic import command
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    issuer = "https://idp.example.com"
    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0022")
        for user_id, name, subject, last_login in (
            (1, "alice", "sub-1", "2026-10-01 10:00:00"),
            # The same person, renamed at the provider: a second user before 0023
            (2, "alice.smith", "sub-1", "2026-10-05 10:00:00"),
            (3, "a.smith", "sub-1", None),
            (4, "bob", "sub-2", None),
        ):
            connection.execute(
                text(
                    "INSERT INTO webuser (id, username, auth_source, oidc_subject, oidc_issuer, "
                    "created_at, updated_at, must_change_password, session_version, "
                    "last_login_at) VALUES (:id, :name, 'oidc', :subject, :issuer, "
                    "'2026-10-01', '2026-10-01', 0, 1, :last_login)"
                ),
                {
                    "id": user_id,
                    "name": name,
                    "subject": subject,
                    "issuer": issuer,
                    "last_login": last_login,
                },
            )
        command.upgrade(database.alembic_config(connection), "head")
        rows = connection.execute(
            text("SELECT username, oidc_issuer, oidc_subject FROM webuser ORDER BY id")
        ).all()
    assert rows == [
        ("alice", None, ""),
        ("alice.smith", issuer, "sub-1"),
        ("a.smith", None, ""),
        ("bob", issuer, "sub-2"),
    ]

    # The index refuses a second user bound to the same identity
    with pytest.raises(IntegrityError), empty_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE webuser SET oidc_issuer = :issuer, oidc_subject = 'sub-2' "
                "WHERE username = 'alice'"
            ),
            {"issuer": issuer},
        )

    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0022")
        indexes = {index["name"] for index in inspect(connection).get_indexes("webuser")}
    assert "ix_webuser_oidc_identity" not in indexes


def test_the_reasons_of_existing_acceptances_become_their_first_comment(empty_engine):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0025")
        connection.execute(
            text(
                "INSERT INTO securityreport (id, project, reviewer, summary, risk_level, "
                "created_at) VALUES (1, 'shop', 'claude', 'Summary', 'LOW', '2026-10-01')"
            )
        )
        for finding_id, status, reason in (
            (1, "ACCEPTED", "Internal tool only"),
            (2, "ACCEPTED", "Already discussed"),
            (3, "FALSE_POSITIVE", "Test fixture"),
        ):
            connection.execute(
                text(
                    "INSERT INTO finding (id, report_id, title, severity, category, description, "
                    "recommendation, status, status_reason, status_approver, status_changed_at) "
                    "VALUES (:id, 1, 'T', 'HIGH', 'code', 'D', 'R', :status, :reason, "
                    "'alice', "
                    "'2026-10-02 10:00:00')"
                ),
                {"id": finding_id, "status": status, "reason": reason},
            )
        connection.execute(
            text(
                "INSERT INTO findingcomment (finding_id, author, body, created_at) "
                "VALUES (2, 'bob', 'Already discussed', '2026-10-03')"
            )
        )
        command.upgrade(database.alembic_config(connection), "head")
        rows = connection.execute(
            text("SELECT finding_id, author, body FROM findingcomment ORDER BY finding_id")
        ).all()

    # Only the acceptances without comments get one; false positives are not acceptances
    assert [tuple(row) for row in rows] == [
        (1, "alice", "Internal tool only"),
        (2, "bob", "Already discussed"),
    ]
