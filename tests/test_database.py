"""Tests of the schema migrations (Alembic) and of the schema checks done at start."""

from types import SimpleNamespace

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from conftest import ADMIN_GRANTS
from sqlalchemy import inspect
from sqlmodel import SQLModel, StaticPool, create_engine

from security_review_mcp import config
from security_review_mcp.auth import web_users
from security_review_mcp.rules import rule_store
from security_review_mcp.storage import database


@pytest.fixture
def empty_engine():
    """Replace the test database by an empty one (no table, no revision)."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    database.set_engine(engine)
    yield engine
    engine.dispose()


def _groups(connection) -> dict[str, dict]:
    """The groups of a database before revision 0039: whether OIDC names them, their roles
    (name, projects) and the usernames of their members."""
    import json

    from sqlalchemy import text

    groups = {}
    for group_id, name, sso in connection.execute(text("SELECT id, name, sso FROM usergroup")):
        roles = {
            (role, tuple(json.loads(projects)))
            for role, projects in connection.execute(
                text(
                    "SELECT a.name, r.projects FROM grouprole r "
                    "JOIN accessrole a ON a.id = r.role_id WHERE r.group_id = :group"
                ),
                {"group": group_id},
            )
        }
        members = sorted(
            row[0]
            for row in connection.execute(
                text(
                    "SELECT w.username FROM groupmember m JOIN webuser w ON w.id = m.user_id "
                    "WHERE m.group_id = :group"
                ),
                {"group": group_id},
            )
        )
        groups[name] = {"sso": bool(sso), "roles": roles, "members": members}
    return groups


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


class _RecordingConnection:
    """Connection of a fake PostgreSQL engine: records the functions it is asked to run."""

    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement):
        self.calls.append(statement.selected_columns[0].name)

    def commit(self):
        self.calls.append("commit")


def test_the_migration_lock_is_released_when_the_migration_fails(monkeypatch):
    calls = []
    engine = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"), connect=lambda: _RecordingConnection(calls)
    )
    monkeypatch.setattr(database, "get_engine", lambda: engine)

    with pytest.raises(RuntimeError), database.migration_lock():
        calls.append("migrate")
        raise RuntimeError("migration failed")

    assert calls == [
        "pg_advisory_lock",
        "commit",
        "migrate",
        "pg_advisory_unlock",
        "commit",
    ]


def test_check_refuses_a_database_that_was_not_migrated(empty_engine):
    with pytest.raises(database.SchemaError, match="security-review-controller db upgrade"):
        database.check_db()

    database.upgrade_db()
    database.check_db()


def test_check_refuses_a_legacy_database_until_it_is_upgraded(empty_engine):
    from alembic import command
    from sqlalchemy import text

    # The tables of version 1.x (those of the baseline revision), but no revision
    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0001")
        connection.execute(text("DROP TABLE alembic_version"))
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
    # Revision 0013 moved the role of the user into its personal group, 0014 into a direct role,
    # 0018 into the groups of its projects and 0039 into these projects, with their reading, to
    # which 0040 adds reports.write
    assert alice["permissions"] == {
        "reports.read": ["billing", "shop-api"],
        "reports.write": ["billing", "shop-api"],
    }
    assert alice["roles"] == []
    assert [(item["project"], item["permissions"]) for item in alice["projects"]] == [
        ("billing", ["reports.read", "reports.write"]),
        ("shop-api", ["reports.read", "reports.write"]),
    ]
    assert (users["bob"]["auth_source"], users["bob"]["permissions"]) == ("local", ADMIN_GRANTS)


def test_roles_and_mappings_become_groups(empty_engine):
    from alembic import command
    from sqlalchemy import text

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
        # The last revision with groups: 0039 is not downgraded
        command.upgrade(database.alembic_config(connection), "0038")
        groups = _groups(connection)
        roles = {
            name: (bool(system), permissions)
            for name, system, permissions in connection.execute(
                text("SELECT name, system, permissions FROM accessrole")
            )
        }

    assert not inspect(empty_engine).has_table("oidcrolemapping")
    columns = {column["name"] for column in inspect(empty_engine).get_columns("webuser")}
    assert not columns & {"role", "projects", "sso_role", "sso_projects"}
    # The personal group user:rita of revision 0013 became a direct role in revision 0014, then
    # the group of its project in revision 0018
    assert set(groups) == {"administrators", "triagers", "sec-team", "devs", "project:shop"}
    assert groups["administrators"]["members"] == ["root"]
    assert groups["administrators"]["sso"] is False
    assert groups["sec-team"]["sso"] is True and groups["sec-team"]["members"] == []
    assert groups["devs"]["roles"] == {("reader", ("shop", "crm")), ("triager", ("shop",))}
    assert groups["project:shop"]["members"] == ["rita"]
    assert groups["triagers"]["members"] == ["tess"]
    # The access given by the OIDC groups at the last login is computed again at the next one
    assert all("sam" not in group["members"] for group in groups.values())
    assert roles["reader"][0] and roles["admin"][0]
    # Revision 0021: triager is an ordinary role, with the permissions it had
    assert roles["triager"] == (False, '["findings.triage", "reports.read"]')

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
        # The last revision with groups: 0039 is not downgraded
        command.upgrade(database.alembic_config(connection), "0038")
        groups = _groups(connection)

    assert not inspect(empty_engine).has_table("userrole")
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
    assert groups["project:crm (2)"]["roles"] == {("reader", ("crm",))}
    members = {name: group["members"] for name, group in groups.items()}
    assert members == {
        "Shop team": ["rita"],
        "project:crm": [],
        "project:crm (2)": ["rita", "sam", "tess"],
        "project:shop:triager": ["tess"],
        "administrators": ["root"],
        "role:triager": ["sam"],
    }

    # Downgrading creates the table again, empty, and keeps the groups
    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0017")
        assert connection.execute(text("SELECT count(*) FROM userrole")).scalar_one() == 0
        assert connection.execute(text("SELECT count(*) FROM usergroup")).scalar_one() == 6


def test_old_dismissals_expire_after_a_grace_period(empty_engine):
    from datetime import UTC, datetime, timedelta

    from alembic import command
    from sqlalchemy import text

    from security_review_mcp.reports import services

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
        # Revision 0039 is not downgraded
        command.upgrade(database.alembic_config(connection), "0038")
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
        # Revision 0039 is not downgraded
        command.upgrade(database.alembic_config(connection), "0038")
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

    from security_review_mcp.observability import audit

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
        command.upgrade(database.alembic_config(connection), "0038")  # 0039 removes triager
        links = connection.execute(text("SELECT token_id FROM apitokenproject")).scalars().all()
        labels = connection.execute(text("SELECT label FROM apitoken")).scalars().all()
        triager = connection.execute(
            text("SELECT system, permissions FROM accessrole WHERE name = 'triager'")
        ).one()

    assert sorted(labels) == ["ci-token", "mcp-token"]
    assert sorted(links) == ["t3", "t4"]
    events = audit.list_events(action="token.revoked")["events"]
    assert sorted((e["actor"], e["target_id"], e["details"]["role"]) for e in events) == [
        ("migration", "t1", "reader"),
        ("migration", "t2", "triager"),
    ]
    assert events[0]["details"]["projects"] in (["shop"], None)
    assert tuple(triager) == (0, '["findings.triage", "reports.read"]')

    with empty_engine.begin() as connection:
        command.downgrade(database.alembic_config(connection), "0020")
        system = connection.execute(
            text("SELECT system FROM accessrole WHERE name = 'triager'")
        ).scalar_one()
    assert system


def test_a_new_database_gets_only_the_built_in_roles(empty_engine):
    from security_review_mcp.auth import access_control

    database.upgrade_db()

    roles = access_control.list_roles()
    assert [(role["name"], role["system"]) for role in roles] == [("admin", True)]


def test_the_mcp_tokens_create_permission_is_removed_from_every_role(empty_engine):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        config = database.alembic_config(connection)
        command.upgrade(config, "0035")
        connection.execute(
            text(
                "INSERT INTO accessrole (name, description, permissions, system, created_at, "
                "updated_at) VALUES ('ops', '', :permissions, 0, '2026-10-01', '2026-10-01')"
            ),
            {"permissions": '["audit.read", "mcp_tokens.create"]'},
        )
        mcp_user = connection.execute(
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
            {"group": group_id, "role": mcp_user},
        )
        command.upgrade(config, "0038")  # 0039 is not downgraded
        roles = dict(connection.execute(text("SELECT name, permissions FROM accessrole")).all())
        bindings = connection.execute(
            text("SELECT COUNT(*) FROM grouprole WHERE group_id = :group"), {"group": group_id}
        ).scalar_one()
        # Downgrading gives the role back, held by no group
        command.downgrade(config, "0035")
        restored = connection.execute(
            text("SELECT permissions FROM accessrole WHERE name = 'mcp-user'")
        ).scalar_one()

    # The role left empty goes with its bindings; the others keep their other permissions
    assert "mcp-user" not in roles and bindings == 0
    assert roles["ops"] == '["audit.read"]'
    assert restored == '["mcp_tokens.create"]'


def test_downgrading_the_api_tokens_deletes_them(empty_engine):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        # Revision 0039 is not downgraded
        command.upgrade(database.alembic_config(connection), "0038")
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
        # Revision 0039 is not downgraded
        command.upgrade(database.alembic_config(connection), "0038")
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


def test_stored_findings_get_their_occurrences(empty_engine):
    from alembic import command
    from sqlalchemy import text

    from security_review_mcp.reports import services

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0030")
        for report_id, day in ((1, "01"), (2, "02"), (3, "03")):
            connection.execute(
                text(
                    "INSERT INTO securityreport (id, project, summary, risk_level, created_at, "
                    "checklist_results, scan_rules) VALUES (:id, 'shop', 'summary', 'HIGH', "
                    ":at, '[]', '[]')"
                ),
                {"id": report_id, "at": f"2026-10-{day} 10:00:00"},
            )
        # SQL injection: fixed in report 1, back in reports 2 and 3; XSS only in report 1
        for finding_id, report_id, title, status in (
            (1, 1, "SQL injection", "FIXED"),
            (2, 1, "XSS", "OPEN"),
            (3, 2, "SQL injection", "OPEN"),
            (4, 3, "SQL Injection ", "ACCEPTED"),
        ):
            connection.execute(
                text(
                    "INSERT INTO finding (id, report_id, title, severity, category, cwe, "
                    "file_path, description, status) VALUES (:id, :report, :title, 'HIGH', "
                    "'code', 'CWE-89', 'app/db.py', 'Concatenated query', :status)"
                ),
                {"id": finding_id, "report": report_id, "title": title, "status": status},
            )
        command.upgrade(database.alembic_config(connection), "head")

    findings = {f.id: f for r in (1, 2, 3) for f in services.get_report(r).findings}
    assert {i: f.superseded_by for i, f in findings.items()} == {1: 4, 2: None, 3: 4, 4: None}
    # The issue came back after its fix: first seen again in report 2
    assert findings[4].first_seen_at.day == 2
    assert [findings[i].status for i in (1, 3)] == ["fixed", "open"]  # statuses unchanged
    assert services.project_posture("shop")["open_findings_total"] == 1


def test_the_dependency_findings_of_a_review_and_a_scan_are_merged(empty_engine):
    from alembic import command
    from sqlalchemy import text

    from security_review_mcp.reports import services

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0040")
        for report_id, day in ((1, "01"), (2, "02")):
            connection.execute(
                text(
                    "INSERT INTO securityreport (id, project, summary, risk_level, created_at, "
                    "checklist_results, scan_rules) VALUES (:id, 'shop', 'summary', 'HIGH', "
                    ":at, '[]', '[]')"
                ),
                {"id": report_id, "at": f"2026-10-{day} 10:00:00"},
            )
        # Report 1: the scan; report 2: the review, which fixed the advisory, other titles
        for finding_id, report_id, title, path, status in (
            (1, 1, "Vulnerable dependency: ecdsa 0.19.2", "uv.lock", "OPEN"),
            (2, 2, "ecdsa : attaque temporelle", "pyproject.toml", "FIXED"),
        ):
            connection.execute(
                text(
                    "INSERT INTO finding (id, report_id, title, severity, category, rule_id, "
                    "file_path, description, status, fingerprint, first_seen_at) VALUES (:id, "
                    ":report, :title, 'HIGH', 'dependency', 'GHSA-wj6h-64fc-37mp', :path, "
                    "'Known issue', :status, :id, :seen)"
                ),
                {
                    "id": finding_id,
                    "report": report_id,
                    "title": title,
                    "path": path,
                    "status": status,
                    "seen": f"2026-10-0{report_id} 10:00:00",
                },
            )
        connection.execute(
            text(
                "INSERT INTO findingcomment (finding_id, author, body, created_at) "
                "VALUES (1, 'bob', 'Seen', '2026-10-01 11:00:00')"
            )
        )
        command.upgrade(database.alembic_config(connection), "head")

    scanned, reviewed = (services.get_report(r).findings[0] for r in (1, 2))
    assert (scanned.superseded_by, reviewed.superseded_by) == (2, None)
    assert reviewed.first_seen_at.day == 1
    assert reviewed.status == "fixed"  # statuses unchanged
    assert [c.body for c in services.list_finding_comments(2)] == ["Seen"]


def test_the_tickets_and_their_settings_move_to_the_connector_names(empty_engine):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        command.upgrade(database.alembic_config(connection), "0031")
        connection.execute(
            text(
                "INSERT INTO securityreport (id, project, reviewer, summary, risk_level, "
                "created_at) VALUES (1, 'shop', 'claude', 'Summary', 'LOW', '2026-10-01')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO finding (id, report_id, title, severity, category, description, "
                "recommendation, status) VALUES (1, 1, 'T', 'HIGH', 'code', 'D', 'R', 'OPEN')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO findingticket (finding_id, kind, project, fingerprint, state, "
                "external_key, url, attempts, created_at, updated_at) VALUES (1, 'jira', 'shop', "
                "'abc', 'sent', 'SEC-1', 'https://jira.example/browse/SEC-1', 1, "
                "'2026-10-02', '2026-10-02')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO tickettarget (project, kind, destination, updated_at) "
                "VALUES ('shop', 'jira', 'SEC', '2026-10-02')"
            )
        )
        for key, value in (
            ("ticketing_jira_url", "https://jira.example"),
            ("ticketing:jira:enabled", "true"),
            ("proxy", "http://proxy:3128"),
        ):
            connection.execute(
                text(
                    "INSERT INTO appsetting (key, value, updated_at, updated_by) "
                    "VALUES (:key, :value, '2026-10-01 10:00:00', 'admin')"
                ),
                {"key": key, "value": value},
            )
        command.upgrade(database.alembic_config(connection), "head")
        tables = set(inspect(connection).get_table_names())
        exports = connection.execute(text("SELECT finding_id, external_key FROM findingexport"))
        targets = connection.execute(text("SELECT project, destination FROM connectortarget"))
        settings = dict(connection.execute(text("SELECT key, value FROM appsetting")).all())
        assert [tuple(row) for row in exports] == [(1, "SEC-1")]
        assert [tuple(row) for row in targets] == [("shop", "SEC")]

    assert not {"findingticket", "tickettarget"} & tables
    assert settings == {
        "connector_jira_url": "https://jira.example",
        "connector:jira:enabled": "true",
        "proxy": "http://proxy:3128",
    }


def test_every_referred_project_becomes_a_known_project(empty_engine):
    from alembic import command
    from sqlalchemy import text

    with empty_engine.begin() as connection:
        config = database.alembic_config(connection)
        command.upgrade(config, "0037")
        connection.execute(
            text(
                "INSERT INTO securityreport (project, summary, risk_level, created_at) "
                "VALUES ('shop', 'Summary', 'LOW', '2026-10-01 10:00:00')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO apitoken (id, label, role, project, token_hash, created_at) "
                "VALUES ('t1', 'ci-billing', 'ci', 'billing', :hash, '2026-10-01')"
            ),
            {"hash": "a" * 64},
        )
        connection.execute(
            text(
                "INSERT INTO apitokenproject (id, token_id, project, created_at) "
                "VALUES ('l1', 't1', 'billing', '2026-10-01')"
            )
        )
        role = connection.execute(text("SELECT id FROM accessrole WHERE name = 'reader'"))
        group = connection.execute(
            text(
                "INSERT INTO usergroup (name, description, sso, created_at, updated_at) "
                "VALUES ('devs', '', 0, '2026-10-01', '2026-10-01') RETURNING id"
            )
        ).scalar_one()
        connection.execute(
            text("INSERT INTO grouprole (group_id, role_id, projects) VALUES (:g, :r, :p)"),
            {"g": group, "r": role.scalar_one(), "p": '["crm"]'},
        )
        connection.execute(
            text(
                "INSERT INTO projectautojoinblock (project, blocked_by, created_at) "
                "VALUES ('vault', 'admin', '2026-10-01')"
            )
        )
        command.upgrade(config, "0038")
        projects = dict(
            connection.execute(text("SELECT name, autojoin_blocked FROM project")).all()
        )
        # Downgrading gives the blocked project back
        command.downgrade(config, "0037")
        blocks = connection.execute(text("SELECT project FROM projectautojoinblock")).all()

    assert projects == {"billing": 0, "crm": 0, "shop": 0, "vault": 1}
    assert [tuple(row) for row in blocks] == [("vault",)]


def test_the_groups_become_roles_of_the_users_without_changing_their_rights(empty_engine):
    from alembic import command
    from sqlalchemy import text

    from security_review_mcp.auth import access_control
    from security_review_mcp.observability import audit

    with empty_engine.begin() as connection:
        config = database.alembic_config(connection)
        command.upgrade(config, "0037")
        now = "2026-10-01 10:00:00"
        for user_id, name, source in (
            (1, "root", "local"),
            (2, "dev", "local"),
            (3, "carol", "oidc"),
            (4, "lea", "local"),
        ):
            connection.execute(
                text(
                    "INSERT INTO webuser (id, username, auth_source, created_at, updated_at, "
                    "session_version, must_change_password) "
                    "VALUES (:id, :name, :source, :now, :now, 1, 0)"
                ),
                {"id": user_id, "name": name, "source": source, "now": now},
            )
        connection.execute(
            text(
                "INSERT INTO accessrole (name, description, permissions, system, created_at, "
                "updated_at) VALUES ('auditor', '', '[\"audit.read\"]', 0, :now, :now)"
            ),
            {"now": now},
        )
        connection.execute(
            text(
                "INSERT INTO accessrole (name, description, permissions, system, created_at, "
                "updated_at) VALUES ('lead', '', :permissions, 0, :now, :now)"
            ),
            {"now": now, "permissions": '["findings.triage", "reports.read"]'},
        )
        roles = dict(connection.execute(text("SELECT name, id FROM accessrole")).all())
        administrators = connection.execute(
            text("SELECT id FROM usergroup WHERE name = 'administrators'")
        ).scalar_one()
        groups = {"administrators": administrators}
        for name, sso in (
            ("project:shop", 0),
            ("devs", 1),
            ("triagers", 0),
            ("auditors", 0),
            ("crm-leads", 0),
        ):
            groups[name] = connection.execute(
                text(
                    "INSERT INTO usergroup (name, description, sso, created_at, updated_at) "
                    "VALUES (:name, '', :sso, :now, :now) RETURNING id"
                ),
                {"name": name, "sso": sso, "now": now},
            ).scalar_one()
        for group, role, projects in (
            ("project:shop", "reader", '["shop"]'),
            ("devs", "reader", '["shop", "crm"]'),
            ("triagers", "triager", "[]"),
            ("auditors", "auditor", "[]"),
            ("crm-leads", "lead", '["crm"]'),
        ):
            connection.execute(
                text("INSERT INTO grouprole (group_id, role_id, projects) VALUES (:g, :r, :p)"),
                {"g": groups[group], "r": roles[role], "p": projects},
            )
        for group, user_id, source in (
            ("administrators", 1, "local"),
            ("project:shop", 2, "local"),
            ("devs", 2, "local"),
            ("devs", 3, "oidc"),
            ("triagers", 2, "local"),
            ("auditors", 2, "local"),
            ("project:shop", 4, "local"),
            ("crm-leads", 4, "local"),
        ):
            connection.execute(
                text(
                    "INSERT INTO groupmember (group_id, user_id, source, created_at) "
                    "VALUES (:g, :u, :s, :now)"
                ),
                {"g": groups[group], "u": user_id, "s": source, "now": now},
            )
        connection.execute(
            text(
                "INSERT INTO apitoken (id, label, role, token_hash, created_at, access_role_id) "
                "VALUES ('t1', 'triage-bot', 'api', :digest, :now, :role)"
            ),
            {"digest": "b" * 64, "now": now, "role": roles["triager"]},
        )
        connection.execute(
            text(
                "INSERT INTO appsetting (key, value, updated_at) "
                "VALUES ('oidc_default_group', 'devs', :now)"
            ),
            {"now": now},
        )
        connection.execute(
            text(
                "INSERT INTO apitoken (id, label, role, project, token_hash, created_at, "
                "access_role_id) VALUES ('t2', 'crm-bot', 'api', 'crm', :digest, :now, :role)"
            ),
            {"digest": "c" * 64, "now": now, "role": roles["lead"]},
        )
        connection.execute(
            text(
                "INSERT INTO apitokenproject (id, token_id, project, created_at) "
                "VALUES ('l2', 't2', 'crm', :now)"
            ),
            {"now": now},
        )
        command.upgrade(config, "head")
        token = connection.execute(
            text("SELECT access_role_id, project_permissions FROM apitoken WHERE id = 't2'")
        ).one()
        settings = connection.execute(text("SELECT key FROM appsetting")).scalars().all()

    users = {user["username"]: user for user in web_users.list_users()}
    assert users["root"]["permissions"] == ADMIN_GRANTS
    # The roles of its groups keep their permissions on the whole controller, the per-project
    # ones move to the projects; triager is removed. Revision 0040 adds reports.write wherever
    # reports.read is held
    assert users["dev"]["permissions"] == {
        "audit.read": None,
        "reports.read": ["crm", "shop"],
        "reports.write": ["crm", "shop"],
    }
    assert [role["name"] for role in users["dev"]["roles"]] == ["auditor"]
    assert [item["project"] for item in users["dev"]["projects"]] == ["crm", "shop"]
    # Roles on different projects: exactly the same rights
    assert users["lea"]["permissions"] == {
        "findings.triage": ["crm"],
        "reports.read": ["crm", "shop"],
        "reports.write": ["crm", "shop"],
    }
    assert {item["project"]: item["permissions"] for item in users["lea"]["projects"]} == {
        "crm": ["findings.triage", "reports.read", "reports.write"],
        "shop": ["reports.read", "reports.write"],
    }
    # The OIDC user keeps the rights of its OIDC group until its next login
    assert users["carol"]["permissions"] == {
        "reports.read": ["crm", "shop"],
        "reports.write": ["crm", "shop"],
    }
    (mapping,) = access_control.list_oidc_mappings()
    assert (mapping["claim"], mapping["roles"], mapping["all_projects_permissions"]) == (
        "devs",
        [],
        [],
    )
    assert mapping["projects"] == [
        {"project": "crm", "permissions": ["reports.read", "reports.write"]},
        {"project": "shop", "permissions": ["reports.read", "reports.write"]},
    ]
    # A role keeps its permissions on the whole controller; a role token keeps its role and gets
    # its per-project permissions (0040 leaves them: it saves no report); a role left empty
    # goes, unless a token uses it
    assert tuple(token) == (roles["lead"], '["findings.triage", "reports.read"]')
    listed = {role["name"]: role["permissions"] for role in access_control.list_roles()}
    assert listed == {"admin": listed["admin"], "auditor": ["audit.read"], "lead": []}
    revoked = audit.list_events(action="token.revoked")["events"]
    assert [(event["actor"], event["target_id"]) for event in revoked] == [("migration", "t1")]
    assert "oidc_default_group" not in settings
    assert not inspect(empty_engine).has_table("usergroup")

    with (
        pytest.raises(RuntimeError, match="cannot be downgraded"),
        empty_engine.begin() as connection,
    ):
        command.downgrade(database.alembic_config(connection), "0038")
