"""Shared fixtures: an isolated in-memory database (with the default rules) and a clean registry."""

import os
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from sqlalchemy import Engine
from sqlmodel import SQLModel, StaticPool, create_engine

from security_review_mcp.auth import access_control, web_users
from security_review_mcp.auth.access_control import Permission
from security_review_mcp.config import Settings, get_settings
from security_review_mcp.reports.services import update_finding_status
from security_review_mcp.rules import registry, rule_store
from security_review_mcp.storage.database import alembic_config, set_engine
from security_review_mcp.storage.models import DISMISSED_STATUSES, FindingPublic, FindingStatus

# The tests ignore the configuration of the machine running them: the developer's .env file and
# the SECREVIEW_* variables of the shell (devcontainer database, Swagger...). A test that needs
# a setting sets it itself (monkeypatch.setenv, Settings(...)).
Settings.model_config["env_file"] = None
for _name in [name for name in os.environ if name.upper().startswith("SECREVIEW_")]:
    del os.environ[_name]
get_settings.cache_clear()


def _memory_engine() -> Engine:
    """Return an engine on a private in-memory SQLite database (one shared connection)."""
    return create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


@pytest.fixture(scope="session")
def seeded_template():
    """Build the schema and seed the default rules once, in a template database.

    Seeding validates every default rule and takes far longer than copying the result.
    """
    engine = _memory_engine()
    SQLModel.metadata.create_all(engine)
    # The schema of the models is the latest revision: a command that migrates finds nothing to do
    with engine.begin() as connection:
        command.stamp(alembic_config(connection), "head")
    set_engine(engine)
    rule_store.seed_defaults()
    access_control.ensure_system_roles()
    set_engine(None)
    yield engine
    engine.dispose()


@pytest.fixture(autouse=True)
def database(seeded_template):
    """Provide a fresh in-memory SQLite database, seeded with the default rules, to each test.

    Each test gets its own copy of the template, so no state leaks from one test to another.
    """
    engine = _memory_engine()
    source = seeded_template.raw_connection()
    target = engine.raw_connection()
    try:
        source.driver_connection.backup(target.driver_connection)
    finally:
        target.close()
        source.close()
    set_engine(engine)
    yield engine
    set_engine(None)
    engine.dispose()


@pytest.fixture
def outdated_schema(database):
    """Mark the test database as one revision behind the latest (``db upgrade`` has work to
    do, ``db status`` reports it)."""
    from security_review_mcp.storage.database import head_revision

    with database.begin() as connection:
        command.stamp(alembic_config(connection), "0038")
    assert head_revision() != "0038"
    return database


@pytest.fixture
def legacy_database(database):
    """Replace the test database by a database of version 1.x: the tables of the baseline
    revision, without any revision."""
    from sqlalchemy import text

    engine = _memory_engine()
    with engine.begin() as connection:
        command.upgrade(alembic_config(connection), "0001")
        connection.execute(text("DROP TABLE alembic_version"))
    set_engine(engine)
    yield engine
    set_engine(database)
    engine.dispose()


@pytest.fixture(autouse=True)
def isolate_controller_environment(monkeypatch):
    """Ignore proxy and OSV update variables of the machine running the tests."""
    for name in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
        "SECREVIEW_OSV_AUTO_UPDATE",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def fast_password_hashing(request, monkeypatch):
    """Hash passwords with a tiny scrypt cost: the production one takes ~150 ms per hash.

    A stored hash carries its own cost, so verification is unchanged. A test marked
    ``real_password_hashing`` keeps the production cost.
    """
    if not request.node.get_closest_marker("real_password_hashing"):
        monkeypatch.setattr(web_users, "SCRYPT_N", 2**4)


@pytest.fixture(scope="session")
def settings_fields_set() -> set[str]:
    """Fields of the cached settings set by a variable when the tests start."""
    return set(get_settings().model_fields_set)


@pytest.fixture(autouse=True)
def reset_settings_fields_set(settings_fields_set):
    """Reset which cached settings count as set by a variable (see app_settings.env_set):
    monkeypatch.setattr marks a field as set, and so does undoing it."""
    object.__setattr__(get_settings(), "__pydantic_fields_set__", set(settings_fields_set))


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


# Permissions of a user who reads or triages every project, or of the admin (see make_user)
READER_GRANTS = {"reports.read": None}
TRIAGER_GRANTS = {"findings.triage": None, "reports.read": None}
ADMIN_GRANTS = {permission.value: None for permission in Permission}
# Per-project permissions of the former roles reader and triager, and of a reviewer (its MCP
# agent saves reports), which make_user and map_claim accept as a ``role``; admin is the built-in
# role, with every per-project permission
ROLE_PERMISSIONS = {
    "reader": ["reports.read"],
    "reviewer": ["reports.read", "reports.write"],
    "triager": ["findings.triage", "reports.read"],
    "admin": ["findings.triage", "reports.read", "reports.write"],
}


def role_id(name: str) -> int:
    """Id of the role ``name``."""
    from security_review_mcp.auth import access_control

    return {item["name"]: item["id"] for item in access_control.list_roles()}[name]


def known_projects(*names: str) -> None:
    """Make the projects ``names`` known (as a first report would)."""
    from security_review_mcp.storage.database import session_scope
    from security_review_mcp.storage.projects import ensure_project

    with session_scope() as session:
        for name in names:
            ensure_project(session, name)


def _access(role: str | None) -> tuple[list[int], list[str]]:
    """Role ids and per-project permissions of ``role``: reader, reviewer and triager are
    per-project permissions, admin the built-in role with every per-project permission, any other
    name a role."""
    if role is None:
        return [], []
    if role in ("reader", "reviewer", "triager"):
        return [], ROLE_PERMISSIONS[role]
    return [role_id(role)], ROLE_PERMISSIONS.get(role, [])


def map_claim(claim: str, role: str | None = None, projects: list[str] | None = None) -> None:
    """Add an OIDC mapping: the value ``claim`` of the roles claim gives ``role`` (see _access)
    on every project, or on ``projects`` (a project not known yet is ignored until it is
    created)."""
    from security_review_mcp.auth import access_control

    current = [
        (
            item["claim"],
            item["role_ids"],
            item["all_projects_permissions"],
            [(entry["project"], entry["permissions"]) for entry in item["projects"]],
        )
        for item in access_control.list_oidc_mappings()
    ]
    roles, permissions = _access(role)
    every = permissions if projects is None else []
    given = [(name, permissions) for name in projects or []] if permissions else []
    access_control.set_oidc_mappings([*current, (claim, roles, every, given)])


def make_user(
    username: str,
    password: str | None,
    role: str | None = None,
    projects: list[str] | None = None,
    created_by: str | None = None,
    auth_source: str = "local",
    must_change: bool = False,
    role_ids: list[int] | None = None,
    read_only: list[str] | None = None,
) -> dict:
    """Create a web user with ``role`` (see _access) on ``projects`` (made known first), or on
    every project without any, the roles ``role_ids`` and the reading of ``read_only``.

    A local user created by an administrator must change its password at its first login; it
    is created as if it had already done it, unless ``must_change``.
    """
    from security_review_mcp.auth import web_users
    from security_review_mcp.storage.database import session_scope
    from security_review_mcp.storage.models import WebUser

    roles, permissions = _access(role)
    roles += role_ids or []
    known_projects(*(projects or []), *(read_only or []))
    bindings = [(name, permissions or ["reports.read"]) for name in projects or []]
    bindings += [(name, ["reports.read"]) for name in read_only or []]
    every = permissions if not projects else []
    created = web_users.create_user(
        username,
        password,
        roles,
        bindings,
        created_by,
        auth_source,
        all_projects_permissions=every,
    )
    if not must_change and created["must_change_password"]:
        with session_scope() as session:
            row = session.get(WebUser, created["id"])
            row.must_change_password = False
            session.add(row)
        created["must_change_password"] = False
    return created


@pytest.fixture
def anyio_backend():
    """Run every async test with asyncio only."""
    return "asyncio"
