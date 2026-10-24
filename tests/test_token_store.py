"""Tokens stored in the database: creation, lookup, revocation, project scope, bootstrap admin."""

from datetime import UTC, datetime, timedelta

import pytest
from conftest import make_user
from sqlmodel import Session, select

from security_review_mcp.auth import token_store
from security_review_mcp.config import get_settings
from security_review_mcp.http_server import Role, TokenInfo, hash_token
from security_review_mcp.observability import audit
from security_review_mcp.storage import database as database_module
from security_review_mcp.storage.models import ApiToken, ApiTokenProject

STORE = token_store.DatabaseTokenStore()


def digest_of(token: str) -> bytes:
    return hash_token(token)


def stored_rows(database) -> list[ApiToken]:
    with Session(database) as session:
        return list(session.exec(select(ApiToken)).all())


def link_rows(database) -> list[ApiTokenProject]:
    with Session(database) as session:
        return list(session.exec(select(ApiTokenProject)).all())


# ── Project tokens ───────────────────────────────────────────────────────────


def test_project_token_is_stored_as_hash_and_revoked(database):
    created = token_store.create_project_token(" ci ", "shop-api")

    (row,) = stored_rows(database)
    assert row.token_hash == digest_of(created["token"]).hex()
    assert created["token"] not in row.model_dump_json()
    assert STORE.lookup(digest_of(created["token"])) == TokenInfo(
        "ci", Role.MCP, projects=frozenset({"shop-api"}), token_id=created["id"]
    )
    listed = token_store.list_project_tokens()
    assert listed == [{key: value for key, value in created.items() if key != "token"}]
    assert created["projects"] == ["shop-api"]
    assert created["token"] not in str(listed)

    token_store.revoke_project_token(created["id"])
    assert STORE.lookup(digest_of(created["token"])) is None
    assert STORE.has_tokens() is False
    # Its project rows are deleted with it
    assert link_rows(database) == []
    with pytest.raises(ValueError, match="not found"):
        token_store.revoke_project_token(created["id"])


def test_token_validation():
    token_store.create_token("ops", Role.ADMIN)

    with pytest.raises(ValueError, match="already exists"):
        token_store.create_project_token("ops", "billing")
    with pytest.raises(ValueError, match="Unknown role"):
        token_store.create_token("boss", "boss")
    with pytest.raises(ValueError, match="admin token cannot be restricted"):
        token_store.create_token("boss-admin", Role.ADMIN, "billing")
    for role in (Role.MCP, Role.CI):
        created = token_store.create_token(f"{role}-billing", role, "billing")
        assert (created["project"], created["projects"]) == ("billing", ["billing"])
    with pytest.raises(ValueError, match="between 1 and 64"):
        token_store.create_project_token("  ", "billing")
    with pytest.raises(ValueError, match="between 1 and 200"):
        token_store.create_project_token("other", "p" * 201)
    with pytest.raises(ValueError, match="at least one project"):
        token_store.create_project_token("other", [])


@pytest.mark.parametrize(
    ("role", "error"),
    [(Role.USER, "through a group"), ("reader", "Unknown role"), ("triager", "Unknown role")],
)
def test_a_token_is_never_given_to_a_person(database, role, error):
    """A person reaches the web API through a session and its groups, never a token (reader and
    triager were the roles of a web session in older versions)."""
    with pytest.raises(ValueError, match=error):
        token_store.create_token("person", role)
    with pytest.raises(ValueError, match="cannot be created in the web interface"):
        token_store.create_project_token("person", ["shop-api"], role)
    assert stored_rows(database) == []

    # A row left by an older version authenticates nothing (fail closed)
    with Session(database) as session:
        session.add(ApiToken(id="t1", label="old", role=str(role), token_hash="ab" * 32))
        session.commit()
    assert STORE.lookup(bytes.fromhex("ab" * 32)) is None


def test_ci_token_is_always_restricted_to_projects():
    with pytest.raises(ValueError, match="ci token must be restricted"):
        token_store.create_token("jenkins", Role.CI)
    with pytest.raises(ValueError, match="ci token must be restricted"):
        token_store.create_token("jenkins", "ci", [])

    created = token_store.create_project_token("jenkins", ["shop-api", "billing"], "ci")
    info = STORE.lookup(digest_of(created["token"]))
    assert (info.role, info.projects) == (Role.CI, frozenset({"shop-api", "billing"}))


def test_project_names_of_a_token_are_normalized():
    created = token_store.create_project_token(
        "jenkins", ["Acme/Shop_API", "shop-api", "git@github.com:acme/Billing.git"], "ci"
    )
    info = STORE.lookup(digest_of(created["token"]))
    assert info.projects == frozenset({"shop-api", "billing"})
    assert [token["label"] for token in token_store.list_tokens(project="SHOP API")] == [
        created["label"]
    ]
    with pytest.raises(ValueError, match="between 1 and 200"):
        token_store.create_project_token("jenkins", ["---"], "ci")


def test_unrestricted_ci_row_reaches_no_project(database):
    # A ci row without projects (written outside create_token) fails closed
    created = token_store.create_token("jenkins", Role.MCP)
    with Session(database) as session:
        row = session.get(ApiToken, created["id"])
        row.role = Role.CI.value
        session.add(row)
        session.commit()

    info = STORE.lookup(digest_of(created["token"]))
    assert (info.role, info.projects) == (Role.CI, frozenset())


def test_project_token_limit(monkeypatch):
    monkeypatch.setattr(token_store, "MAX_TOKENS", 2)
    token_store.create_project_token("one", "shop-api")
    token_store.create_project_token("two", "shop-api")

    with pytest.raises(ValueError, match="limit of 2"):
        token_store.create_project_token("three", "shop-api")


def test_unknown_token_is_rejected():
    assert STORE.lookup(digest_of("z" * 40)) is None


def test_admin_token_is_not_a_project_token(database):
    password = token_store.create_token("ops", Role.ADMIN)["token"]

    (row,) = stored_rows(database)
    assert password not in row.model_dump_json()
    info = STORE.lookup(digest_of(password))
    assert (info.label, info.role, info.projects) == ("ops", Role.ADMIN, None)
    # The administrator is not a project token: it is not listed nor revocable as one
    assert token_store.list_project_tokens() == []
    with pytest.raises(ValueError, match="not found"):
        token_store.revoke_project_token(row.id)


def test_revoke_token_by_id_or_label():
    admin = token_store.create_token("ops", Role.ADMIN)
    ci = token_store.create_token("ci", Role.MCP)

    assert token_store.revoke_token("ops")["id"] == admin["id"]
    assert token_store.revoke_token(ci["id"])["label"] == "ci"
    assert STORE.has_tokens() is False
    with pytest.raises(ValueError, match="not found"):
        token_store.revoke_token("ci")


def test_list_tokens_filters_by_project_and_hides_hashes(database):
    token_store.create_token("ci", Role.MCP)
    shop = token_store.create_project_token("shop", "shop-api")

    assert [token["label"] for token in token_store.list_tokens()] == ["ci", "shop"]
    assert token_store.list_tokens("shop-api") == [
        {key: value for key, value in shop.items() if key != "token"}
    ]
    assert token_store.list_tokens()[0]["projects"] is None
    assert stored_rows(database)[0].token_hash not in str(token_store.list_tokens())


def test_web_users_count_as_credentials_of_the_controller_only():
    make_user("alice", "Correct horse battery 9", "reader")

    assert STORE.has_tokens() is False
    assert token_store.DatabaseTokenStore(include_users=True).has_tokens() is True


# ── Multi-project tokens ─────────────────────────────────────────────────────


def test_token_restricted_to_several_projects(database):
    created = token_store.create_token("ci", Role.MCP, [" shop-api ", "billing", "shop-api"])

    assert (created["project"], created["projects"]) == ("shop-api", ["shop-api", "billing"])
    assert STORE.lookup(digest_of(created["token"])).projects == {"shop-api", "billing"}
    assert [token["label"] for token in token_store.list_tokens("billing")] == ["ci"]
    assert token_store.list_tokens("other") == []
    with pytest.raises(ValueError, match="admin token cannot be restricted"):
        token_store.create_token("boss", Role.ADMIN, ["a", "b"])


def test_project_count_of_a_token_is_bounded(monkeypatch):
    monkeypatch.setattr(token_store, "MAX_PROJECTS_PER_TOKEN", 2)

    with pytest.raises(ValueError, match="at most 2 projects"):
        token_store.create_token("ci", Role.MCP, ["a", "b", "c"])
    created = token_store.create_token("ci", Role.MCP, ["a", "b"])
    with pytest.raises(ValueError, match="at most 2 projects"):
        token_store.set_token_projects(created["id"], ["a", "b", "c"])


def test_legacy_project_tokens_are_migrated(database):
    with Session(database) as session:
        session.add(
            ApiToken(id="t1", label="old", role="mcp", project="shop-api", token_hash="ab" * 32)
        )
        session.add(ApiToken(id="t2", label="admin", role="admin", token_hash="cd" * 32))
        session.commit()

    # Before the migration a legacy token stays restricted to its project
    assert STORE.lookup(bytes.fromhex("ab" * 32)).projects == {"shop-api"}
    # The baseline migration completes a database created by version 1.x
    database_module.upgrade_db()
    database_module.upgrade_db()  # already at the latest revision: nothing is copied twice

    links = {link.token_id: link.project for link in link_rows(database)}
    assert links == {"t1": "shop-api"}
    assert STORE.lookup(bytes.fromhex("ab" * 32)).projects == {"shop-api"}
    assert STORE.lookup(bytes.fromhex("cd" * 32)).projects is None


# ── Expiry and rotation ──────────────────────────────────────────────────────


def _set_dates(database, label: str, **values) -> None:
    """Change date columns of a stored token (simulates the passing of time)."""
    with Session(database) as session:
        row = session.exec(select(ApiToken).where(ApiToken.label == label)).one()
        for name, value in values.items():
            setattr(row, name, value)
        session.add(row)
        session.commit()


def test_a_token_without_expiry_never_expires():
    created = token_store.create_token("dev", Role.MCP)

    assert created["expires_at"] is None
    assert created["expired"] is False
    assert STORE.lookup(digest_of(created["token"])).expired is False


def test_an_expired_token_is_marked_but_still_counts_as_configured(database):
    created = token_store.create_token("dev", Role.MCP, expires_in_days=30)
    assert created["expires_at"] is not None

    _set_dates(database, "dev", expires_at=datetime.now(UTC) - timedelta(seconds=1))

    assert STORE.lookup(digest_of(created["token"])).expired is True
    (listed,) = token_store.list_tokens()
    assert listed["expired"] is True
    # Fail closed: expired tokens never turn authentication off
    assert STORE.has_tokens() is True


def test_token_max_days_is_the_default_and_the_limit(monkeypatch):
    monkeypatch.setattr(get_settings(), "token_max_days", 90)

    created = token_store.create_token("dev", Role.MCP)
    expires_at = datetime.fromisoformat(created["expires_at"])
    assert timedelta(days=89) < expires_at - datetime.now(UTC) <= timedelta(days=90)
    assert token_store.create_token("short", Role.MCP, expires_in_days=7)["expires_at"]
    with pytest.raises(ValueError, match="between 1 and 90 days"):
        token_store.create_token("long", Role.MCP, expires_in_days=91)
    with pytest.raises(ValueError, match="between 1 and 90 days"):
        token_store.create_token("zero", Role.MCP, expires_in_days=0)


def test_rotation_replaces_the_secret_and_keeps_the_token(database):
    created = token_store.create_token("ci", Role.MCP, ["shop-api"])

    rotated = token_store.rotate_token("ci")

    assert rotated["id"] == created["id"]
    assert rotated["projects"] == ["shop-api"]
    assert rotated["token"] != created["token"]
    assert rotated["rotated_at"] is not None
    assert rotated["grace_until"] is None
    assert STORE.lookup(digest_of(created["token"])) is None
    assert STORE.lookup(digest_of(rotated["token"])).label == "ci"
    (row,) = stored_rows(database)
    assert row.previous_token_hash is None
    assert rotated["token"] not in row.model_dump_json()


def test_the_previous_secret_works_during_the_grace_period_only(database):
    created = token_store.create_token("ci", Role.MCP)
    rotated = token_store.rotate_token(created["id"], grace_hours=24)

    assert rotated["grace_until"] is not None
    assert STORE.lookup(digest_of(created["token"])).label == "ci"
    assert STORE.lookup(digest_of(rotated["token"])).label == "ci"

    _set_dates(database, "ci", previous_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    assert STORE.lookup(digest_of(created["token"])) is None
    assert STORE.lookup(digest_of(rotated["token"])).label == "ci"


def test_an_expired_secret_never_comes_back_with_a_rotation(database):
    created = token_store.create_token("ci", Role.MCP, expires_in_days=1)
    _set_dates(database, "ci", expires_at=datetime.now(UTC) - timedelta(seconds=1))

    rotated = token_store.rotate_token("ci", grace_hours=24, expires_in_days=30)

    assert rotated["grace_until"] is None
    assert rotated["expired"] is False
    assert STORE.lookup(digest_of(created["token"])) is None
    assert STORE.lookup(digest_of(rotated["token"])).expired is False


def test_rotation_refuses_bad_requests():
    token_store.create_token("ops", Role.ADMIN)

    with pytest.raises(ValueError, match="not found"):
        token_store.rotate_token("missing")
    with pytest.raises(ValueError, match="grace period"):
        token_store.rotate_token("ops", grace_hours=token_store.MAX_ROTATION_GRACE_HOURS + 1)
    # The web interface only rotates project tokens
    ops = next(token for token in token_store.list_tokens() if token["label"] == "ops")
    with pytest.raises(ValueError, match="Project token"):
        token_store.rotate_token(ops["id"], project_token=True)


def test_a_metrics_token_cannot_be_restricted_to_projects():
    assert token_store.create_token("prometheus", Role.METRICS)["projects"] is None
    with pytest.raises(ValueError, match="metrics token cannot be restricted"):
        token_store.create_token("scraper", Role.METRICS, ["shop-api"])


def test_token_counts_by_role_and_state(database):
    token_store.create_token("dev", Role.MCP)
    token_store.create_token("soon", Role.MCP, expires_in_days=3)
    token_store.create_token("old", Role.ADMIN, expires_in_days=30)
    _set_dates(database, "old", expires_at=datetime.now(UTC) - timedelta(days=1))

    counts = token_store.token_counts()

    assert counts["by_role_and_state"] == {("mcp", "active"): 2, ("admin", "expired"): 1}
    assert counts["expiring_soon"] == 1


# ── Projects of a web token ──────────────────────────────────────────────────


def test_web_token_for_every_project():
    created = token_store.create_project_token("portal", None, Role.MCP)

    assert (created["project"], created["projects"]) == (None, None)
    info = STORE.lookup(digest_of(created["token"]))
    assert (info.role, info.projects) == (Role.MCP, None)
    assert [token["label"] for token in token_store.list_project_tokens()] == ["portal"]
    # An empty list is refused, never read as every project
    with pytest.raises(ValueError, match="at least one project"):
        token_store.create_project_token("empty", [])
    with pytest.raises(ValueError, match="ci token must be restricted"):
        token_store.create_project_token("pipeline", None, Role.CI)
    with pytest.raises(ValueError, match="cannot be created in the web interface"):
        token_store.create_project_token("boss", None, Role.ADMIN)


def test_set_token_projects_restricts_and_widens_a_token(database):
    created = token_store.create_project_token("dev", ["shop-api"], Role.MCP)
    digest = digest_of(created["token"])

    widened = token_store.set_token_projects(created["id"], None, actor="user:root")

    assert (widened["project"], widened["projects"]) == (None, None)
    assert STORE.lookup(digest).projects is None
    assert link_rows(database) == []
    restricted = token_store.set_token_projects(created["id"], ["billing", " shop-api "])
    assert (restricted["project"], restricted["projects"]) == ("billing", ["billing", "shop-api"])
    assert STORE.lookup(digest).projects == frozenset({"billing", "shop-api"})
    # The secret is kept and every change is audited with the previous projects
    (latest, first) = audit.list_events(action="token.projects_changed")["events"]
    assert (first["actor"], first["details"]["previous_projects"]) == ("user:root", ["shop-api"])
    assert (latest["details"]["previous_projects"], latest["details"]["projects"]) == (
        None,
        ["billing", "shop-api"],
    )


def test_set_token_projects_refusals():
    admin = token_store.create_token("ops", Role.ADMIN)
    ci = token_store.create_project_token("pipeline", ["shop-api"], Role.CI)
    reader = token_store.create_project_token("reader", ["shop-api"])

    with pytest.raises(ValueError, match="not found"):
        token_store.set_token_projects(admin["id"], ["shop-api"])
    with pytest.raises(ValueError, match="not found"):
        token_store.set_token_projects("missing", None)
    with pytest.raises(ValueError, match="ci token must be restricted"):
        token_store.set_token_projects(ci["id"], None)
    with pytest.raises(ValueError, match="at least one project"):
        token_store.set_token_projects(reader["id"], [])
    with pytest.raises(ValueError, match="at most"):
        token_store.set_token_projects(
            reader["id"], [f"p{index}" for index in range(token_store.MAX_PROJECTS_PER_TOKEN + 1)]
        )
    # Nothing changed
    assert STORE.lookup(digest_of(ci["token"])).projects == frozenset({"shop-api"})
    assert STORE.lookup(digest_of(admin["token"])).projects is None


# ── api tokens ───────────────────────────────────────────────────────────────


def test_an_api_token_needs_a_role_or_an_owner(database):
    with pytest.raises(ValueError, match="created with a role"):
        token_store.create_token("swagger", Role.API)
    with pytest.raises(ValueError, match="needs a role"):
        token_store.create_project_token("swagger", None, Role.API)

    # A stored api row without role nor owner authenticates nothing (fail closed)
    with Session(database) as session:
        session.add(ApiToken(id="t1", label="orphan", role="api", token_hash="ab" * 32))
        session.commit()
    assert STORE.lookup(bytes.fromhex("ab" * 32)) is None


def test_a_role_api_token_without_its_role_authenticates_nothing(database):
    from security_review_mcp.auth import access_control

    role = access_control.create_role("Auditor", ["audit.read"])
    created = token_store.create_project_token("audit", None, Role.API, access_role_id=role["id"])
    info = STORE.lookup(digest_of(created["token"]))
    assert (info.role, dict(info.grants)) == (Role.API, {"audit.read": None})

    with Session(database) as session:
        row = session.get(ApiToken, created["id"])
        row.access_role_id = 999
        session.add(row)
        session.commit()
    assert STORE.lookup(digest_of(created["token"])) is None


def test_the_label_of_a_personal_token_names_its_user():
    from conftest import make_user

    user = make_user("a" * 60, "Correct horse battery 9", "reader")

    with pytest.raises(ValueError, match="at most 3 characters"):
        token_store.create_personal_token(user["id"], "four")
    created = token_store.create_personal_token(user["id"], "abc")
    assert created["label"] == "a" * 60 + ":abc"
    with pytest.raises(ValueError, match="cannot be rotated"):
        token_store.rotate_token(created["id"])
    with pytest.raises(ValueError, match="not found"):
        token_store.create_personal_token(999, "x")


@pytest.mark.parametrize("role", [Role.MCP, Role.CI])
def test_a_personal_token_reaches_the_projects_its_user_may_read(role):
    """The projects are read at each request: a project granted or removed applies at once."""
    from conftest import group_for

    from security_review_mcp.auth import web_users

    user = make_user("alice", "Correct horse battery 9", "reader", ["shop-api"])
    created = token_store.create_personal_token(user["id"], "agent", role=role)
    assert (created["role"], created["personal"], created["projects"]) == (role, True, None)

    info = STORE.lookup(digest_of(created["token"]))
    assert (info.role, info.projects, info.owner) == (role, frozenset({"shop-api"}), "alice")
    # The owner names the author of a report, never a web session (user_id)
    assert info.user_id is None
    listed = token_store.list_personal_tokens(user["id"])
    assert [item["projects"] for item in listed] == [["shop-api"]]

    web_users.update_user(user["id"], [group_for("reader", ["billing", "shop-api"])])
    info = STORE.lookup(digest_of(created["token"]))
    assert info.projects == frozenset({"billing", "shop-api"})
    # Without any group, the token reaches no project (never every project)
    web_users.update_user(user["id"], [])
    assert STORE.lookup(digest_of(created["token"])).projects == frozenset()
    web_users.update_user(user["id"], [group_for("reader")])
    assert STORE.lookup(digest_of(created["token"])).projects is None


def test_a_personal_mcp_token_reaches_a_project_its_user_creates():
    from security_review_mcp.auth import access_control

    role = access_control.create_role("Creator", ["projects.create"])
    group = access_control.create_group("creators")
    access_control.set_group_roles(group["id"], [(role["id"], None)])
    user = make_user("carol", "Correct horse battery 9", group_ids=[group["id"]])
    created = token_store.create_personal_token(user["id"], "agent", role="mcp")
    assert STORE.lookup(digest_of(created["token"])).projects == frozenset()

    access_control.create_project(user["id"], "mobile-app")

    assert STORE.lookup(digest_of(created["token"])).projects == frozenset({"mobile-app"})


def test_a_personal_mcp_token_keeps_the_projects_of_its_user():
    user = make_user("alice", "Correct horse battery 9", "reader", ["shop-api"])
    created = token_store.create_personal_token(user["id"], "agent", role="mcp")

    with pytest.raises(ValueError, match="no projects"):
        token_store.set_token_projects(created["id"], ["billing"])
    with pytest.raises(ValueError, match="cannot be rotated"):
        token_store.rotate_token(created["id"])


def test_a_personal_mcp_token_stops_with_its_user():
    from security_review_mcp.auth import web_users

    user = make_user("alice", "Correct horse battery 9", "reader", ["shop-api"])
    created = token_store.create_personal_token(user["id"], "agent", role="mcp")

    # A password set by an administrator stops it until the user chooses its own
    web_users.set_password(user["id"], "Another horse battery 9")
    assert STORE.lookup(digest_of(created["token"])) is None
    web_users.set_password(user["id"], "Correct horse battery 9", must_change=False)
    assert STORE.lookup(digest_of(created["token"])) is not None

    web_users.delete_user(user["id"], "token:admin")

    assert STORE.lookup(digest_of(created["token"])) is None


def test_personal_tokens_are_bounded_per_role(monkeypatch):
    user = make_user("alice", "Correct horse battery 9", "reader")
    token_store.create_personal_token(user["id"], "rest")
    token_store.create_personal_token(user["id"], "agent", role="mcp")

    # One token of each role by default (SECREVIEW_PERSONAL_TOKENS_PER_USER)
    with pytest.raises(ValueError, match="at most 1 personal api token"):
        token_store.create_personal_token(user["id"], "rest-2")
    with pytest.raises(ValueError, match="at most 1 personal mcp token"):
        token_store.create_personal_token(user["id"], "agent-2", role="mcp")
    monkeypatch.setattr(get_settings(), "personal_tokens_per_user", 2)
    token_store.create_personal_token(user["id"], "agent-2", role="mcp")
    # Only an api, mcp or ci token is personal
    for role in ("admin", "metrics", "nope"):
        with pytest.raises(ValueError, match="cannot create a personal"):
            token_store.create_personal_token(user["id"], "other", role=role)


def test_only_a_personal_token_has_a_colon_in_its_label():
    """``<username>:<label>`` names the user of a personal token: no other token imitates it."""
    with pytest.raises(ValueError, match="must not contain ':'"):
        token_store.create_token("alice:swagger", Role.MCP)
    with pytest.raises(ValueError, match="must not contain ':'"):
        token_store.create_project_token("alice:swagger", None, Role.MCP)
