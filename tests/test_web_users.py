"""Web users: password hashing, accounts, sessions, login throttling and the ``user`` CLI."""

import json

import pytest
from conftest import ADMIN_GRANTS, TRIAGER_GRANTS, group_for, make_user
from sqlmodel import Session, select

from security_review_mcp import access_control, cli, oidc, web_users
from security_review_mcp.config import Settings
from security_review_mcp.http_server import Role
from security_review_mcp.services import NotFoundError
from security_review_mcp.storage.models import WebUser

PASSWORD = "Correct horse battery 9"
SECRET = "s" * 40


def stored(database, username: str) -> WebUser:
    with Session(database) as session:
        return session.exec(select(WebUser).where(WebUser.username == username)).one()


# ── Passwords ────────────────────────────────────────────────────────────────


def test_password_hash_is_salted_and_verified():
    first, second = web_users.hash_password(PASSWORD), web_users.hash_password(PASSWORD)

    assert first != second and PASSWORD not in first
    assert first.startswith("scrypt$16384$8$5$")
    assert web_users.verify_password(PASSWORD, first)
    assert not web_users.verify_password(PASSWORD + "!", first)


@pytest.mark.parametrize(
    "stored_hash",
    [
        "",
        "plain-text",
        "bcrypt$16384$8$5$c2FsdA$a2V5",
        "scrypt$1000$8$5$c2FsdA$a2V5",  # N is not a power of two
        "scrypt$2097152$8$5$c2FsdA$a2V5",  # N above the accepted bound
        "scrypt$16384$8$99$c2FsdA$a2V5",  # p above the accepted bound
        "scrypt$16384$8$5$!!$a2V5",
        "scrypt$16384$8$5$c2FsdA$",
    ],
)
def test_malformed_or_oversized_hashes_never_match(stored_hash):
    assert web_users.verify_password(PASSWORD, stored_hash) is False


@pytest.mark.parametrize(
    ("password", "message"),
    [
        ("Sh0rt!", "between 12 and 256"),
        ("Xx1!" * 65, "between 12 and 256"),
        ("only lowercase 1!", "an uppercase letter"),
        ("ONLY UPPERCASE 1!", "a lowercase letter"),
        ("No digit at all!", "a digit"),
        ("NoSymbolAtAll123", "neither a letter nor a digit"),
        (" " * 12, "a lowercase letter, an uppercase letter, a digit"),
        ("Abcdefghij1\n", "control characters"),
    ],
)
def test_weak_or_invalid_passwords_are_refused(password, message):
    with pytest.raises(ValueError, match=message):
        make_user("alice", password, "reader")


def test_generated_passwords_follow_the_policy():
    passwords = [web_users.generate_password() for _ in range(50)]

    assert all(len(password) == web_users.GENERATED_PASSWORD_CHARS for password in passwords)
    assert all(web_users.password_problems(password) == [] for password in passwords)


def test_the_policy_applies_to_new_passwords_only(database):
    # A password stored before the policy (written directly) keeps working
    user = make_user("alice", PASSWORD, "reader")
    with Session(database) as session:
        row = session.get(WebUser, user["id"])
        row.password_hash = web_users.hash_password("old weak password")
        session.add(row)
        session.commit()

    assert web_users.authenticate("alice", "old weak password") is not None
    with pytest.raises(ValueError, match="an uppercase letter"):
        web_users.change_own_password(user["id"], "old weak password", "another weak one")


@pytest.mark.parametrize("username", ["", " ", "a" * 65, "bob smith", "-bob", "bo\nb", "é"])
def test_invalid_usernames_are_refused(username):
    with pytest.raises(ValueError, match="Username"):
        make_user(username, PASSWORD, "reader")


# ── Accounts ─────────────────────────────────────────────────────────────────


def test_create_user_stores_only_a_hash(database):
    created = make_user("alice", PASSWORD, "triager", ["shop-api"], "ops")

    assert "password" not in created
    row = stored(database, "alice")
    assert PASSWORD not in row.model_dump_json()
    assert "password_hash" not in json.dumps(web_users.list_users())


def test_create_user_generates_a_password_shown_once():
    created = make_user("alice", None, "reader")

    assert web_users.authenticate("alice", created["password"])["username"] == "alice"
    assert "password" not in web_users.list_users()[0]


def test_duplicate_users_and_unknown_groups_are_refused():
    make_user("alice", PASSWORD, "reader")

    with pytest.raises(ValueError, match="already exists"):
        make_user("alice", PASSWORD, "admin")
    with pytest.raises(NotFoundError, match="Group 999"):
        web_users.create_user("bob", PASSWORD, [999])
    # Nothing is created when a group is unknown
    assert [user["username"] for user in web_users.list_users()] == ["alice"]


def test_a_user_without_groups_has_no_permission():
    signer = oidc.SessionSigner(SECRET)
    user = web_users.create_user("alice", PASSWORD)

    assert (user["groups"], user["permissions"]) == ([], {})
    with pytest.raises(ValueError, match="no permission"):
        web_users.new_session(signer, user["id"])


def test_user_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(web_users, "MAX_USERS", 1)
    make_user("alice", PASSWORD, "reader")

    with pytest.raises(ValueError, match="limit of 1"):
        make_user("bob", PASSWORD, "reader")


def test_authenticate_checks_the_password_and_records_the_login(database):
    make_user("alice", PASSWORD, "reader")

    assert web_users.authenticate("alice", "wrong password!") is None
    assert web_users.authenticate("nobody", PASSWORD) is None
    assert stored(database, "alice").last_login_at is None
    user = web_users.authenticate("alice", PASSWORD)
    assert user is not None and user["last_login_at"] is not None


@pytest.mark.parametrize("auth_source", ["local", "oidc"])
def test_last_administrator_is_kept(auth_source):
    password = PASSWORD if auth_source == "local" else None
    admin = make_user("admin", password, "admin", auth_source=auth_source)
    readers = group_for("reader", ["shop-api"])

    with pytest.raises(ValueError, match="last holder of users.manage"):
        web_users.delete_user(admin["id"])
    with pytest.raises(ValueError, match="keep the users.manage"):
        web_users.update_user(admin["id"], [readers])
    # A refused deletion revokes no OIDC identity
    assert web_users.list_revoked_users() == []

    other = make_user("root", PASSWORD, "admin")
    demoted = web_users.update_user(admin["id"], [readers])
    assert demoted["permissions"] == {"reports.read": ["shop-api"]}
    with pytest.raises(ValueError, match="last holder of users.manage"):
        web_users.delete_user(other["id"])


def test_unknown_users_raise_not_found():
    with pytest.raises(NotFoundError):
        web_users.delete_user(42)
    with pytest.raises(NotFoundError):
        web_users.find_user("nobody")


def test_change_own_password_needs_the_current_one():
    user = make_user("alice", PASSWORD, "reader")

    with pytest.raises(ValueError, match="current password is wrong"):
        web_users.change_own_password(user["id"], "not the password", "Another long secret 2")
    with pytest.raises(ValueError, match="must differ"):
        web_users.change_own_password(user["id"], PASSWORD, PASSWORD)
    web_users.change_own_password(user["id"], PASSWORD, "Another long secret 2")
    assert web_users.authenticate("alice", PASSWORD) is None
    assert web_users.authenticate("alice", "Another long secret 2") is not None


def test_a_password_set_by_someone_else_must_be_changed(database):
    signer = oidc.SessionSigner(SECRET)
    created = web_users.create_user("alice", PASSWORD, [group_for("reader")], created_by="admin")
    assert created["must_change_password"] is True
    assert web_users.new_session(signer, created["id"])["must_change_password"] is True
    session = web_users.new_session(signer, created["id"])["session"]
    assert web_users.SessionVerifier(signer).verify_session(session).must_change_password

    # Changed by the user itself: done
    web_users.change_own_password(created["id"], PASSWORD, "Another long secret 2")
    assert web_users.find_user("alice")["must_change_password"] is False
    # Reset by an administrator: to change again
    web_users.set_password(created["id"])
    assert web_users.find_user("alice")["must_change_password"] is True
    # An OIDC user has no password to change
    sso = web_users.create_user("bob", None, None, auth_source="oidc")
    assert sso["must_change_password"] is False


def test_bootstrap_admin_is_created_once_while_no_user_exists():
    assert web_users.ensure_bootstrap_admin() is True
    assert web_users.ensure_bootstrap_admin() is False
    # Its random password is never handed out: the operator sets one with the CLI
    admin = web_users.find_user("admin")
    password = web_users.set_password(admin["id"])["password"]
    user = web_users.authenticate("admin", password)
    assert (user["permissions"], user["created_by"]) == (ADMIN_GRANTS, "bootstrap")
    assert [group["name"] for group in user["groups"]] == ["administrators"]
    assert user["must_change_password"] is True


def test_no_bootstrap_admin_once_another_user_exists():
    make_user("alice", PASSWORD, "reader")

    assert web_users.ensure_bootstrap_admin() is False
    assert [user["username"] for user in web_users.list_users()] == ["alice"]


# ── Sessions ─────────────────────────────────────────────────────────────────


def test_session_follows_the_stored_user():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    user = make_user("alice", PASSWORD, "reader", ["shop-api"])
    session = web_users.new_session(signer, user["id"])["session"]

    info = verifier.verify_session(session)
    assert (info.label, info.role, info.projects, info.user_id) == (
        "alice",
        Role.USER,
        frozenset({"shop-api"}),
        user["id"],
    )
    assert info.grants == {"reports.read": frozenset({"shop-api"})}
    # A new group applies to the open session at once
    web_users.update_user(user["id"], [group_for("triager")])
    info = verifier.verify_session(session)
    assert (info.role, info.projects, info.grants) == (Role.USER, None, TRIAGER_GRANTS)
    # A deleted user loses its sessions
    make_user("root", PASSWORD, "admin")
    web_users.delete_user(user["id"])
    assert verifier.verify_session(session) is None


def test_password_change_ends_the_previous_sessions():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    user = make_user("alice", PASSWORD, "reader")
    before = web_users.new_session(signer, user["id"])["session"]
    assert verifier.verify_session(before) is not None

    # Even within the same second as the session: the version, not the time, is compared
    web_users.set_password(user["id"], "Another long secret 2")

    assert verifier.verify_session(before) is None
    after = web_users.new_session(signer, user["id"])
    assert after["username"] == "alice"
    assert verifier.verify_session(after["session"]).user_id == user["id"]


# ── OIDC users ────────────────────────────────────────────────────────────────


def sso_settings(**values) -> Settings:
    """OIDC settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


ISSUER = "https://sso.example.com"


def identity(
    username: str | None = "alice", subject: str = "sub-1", *groups: str, issuer: str = ISSUER
):
    """A verified OIDC login."""
    return oidc.OidcIdentity(
        username=username,
        subject=subject,
        issuer=issuer,
        groups=frozenset(groups),
        label=f"oidc:{username}",
        return_url="/",
    )


def login(signer, user=None, **settings) -> dict:
    """Run web_users.oidc_login with these settings."""
    return web_users.oidc_login(signer, user or identity(), sso_settings(**settings))


def test_sso_user_has_no_password_and_may_have_no_group(database):
    created = web_users.create_user("alice", None, None, created_by="admin", auth_source="oidc")

    assert (created["auth_source"], created["groups"], created["permissions"]) == (
        "oidc",
        [],
        {},
    )
    assert "password" not in created and created["password_changed_at"] is None
    assert stored(database, "alice").password_hash is None
    with pytest.raises(ValueError, match="no password"):
        make_user("bob", PASSWORD, "reader", auth_source="oidc")
    with pytest.raises(ValueError, match="no password"):
        web_users.set_password(created["id"])
    with pytest.raises(ValueError, match="no password"):
        web_users.change_own_password(created["id"], PASSWORD, PASSWORD + "!")
    with pytest.raises(ValueError, match="Source"):
        make_user("erin", None, "reader", auth_source="ldap")
    # An OIDC user never logs in with a password
    assert web_users.authenticate("alice", "") is None
    assert web_users.authenticate("alice", PASSWORD) is None


def test_sso_login_refuses_an_unknown_user_without_auto_creation():
    signer = oidc.SessionSigner(SECRET)
    group_for("reader", name="devs", sso=True)
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity("alice", "sub-1", "devs"))
    assert exc.value.code == "unknown_user"
    assert web_users.list_users() == []


def test_sso_login_creates_the_user_when_auto_creation_is_enabled(database):
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    group_for("triager", name="devs", sso=True)
    user_identity = identity("alice", "sub-1", "devs", "unknown")
    result = login(signer, user_identity, oidc_auto_create_users=True)

    (user,) = web_users.list_users()
    assert (user["username"], user["auth_source"], user["created_by"]) == (
        "alice",
        "oidc",
        "oidc",
    )
    assert [(g["name"], g["source"]) for g in user["groups"]] == [("devs", "oidc")]
    assert user["permissions"] == TRIAGER_GRANTS
    assert user["sso_linked"] and user["last_login_at"]
    assert stored(database, "alice").oidc_subject == "sub-1"
    info = verifier.verify_session(result["session"])
    assert (info.label, info.role, info.auth_source) == ("oidc:alice", Role.USER, "oidc")
    assert info.grants == TRIAGER_GRANTS


def test_sso_login_never_creates_a_user_without_a_permission():
    signer = oidc.SessionSigner(SECRET)
    # A group of the claim without any role gives no permission either
    access_control.create_group("devs")
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity("alice", "sub-1", "devs"), oidc_auto_create_users=True)
    assert exc.value.code == "forbidden"
    assert web_users.list_users() == []


def test_sso_login_only_matches_the_groups_open_to_sso():
    signer = oidc.SessionSigner(SECRET)
    group_for("admin", name="local-admins", sso=False)
    make_user("alice", None, "reader", ["shop"], auth_source="oidc")

    login(signer, identity("alice", "sub-1", "local-admins"))
    user = web_users.find_user("alice")
    assert user["permissions"] == {"reports.read": ["shop"]}
    assert [group["name"] for group in user["groups"]] == ["reader:shop"]


def test_sso_login_joins_the_default_group():
    signer = oidc.SessionSigner(SECRET)
    group_for("reader", name="everyone", sso=False)

    login(signer, oidc_auto_create_users=True, oidc_default_group="everyone")
    user = web_users.find_user("alice")
    assert [(g["name"], g["source"]) for g in user["groups"]] == [("everyone", "oidc")]
    # A default group that does not exist gives nothing
    bob = identity("bob", "sub-2")
    with pytest.raises(oidc.OidcError):
        login(signer, bob, oidc_auto_create_users=True, oidc_default_group="missing")


def test_sso_login_creates_the_admin_groups_of_the_settings():
    signer = oidc.SessionSigner(SECRET)
    settings = {"oidc_auto_create_users": True, "oidc_admin_groups": "sec-admins, ops"}

    login(signer, identity("alice", "sub-1", "sec-admins"), **settings)

    assert web_users.find_user("alice")["permissions"] == ADMIN_GRANTS
    groups = {group["name"]: group for group in access_control.list_groups()}
    assert "ops" not in groups  # created only when one of its members logs in
    assert groups["sec-admins"]["sso"] is True
    assert [role["name"] for role in groups["sec-admins"]["roles"]] == ["admin"]
    # An existing group is left as the administrators changed it
    make_user("root", PASSWORD, "admin")
    access_control.set_group_roles(groups["sec-admins"]["id"], [])
    with pytest.raises(oidc.OidcError):
        login(signer, identity("alice", "sub-1", "sec-admins"), **settings)


def test_sso_login_combines_the_given_groups_with_the_sso_ones(database):
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    make_user("alice", None, "reader", ["shop"], auth_source="oidc")
    group_for("reader", ["billing"], name="devs", sso=True)
    group_for("triager", ["crm"], name="leads", sso=True)

    info = verifier.verify_session(login(signer, identity("alice", "sub-1", "devs"))["session"])
    assert (info.projects, info.grants) == (
        frozenset({"shop", "billing"}),
        {"reports.read": frozenset({"shop", "billing"})},
    )
    # Each permission keeps its own projects: reading is not narrowed by a triage group
    info = verifier.verify_session(login(signer, identity("alice", "sub-1", "leads"))["session"])
    assert (info.projects, info.grants["findings.triage"]) == (
        frozenset({"shop", "crm"}),
        frozenset({"crm"}),
    )
    # The OIDC groups are replaced at each login
    login(signer, identity("alice", "sub-1"))
    user = web_users.find_user("alice")
    assert [group["source"] for group in user["groups"]] == ["local"]
    assert user["permissions"] == {"reports.read": ["shop"]}


def test_sso_login_never_opens_a_local_account():
    signer = oidc.SessionSigner(SECRET)
    make_user("alice", PASSWORD, "admin")
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, oidc_auto_create_users=True)
    assert exc.value.code == "conflict"


@pytest.mark.parametrize(
    "other",
    [
        identity("alice", "sub-2"),
        # Same subject, other identity provider: another account
        identity("alice", "sub-1", issuer="https://evil.example.com"),
    ],
)
def test_sso_user_is_bound_to_its_first_identity(database, other):
    signer = oidc.SessionSigner(SECRET)
    make_user("alice", None, "reader", auth_source="oidc")
    login(signer, identity("alice", "sub-1"))
    login(signer, identity("alice", "sub-1"))

    with pytest.raises(oidc.OidcError) as exc:
        login(signer, other)
    assert exc.value.code == "conflict"
    row = stored(database, "alice")
    assert (row.oidc_subject, row.oidc_issuer) == ("sub-1", ISSUER)


def test_sso_user_keeps_its_account_when_its_name_changes_at_the_provider(database):
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    group_for("reader", name="everyone")
    settings = {"oidc_auto_create_users": True, "oidc_default_group": "everyone"}
    login(signer, identity("alice", "sub-1"), **settings)

    # Same issuer and subject, new username claim: the same account, under its first name
    result = login(signer, identity("alice.smith", "sub-1"), **settings)

    assert [user["username"] for user in web_users.list_users()] == ["alice"]
    assert verifier.verify_session(result["session"]).label == "oidc:alice"


def test_sso_login_opens_the_bound_user_before_a_user_of_its_name(database):
    signer = oidc.SessionSigner(SECRET)
    make_user("alice", None, "reader", ["shop"], auth_source="oidc")
    make_user("bob", None, "reader", ["billing"], auth_source="oidc")
    login(signer, identity("alice", "sub-1"))

    # The username claim names bob, created beforehand and not bound: alice opens, bob stays free
    result = login(signer, identity("bob", "sub-1"))

    assert result["username"] == "alice"
    assert stored(database, "bob").oidc_subject is None
    # The same subject of another provider is another identity: it binds bob
    login(signer, identity("bob", "sub-1", issuer="https://other.example.com"))
    assert stored(database, "bob").oidc_issuer == "https://other.example.com"


def test_sso_user_unbound_by_the_migration_never_logs_in_again(database):
    signer = oidc.SessionSigner(SECRET)
    make_user("alice", None, "reader", auth_source="oidc")
    with Session(database) as session:
        row = session.exec(select(WebUser).where(WebUser.username == "alice")).one()
        row.oidc_subject, row.oidc_issuer = "", None
        session.add(row)
        session.commit()

    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity("alice", "sub-1"))
    assert exc.value.code == "conflict"


def test_sso_user_bound_before_the_issuer_was_recorded_gets_it(database):
    signer = oidc.SessionSigner(SECRET)
    make_user("alice", None, "reader", auth_source="oidc")
    login(signer, identity("alice", "sub-1"))
    with Session(database) as session:
        row = session.exec(select(WebUser).where(WebUser.username == "alice")).one()
        row.oidc_issuer = None
        session.add(row)
        session.commit()

    login(signer, identity("alice", "sub-1"))

    assert stored(database, "alice").oidc_issuer == ISSUER


@pytest.mark.parametrize(
    ("username", "subject", "code"),
    [
        *[(name, "sub-1", "username") for name in (None, "", "bob smith", "a" * 65, "bo\u200bb")],
        *[("alice", subject, "token") for subject in ("", "s" * 256, "sub-é")],
    ],
)
def test_sso_login_refuses_an_invalid_identity(username, subject, code):
    signer = oidc.SessionSigner(SECRET)
    make_user("alice", None, "reader", auth_source="oidc")
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity(username, subject), oidc_auto_create_users=True)
    assert exc.value.code == code
    assert not web_users.find_user("alice")["sso_linked"]


def test_sso_user_without_any_role_is_refused_and_its_sessions_end():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    group_for("reader", name="devs", sso=True)
    created = web_users.create_user("alice", None, None, auth_source="oidc")
    session = login(signer, identity("alice", "sub-1", "devs"))["session"]
    assert verifier.verify_session(session) is not None

    # Removed from its groups: refused at the next login, and its open sessions stop
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity("alice", "sub-1"))
    assert exc.value.code == "forbidden"
    assert verifier.verify_session(session) is None
    web_users.delete_user(created["id"])


def test_deleted_sso_user_is_never_created_again_by_a_login():
    signer = oidc.SessionSigner(SECRET)
    group_for("reader", name="everyone")
    settings = {"oidc_auto_create_users": True, "oidc_default_group": "everyone"}
    session = login(signer, **settings)["session"]
    created = web_users.find_user("alice")

    deleted = web_users.delete_user(created["id"], deleted_by="root")

    assert deleted["username"] == "alice"
    assert web_users.SessionVerifier(signer).verify_session(session) is None
    assert [(item["username"], item["revoked_by"]) for item in web_users.list_revoked_users()] == [
        ("alice", "root")
    ]
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, **settings)
    assert exc.value.code == "revoked"
    assert web_users.list_users() == []


def test_deleted_sso_user_renamed_at_the_provider_is_never_created_again():
    signer = oidc.SessionSigner(SECRET)
    group_for("reader", name="everyone")
    settings = {"oidc_auto_create_users": True, "oidc_default_group": "everyone"}
    login(signer, identity("alice", "sub-1"), **settings)
    web_users.delete_user(web_users.find_user("alice")["id"], deleted_by="root")

    # Same issuer and subject under a new name: still the deleted user
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity("alice.smith", "sub-1"), **settings)
    assert exc.value.code == "revoked"
    # Another subject, or the same subject of another provider, is another person
    login(signer, identity("carol", "sub-2"), **settings)
    login(signer, identity("dave", "sub-1", issuer="https://other.example.com"), **settings)
    assert sorted(user["username"] for user in web_users.list_users()) == ["carol", "dave"]

    # Lifted by an administrator: the identity may log in again
    web_users.lift_revocation("alice")
    login(signer, identity("alice.smith", "sub-1"), **settings)
    assert "alice.smith" in [user["username"] for user in web_users.list_users()]


def test_revocation_is_lifted_by_an_administrator():
    signer = oidc.SessionSigner(SECRET)
    group_for("reader", name="everyone")
    settings = {"oidc_auto_create_users": True, "oidc_default_group": "everyone"}
    for name in ("alice", "carol"):
        created = web_users.create_user(name, None, None, auth_source="oidc")
        web_users.delete_user(created["id"])
    assert len(web_users.list_revoked_users()) == 2

    # Created again by hand, or revocation lifted
    make_user("alice", None, "reader", auth_source="oidc")
    web_users.lift_revocation("carol")

    assert web_users.list_revoked_users() == []
    login(signer, identity("carol", "sub-3"), **settings)
    assert web_users.find_user("carol")["auth_source"] == "oidc"
    with pytest.raises(NotFoundError):
        web_users.lift_revocation("carol")


def test_deleting_a_local_user_revokes_nothing():
    created = make_user("alice", PASSWORD, "reader")
    web_users.delete_user(created["id"])
    assert web_users.list_revoked_users() == []


def test_last_administrator_by_its_sso_groups_is_kept():
    signer = oidc.SessionSigner(SECRET)
    group_for("admin", name="secreview-admins", sso=True)
    web_users.create_user("alice", None, None, auth_source="oidc")
    login(signer, identity("alice", "sub-1", "secreview-admins"))
    alice = web_users.find_user("alice")
    assert alice["permissions"] == ADMIN_GRANTS
    root = make_user("root", PASSWORD, "admin")

    # Demoting the local admin keeps an administrator (alice, by its OIDC group)
    web_users.update_user(root["id"], [group_for("reader")])
    with pytest.raises(ValueError, match="last holder of users.manage"):
        web_users.delete_user(alice["id"])
    # The groups given by hand may change: the OIDC group keeps it administrator
    updated = web_users.update_user(alice["id"], [group_for("reader")])
    assert updated["permissions"] == ADMIN_GRANTS


# ── CLI ──────────────────────────────────────────────────────────────────────


def run_cli(capsys, *argv: str) -> tuple[int, object]:
    """Run ``security-review-controller user ...`` and decode its JSON output."""
    code = cli.run(["user", *argv])
    out = capsys.readouterr().out
    return code, json.loads(out) if out else None


def test_user_cli_create_list_set_groups_delete(capsys):
    group_for("triager", ["shop"], name="shop-triagers")
    code, created = run_cli(capsys, "create", "alice", "--group", "shop-triagers")

    assert code == cli.EXIT_PASSED
    assert created["created_by"] == "cli"
    assert created["permissions"]["findings.triage"] == ["shop"]
    assert web_users.authenticate("alice", created["password"]) is not None
    code, listed = run_cli(capsys, "list")
    assert [user["username"] for user in listed] == ["alice"]
    assert "password" not in listed[0] and "password_hash" not in listed[0]
    code, updated = run_cli(capsys, "set-groups", "alice")
    assert (code, updated["groups"], updated["permissions"]) == (cli.EXIT_PASSED, [], {})
    code, deleted = run_cli(capsys, "delete", "alice")
    assert (code, deleted["username"]) == (cli.EXIT_PASSED, "alice")


def test_user_cli_restores_the_administrators_group(capsys):
    make_user("alice", PASSWORD, "reader")

    code, updated = run_cli(capsys, "set-groups", "alice", "--group", "administrators")

    assert (code, updated["permissions"]) == (cli.EXIT_PASSED, ADMIN_GRANTS)
    assert [group["name"] for group in updated["groups"]] == ["administrators"]


def test_user_cli_creates_an_sso_user(capsys):
    code, created = run_cli(capsys, "create", "alice@example.com", "--sso")

    assert code == cli.EXIT_PASSED
    assert (created["auth_source"], created["groups"]) == ("oidc", [])
    assert "password" not in created
    group_for("triager")
    code, updated = run_cli(capsys, "set-groups", "alice@example.com", "--group", "triager")
    assert (code, updated["permissions"]) == (cli.EXIT_PASSED, TRIAGER_GRANTS)
    # An unknown group is refused; an OIDC user never has a password
    assert cli.run(["user", "create", "bob", "--group", "nope"]) == cli.EXIT_ERROR
    with pytest.raises(SystemExit) as exc:
        cli.run(["user", "create", "carol", "--sso", "--password-stdin"])
    assert exc.value.code == cli.EXIT_ERROR


def test_group_cli_lists_the_groups_and_the_roles(capsys):
    group_for("reader", ["shop"], name="devs", sso=True)

    assert cli.run(["group", "list"]) == cli.EXIT_PASSED
    groups = json.loads(capsys.readouterr().out)
    assert [(g["name"], g["roles"][0]["projects"]) for g in groups] == [("devs", ["shop"])]
    assert cli.run(["group", "roles"]) == cli.EXIT_PASSED
    roles = json.loads(capsys.readouterr().out)
    assert [role["name"] for role in roles] == ["admin", "reader", "mcp-user", "triager"]


def test_user_cli_reads_the_password_on_stdin(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(PASSWORD + "\n"))

    code, created = run_cli(capsys, "create", "alice", "--password-stdin")

    assert code == cli.EXIT_PASSED and "password" not in created
    assert web_users.authenticate("alice", PASSWORD) is not None


def test_user_cli_reset_password(capsys):
    make_user("admin", PASSWORD, "admin")

    code, reset = run_cli(capsys, "reset-password", "admin")

    assert code == cli.EXIT_PASSED
    assert web_users.authenticate("admin", PASSWORD) is None
    assert web_users.authenticate("admin", reset["password"]) is not None


def test_user_cli_errors_exit_with_2(capsys):
    make_user("admin", PASSWORD, "admin")

    assert cli.run(["user", "delete", "admin"]) == cli.EXIT_ERROR
    assert cli.run(["user", "delete", "nobody"]) == cli.EXIT_ERROR
    assert cli.run(["user", "create", "bad name"]) == cli.EXIT_ERROR
    with pytest.raises(SystemExit) as exc:
        cli.run(["user", "set-role", "admin"])  # replaced by set-groups
    assert exc.value.code == cli.EXIT_ERROR


def test_session_of_a_deleted_user_never_opens_a_recreated_account():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    make_user("root", PASSWORD, "admin")
    alice = make_user("alice", PASSWORD, "reader")
    session = web_users.new_session(signer, alice["id"])["session"]
    web_users.delete_user(alice["id"])

    # SQLite reuses the id of the last deleted row: same id, same or other username
    for username in ("mallory", "alice"):
        recreated = make_user(username, PASSWORD, "admin")
        assert recreated["id"] == alice["id"]
        assert verifier.verify_session(session) is None
        web_users.delete_user(recreated["id"])


def test_the_theme_of_a_user_is_checked_and_kept():
    user = make_user("alice", PASSWORD, "reader")

    assert web_users.get_preferences(user["id"]) == {"theme": "auto"}
    assert web_users.set_theme(user["id"], "light") == {"theme": "light"}
    assert web_users.get_preferences(user["id"]) == {"theme": "light"}
    with pytest.raises(ValueError, match="theme"):
        web_users.set_theme(user["id"], "<script>")
