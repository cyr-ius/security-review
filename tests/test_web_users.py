"""Web users: password hashing, accounts, sessions, login throttling and the ``user`` CLI."""

import json

import jwt
import pytest
from sqlmodel import Session, select

from security_review_mcp import cli, oidc, role_mapping, web_users
from security_review_mcp.config import Settings
from security_review_mcp.http_server import Role
from security_review_mcp.models import WebUser
from security_review_mcp.services import NotFoundError

PASSWORD = "correct horse battery"
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
        ("short", "between 12 and 256"),
        ("x" * 257, "between 12 and 256"),
        (" " * 12, "blank"),
        ("abcdefghijk\n", "control characters"),
    ],
)
def test_weak_or_invalid_passwords_are_refused(password, message):
    with pytest.raises(ValueError, match=message):
        web_users.create_user("alice", password, "reader")


@pytest.mark.parametrize("username", ["", " ", "a" * 65, "bob smith", "-bob", "bo\nb", "é"])
def test_invalid_usernames_are_refused(username):
    with pytest.raises(ValueError, match="Username"):
        web_users.create_user(username, PASSWORD, "reader")


# ── Accounts ─────────────────────────────────────────────────────────────────


def test_create_user_stores_only_a_hash(database):
    created = web_users.create_user("alice", PASSWORD, "triager", ["shop-api"], "ops")

    assert "password" not in created
    assert (created["username"], created["role"], created["projects"]) == (
        "alice",
        "triager",
        ["shop-api"],
    )
    row = stored(database, "alice")
    assert PASSWORD not in row.model_dump_json()
    assert "password_hash" not in json.dumps(web_users.list_users())


def test_create_user_generates_a_password_shown_once():
    created = web_users.create_user("alice", None, "reader")

    assert len(created["password"]) >= 24
    assert web_users.authenticate("alice", created["password"])["username"] == "alice"
    assert "password" not in web_users.list_users()[0]


def test_duplicate_users_and_admin_projects_are_refused():
    web_users.create_user("alice", PASSWORD, "reader")

    with pytest.raises(ValueError, match="already exists"):
        web_users.create_user("alice", PASSWORD, "admin")
    with pytest.raises(ValueError, match="every project"):
        web_users.create_user("bob", PASSWORD, "admin", ["shop-api"])
    with pytest.raises(ValueError, match="reader, triager or admin"):
        web_users.create_user("bob", PASSWORD, "mcp")


def test_user_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(web_users, "MAX_USERS", 1)
    web_users.create_user("alice", PASSWORD, "reader")

    with pytest.raises(ValueError, match="limit of 1"):
        web_users.create_user("bob", PASSWORD, "reader")


def test_authenticate_checks_the_password_and_records_the_login(database):
    web_users.create_user("alice", PASSWORD, "reader")

    assert web_users.authenticate("alice", "wrong password!") is None
    assert web_users.authenticate("nobody", PASSWORD) is None
    assert stored(database, "alice").last_login_at is None
    user = web_users.authenticate("alice", PASSWORD)
    assert user is not None and user["last_login_at"] is not None


def test_last_administrator_is_kept():
    admin = web_users.create_user("admin", PASSWORD, "admin")

    with pytest.raises(ValueError, match="last administrator"):
        web_users.delete_user(admin["id"])
    with pytest.raises(ValueError, match="last administrator"):
        web_users.update_user(admin["id"], "reader")

    other = web_users.create_user("root", PASSWORD, "admin")
    assert web_users.update_user(admin["id"], "reader", ["shop-api"])["role"] == "reader"
    with pytest.raises(ValueError, match="last administrator"):
        web_users.delete_user(other["id"])


def test_unknown_users_raise_not_found():
    with pytest.raises(NotFoundError):
        web_users.delete_user(42)
    with pytest.raises(NotFoundError):
        web_users.find_user("nobody")


def test_change_own_password_needs_the_current_one():
    user = web_users.create_user("alice", PASSWORD, "reader")

    with pytest.raises(ValueError, match="current password is wrong"):
        web_users.change_own_password(user["id"], "not the password", "another long secret")
    with pytest.raises(ValueError, match="must differ"):
        web_users.change_own_password(user["id"], PASSWORD, PASSWORD)
    web_users.change_own_password(user["id"], PASSWORD, "another long secret")
    assert web_users.authenticate("alice", PASSWORD) is None
    assert web_users.authenticate("alice", "another long secret") is not None


def test_bootstrap_admin_is_created_once_while_no_user_exists():
    password = web_users.ensure_bootstrap_admin()

    assert password is not None
    assert web_users.ensure_bootstrap_admin() is None
    user = web_users.authenticate("admin", password)
    assert (user["role"], user["projects"], user["created_by"]) == ("admin", None, "bootstrap")


def test_no_bootstrap_admin_once_another_user_exists():
    web_users.create_user("alice", PASSWORD, "reader")

    assert web_users.ensure_bootstrap_admin() is None
    assert [user["username"] for user in web_users.list_users()] == ["alice"]


# ── Sessions ─────────────────────────────────────────────────────────────────


def test_session_follows_the_stored_user():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    user = web_users.create_user("alice", PASSWORD, "reader", ["shop-api"])
    session = web_users.new_session(signer, user["id"])["session"]

    info = verifier.verify_session(session)
    assert (info.label, info.role, info.projects, info.user_id) == (
        "alice",
        Role.READER,
        frozenset({"shop-api"}),
        user["id"],
    )
    # A new role applies to the open session at once
    web_users.update_user(user["id"], "triager")
    info = verifier.verify_session(session)
    assert (info.role, info.projects) == (Role.TRIAGER, None)
    # A deleted user loses its sessions
    web_users.create_user("root", PASSWORD, "admin")
    web_users.delete_user(user["id"])
    assert verifier.verify_session(session) is None


def test_password_change_ends_the_previous_sessions():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    user = web_users.create_user("alice", PASSWORD, "reader")
    before = web_users.new_session(signer, user["id"])["session"]
    assert verifier.verify_session(before) is not None

    # Even within the same second as the session: the version, not the time, is compared
    web_users.set_password(user["id"], "another long secret")

    assert verifier.verify_session(before) is None
    after = web_users.new_session(signer, user["id"])
    assert (after["username"], after["role"]) == ("alice", Role.READER)
    assert verifier.verify_session(after["session"]).user_id == user["id"]


def test_sessions_with_a_tampered_user_claim_are_refused():
    signer = oidc.SessionSigner(SECRET)
    user = web_users.create_user("alice", PASSWORD, "reader")
    # A user id without its version (or a non-integer one) is never accepted
    payload = signer.decode_session(web_users.new_session(signer, user["id"])["session"])
    for claims in ({"uver": None}, {"uid": "1"}, {"uver": True}):
        forged = jwt.encode(
            {k: v for k, v in {**payload, **claims}.items() if v is not None},
            signer._session_key,
            algorithm="HS256",
        )
        assert signer.decode_session(forged) is None


def test_sessions_without_a_web_user_are_refused():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    now = 1_900_000_000
    # A session that names no web user (as issued by older versions to OIDC users) is refused
    unbound = jwt.encode(
        {
            "iss": oidc.SESSION_ISSUER,
            "aud": oidc.SESSION_AUDIENCE,
            "sub": "oidc:bob",
            "role": "admin",
            "projects": None,
            "iat": now,
            "exp": now + 3600,
        },
        signer._session_key,
        algorithm="HS256",
    )
    assert verifier.owns(unbound)
    assert verifier.verify_session(unbound) is None
    # A session signed with another secret is refused
    user = web_users.create_user("bob", PASSWORD, "admin")
    other = oidc.SessionSigner("o" * 40).issue_session("bob", Role.ADMIN, None, user["id"], 0)
    assert verifier.verify_session(other) is None


# ── SSO users ────────────────────────────────────────────────────────────────


def sso_settings(**values) -> Settings:
    """OIDC settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


def identity(username: str | None = "alice", subject: str = "sub-1", *groups: str):
    """A verified OIDC login."""
    return oidc.OidcIdentity(
        username=username,
        subject=subject,
        groups=frozenset(groups),
        label=f"oidc:{username}",
        return_url="/",
    )


def login(signer, user=None, **settings) -> dict:
    """Run web_users.oidc_login with these settings."""
    return web_users.oidc_login(signer, user or identity(), sso_settings(**settings))


def test_sso_user_has_no_password_and_may_have_no_role(database):
    created = web_users.create_user("alice", None, None, created_by="admin", auth_source="oidc")

    assert (created["auth_source"], created["role"], created["effective_role"]) == (
        "oidc",
        None,
        None,
    )
    assert "password" not in created and created["password_changed_at"] is None
    assert stored(database, "alice").password_hash is None
    with pytest.raises(ValueError, match="no password"):
        web_users.create_user("bob", PASSWORD, "reader", auth_source="oidc")
    with pytest.raises(ValueError, match="no password"):
        web_users.set_password(created["id"])
    with pytest.raises(ValueError, match="no password"):
        web_users.change_own_password(created["id"], PASSWORD, PASSWORD + "!")
    with pytest.raises(ValueError, match="cannot list projects"):
        web_users.create_user("carol", None, None, ["shop"], auth_source="oidc")
    # A local user always needs a role and a password
    with pytest.raises(ValueError, match="needs a role"):
        web_users.create_user("dave", PASSWORD, None)
    with pytest.raises(ValueError, match="Source"):
        web_users.create_user("erin", None, "reader", auth_source="ldap")


def test_sso_user_never_logs_in_with_a_password(database):
    web_users.create_user("alice", None, "admin", auth_source="oidc")
    assert web_users.authenticate("alice", "") is None
    assert web_users.authenticate("alice", PASSWORD) is None


def test_sso_login_refuses_an_unknown_user_without_auto_creation():
    signer = oidc.SessionSigner(SECRET)
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity("alice", "sub-1", "devs"), oidc_default_role="reader")
    assert exc.value.code == "unknown_user"
    assert web_users.list_users() == []


def test_sso_login_creates_the_user_when_auto_creation_is_enabled(database):
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    result = login(signer, oidc_auto_create_users=True, oidc_default_role="triager")

    (user,) = web_users.list_users()
    assert (user["username"], user["auth_source"], user["created_by"]) == (
        "alice",
        "oidc",
        "oidc",
    )
    assert (user["role"], user["sso_role"], user["effective_role"]) == (None, "triager", "triager")
    assert user["sso_linked"] and user["last_login_at"]
    assert stored(database, "alice").oidc_subject == "sub-1"
    info = verifier.verify_session(result["session"])
    assert (info.label, info.role, info.auth_source) == ("oidc:alice", Role.TRIAGER, "oidc")


def test_sso_login_never_creates_a_user_without_a_role():
    signer = oidc.SessionSigner(SECRET)
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, oidc_auto_create_users=True)
    assert exc.value.code == "forbidden"
    assert web_users.list_users() == []


def test_sso_login_opens_a_user_created_by_an_administrator():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    web_users.create_user("alice", None, "reader", ["shop"], auth_source="oidc")

    # No group and no default role: its own role applies
    info = verifier.verify_session(login(signer)["session"])
    assert (info.role, info.projects) == (Role.READER, frozenset({"shop"}))


def test_sso_login_combines_the_own_role_with_the_groups(database):
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    web_users.create_user("alice", None, "reader", ["shop"], auth_source="oidc")
    role_mapping.create_mapping("devs", "reader", ["billing"])
    role_mapping.create_mapping("leads", "triager", ["crm"])

    info = verifier.verify_session(login(signer, identity("alice", "sub-1", "devs"))["session"])
    assert (info.role, info.projects) == (Role.READER, frozenset({"shop", "billing"}))
    # A higher role of the groups wins, on its own projects
    info = verifier.verify_session(login(signer, identity("alice", "sub-1", "leads"))["session"])
    assert (info.role, info.projects) == (Role.TRIAGER, frozenset({"crm"}))
    # The access of the groups is refreshed at each login
    login(signer, identity("alice", "sub-1"))
    user = web_users.find_user("alice")
    assert (user["sso_role"], user["effective_role"]) == (None, "reader")


def test_sso_login_never_opens_a_local_account():
    signer = oidc.SessionSigner(SECRET)
    web_users.create_user("alice", PASSWORD, "admin")
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, oidc_auto_create_users=True, oidc_default_role="reader")
    assert exc.value.code == "conflict"


def test_sso_user_is_bound_to_its_first_subject():
    signer = oidc.SessionSigner(SECRET)
    web_users.create_user("alice", None, "reader", auth_source="oidc")
    login(signer, identity("alice", "sub-1"))
    login(signer, identity("alice", "sub-1"))
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity("alice", "sub-2"))
    assert exc.value.code == "conflict"


@pytest.mark.parametrize("username", [None, "", "bob smith", "a" * 65, "bo\u200bb"])
def test_sso_login_refuses_a_missing_or_invalid_username(username):
    signer = oidc.SessionSigner(SECRET)
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity(username), oidc_auto_create_users=True, oidc_default_role="reader")
    assert exc.value.code == "username"


@pytest.mark.parametrize("subject", ["", "s" * 256, "sub-é"])
def test_sso_login_refuses_an_invalid_subject(subject):
    signer = oidc.SessionSigner(SECRET)
    web_users.create_user("alice", None, "reader", auth_source="oidc")
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity("alice", subject))
    assert exc.value.code == "token"
    assert not web_users.find_user("alice")["sso_linked"]


def test_sso_user_without_any_role_is_refused_and_its_sessions_end():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    role_mapping.create_mapping("devs", "reader")
    created = web_users.create_user("alice", None, None, auth_source="oidc")
    session = login(signer, identity("alice", "sub-1", "devs"))["session"]
    assert verifier.verify_session(session) is not None

    # Removed from its groups: refused at the next login, and its open sessions stop
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, identity("alice", "sub-1"))
    assert exc.value.code == "forbidden"
    assert verifier.verify_session(session) is None
    web_users.delete_user(created["id"])


def test_deleting_an_sso_user_ends_its_sessions():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    created = web_users.create_user("alice", None, "triager", auth_source="oidc")
    session = login(signer)["session"]
    assert verifier.verify_session(session).role == Role.TRIAGER

    web_users.delete_user(created["id"])
    assert verifier.verify_session(session) is None


def test_deleted_sso_user_is_never_created_again_by_a_login():
    signer = oidc.SessionSigner(SECRET)
    settings = {"oidc_auto_create_users": True, "oidc_default_role": "reader"}
    login(signer, **settings)
    created = web_users.find_user("alice")

    deleted = web_users.delete_user(created["id"], deleted_by="root")

    assert deleted["username"] == "alice"
    assert [(item["username"], item["revoked_by"]) for item in web_users.list_revoked_users()] == [
        ("alice", "root")
    ]
    with pytest.raises(oidc.OidcError) as exc:
        login(signer, **settings)
    assert exc.value.code == "revoked"
    assert web_users.list_users() == []


def test_revocation_is_lifted_by_an_administrator():
    signer = oidc.SessionSigner(SECRET)
    settings = {"oidc_auto_create_users": True, "oidc_default_role": "reader"}
    for name in ("alice", "bob", "carol"):
        created = web_users.create_user(name, None, None, auth_source="oidc")
        web_users.delete_user(created["id"])
    assert len(web_users.list_revoked_users()) == 3

    # Created again by hand, by an enrollment approval, or revocation lifted
    web_users.create_user("alice", None, "reader", auth_source="oidc")
    web_users.grant_project("bob", "shop", "admin", create_sso=True)
    web_users.lift_revocation("carol")

    assert web_users.list_revoked_users() == []
    login(signer, identity("carol", "sub-3"), **settings)
    assert web_users.find_user("carol")["auth_source"] == "oidc"
    with pytest.raises(NotFoundError):
        web_users.lift_revocation("carol")


def test_deleting_a_local_user_revokes_nothing():
    created = web_users.create_user("alice", PASSWORD, "reader")
    web_users.delete_user(created["id"])
    assert web_users.list_revoked_users() == []


def test_last_administrator_counts_sso_administrators():
    root = web_users.create_user("root", PASSWORD, "admin")
    sso_admin = web_users.create_user("alice", None, "admin", auth_source="oidc")

    # Two administrators: the local one may go, the SSO one is then the last
    web_users.delete_user(root["id"])
    with pytest.raises(ValueError, match="last administrator"):
        web_users.delete_user(sso_admin["id"])
    with pytest.raises(ValueError, match="last administrator"):
        web_users.update_user(sso_admin["id"], None)
    assert web_users.list_revoked_users() == []


def test_last_administrator_by_its_groups_is_kept():
    signer = oidc.SessionSigner(SECRET)
    role_mapping.create_mapping("secreview-admins", "admin")
    web_users.create_user("alice", None, None, auth_source="oidc")
    login(signer, identity("alice", "sub-1", "secreview-admins"))
    alice = web_users.find_user("alice")
    assert (alice["role"], alice["sso_role"]) == (None, "admin")
    root = web_users.create_user("root", PASSWORD, "admin")

    # Demoting the local admin keeps an administrator (alice, by its groups)
    web_users.update_user(root["id"], "reader")
    with pytest.raises(ValueError, match="last administrator"):
        web_users.delete_user(alice["id"])
    # Its own role may change: the role of its groups keeps it administrator
    assert web_users.update_user(alice["id"], "reader")["effective_role"] == "admin"


# ── Access given at the approval of an enrollment ────────────────────────────


def test_grant_project_extends_a_restricted_user():
    web_users.create_user("alice", PASSWORD, "triager", ["shop"])
    granted = web_users.grant_project("alice", "billing", "admin", create_sso=False)
    assert (granted["role"], granted["projects"]) == ("triager", ["shop", "billing"])
    # Already reached: unchanged
    assert web_users.grant_project("alice", "shop", "admin", False)["projects"] == [
        "shop",
        "billing",
    ]


def test_grant_project_leaves_an_unrestricted_user_unchanged():
    web_users.create_user("root", PASSWORD, "admin")
    web_users.create_user("bob", PASSWORD, "reader")
    assert web_users.grant_project("root", "shop", None, False)["projects"] is None
    assert web_users.grant_project("bob", "shop", None, False)["projects"] is None


def test_grant_project_gives_reader_to_an_sso_user_without_role():
    web_users.create_user("alice", None, None, auth_source="oidc")
    granted = web_users.grant_project("alice", "shop", None, False)
    assert (granted["role"], granted["projects"]) == ("reader", ["shop"])


def test_grant_project_creates_an_sso_user_only_when_allowed():
    with pytest.raises(ValueError, match="not found"):
        web_users.check_project_grant("alice", create_sso=False)
    assert web_users.list_users() == []

    created = web_users.grant_project("alice", "shop", "admin", create_sso=True)
    assert (created["auth_source"], created["role"], created["projects"]) == (
        "oidc",
        "reader",
        ["shop"],
    )
    assert created["created_by"] == "admin"


def test_grant_project_is_bounded(monkeypatch):
    monkeypatch.setattr(web_users, "MAX_PROJECTS_PER_TOKEN", 1)
    web_users.create_user("alice", PASSWORD, "reader", ["shop"])
    with pytest.raises(ValueError, match="already reaches 1 projects"):
        web_users.check_project_grant("alice", False)
    monkeypatch.setattr(web_users, "MAX_USERS", 1)
    with pytest.raises(ValueError, match="limit of 1 web users"):
        web_users.check_project_grant("bob", True)


# ── Login throttling ─────────────────────────────────────────────────────────


def test_throttle_locks_a_username_per_address():
    throttle = web_users.LoginThrottle(max_per_user=2, max_per_address=10)

    throttle.failed("Alice", "10.0.0.1")
    assert not throttle.blocked("alice", "10.0.0.1")
    throttle.failed("alice", "10.0.0.1")
    assert throttle.blocked("ALICE", "10.0.0.1")
    # Another address is not locked out by these failures
    assert not throttle.blocked("alice", "10.0.0.2")


def test_throttle_locks_an_address_trying_many_usernames():
    throttle = web_users.LoginThrottle(max_per_user=5, max_per_address=3)

    for name in ("a", "b", "c"):
        throttle.failed(name, "10.0.0.1")

    assert throttle.blocked("d", "10.0.0.1")


def test_throttle_forgets_old_failures_and_successes():
    throttle = web_users.LoginThrottle(max_per_user=1, max_per_address=10, window=0)
    throttle.failed("alice", "10.0.0.1")
    assert not throttle.blocked("alice", "10.0.0.1")

    throttle = web_users.LoginThrottle(max_per_user=1, max_per_address=10)
    throttle.failed("alice", "10.0.0.1")
    throttle.succeeded("alice", "10.0.0.1")
    assert not throttle.blocked("alice", "10.0.0.1")


def test_throttle_memory_is_bounded():
    throttle = web_users.LoginThrottle(max_keys=10)

    for index in range(100):
        throttle.failed(f"user{index}", f"10.0.0.{index}")

    assert len(throttle._failures) == 10


# ── CLI ──────────────────────────────────────────────────────────────────────


def run_cli(capsys, *argv: str) -> tuple[int, object]:
    """Run ``security-review-controller user ...`` and decode its JSON output."""
    code = cli.run(["user", *argv])
    out = capsys.readouterr().out
    return code, json.loads(out) if out else None


def test_user_cli_create_list_set_role_delete(capsys):
    code, created = run_cli(capsys, "create", "alice", "--role", "triager", "--project", "shop")

    assert code == cli.EXIT_PASSED
    assert (created["role"], created["projects"], created["created_by"]) == (
        "triager",
        ["shop"],
        "cli",
    )
    assert web_users.authenticate("alice", created["password"]) is not None
    code, listed = run_cli(capsys, "list")
    assert [user["username"] for user in listed] == ["alice"]
    assert "password" not in listed[0] and "password_hash" not in listed[0]
    code, updated = run_cli(capsys, "set-role", "alice", "--role", "reader")
    assert (code, updated["role"], updated["projects"]) == (cli.EXIT_PASSED, "reader", None)
    code, deleted = run_cli(capsys, "delete", "alice")
    assert (code, deleted["username"]) == (cli.EXIT_PASSED, "alice")


def test_user_cli_creates_an_sso_user(capsys):
    code, created = run_cli(capsys, "create", "alice@example.com", "--sso", "--role", "none")

    assert code == cli.EXIT_PASSED
    assert (created["auth_source"], created["role"]) == ("oidc", None)
    assert "password" not in created
    code, updated = run_cli(capsys, "set-role", "alice@example.com", "--role", "triager")
    assert (code, updated["role"]) == (cli.EXIT_PASSED, "triager")
    # A local user always has a role; an SSO user never has a password
    assert cli.run(["user", "create", "bob", "--role", "none"]) == cli.EXIT_ERROR
    assert "needs a role" in json.loads(capsys.readouterr().err)["error"]
    with pytest.raises(SystemExit) as exc:
        cli.run(["user", "create", "carol", "--sso", "--password-stdin"])
    assert exc.value.code == cli.EXIT_ERROR


def test_user_cli_reads_the_password_on_stdin(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(PASSWORD + "\n"))

    code, created = run_cli(capsys, "create", "alice", "--password-stdin")

    assert code == cli.EXIT_PASSED and "password" not in created
    assert web_users.authenticate("alice", PASSWORD) is not None


def test_user_cli_reset_password(capsys):
    web_users.create_user("admin", PASSWORD, "admin")

    code, reset = run_cli(capsys, "reset-password", "admin")

    assert code == cli.EXIT_PASSED
    assert web_users.authenticate("admin", PASSWORD) is None
    assert web_users.authenticate("admin", reset["password"]) is not None


def test_user_cli_errors_exit_with_2(capsys):
    web_users.create_user("admin", PASSWORD, "admin")

    assert cli.run(["user", "delete", "admin"]) == cli.EXIT_ERROR
    assert "last administrator" in json.loads(capsys.readouterr().err)["error"]
    assert cli.run(["user", "delete", "nobody"]) == cli.EXIT_ERROR
    assert "not found" in json.loads(capsys.readouterr().err)["error"]
    assert cli.run(["user", "create", "bad name"]) == cli.EXIT_ERROR
    with pytest.raises(SystemExit) as exc:
        cli.run(["user", "set-role", "admin"])
    assert exc.value.code == cli.EXIT_ERROR


def test_session_of_a_deleted_user_never_opens_a_recreated_account():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    web_users.create_user("root", PASSWORD, "admin")
    alice = web_users.create_user("alice", PASSWORD, "reader")
    session = web_users.new_session(signer, alice["id"])["session"]
    web_users.delete_user(alice["id"])

    # SQLite reuses the id of the last deleted row: same id, same or other username
    for username in ("mallory", "alice"):
        recreated = web_users.create_user(username, PASSWORD, "admin")
        assert recreated["id"] == alice["id"]
        assert verifier.verify_session(session) is None
        web_users.delete_user(recreated["id"])
