"""Web users: password hashing, accounts, sessions, login throttling and the ``user`` CLI."""

import json

import jwt
import pytest
from sqlmodel import Session, select

from security_review_mcp import cli, oidc, web_users
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


def test_oidc_sessions_are_trusted_as_signed():
    signer = oidc.SessionSigner(SECRET)
    verifier = web_users.SessionVerifier(signer)
    session = signer.issue_session("bob", Role.TRIAGER)

    info = verifier.verify_session(session)
    assert (info.label, info.role, info.user_id) == ("bob", Role.TRIAGER, None)
    assert verifier.owns(session)
    assert verifier.verify_session(session + "x") is None
    # A session signed with another secret is refused
    other = oidc.SessionSigner("o" * 40).issue_session("bob", Role.ADMIN, user_id=1)
    assert verifier.verify_session(other) is None


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
