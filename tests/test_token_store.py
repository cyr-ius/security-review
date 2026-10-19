"""Tokens stored in the database: creation, lookup, revocation, project scope, bootstrap admin."""

import re
from datetime import UTC, datetime, timedelta

import pytest
from conftest import make_user
from sqlmodel import Session, select

from security_review_mcp import audit, token_store
from security_review_mcp import database as database_module
from security_review_mcp.config import get_settings
from security_review_mcp.http_server import Role, TokenInfo, hash_token
from security_review_mcp.models import ApiToken, ApiTokenProject

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
    assert (created["projects"], created["pending_projects"]) == (["shop-api"], [])
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


# ── Enrollment requests ──────────────────────────────────────────────────────


def test_enrollment_request_authenticates_nothing_until_approved(database):
    request = token_store.request_enrollment(
        "shop-api", requested_by="alice", requested_from="10.0.0.7"
    )

    assert (request["role"], request["project"]) == ("mcp", "shop-api")
    assert request["status"] == "pending"
    assert request["label"].startswith("shop-api-enroll-")
    assert (request["requested_by"], request["requested_from"]) == ("alice", "10.0.0.7")
    assert (request["kind"], request["projects"], request["pending_projects"]) == (
        "new",
        [],
        ["shop-api"],
    )
    (row,) = stored_rows(database)
    assert row.token_hash == digest_of(request["token"]).hex()
    assert request["token"] not in row.model_dump_json()
    pending = STORE.lookup(digest_of(request["token"]))
    assert pending.pending is True
    # A pending request does not switch authentication on and is not an active project token
    assert STORE.has_tokens() is False
    assert token_store.list_project_tokens() == []
    (listed,) = token_store.list_enrollments()
    assert (listed["id"], listed["token_id"], listed["kind"]) == (
        request["request_id"],
        request["id"],
        "new",
    )
    assert token_store.enrollment_status(request["id"])["status"] == "pending"

    approved = token_store.approve_enrollment(request["label"])

    assert approved["status"] == "active"
    assert STORE.lookup(digest_of(request["token"])) == TokenInfo(
        request["label"], Role.MCP, projects=frozenset({"shop-api"}), token_id=request["id"]
    )
    assert STORE.has_tokens() is True
    assert token_store.list_enrollments() == []
    assert [item["id"] for item in token_store.list_project_tokens()] == [request["id"]]
    assert token_store.enrollment_status(request["id"])["status"] == "active"
    with pytest.raises(ValueError, match="not found"):
        token_store.approve_enrollment(request["id"])


def test_reject_enrollment_only_deletes_pending_requests():
    active = token_store.create_token("ci", Role.MCP, "shop-api")
    request = token_store.request_enrollment("shop-api", label="shop-dev")

    assert token_store.reject_enrollment(request["id"])["label"] == request["label"]
    assert STORE.lookup(digest_of(request["token"])) is None
    assert token_store.enrollment_status(request["id"]) == {"status": "not_enrolled"}
    with pytest.raises(ValueError, match="not found"):
        token_store.reject_enrollment(active["id"])
    assert STORE.lookup(digest_of(active["token"])) is not None


def test_enrollment_request_validation_and_redaction():
    with pytest.raises(ValueError, match="between 1 and 200"):
        token_store.request_enrollment(" ")
    assert len(token_store.request_enrollment("shop-api", label="x" * 65)["label"]) == 64
    # The requested label always gets a random suffix: an anonymous client cannot learn which
    # labels already exist
    token_store.create_token("ops", Role.ADMIN)
    taken = [token_store.request_enrollment("shop-api", label="ops")["label"] for _ in range(2)]
    assert all(re.fullmatch(r"ops-[0-9a-f]{6}", label) for label in taken)
    assert taken[0] != taken[1]

    request = token_store.request_enrollment(
        "p" * 200, requested_by="bob password=Sup3rSecret99 " + "x" * 300
    )

    assert len(request["label"]) <= token_store.MAX_LABEL_CHARS
    assert "Sup3rSecret99" not in request["requested_by"]
    assert len(request["requested_by"]) == token_store.MAX_REQUESTED_BY_CHARS


def test_pending_enrollments_are_bounded_and_expire(monkeypatch, database):
    monkeypatch.setattr(token_store, "MAX_PENDING_ENROLLMENTS", 2)
    first = token_store.request_enrollment("shop-api")
    token_store.request_enrollment("billing")

    with pytest.raises(ValueError, match="Too many enrollment requests"):
        token_store.request_enrollment("other")

    # A request nobody decided on is dropped after ENROLLMENT_TTL, which frees a slot
    with Session(database) as session:
        row = session.get(ApiToken, first["id"])
        row.created_at = row.created_at - token_store.ENROLLMENT_TTL - timedelta(minutes=1)
        session.add(row)
        session.commit()
    token_store.request_enrollment("other")

    assert STORE.lookup(digest_of(first["token"])) is None
    assert sorted(item["project"] for item in token_store.list_enrollments()) == [
        "billing",
        "other",
    ]


def test_pending_enrollments_are_bounded_per_address(monkeypatch):
    monkeypatch.setattr(token_store, "MAX_PENDING_PER_ADDRESS", 2)
    first = token_store.request_enrollment("shop-api", requested_from="203.0.113.7")
    token_store.request_enrollment("billing", requested_from="203.0.113.7")

    # One client cannot fill the whole queue: its next request is refused...
    with pytest.raises(ValueError, match="from this address"):
        token_store.request_enrollment("other", requested_from="203.0.113.7")
    created = token_store.create_token("ci", Role.MCP, "shop-api")
    with pytest.raises(ValueError, match="from this address"):
        token_store.request_additional_project(created["id"], "crm", requested_from="203.0.113.7")
    # ...while the other clients (and stdio, without address) still enroll
    token_store.request_enrollment("other", requested_from="198.51.100.2")
    token_store.request_enrollment("local")

    # A decision frees a slot of the address
    token_store.reject_enrollment(first["request_id"])
    token_store.request_enrollment("other", requested_from="203.0.113.7")


# ── Multi-project tokens and complementary enrollment ───────────────────────


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
        token_store.request_additional_project(created["id"], "c")


def test_complementary_enrollment_adds_a_project_once_approved(database):
    created = token_store.create_token("ci", Role.MCP, "shop-api")

    request = token_store.request_additional_project(
        created["id"],
        " billing ",
        requested_by="alice token=Sup3rSecret99",
        requested_from="10.1.2.3",
    )

    assert (request["kind"], request["project"], request["status"]) == (
        "additional",
        "billing",
        "pending",
    )
    assert (request["token_id"], request["label"], request["projects"]) == (
        created["id"],
        "ci",
        ["shop-api"],
    )
    assert "token" not in request and "Sup3rSecret99" not in request["requested_by"]
    # The token keeps working for its first project while the request waits
    info = STORE.lookup(digest_of(created["token"]))
    assert (info.pending, info.projects) == (False, frozenset({"shop-api"}))
    assert [item["id"] for item in token_store.list_enrollments()] == [request["id"]]
    status = token_store.enrollment_status(created["id"])
    assert (status["status"], status["projects"], status["pending_projects"]) == (
        "active",
        ["shop-api"],
        ["billing"],
    )
    for project, message in (("shop-api", "already reaches"), ("billing", "already waiting")):
        with pytest.raises(ValueError, match=message):
            token_store.request_additional_project(created["id"], project)

    approved = token_store.approve_enrollment(request["id"])

    assert (approved["status"], approved["projects"]) == ("active", ["shop-api", "billing"])
    assert STORE.lookup(digest_of(created["token"])).projects == {"shop-api", "billing"}
    assert token_store.list_enrollments() == []
    # Still one token, one secret
    assert len(stored_rows(database)) == 1


def test_rejected_complementary_request_keeps_the_token():
    created = token_store.create_token("ci", Role.MCP, "shop-api")
    request = token_store.request_additional_project(created["id"], "billing")

    rejected = token_store.reject_enrollment(request["id"])

    assert (rejected["kind"], rejected["project"]) == ("additional", "billing")
    assert STORE.lookup(digest_of(created["token"])).projects == {"shop-api"}
    assert token_store.list_enrollments() == []
    # The project can be requested again
    token_store.request_additional_project(created["id"], "billing")


def test_complementary_enrollment_is_refused_for_unsuitable_tokens():
    admin = token_store.create_token("ops", Role.ADMIN)
    pending = token_store.request_enrollment("shop-api")

    with pytest.raises(ValueError, match="already reaches every project"):
        token_store.request_additional_project(admin["id"], "billing")
    with pytest.raises(ValueError, match="still waiting"):
        token_store.request_additional_project(pending["id"], "billing")
    with pytest.raises(ValueError, match="Token not found"):
        token_store.request_additional_project("unknown", "billing")
    with pytest.raises(ValueError, match="between 1 and 200"):
        token_store.request_additional_project(admin["id"], " ")


def test_approval_by_token_reference_needs_a_single_pending_request():
    created = token_store.create_token("ci", Role.MCP, "shop-api")
    first = token_store.request_additional_project(created["id"], "billing")
    token_store.request_additional_project(created["id"], "crm")

    with pytest.raises(ValueError, match="several pending requests"):
        token_store.approve_enrollment("ci")
    token_store.approve_enrollment(first["id"])

    assert token_store.approve_enrollment("ci")["project"] == "crm"
    assert STORE.lookup(digest_of(created["token"])).projects == {"shop-api", "billing", "crm"}


def test_complementary_requests_count_in_the_pending_limit_and_expire(monkeypatch, database):
    monkeypatch.setattr(token_store, "MAX_PENDING_ENROLLMENTS", 1)
    created = token_store.create_token("ci", Role.MCP, "shop-api")
    request = token_store.request_additional_project(created["id"], "billing")

    with pytest.raises(ValueError, match="Too many enrollment requests"):
        token_store.request_enrollment("other")

    with Session(database) as session:
        link = session.get(ApiTokenProject, request["id"])
        link.created_at = link.created_at - token_store.ENROLLMENT_TTL - timedelta(minutes=1)
        session.add(link)
        session.commit()
    token_store.request_enrollment("other")

    # Only the expired project was dropped: the token is untouched
    assert STORE.lookup(digest_of(created["token"])).projects == {"shop-api"}
    assert [item["project"] for item in token_store.list_enrollments()] == ["other"]


def test_legacy_project_tokens_are_migrated(database):
    with Session(database) as session:
        session.add(
            ApiToken(id="t1", label="old", role="mcp", project="shop-api", token_hash="ab" * 32)
        )
        session.add(ApiToken(id="t2", label="admin", role="admin", token_hash="cd" * 32))
        session.add(
            ApiToken(
                id="t3",
                label="asked",
                role="mcp",
                project="billing",
                status="pending",
                token_hash="ef" * 32,
            )
        )
        session.commit()

    # Before the migration a legacy token stays restricted to its project
    assert STORE.lookup(bytes.fromhex("ab" * 32)).projects == {"shop-api"}
    # The baseline migration completes a database created by version 1.x
    database_module.upgrade_db()
    database_module.upgrade_db()  # already at the latest revision: nothing is copied twice

    links = {link.token_id: (link.project, link.status) for link in link_rows(database)}
    assert links == {"t1": ("shop-api", "active"), "t3": ("billing", "pending")}
    assert STORE.lookup(bytes.fromhex("ab" * 32)).projects == {"shop-api"}
    assert STORE.lookup(bytes.fromhex("cd" * 32)).projects is None
    assert [item["token_id"] for item in token_store.list_enrollments()] == ["t3"]


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
    # Enrollment requests follow the same limit
    request = token_store.request_enrollment("shop-api")
    assert request["expires_at"] is not None


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
    token_store.request_enrollment("shop-api", label="dev")
    token_store.create_token("ops", Role.ADMIN)

    with pytest.raises(ValueError, match="not found"):
        token_store.rotate_token("missing")
    with pytest.raises(ValueError, match="grace period"):
        token_store.rotate_token("ops", grace_hours=token_store.MAX_ROTATION_GRACE_HOURS + 1)
    (pending,) = token_store.list_enrollments()
    with pytest.raises(ValueError, match="waiting for approval"):
        token_store.rotate_token(pending["token_id"])
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
    token_store.request_enrollment("shop-api")

    counts = token_store.token_counts()

    assert counts["by_role_and_state"] == {
        ("mcp", "active"): 2,
        ("admin", "expired"): 1,
        ("mcp", "pending"): 1,
    }
    assert counts["expiring_soon"] == 1
    assert counts["pending_enrollments"] == 1


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


def test_set_token_projects_settles_the_pending_requests(database):
    created = token_store.create_project_token("dev", ["shop-api"], Role.MCP)
    token_store.request_additional_project(created["id"], "billing")
    token_store.request_additional_project(created["id"], "crm")

    updated = token_store.set_token_projects(created["id"], ["billing"])

    # The granted request is approved, the other one keeps waiting
    assert (updated["projects"], updated["pending_projects"]) == (["billing"], ["crm"])
    assert [request["project"] for request in token_store.list_enrollments()] == ["crm"]
    widened = token_store.set_token_projects(created["id"], None)
    assert (widened["projects"], widened["pending_projects"]) == (None, [])
    assert token_store.list_enrollments() == []


def test_set_token_projects_refusals():
    admin = token_store.create_token("ops", Role.ADMIN)
    ci = token_store.create_project_token("pipeline", ["shop-api"], Role.CI)
    reader = token_store.create_project_token("reader", ["shop-api"])
    pending = token_store.request_enrollment("billing", label="newcomer")

    with pytest.raises(ValueError, match="not found"):
        token_store.set_token_projects(admin["id"], ["shop-api"])
    with pytest.raises(ValueError, match="not found"):
        token_store.set_token_projects("missing", None)
    with pytest.raises(ValueError, match="ci token must be restricted"):
        token_store.set_token_projects(ci["id"], None)
    with pytest.raises(ValueError, match="at least one project"):
        token_store.set_token_projects(reader["id"], [])
    with pytest.raises(ValueError, match="waiting for approval"):
        token_store.set_token_projects(pending["id"], ["billing"])
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
    from security_review_mcp import access_control

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


def test_a_personal_mcp_token_reaches_the_projects_its_user_may_read():
    """The projects are read at each request: a project granted or removed applies at once."""
    from conftest import group_for

    from security_review_mcp import web_users

    user = make_user("alice", "Correct horse battery 9", "reader", ["shop-api"])
    created = token_store.create_personal_token(user["id"], "agent", role="mcp")
    assert (created["role"], created["personal"], created["projects"]) == ("mcp", True, None)

    info = STORE.lookup(digest_of(created["token"]))
    assert (info.role, info.projects) == (Role.MCP, frozenset({"shop-api"}))
    listed = token_store.list_personal_tokens(user["id"])
    assert [item["projects"] for item in listed] == [["shop-api"]]
    assert token_store.enrollment_status(created["id"])["projects"] == ["shop-api"]

    web_users.update_user(user["id"], [group_for("reader", ["billing", "shop-api"])])
    info = STORE.lookup(digest_of(created["token"]))
    assert info.projects == frozenset({"billing", "shop-api"})
    # Without any group, the token reaches no project (never every project)
    web_users.update_user(user["id"], [])
    assert STORE.lookup(digest_of(created["token"])).projects == frozenset()
    web_users.update_user(user["id"], [group_for("reader")])
    assert STORE.lookup(digest_of(created["token"])).projects is None


def test_a_personal_mcp_token_has_no_complementary_enrollment():
    user = make_user("alice", "Correct horse battery 9", "reader", ["shop-api"])
    created = token_store.create_personal_token(user["id"], "agent", role="mcp")

    with pytest.raises(ValueError, match="give your account access to project 'billing'"):
        token_store.request_additional_project(created["id"], "billing")
    with pytest.raises(ValueError, match="no projects"):
        token_store.set_token_projects(created["id"], ["billing"])
    with pytest.raises(ValueError, match="cannot be rotated"):
        token_store.rotate_token(created["id"])
    assert token_store.list_enrollments() == []


def test_a_personal_mcp_token_stops_with_its_user():
    from security_review_mcp import web_users

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
    # Only an api or an mcp token is personal
    for role in ("ci", "admin", "metrics", "nope"):
        with pytest.raises(ValueError, match="cannot create a personal"):
            token_store.create_personal_token(user["id"], "other", role=role)


def test_only_a_personal_token_has_a_colon_in_its_label():
    """``<username>:<label>`` names the user of a personal token: no other token imitates it."""
    with pytest.raises(ValueError, match="must not contain ':'"):
        token_store.create_token("alice:swagger", Role.MCP)
    with pytest.raises(ValueError, match="must not contain ':'"):
        token_store.create_project_token("alice:swagger", None, Role.MCP)
    request = token_store.request_enrollment("shop-api", label="alice:swagger")
    assert ":" not in request["label"] and request["label"].startswith("alice-swagger")
