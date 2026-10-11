"""Tokens stored in the database: creation, lookup, revocation, project scope, bootstrap admin."""

import re
from datetime import timedelta

import pytest
from sqlmodel import Session, select

from security_review_mcp import token_store
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
        "ci", Role.READER, projects=frozenset({"shop-api"}), token_id=created["id"]
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
    for role in (Role.MCP, Role.READER, Role.TRIAGER):
        created = token_store.create_token(f"{role}-billing", role, "billing")
        assert (created["project"], created["projects"]) == ("billing", ["billing"])
    with pytest.raises(ValueError, match="between 1 and 64"):
        token_store.create_project_token("  ", "billing")
    with pytest.raises(ValueError, match="between 1 and 200"):
        token_store.create_project_token("other", "p" * 201)
    with pytest.raises(ValueError, match="at least one project"):
        token_store.create_project_token("other", [])


def test_project_token_limit(monkeypatch):
    monkeypatch.setattr(token_store, "MAX_TOKENS", 2)
    token_store.create_project_token("one", "shop-api")
    token_store.create_project_token("two", "shop-api")

    with pytest.raises(ValueError, match="limit of 2"):
        token_store.create_project_token("three", "shop-api")


def test_unknown_token_is_rejected():
    assert STORE.lookup(digest_of("z" * 40)) is None


# ── Bootstrap administrator ──────────────────────────────────────────────────


def test_bootstrap_admin_is_created_once(database):
    password = token_store.ensure_bootstrap_admin()

    assert password is not None
    assert token_store.ensure_bootstrap_admin() is None
    (row,) = stored_rows(database)
    assert password not in row.model_dump_json()
    info = STORE.lookup(digest_of(password))
    assert (info.label, info.role, info.projects) == ("bootstrap-admin", Role.ADMIN, None)
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


def test_reset_bootstrap_admin_replaces_the_password():
    first = token_store.ensure_bootstrap_admin()
    second = token_store.reset_bootstrap_admin()

    assert STORE.lookup(digest_of(first)) is None
    assert STORE.lookup(digest_of(second)).role == Role.ADMIN


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
            ApiToken(id="t1", label="old", role="reader", project="shop-api", token_hash="ab" * 32)
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
    assert token_store.migrate_legacy_projects() == 2
    assert token_store.migrate_legacy_projects() == 0

    links = {link.token_id: (link.project, link.status) for link in link_rows(database)}
    assert links == {"t1": ("shop-api", "active"), "t3": ("billing", "pending")}
    assert STORE.lookup(bytes.fromhex("ab" * 32)).projects == {"shop-api"}
    assert STORE.lookup(bytes.fromhex("cd" * 32)).projects is None
    assert [item["token_id"] for item in token_store.list_enrollments()] == ["t3"]
