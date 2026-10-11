"""Tokens stored in the database: creation, lookup, revocation, project scope, bootstrap admin."""

import re
from datetime import timedelta

import pytest
from sqlmodel import Session, select

from security_review_mcp import token_store
from security_review_mcp.http_server import Role, TokenInfo, hash_token
from security_review_mcp.models import ApiToken

STORE = token_store.DatabaseTokenStore()


def digest_of(token: str) -> bytes:
    return hash_token(token)


def stored_rows(database) -> list[ApiToken]:
    with Session(database) as session:
        return list(session.exec(select(ApiToken)).all())


# ── Project tokens ───────────────────────────────────────────────────────────


def test_project_token_is_stored_as_hash_and_revoked(database):
    created = token_store.create_project_token(" ci ", "shop-api")

    (row,) = stored_rows(database)
    assert row.token_hash == digest_of(created["token"]).hex()
    assert created["token"] not in row.model_dump_json()
    assert STORE.lookup(digest_of(created["token"])) == TokenInfo(
        "ci", Role.READER, project="shop-api", token_id=created["id"]
    )
    listed = token_store.list_project_tokens()
    assert listed == [
        {key: created[key] for key in ("id", "label", "role", "project", "status", "created_at")}
    ]
    assert created["token"] not in str(listed)

    token_store.revoke_project_token(created["id"])
    assert STORE.lookup(digest_of(created["token"])) is None
    assert STORE.has_tokens() is False
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
        assert token_store.create_token(f"{role}-billing", role, "billing")["project"] == "billing"
    with pytest.raises(ValueError, match="between 1 and 64"):
        token_store.create_project_token("  ", "billing")
    with pytest.raises(ValueError, match="between 1 and 200"):
        token_store.create_project_token("other", "p" * 201)


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
    assert (info.label, info.role, info.project) == ("bootstrap-admin", Role.ADMIN, None)
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
        {key: shop[key] for key in ("id", "label", "role", "project", "status", "created_at")}
    ]
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
    (row,) = stored_rows(database)
    assert row.token_hash == digest_of(request["token"]).hex()
    assert request["token"] not in row.model_dump_json()
    pending = STORE.lookup(digest_of(request["token"]))
    assert pending.pending is True
    # A pending request does not switch authentication on and is not an active project token
    assert STORE.has_tokens() is False
    assert token_store.list_project_tokens() == []
    assert [item["id"] for item in token_store.list_tokens(pending=True)] == [request["id"]]
    assert token_store.enrollment_status(request["id"])["status"] == "pending"

    approved = token_store.approve_enrollment(request["label"])

    assert approved["status"] == "active"
    assert STORE.lookup(digest_of(request["token"])) == TokenInfo(
        request["label"], Role.MCP, project="shop-api", token_id=request["id"]
    )
    assert STORE.has_tokens() is True
    assert token_store.list_tokens(pending=True) == []
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
    assert sorted(item["project"] for item in token_store.list_tokens(pending=True)) == [
        "billing",
        "other",
    ]
