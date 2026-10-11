"""Tokens stored in the database: creation, lookup, revocation, project scope, bootstrap admin."""

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
        {key: created[key] for key in ("id", "label", "role", "project", "created_at")}
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
        {key: shop[key] for key in ("id", "label", "role", "project", "created_at")}
    ]
    assert stored_rows(database)[0].token_hash not in str(token_store.list_tokens())


def test_reset_bootstrap_admin_replaces_the_password():
    first = token_store.ensure_bootstrap_admin()
    second = token_store.reset_bootstrap_admin()

    assert STORE.lookup(digest_of(first)) is None
    assert STORE.lookup(digest_of(second)).role == Role.ADMIN
