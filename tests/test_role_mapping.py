"""OIDC role mapping: stored mappings, static groups and resolution of a login."""

import pytest

from security_review_mcp import role_mapping, services
from security_review_mcp.config import Settings
from security_review_mcp.http_server import Role
from security_review_mcp.role_mapping import Access


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


def resolve(*groups: str, **settings) -> Access | None:
    return role_mapping.resolve(set(groups), make_settings(**settings))


# ── Stored mappings ──────────────────────────────────────────────────────────


def test_create_list_update_delete():
    created = role_mapping.create_mapping(
        " payments ", "triager", ["billing", "billing", "shop-api"], created_by="admin"
    )
    assert created["claim_value"] == "payments"
    assert created["projects"] == ["billing", "shop-api"]
    assert created["source"] == "database" and created["created_by"] == "admin"
    role_mapping.create_mapping("payments", "reader")

    listed = role_mapping.list_mappings()
    assert [(item["role"], item["projects"]) for item in listed] == [
        ("reader", None),
        ("triager", ["billing", "shop-api"]),
    ]

    updated = role_mapping.update_mapping(created["id"], [])
    assert updated["projects"] is None
    assert role_mapping.delete_mapping(created["id"])["role"] == "triager"
    assert len(role_mapping.list_mappings()) == 1
    with pytest.raises(services.NotFoundError):
        role_mapping.delete_mapping(created["id"])
    with pytest.raises(services.NotFoundError):
        role_mapping.update_mapping(created["id"], ["x"])


@pytest.mark.parametrize(
    ("claim_value", "role", "projects", "message"),
    [
        ("", "reader", None, "between 1 and 200"),
        ("x" * 201, "reader", None, "between 1 and 200"),
        ("a\nb", "reader", None, "control characters"),
        ("devs", "mcp", None, "reader, triager or admin"),
        ("devs", "owner", None, "reader, triager or admin"),
        ("devs", "admin", ["shop-api"], "every project"),
        ("devs", "reader", [f"p{i}" for i in range(51)], "at most 50"),
        ("devs", "reader", [" "], "Project"),
        ("devs", "reader", ["shop\napi"], "control characters"),
    ],
)
def test_invalid_mappings_are_refused(claim_value, role, projects, message):
    with pytest.raises(ValueError, match=message):
        role_mapping.create_mapping(claim_value, role, projects)


def test_duplicate_mapping_is_refused():
    role_mapping.create_mapping("devs", "reader")
    with pytest.raises(ValueError, match="already mapped"):
        role_mapping.create_mapping("devs", "reader", ["shop-api"])


def test_number_of_mappings_is_bounded(monkeypatch):
    monkeypatch.setattr(role_mapping, "MAX_MAPPINGS", 2)
    role_mapping.create_mapping("a", "reader")
    role_mapping.create_mapping("b", "reader")
    with pytest.raises(ValueError, match="At most 2"):
        role_mapping.create_mapping("c", "reader")


def test_static_mappings_come_from_the_variables():
    settings = make_settings(oidc_admin_groups="ops, sec", oidc_reader_groups="devs")
    assert role_mapping.static_mappings(settings) == [
        {"claim_value": "ops", "role": "admin", "projects": None, "source": "environment"},
        {"claim_value": "sec", "role": "admin", "projects": None, "source": "environment"},
        {"claim_value": "devs", "role": "reader", "projects": None, "source": "environment"},
    ]


# ── Resolution ───────────────────────────────────────────────────────────────


def test_no_match_is_refused_unless_a_default_role_is_set():
    assert resolve("marketing") is None
    assert resolve() is None
    assert resolve("marketing", oidc_default_role="reader") == Access(Role.READER)


def test_highest_role_wins():
    role_mapping.create_mapping("devs", "reader")
    role_mapping.create_mapping("leads", "triager", ["shop-api"])
    assert resolve("devs") == Access(Role.READER)
    assert resolve("devs", "leads") == Access(Role.TRIAGER, frozenset({"shop-api"}))
    assert resolve("devs", oidc_admin_groups="devs") == Access(Role.ADMIN)


def test_projects_of_the_winning_role_are_merged():
    role_mapping.create_mapping("team-a", "reader", ["shop-api"])
    role_mapping.create_mapping("team-b", "reader", ["billing", "shop-api"])
    assert resolve("team-a", "team-b") == Access(Role.READER, frozenset({"shop-api", "billing"}))


def test_an_unrestricted_mapping_of_the_winning_role_reaches_every_project():
    role_mapping.create_mapping("team-a", "reader", ["shop-api"])
    role_mapping.create_mapping("everyone", "reader")
    assert resolve("team-a", "everyone") == Access(Role.READER)
    # A static group always reaches every project
    assert resolve("team-a", oidc_reader_groups="team-a") == Access(Role.READER)


def test_lower_role_projects_are_not_added_to_a_higher_role():
    role_mapping.create_mapping("readers", "reader", ["billing"])
    role_mapping.create_mapping("triagers", "triager", ["shop-api"])
    assert resolve("readers", "triagers") == Access(Role.TRIAGER, frozenset({"shop-api"}))


def test_too_many_projects_for_one_session_are_refused(monkeypatch):
    monkeypatch.setattr(role_mapping, "MAX_SESSION_PROJECTS", 2)
    role_mapping.create_mapping("team-a", "reader", ["a", "b"])
    role_mapping.create_mapping("team-b", "reader", ["c"])
    assert resolve("team-a") == Access(Role.READER, frozenset({"a", "b"}))
    with pytest.raises(ValueError, match="more than 2 projects"):
        resolve("team-a", "team-b")


def test_matching_is_exact():
    role_mapping.create_mapping("Devs", "reader")
    assert resolve("devs") is None
    assert resolve("Devs ") is None


# ── Combination with the role of a web user ──────────────────────────────────


def test_combine_keeps_the_highest_role_and_merges_its_projects():
    assert role_mapping.combine([]) is None
    assert role_mapping.combine([(Role.READER, ["a"]), (Role.READER, ["b"])]) == Access(
        Role.READER, frozenset({"a", "b"})
    )
    assert role_mapping.combine([(Role.READER, ["a"]), (Role.TRIAGER, ["b"])]) == Access(
        Role.TRIAGER, frozenset({"b"})
    )
    # An unrestricted access of the winning role reaches every project
    assert role_mapping.combine([(Role.READER, ["a"]), (Role.READER, None)]) == Access(Role.READER)
    assert role_mapping.combine([(Role.ADMIN, None), (Role.READER, ["a"])]) == Access(Role.ADMIN)


def test_combine_refuses_too_many_projects(monkeypatch):
    monkeypatch.setattr(role_mapping, "MAX_SESSION_PROJECTS", 2)
    with pytest.raises(ValueError, match="more than 2 projects"):
        role_mapping.combine([(Role.READER, ["a", "b"]), (Role.READER, ["c"])])
