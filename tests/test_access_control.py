"""Access control: permissions, roles, groups, members and the grants they give."""

import pytest
from conftest import group_for, make_user

from security_review_mcp import access_control, audit, web_users
from security_review_mcp.access_control import Permission
from security_review_mcp.database import session_scope
from security_review_mcp.http_server import Role
from security_review_mcp.services import NotFoundError

PASSWORD = "Correct horse battery 9"


def grants_of(user_id: int) -> dict:
    """Grants of a web user, read in a new session."""
    with session_scope() as session:
        return access_control.user_grants(session, user_id)


def role_id(name: str) -> int:
    """Id of a role by name."""
    return next(role["id"] for role in access_control.list_roles() if role["name"] == name)


# ── Grants ───────────────────────────────────────────────────────────────────


def test_combine_keeps_the_projects_of_each_permission():
    grants = access_control.combine(
        [
            ({"reports.read"}, ["shop"]),
            ({"reports.read", "findings.triage"}, ["crm"]),
            ({"audit.read"}, ["ignored"]),
        ]
    )

    assert grants == {
        "reports.read": frozenset({"shop", "crm"}),
        "findings.triage": frozenset({"crm"}),
        # A permission on the whole controller is never limited to projects
        "audit.read": None,
    }


def test_combine_reaches_every_project_when_one_binding_does():
    grants = access_control.combine([({"reports.read"}, ["shop"]), ({"reports.read"}, None)])
    assert grants == {"reports.read": None}
    grants = access_control.combine([({"reports.read"}, None), ({"reports.read"}, ["shop"])])
    assert grants == {"reports.read": None}


def test_combine_bounds_the_projects_of_a_permission(monkeypatch):
    monkeypatch.setattr(access_control, "MAX_SESSION_PROJECTS", 2)
    with pytest.raises(ValueError, match="more than 2 projects"):
        access_control.combine([({"reports.read"}, ["a", "b", "c"])])


@pytest.mark.parametrize(
    ("role", "projects", "expected"),
    [
        (Role.READER, ["shop"], {"reports.read": frozenset({"shop"})}),
        (
            Role.TRIAGER,
            None,
            {"reports.read": None, "findings.triage": None},
        ),
        (Role.ADMIN, None, {permission.value: None for permission in Permission}),
        (Role.MCP, None, {}),
        (Role.CI, ["shop"], {}),
    ],
)
def test_token_grants_follow_the_system_roles(role, projects, expected):
    assert access_control.token_grants(role, projects) == expected


def test_summary_role_sums_up_the_grants():
    assert access_control.summary_role(access_control.token_grants(Role.ADMIN, None)) == Role.ADMIN
    # Every permission, but limited to projects: not an administrator
    limited = {permission.value: None for permission in Permission} | {
        "reports.read": frozenset({"shop"})
    }
    assert access_control.summary_role(limited) == Role.TRIAGER
    assert access_control.summary_role({"audit.read": None}) == Role.READER


def test_allows_and_scope():
    grants = {"reports.read": frozenset({"shop"}), "audit.read": None}

    assert access_control.allows(grants, Permission.REPORTS_READ)
    assert access_control.allows(grants, Permission.REPORTS_READ, "shop")
    assert not access_control.allows(grants, Permission.REPORTS_READ, "crm")
    assert access_control.allows(grants, Permission.AUDIT_READ, "anything")
    assert not access_control.allows(grants, Permission.USERS_MANAGE)
    assert access_control.scope(grants, Permission.REPORTS_READ) == frozenset({"shop"})
    assert access_control.scope(grants, Permission.FINDINGS_TRIAGE) == frozenset()


# ── Roles ────────────────────────────────────────────────────────────────────


def test_system_roles_exist_and_cannot_change():
    roles = {role["name"]: role for role in access_control.list_roles()}

    assert [name for name, role in roles.items() if role["system"]] == [
        "admin",
        "reader",
        "triager",
    ]
    assert roles["admin"]["permissions"] == sorted(p.value for p in Permission)
    assert roles["reader"]["scoped"] and not roles["admin"]["scoped"]
    with pytest.raises(ValueError, match="cannot be changed"):
        access_control.update_role(roles["reader"]["id"], ["audit.read"])
    with pytest.raises(ValueError, match="cannot be deleted"):
        access_control.delete_role(roles["admin"]["id"])
    # Created once
    assert access_control.ensure_system_roles() == {name: roles[name]["id"] for name in roles}


def test_custom_roles_are_created_updated_and_deleted():
    created = access_control.create_role(
        "Auditor", ["audit.read", "reports.read", "audit.read"], "Reads the log", actor="user:root"
    )

    assert (created["name"], created["permissions"], created["system"]) == (
        "Auditor",
        ["audit.read", "reports.read"],
        False,
    )
    assert (created["description"], created["groups"], created["scoped"]) == (
        "Reads the log",
        0,
        False,
    )
    updated = access_control.update_role(created["id"], ["reports.read"], "", name="Readers 2")
    assert (updated["name"], updated["permissions"], updated["scoped"]) == (
        "Readers 2",
        ["reports.read"],
        True,
    )
    deleted = access_control.delete_role(created["id"])
    assert deleted["name"] == "Readers 2"
    with pytest.raises(NotFoundError):
        access_control.delete_role(created["id"])


@pytest.mark.parametrize(
    ("name", "permissions", "description", "message"),
    [
        ("", ["audit.read"], "", "between 1 and 64"),
        ("x" * 65, ["audit.read"], "", "between 1 and 64"),
        ("bad\nname", ["audit.read"], "", "control characters"),
        ("Auditor", [], "", "at least one permission"),
        ("Auditor", ["root.everything"], "", "Unknown permission"),
        ("Auditor", ["audit.read"], "x" * 501, "at most 500"),
        ("Auditor", ["audit.read"], "bad\x00text", "control characters"),
    ],
)
def test_invalid_roles_are_refused(name, permissions, description, message):
    with pytest.raises(ValueError, match=message):
        access_control.create_role(name, permissions, description)


def test_duplicate_roles_and_the_role_limit_are_refused(monkeypatch):
    access_control.create_role("Auditor", ["audit.read"])
    with pytest.raises(ValueError, match="already exists"):
        access_control.create_role("Auditor", ["reports.read"])
    with pytest.raises(ValueError, match="already exists"):
        access_control.create_role("reader", ["reports.read"])
    monkeypatch.setattr(access_control, "MAX_ROLES", 4)
    with pytest.raises(ValueError, match="At most 4 roles"):
        access_control.create_role("Other", ["audit.read"])


def test_a_role_limited_to_projects_cannot_gain_controller_permissions():
    role = access_control.create_role("Shop readers", ["reports.read"])
    group = access_control.create_group("shop")
    access_control.set_group_roles(group["id"], [(role["id"], ["shop"])])

    with pytest.raises(ValueError, match="limited to projects"):
        access_control.update_role(role["id"], ["reports.read", "audit.read"])


def test_a_role_change_applies_to_the_members_at_once():
    role = access_control.create_role("Auditor", ["audit.read"])
    group = access_control.create_group("auditors")
    access_control.set_group_roles(group["id"], [(role["id"], None)])
    user = web_users.create_user("alice", PASSWORD, [group["id"]])
    assert grants_of(user["id"]) == {"audit.read": None}

    access_control.update_role(role["id"], ["audit.read", "rules.manage"])
    assert grants_of(user["id"]) == {"audit.read": None, "rules.manage": None}
    access_control.delete_role(role["id"])
    assert grants_of(user["id"]) == {}
    assert access_control.get_group(group["id"])["roles"] == []


# ── Groups ───────────────────────────────────────────────────────────────────


def test_groups_are_created_with_roles_and_members():
    group = access_control.create_group("devs", "Developers", sso=True, actor="user:root")
    alice = web_users.create_user("alice", PASSWORD)
    bob = web_users.create_user("bob", PASSWORD)

    access_control.set_group_roles(
        group["id"], [(role_id("reader"), ["shop", "crm"]), (role_id("triager"), ["shop"])]
    )
    updated = access_control.set_group_members(group["id"], [alice["id"], bob["id"], bob["id"]])

    assert (updated["name"], updated["description"], updated["sso"]) == ("devs", "Developers", True)
    assert [(r["name"], r["projects"]) for r in updated["roles"]] == [
        ("reader", ["shop", "crm"]),
        ("triager", ["shop"]),
    ]
    assert [(m["username"], m["source"]) for m in updated["members"]] == [
        ("alice", "local"),
        ("bob", "local"),
    ]
    assert grants_of(alice["id"]) == {
        "reports.read": frozenset({"shop", "crm"}),
        "findings.triage": frozenset({"shop"}),
    }
    # Replacing the members keeps the OIDC ones and removes the others
    removed = access_control.set_group_members(group["id"], [bob["id"]])
    assert [m["username"] for m in removed["members"]] == ["bob"]
    assert grants_of(alice["id"]) == {}


@pytest.mark.parametrize(
    ("bindings", "message"),
    [
        ([("admin", ["shop"])], "cannot list projects"),
        ([("reader", ["shop"]), ("reader", None)], "given twice"),
        ([("reader", [f"p{i}" for i in range(51)])], "at most 50 projects"),
        ([("reader", ["bad\x01"])], "control characters"),
    ],
)
def test_invalid_group_roles_are_refused(bindings, message):
    group = access_control.create_group("devs")
    with pytest.raises(ValueError, match=message):
        access_control.set_group_roles(
            group["id"], [(role_id(name), projects) for name, projects in bindings]
        )


def test_group_roles_and_members_are_bounded_and_checked(monkeypatch):
    group = access_control.create_group("devs")
    with pytest.raises(NotFoundError, match="Role 999"):
        access_control.set_group_roles(group["id"], [(999, None)])
    with pytest.raises(NotFoundError, match="Web user 999"):
        access_control.set_group_members(group["id"], [999])
    with pytest.raises(NotFoundError, match="Group 999"):
        access_control.set_group_members(999, [])
    monkeypatch.setattr(access_control, "MAX_ROLES_PER_GROUP", 1)
    with pytest.raises(ValueError, match="at most 1 roles"):
        access_control.set_group_roles(group["id"], [(1, None), (2, None)])
    monkeypatch.setattr(access_control, "MAX_MEMBERS_PER_CHANGE", 1)
    with pytest.raises(ValueError, match="At most 1 members"):
        access_control.set_group_members(group["id"], [1, 2])


@pytest.mark.parametrize("name", ["", " ", "x" * 201, "devs\nadmins"])
def test_invalid_group_names_are_refused(name):
    with pytest.raises(ValueError, match="Group name"):
        access_control.create_group(name)


def test_duplicate_groups_and_the_group_limit_are_refused(monkeypatch):
    access_control.create_group("devs")
    with pytest.raises(ValueError, match="already exists"):
        access_control.create_group("devs")
    other = access_control.create_group("ops")
    with pytest.raises(ValueError, match="already exists"):
        access_control.update_group(other["id"], "devs")
    monkeypatch.setattr(access_control, "MAX_GROUPS", 2)
    with pytest.raises(ValueError, match="At most 2 groups"):
        access_control.create_group("qa")


def test_renaming_a_group_or_closing_it_to_sso_drops_its_sso_members():
    group_id = group_for("reader", name="devs", sso=True)
    alice = web_users.create_user("alice", None, auth_source="oidc")
    bob = web_users.create_user("bob", PASSWORD, [group_id])
    with session_scope() as session:
        access_control.sync_sso_groups(session, alice["id"], {"devs"}, _settings())
    assert grants_of(alice["id"]) == {"reports.read": None}

    access_control.update_group(group_id, "developers", "", sso=True)
    assert grants_of(alice["id"]) == {}
    with session_scope() as session:
        access_control.sync_sso_groups(session, alice["id"], {"developers"}, _settings())
    access_control.update_group(group_id, "developers", "", sso=False)
    assert grants_of(alice["id"]) == {}
    # The members added by an administrator stay
    assert grants_of(bob["id"]) == {"reports.read": None}


def test_deleting_a_group_removes_its_roles_and_members():
    group_id = group_for("reader", name="devs")
    alice = web_users.create_user("alice", PASSWORD, [group_id])

    deleted = access_control.delete_group(group_id, actor="user:root")

    assert deleted["name"] == "devs"
    assert grants_of(alice["id"]) == {}
    assert web_users.find_user("alice")["groups"] == []
    with pytest.raises(NotFoundError):
        access_control.get_group(group_id)


def test_sync_sso_groups_replaces_only_the_sso_memberships():
    devs = group_for("reader", ["shop"], name="devs", sso=True)
    group_for("triager", name="leads", sso=True)
    given = group_for("reader", ["crm"], name="given")
    alice = web_users.create_user("alice", None, [given], auth_source="oidc")

    with session_scope() as session:
        joined = access_control.sync_sso_groups(
            session, alice["id"], {"devs", "leads", "unknown"}, _settings()
        )
    assert joined == ["devs", "leads"]
    with session_scope() as session:
        assert access_control.sync_sso_groups(session, alice["id"], {"devs"}, _settings()) == [
            "devs"
        ]
        groups = access_control.user_groups(session, alice["id"])
    assert [(g["name"], g["source"]) for g in groups] == [("devs", "oidc"), ("given", "local")]
    assert devs in [g["group_id"] for g in groups]


# ── Direct roles of a user ───────────────────────────────────────────────────


def set_roles(user_id: int, bindings, actor: str | None = None) -> None:
    """Replace the direct roles of a user in a new session."""
    with session_scope() as session:
        access_control.set_user_roles(session, user_id, bindings, actor)


def test_direct_roles_add_to_the_roles_of_the_groups():
    alice = make_user("alice", PASSWORD, "reader", ["shop"])
    set_roles(alice["id"], [(role_id("triager"), ["crm", "billing"])])

    assert grants_of(alice["id"]) == {
        "reports.read": frozenset({"shop", "crm", "billing"}),
        "findings.triage": frozenset({"crm", "billing"}),
    }
    user = web_users.find_user("alice")
    assert user["roles"] == [
        {"role_id": role_id("triager"), "name": "triager", "projects": ["crm", "billing"]}
    ]
    assert [group["name"] for group in user["groups"]] == ["reader:shop"]
    # A direct role on every project wins over the projects of the groups
    set_roles(alice["id"], [(role_id("reader"), None)])
    assert grants_of(alice["id"]) == {"reports.read": None}
    assert web_users.find_user("alice")["roles"][0]["projects"] is None


def test_a_user_without_group_gets_access_from_its_direct_roles():
    bob = web_users.create_user("bob", PASSWORD, roles=[(role_id("reader"), ["shop"])])
    assert bob["groups"] == []
    assert (bob["effective_role"], bob["permissions"]) == ("reader", {"reports.read": ["shop"]})
    # update_user leaves the groups alone when they are not given
    updated = web_users.update_user(bob["id"], None, "root", [])
    assert (updated["roles"], updated["permissions"]) == ([], {})


@pytest.mark.parametrize(
    ("bindings", "message"),
    [
        ([("admin", ["shop"])], "cannot list projects"),
        ([("reader", None), ("reader", ["shop"])], "given twice"),
        ([("reader", ["bad\x00name"])], "control characters"),
    ],
)
def test_invalid_direct_roles_are_refused(bindings, message):
    alice = web_users.create_user("alice", PASSWORD)
    with pytest.raises(ValueError, match=message):
        set_roles(alice["id"], [(role_id(name), projects) for name, projects in bindings])
    assert web_users.find_user("alice")["roles"] == []


def test_direct_roles_are_bounded_and_checked(monkeypatch):
    alice = web_users.create_user("alice", PASSWORD)
    with pytest.raises(NotFoundError, match="Role 999"):
        set_roles(alice["id"], [(999, None)])
    monkeypatch.setattr(access_control, "MAX_ROLES_PER_USER", 1)
    with pytest.raises(ValueError, match="at most 1 direct roles"):
        set_roles(alice["id"], [(role_id("reader"), None), (role_id("triager"), None)])
    monkeypatch.setattr(access_control, "MAX_PROJECTS_PER_TOKEN", 2)
    with pytest.raises(ValueError, match="at most 2 projects"):
        set_roles(alice["id"], [(role_id("reader"), ["a", "b", "c"])])


def test_a_role_limited_to_projects_for_a_user_cannot_gain_controller_permissions():
    role = access_control.create_role("Shop readers", ["reports.read"])
    alice = web_users.create_user("alice", PASSWORD)
    set_roles(alice["id"], [(role["id"], ["shop"])])
    assert access_control.list_roles()[-1]["users"] == 1

    with pytest.raises(ValueError, match="limited to projects for a user"):
        access_control.update_role(role["id"], ["reports.read", "audit.read"])
    access_control.delete_role(role["id"])
    assert web_users.find_user("alice")["roles"] == []


def test_deleting_a_user_removes_its_direct_roles():
    make_user("root", PASSWORD, "admin")
    alice = web_users.create_user("alice", PASSWORD, roles=[(role_id("reader"), ["shop"])])
    web_users.delete_user(alice["id"])
    again = web_users.create_user("alice", PASSWORD)
    assert again["roles"] == [] and again["permissions"] == {}


def test_find_roles_reads_the_command_line():
    with session_scope() as session:
        bindings = access_control.find_roles(session, ["reader", "triager:shop, crm"])
        with pytest.raises(NotFoundError, match="Role 'ghost'"):
            access_control.find_roles(session, ["ghost:shop"])
    assert bindings == [(role_id("reader"), None), (role_id("triager"), ["shop", "crm"])]


# ── The last holder of users.manage ──────────────────────────────────────────


def test_no_change_removes_the_last_holder_of_users_manage():
    root = make_user("root", PASSWORD, "admin")
    (group,) = [g for g in access_control.list_groups() if g["name"] == "admin"]
    managers = access_control.create_role("Managers", ["users.manage"])

    with pytest.raises(ValueError, match="keep the users.manage"):
        access_control.delete_group(group["id"])
    with pytest.raises(ValueError, match="keep the users.manage"):
        access_control.set_group_roles(group["id"], [(role_id("reader"), None)])
    with pytest.raises(ValueError, match="keep the users.manage"):
        access_control.set_group_members(group["id"], [])
    # Another holder through a custom role: the change is accepted
    other = access_control.create_group("managers")
    access_control.set_group_roles(other["id"], [(managers["id"], None)])
    access_control.set_group_members(other["id"], [root["id"]])
    access_control.delete_group(group["id"])
    with pytest.raises(ValueError, match="keep the users.manage"):
        access_control.update_role(managers["id"], ["audit.read"])
    with pytest.raises(ValueError, match="keep the users.manage"):
        access_control.delete_role(managers["id"])
    assert access_control.get_group(other["id"])["roles"][0]["name"] == "Managers"


def test_a_direct_admin_role_counts_as_a_holder_of_users_manage():
    root = web_users.create_user("root", PASSWORD, roles=[(role_id("admin"), None)])
    with session_scope() as session:
        assert access_control.managers(session) == {root["id"]}
    with pytest.raises(ValueError, match="keep the users.manage"):
        web_users.update_user(root["id"], None, "root", [(role_id("reader"), None)])
    with pytest.raises(ValueError, match="cannot be deleted"):
        web_users.delete_user(root["id"])
    # Another holder through a group: the direct role may go
    make_user("bob", PASSWORD, "admin")
    assert web_users.update_user(root["id"], None, "root", [])["roles"] == []


def test_the_guard_does_not_block_a_database_without_any_manager():
    group = access_control.create_group("devs")
    access_control.set_group_roles(group["id"], [(role_id("reader"), None)])
    access_control.delete_group(group["id"])


# ── Audit ────────────────────────────────────────────────────────────────────


def test_access_changes_are_audited():
    make_user("root", PASSWORD, "admin")
    role = access_control.create_role("Auditor", ["audit.read"], actor="user:root")
    group = access_control.create_group("auditors", actor="user:root")
    access_control.set_group_roles(group["id"], [(role["id"], None)], actor="user:root")
    alice = web_users.create_user("alice", PASSWORD)
    access_control.set_group_members(group["id"], [alice["id"]], actor="user:root")
    web_users.update_user(alice["id"], [], "user:root")
    web_users.update_user(
        alice["id"], None, "user:root", [(role["id"], None), (role_id("reader"), ["shop"])]
    )
    access_control.update_group(group["id"], "audit-team", actor="user:root")
    access_control.delete_group(group["id"], actor="user:root")
    access_control.delete_role(role["id"], actor="user:root")

    events = audit.list_events(actor="user:root")["events"]
    assert [event["action"] for event in reversed(events)] == [
        "role.created",
        "group.created",
        "group.roles_changed",
        "group.members_changed",
        "user.groups_changed",
        "user.roles_changed",
        "group.updated",
        "group.deleted",
        "role.deleted",
    ]
    members = next(e for e in events if e["action"] == "group.members_changed")
    assert members["details"] == {"added": [alice["id"]], "name": "auditors", "removed": []}
    roles = next(e for e in events if e["action"] == "user.roles_changed")
    assert roles["target_id"] == str(alice["id"])
    assert roles["details"] == {"roles": ["Auditor", "reader:shop"]}


def _settings(**values):
    """Settings that ignore the developer's .env file."""
    from security_review_mcp.config import Settings

    return Settings(_env_file=None, **values)
