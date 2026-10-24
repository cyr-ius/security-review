"""Access control: permissions, roles, groups, members and the grants they give."""

import pytest
from conftest import group_for, make_user
from sqlmodel import select

from security_review_mcp import access_control, audit, web_users
from security_review_mcp.access_control import Permission
from security_review_mcp.http_server import Role
from security_review_mcp.reports.services import NotFoundError
from security_review_mcp.storage.database import session_scope

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
        (Role.ADMIN, None, {permission.value: None for permission in Permission}),
        (Role.MCP, None, {}),
        (Role.CI, ["shop"], {}),
        (Role.METRICS, None, {}),
        # Never the role of a token (a stored one authenticates nothing): no permission either
        (Role.USER, None, {}),
    ],
)
def test_token_grants_only_give_permissions_to_admin(role, projects, expected):
    assert access_control.token_grants(role, projects) == expected


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


def test_built_in_roles_exist_and_cannot_change():
    roles = {role["name"]: role for role in access_control.list_roles()}

    assert [name for name, role in roles.items() if role["system"]] == ["admin", "reader"]
    assert roles["admin"]["permissions"] == sorted(p.value for p in Permission)
    assert roles["reader"]["scoped"] and not roles["admin"]["scoped"]
    with pytest.raises(ValueError, match="cannot be changed"):
        access_control.update_role(roles["reader"]["id"], ["audit.read"])
    with pytest.raises(ValueError, match="cannot be deleted"):
        access_control.delete_role(roles["admin"]["id"])
    # Created once
    built_in = {name: roles[name]["id"] for name in ("admin", "reader")}
    assert access_control.ensure_system_roles() == built_in


def test_mcp_user_is_an_ordinary_role_that_creates_mcp_tokens():
    roles = {role["name"]: role for role in access_control.list_roles()}
    mcp_user = roles["mcp-user"]
    assert not mcp_user["system"] and not mcp_user["scoped"]
    assert mcp_user["permissions"] == ["mcp_tokens.create"]
    assert {"name": "mcp_tokens.create", "scoped": False} in access_control.list_permissions()
    # A controller-wide permission: never limited to projects
    with pytest.raises(ValueError):
        access_control.clean_projects(["mcp_tokens.create"], ["shop"])
    access_control.delete_role(mcp_user["id"])


def test_triager_is_an_ordinary_role():
    roles = {role["name"]: role for role in access_control.list_roles()}
    triager = roles["triager"]
    assert not triager["system"] and triager["scoped"]
    assert triager["permissions"] == ["findings.triage", "reports.read"]

    changed = access_control.update_role(
        triager["id"], ["findings.triage", "reports.read"], "Triage of a team"
    )
    assert changed["description"] == "Triage of a team"
    access_control.delete_role(triager["id"])
    # Not created again: only the built-in roles are
    access_control.ensure_system_roles()
    assert "triager" not in {role["name"] for role in access_control.list_roles()}


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
        ([("reader", ["\x01"])], "between 1 and 200"),
    ],
)
def test_invalid_group_roles_are_refused(bindings, message):
    group = access_control.create_group("devs")
    with pytest.raises(ValueError, match=message):
        access_control.set_group_roles(
            group["id"], [(role_id(name), projects) for name, projects in bindings]
        )


def test_a_group_is_not_open_to_oidc_unless_asked():
    assert access_control.create_group("devs")["sso"] is False
    assert access_control.create_group("ops", sso=True)["sso"] is True


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


# ── Project groups ───────────────────────────────────────────────────────────


def ensure_project_group(project: str, actor: str | None = None) -> dict:
    """Project group of a project, read in a new session."""
    with session_scope() as session:
        group_id = access_control.ensure_project_group(session, project, actor).id
    return access_control.get_group(group_id)


def test_a_project_group_reads_its_project_only_and_is_reused():
    group = ensure_project_group("shop", actor="user:root")

    assert (group["name"], group["sso"], group["created_by"]) == (
        "project:shop",
        False,
        "user:root",
    )
    assert [(r["name"], r["projects"]) for r in group["roles"]] == [("reader", ["shop"])]
    assert ensure_project_group(" shop ")["id"] == group["id"]
    (created,) = audit.list_events(action="group.created")["events"]
    assert created["details"] == {"name": "project:shop", "sso": False, "project": "shop"}


def test_a_project_group_is_never_a_group_with_more_roles_or_open_to_oidc():
    wider = access_control.create_group("project:shop", sso=False)
    access_control.set_group_roles(
        wider["id"], [(role_id("reader"), ["shop"]), (role_id("triager"), ["crm"])]
    )
    oidc = access_control.create_group("shop-readers", sso=True)
    access_control.set_group_roles(oidc["id"], [(role_id("reader"), ["shop"])])

    group = ensure_project_group("shop")

    # The name of the wider group is taken: the new group gets a number
    assert group["id"] not in (wider["id"], oidc["id"])
    assert group["name"] == "project:shop (2)"


def test_a_group_made_by_an_administrator_with_the_same_role_is_reused():
    given = access_control.create_group("Shop team", sso=False)
    access_control.set_group_roles(given["id"], [(role_id("reader"), ["shop"])])
    assert ensure_project_group("shop")["id"] == given["id"]


def test_the_name_of_a_project_group_fits_a_group_name():
    project = "p" * 200
    group = ensure_project_group(project)
    assert len(group["name"]) == access_control.MAX_GROUP_NAME_CHARS
    assert group["roles"][0]["projects"] == [project]


def test_project_groups_are_bounded_and_checked(monkeypatch):
    # The project is normalized: no control character reaches the group name
    assert ensure_project_group("Bad\x00Name")["name"] == "project:bad-name"
    with pytest.raises(ValueError, match="between 1 and"):
        ensure_project_group(" ")
    access_control.create_group("devs")
    monkeypatch.setattr(access_control, "MAX_GROUPS", 1)
    with pytest.raises(ValueError, match="At most 1 groups"):
        ensure_project_group("shop")


def test_a_project_group_created_concurrently_is_refused(monkeypatch):
    access_control.create_group("project:shop")
    # Another approval created the group between the lookup of the name and the insert
    monkeypatch.setattr(
        access_control, "_project_group_name", lambda session, project: "project:shop"
    )
    with pytest.raises(ValueError, match="created concurrently; retry"):
        ensure_project_group("shop")
    assert [group["name"] for group in access_control.list_groups()] == ["project:shop"]


# ── Project creation ─────────────────────────────────────────────────────────


def enrolled(project: str) -> int:
    """Id of the pending project ``project``, requested by an enrollment."""
    access_control.enroll_project(project)
    return next(
        item["id"] for item in access_control.list_enrollments() if item["project"] == project
    )


def creator() -> dict:
    """A web user whose only role holds ``projects.create``."""
    role = access_control.create_role("Creator", [Permission.PROJECTS_CREATE])
    group = access_control.create_group("creators")
    access_control.set_group_roles(group["id"], [(role["id"], None)])
    return web_users.create_user("carol", PASSWORD, [group["id"]])


@pytest.mark.parametrize("permission", [Permission.PROJECTS_CREATE, Permission.PROJECTS_DELETE])
def test_project_permissions_are_on_the_whole_controller(permission):
    """projects.delete is never limited to projects: its route checks no project scope."""
    assert permission not in access_control.SCOPED_PERMISSIONS
    assert permission in access_control.SYSTEM_ROLES["admin"]
    assert {"name": permission.value, "scoped": False} in access_control.list_permissions()
    role = access_control.create_role(f"Role {permission.value}", [permission])
    group = access_control.create_group(f"group {permission.value}")
    with pytest.raises(ValueError, match="cannot list projects"):
        access_control.set_group_roles(group["id"], [(role["id"], ["shop"])])


def test_a_created_project_is_read_by_its_creator_only():
    carol = creator()
    other = web_users.create_user("dave", PASSWORD)

    created = access_control.create_project(carol["id"], " mobile-app ", "user:carol")

    assert (created["project"], created["group"]) == ("mobile-app", "project:mobile-app")
    assert grants_of(carol["id"]) == {
        "projects.create": None,
        "reports.read": frozenset({"mobile-app"}),
    }
    assert grants_of(other["id"]) == {}
    (event,) = audit.list_events(action="project.created")["events"]
    assert (event["actor"], event["project"], event["target_id"]) == (
        "user:carol",
        "mobile-app",
        "mobile-app",
    )
    assert event["details"] == {"group": "project:mobile-app", "user_id": carol["id"]}


def test_creating_a_project_never_opens_an_existing_one():
    """projects.create would otherwise let its holder read the reports of any project."""
    from security_review_mcp import token_store
    from security_review_mcp.reports import services

    carol = creator()
    services.save_report("shop", "Review", [])
    ensure_project_group("crm")
    triage = access_control.create_group("triage")
    access_control.set_group_roles(triage["id"], [(role_id("triager"), ["billing"])])
    token_store.create_token("ci-hr", Role.CI, projects=["hr"])
    access_control.approve_enrollment(enrolled("payroll"))

    for project in ("shop", "crm", "billing", "hr", "payroll"):
        with pytest.raises(ValueError, match=f"Project '{project}' already exists"):
            access_control.create_project(carol["id"], project, "user:carol")
    # A variant of a known name is the same project once normalized: refused too
    for variant in ("SHOP", "acme/Shop.git", "https://git.example.com/hr/Payroll"):
        with pytest.raises(ValueError, match="already exists"):
            access_control.create_project(carol["id"], variant, "user:carol")
    # The second creation of a project is refused too
    access_control.create_project(carol["id"], "new", "user:carol")
    with pytest.raises(ValueError, match="already exists"):
        access_control.create_project(carol["id"], "new", "user:carol")
    assert grants_of(carol["id"])["reports.read"] == frozenset({"new"})


def test_project_creation_checks_the_name_and_the_user():
    carol = creator()
    # The name is normalized: control characters alone leave nothing
    with pytest.raises(ValueError, match="between 1 and"):
        access_control.create_project(carol["id"], "\x00\x01")
    with pytest.raises(ValueError, match="between 1 and"):
        access_control.create_project(carol["id"], " ")
    with pytest.raises(NotFoundError):
        access_control.create_project(999, "shop")
    assert audit.list_events(action="project.created")["events"] == []


def test_deleting_a_project_removes_everything_that_refers_to_it():
    from sqlmodel import select

    from security_review_mcp import token_store
    from security_review_mcp.reports import services
    from security_review_mcp.storage.models import (
        FindingComment,
        FindingCreate,
        FindingTicket,
        Severity,
        TicketState,
        TicketTarget,
    )
    from security_review_mcp.ticketing import registry, set_target

    finding = FindingCreate(title="SQL injection", severity=Severity.HIGH, description="Query")
    shop = services.save_report("shop", "Review", [finding])
    shop_finding = services.get_report(shop["report_id"]).findings[0]
    services.add_finding_comment(shop_finding.id, "ann", "Seen")
    set_target("shop", registry.get("jira"), "SEC", None, "user:root")
    with session_scope() as session:
        session.add(
            FindingTicket(
                finding_id=shop_finding.id,
                kind="jira",
                project="shop",
                fingerprint="f" * 32,
                state=TicketState.SENT,
                external_key="SEC-1",
            )
        )
    kept = services.save_report("crm", "Review", [finding])
    carol = creator()
    access_control.create_project(carol["id"], "shop-mobile")
    group = ensure_project_group("shop")
    triage = access_control.create_group("triage")
    access_control.set_group_roles(
        triage["id"], [(role_id("triager"), ["shop", "crm"]), (role_id("reader"), ["shop"])]
    )
    token_store.create_token("ci-shop", Role.CI, projects=["shop"])
    token_store.create_token("ci-both", Role.CI, projects=["shop", "crm"])

    deleted = access_control.delete_project("Shop", "user:root")

    assert deleted == {
        "project": "shop",
        "reports": 1,
        "findings": 1,
        "groups_deleted": [group["name"]],
        "groups_changed": ["triage"],
        "tokens_revoked": 1,
        "tokens_changed": 1,
    }
    assert [item["project"] for item in services.list_projects(set())] == ["crm"]
    with session_scope() as session:
        assert session.exec(select(FindingComment)).all() == []
        assert session.exec(select(FindingTicket)).all() == []
        assert session.exec(select(TicketTarget)).all() == []
        assert not access_control.project_exists(session, "shop")
        assert access_control.project_exists(session, "shop-mobile")
    assert services.get_report(kept["report_id"]).project == "crm"
    # The reader role on "shop" alone is removed, never left reaching every project
    roles = access_control.get_group(triage["id"])["roles"]
    assert [(role["name"], role["projects"]) for role in roles] == [("triager", ["crm"])]
    tokens = {token["label"]: token for token in token_store.list_tokens()}
    assert "ci-shop" not in tokens
    assert tokens["ci-both"]["projects"] == ["crm"]
    (event,) = audit.list_events(action="project.deleted")["events"]
    assert (event["actor"], event["project"]) == ("user:root", "shop")
    with pytest.raises(NotFoundError):
        access_control.delete_project("shop")


# ── Enrollment ───────────────────────────────────────────────────────────────


def test_an_enrolled_project_waits_for_an_approval_and_gives_no_access():
    """Anybody may enroll: the project waits, its approval creates it without any member, and
    the answer never tells whether the project existed."""
    from security_review_mcp.reports import services

    services.save_report("shop", "Review", [])
    requested = access_control.enroll_project(" Mobile-App ", "alice password=hunter2", "10.0.0.1")
    known = access_control.enroll_project("shop")

    assert requested["project"] == "mobile-app"
    assert {key: str(value).replace("shop", "P") for key, value in known.items()} == {
        key: str(value).replace("mobile-app", "P") for key, value in requested.items()
    }
    (pending,) = access_control.list_enrollments()
    assert (pending["project"], pending["requested_from"]) == ("mobile-app", "10.0.0.1")
    assert "hunter2" not in pending["requested_by"]
    with session_scope() as session:
        # Pending: not a project yet
        assert not access_control.project_exists(session, "mobile-app")

    approved = access_control.approve_enrollment(pending["id"], "user:root")

    assert approved["group"] == "project:mobile-app"
    assert access_control.list_enrollments() == []
    group = access_control.get_group(approved["group_id"])
    assert (group["members"], group["created_by"]) == ([], "user:root")
    assert grants_of(web_users.create_user("root", PASSWORD)["id"]) == {}
    events = audit.list_events(project="mobile-app")["events"]
    approved_event = next(e for e in events if e["action"] == "enrollment.approved")
    assert (approved_event["actor"], approved_event["details"]["group"]) == (
        "user:root",
        "project:mobile-app",
    )
    requested_event = next(e for e in events if e["action"] == "enrollment.requested")
    assert (requested_event["actor"], requested_event["details"]["requested"]) == (
        "anonymous",
        True,
    )
    with pytest.raises(NotFoundError):
        access_control.reject_enrollment(pending["id"])


def test_enrollments_are_bounded_and_expire(monkeypatch):
    from datetime import timedelta

    from security_review_mcp.config import get_settings
    from security_review_mcp.storage.models import ProjectEnrollment, utcnow

    monkeypatch.setattr(access_control, "MAX_PENDING_PROJECTS", 2)
    monkeypatch.setattr(access_control, "MAX_ENROLLMENTS_PER_ADDRESS", 3)
    access_control.enroll_project("first", requested_from="10.0.0.1")
    access_control.enroll_project("second", requested_from="10.0.0.2")

    with pytest.raises(ValueError, match="Too many projects"):
        access_control.enroll_project("third")
    # A pending project is never refused by the limit, nor requested twice
    access_control.enroll_project("first")
    access_control.enroll_project("first", requested_from="10.0.0.1")
    access_control.enroll_project("first", requested_from="10.0.0.1")
    with pytest.raises(access_control.EnrollmentThrottled, match="retry later"):
        access_control.enroll_project("first", requested_from="10.0.0.1")
    assert [item["project"] for item in access_control.list_enrollments()] == ["first", "second"]
    # Rejected: deleted, no project; "first", nobody approved it in time, is deleted too
    second = access_control.list_enrollments()[1]
    access_control.reject_enrollment(second["id"], "user:root")
    monkeypatch.setattr(get_settings(), "project_enrollment_ttl_days", 3)
    with session_scope() as session:
        for row in session.exec(select(ProjectEnrollment)).all():
            row.created_at = utcnow() - timedelta(days=3, minutes=1)
            session.add(row)
    access_control.enroll_project("third")

    assert [item["project"] for item in access_control.list_enrollments()] == ["third"]
    with session_scope() as session:
        assert not access_control.project_exists(session, "first")
    rejected = audit.list_events(action="enrollment.rejected")["events"]
    assert [(event["project"], event["actor"]) for event in rejected] == [
        ("first", "enrollment"),
        ("second", "user:root"),
    ]


def test_creating_a_project_settles_its_pending_request():
    carol = creator()
    access_control.enroll_project("mobile-app")

    access_control.create_project(carol["id"], "mobile-app", "user:carol")

    assert access_control.list_enrollments() == []
    assert grants_of(carol["id"])["reports.read"] == frozenset({"mobile-app"})


def test_adding_a_user_to_a_group_is_audited_once():
    alice = web_users.create_user("alice", PASSWORD)
    group = ensure_project_group("shop")
    for _ in range(2):
        with session_scope() as session:
            access_control.add_user_to_group(session, alice["id"], group["id"], "user:root")

    assert grants_of(alice["id"]) == {"reports.read": frozenset({"shop"})}
    (event,) = audit.list_events(action="user.groups_changed")["events"]
    assert (event["actor"], event["target_id"]) == ("user:root", str(alice["id"]))
    assert event["details"] == {"added": [group["id"]], "removed": []}


def test_a_user_has_no_role_of_its_own():
    alice = web_users.create_user("alice", PASSWORD)
    assert "roles" not in alice
    assert "users" not in access_control.list_roles()[0]
    with pytest.raises(TypeError):
        web_users.create_user("bob", PASSWORD, roles=[(role_id("admin"), None)])  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        web_users.update_user(alice["id"], None, "root", [(role_id("admin"), None)])  # type: ignore[call-arg]
    assert grants_of(alice["id"]) == {}


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
        "group.updated",
        "group.deleted",
        "role.deleted",
    ]
    members = next(e for e in events if e["action"] == "group.members_changed")
    assert members["details"] == {"added": [alice["id"]], "name": "auditors", "removed": []}


def _settings(**values):
    """Settings that ignore the developer's .env file."""
    from security_review_mcp.config import Settings

    return Settings(_env_file=None, **values)
