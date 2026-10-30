"""Access control: permissions, roles, the roles of the users and the grants they give."""

import pytest
from conftest import known_projects, make_user, map_claim
from sqlmodel import select

from security_review_mcp.auth import access_control, web_users
from security_review_mcp.auth.access_control import Permission
from security_review_mcp.http_server import Role
from security_review_mcp.observability import audit
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


def test_the_built_in_admin_role_holds_the_permissions_on_the_whole_controller():
    (admin,) = access_control.list_roles()

    assert (admin["name"], admin["system"]) == ("admin", True)
    assert admin["permissions"] == sorted(access_control.SITE_PERMISSIONS)
    with pytest.raises(ValueError, match="cannot be changed"):
        access_control.update_role(admin["id"], ["audit.read"])
    with pytest.raises(ValueError, match="cannot be deleted"):
        access_control.delete_role(admin["id"])
    # Created once
    assert access_control.ensure_system_roles() == {"admin": admin["id"]}


def test_custom_roles_are_created_updated_and_deleted():
    created = access_control.create_role(
        "Auditor", ["audit.read", "rules.manage", "audit.read"], "Reads the log", actor="user:root"
    )

    assert (created["name"], created["permissions"], created["system"]) == (
        "Auditor",
        ["audit.read", "rules.manage"],
        False,
    )
    assert (created["description"], created["users"]) == ("Reads the log", 0)
    updated = access_control.update_role(created["id"], ["audit.read"], "", name="Auditors 2")
    assert (updated["name"], updated["permissions"]) == ("Auditors 2", ["audit.read"])
    deleted = access_control.delete_role(created["id"])
    assert deleted["name"] == "Auditors 2"
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
        # The per-project permissions are given with the projects, never by a role
        ("Reader", ["audit.read", "reports.read"], "", "no per-project permission"),
    ],
)
def test_invalid_roles_are_refused(name, permissions, description, message):
    with pytest.raises(ValueError, match=message):
        access_control.create_role(name, permissions, description)


def test_duplicate_roles_and_the_role_limit_are_refused(monkeypatch):
    access_control.create_role("Auditor", ["audit.read"])
    with pytest.raises(ValueError, match="already exists"):
        access_control.create_role("Auditor", ["rules.manage"])
    with pytest.raises(ValueError, match="already exists"):
        access_control.create_role("admin", ["rules.manage"])
    monkeypatch.setattr(access_control, "MAX_ROLES", 2)
    with pytest.raises(ValueError, match="At most 2 roles"):
        access_control.create_role("Other", ["audit.read"])


def test_a_user_holds_the_permissions_of_its_roles_and_those_of_each_of_its_projects():
    role = access_control.create_role("Auditor", ["audit.read"])
    known_projects("shop", "crm", "billing")
    alice = web_users.create_user(
        "alice",
        PASSWORD,
        [role["id"]],
        [("shop", ["reports.read"]), ("crm", ["reports.read", "findings.triage"])],
    )

    # Its role on the whole controller, the permissions of each project on that project
    assert grants_of(alice["id"]) == {
        "audit.read": None,
        "findings.triage": frozenset({"crm"}),
        "reports.read": frozenset({"crm", "shop"}),
    }
    assert [(item["project"], item["permissions"]) for item in alice["projects"]] == [
        ("crm", ["findings.triage", "reports.read"]),
        ("shop", ["reports.read"]),
    ]
    # Permissions on every project add up with those of the projects
    web_users.update_user(alice["id"], None, all_projects_permissions=["reports.read"])
    assert grants_of(alice["id"]) == {
        "audit.read": None,
        "findings.triage": frozenset({"crm"}),
        "reports.read": None,
    }
    # Without any role nor project, nothing
    bob = web_users.create_user("bob", PASSWORD)
    assert grants_of(bob["id"]) == {}


def test_a_role_change_applies_to_its_users_at_once():
    role = access_control.create_role("Auditor", ["audit.read"])
    user = web_users.create_user("alice", PASSWORD, [role["id"]])
    assert grants_of(user["id"]) == {"audit.read": None}
    listed = {item["name"]: item for item in access_control.list_roles()}
    assert listed["Auditor"]["users"] == 1

    access_control.update_role(role["id"], ["audit.read", "rules.manage"])
    # Who manages the rules also reads them
    assert grants_of(user["id"]) == {"audit.read": None, "rules.manage": None, "rules.read": None}
    access_control.delete_role(role["id"])
    assert grants_of(user["id"]) == {}
    assert web_users.find_user("alice")["roles"] == []


# ── Roles of the users ───────────────────────────────────────────────────────


def test_the_projects_of_a_user_are_replaced_bounded_and_checked(monkeypatch):
    known_projects("shop", "crm")
    alice = web_users.create_user("alice", PASSWORD)

    def set_projects(*projects):
        with session_scope() as session:
            access_control.set_user_projects(session, alice["id"], projects, None, "user:root")

    set_projects(
        ("shop", ["reports.read"]), (" Shop ", ["findings.triage"]), ("crm", ["reports.read"])
    )
    assert grants_of(alice["id"])["findings.triage"] == frozenset({"shop"})
    set_projects(("crm", ["reports.read"]))
    assert grants_of(alice["id"]) == {"reports.read": frozenset({"crm"})}
    with pytest.raises(NotFoundError, match="Project 'billing'"):
        set_projects(("billing", ["reports.read"]))
    with pytest.raises(ValueError, match="at least one per-project permission"):
        set_projects(("shop", []))
    with pytest.raises(ValueError, match="not a per-project permission"):
        set_projects(("shop", ["audit.read"]))
    monkeypatch.setattr(access_control, "MAX_SESSION_PROJECTS", 1)
    with pytest.raises(ValueError, match="at most 1 projects"):
        set_projects(("shop", ["reports.read"]), ("crm", ["reports.read"]))
    (event,) = audit.list_events(action="user.projects_changed")["events"][:1]
    assert (event["details"]["projects"], event["details"]["removed"]) == (
        ["crm=reports.read"],
        ["shop"],
    )


def test_the_members_of_a_project_are_listed_and_replaced():
    known_projects("shop")
    alice = make_user("alice", PASSWORD, "reader", ["shop"])
    bob = web_users.create_user("bob", PASSWORD)

    members = access_control.set_project_members(
        "shop", [(bob["id"], ["reports.read", "findings.triage"])], "user:root"
    )

    assert [(m["username"], m["permissions"]) for m in members] == [
        ("bob", ["findings.triage", "reports.read"])
    ]
    assert grants_of(alice["id"]) == {}
    assert grants_of(bob["id"])["findings.triage"] == frozenset({"shop"})
    assert access_control.list_project_members("shop") == members
    with pytest.raises(NotFoundError, match="Web user 999"):
        access_control.set_project_members("shop", [(999, ["reports.read"])])
    with pytest.raises(NotFoundError):
        access_control.list_project_members("unknown")
    events = audit.list_events(action="user.projects_changed")["events"]
    assert {event["target_id"] for event in events[:2]} == {str(alice["id"]), str(bob["id"])}


# ── OIDC mappings ────────────────────────────────────────────────────────────


def test_oidc_mappings_give_their_roles_and_projects_to_the_claims_of_the_last_login():
    known_projects("shop")
    alice = web_users.create_user("alice", None, auth_source="oidc")
    map_claim("devs", "reader", ["shop", "not-yet"])
    map_claim("leads", "triager")

    with session_scope() as session:
        kept = access_control.sync_oidc_claims(
            session, alice["id"], {"devs", "unknown"}, _settings()
        )
    assert kept == ["devs"]
    # A project not known yet is ignored, until it is created
    assert grants_of(alice["id"]) == {"reports.read": frozenset({"shop"})}
    known_projects("not-yet")
    assert grants_of(alice["id"]) == {"reports.read": frozenset({"not-yet", "shop"})}
    # A change of the mappings applies at once
    auditor = access_control.create_role("Auditor", ["audit.read"])
    access_control.set_oidc_mappings(
        [("devs", [auditor["id"]], ["findings.triage", "reports.read"], [])], "user:root"
    )
    assert grants_of(alice["id"]) == {
        "audit.read": None,
        "findings.triage": None,
        "reports.read": None,
    }
    (event,) = audit.list_events(action="oidc.mappings_changed")["events"][:1]
    assert event["details"]["count"] == 1


READ = ["reports.read"]


@pytest.mark.parametrize(
    ("mappings", "message"),
    [
        ([("devs", [], READ, []), ("devs", [], [], [("shop", READ)])], "twice"),
        ([("devs", [], [], [])], "neither a role nor a project"),
        ([("devs", [], [], [(f"p{i}", READ) for i in range(51)])], "at most 50 projects"),
        ([("", [], READ, [])], "between 1 and 200"),
        ([("de\nvs", [], READ, [])], "control characters"),
        ([("devs", [], ["audit.read"], [])], "not a per-project permission"),
        ([("devs", [], [], [("shop", [])])], "at least one per-project permission"),
    ],
)
def test_invalid_oidc_mappings_are_refused(mappings, message):
    with pytest.raises(ValueError, match=message):
        access_control.set_oidc_mappings(mappings)


def test_an_oidc_mapping_may_give_roles_or_projects_only():
    auditor = access_control.create_role("Auditor", ["audit.read"])
    mappings = access_control.set_oidc_mappings(
        [("auditors", [auditor["id"]], [], []), ("shop-team", [], [], [("shop", READ)])]
    )
    assert [(m["claim"], m["roles"], m["projects"]) for m in mappings] == [
        ("auditors", ["Auditor"], []),
        ("shop-team", [], [{"project": "shop", "permissions": READ}]),
    ]


# ── Project creation ─────────────────────────────────────────────────────────


def enrolled(project: str) -> int:
    """Id of the pending project ``project``, requested by a token without a user."""
    access_control.request_project(project)
    return next(
        item["id"] for item in access_control.list_enrollments() if item["project"] == project
    )


def creator() -> dict:
    """A web user whose only role holds ``projects.create``."""
    role = access_control.create_role("Creator", [Permission.PROJECTS_CREATE])
    return web_users.create_user("carol", PASSWORD, [role["id"]])


@pytest.mark.parametrize("permission", [Permission.PROJECTS_CREATE, Permission.PROJECTS_DELETE])
def test_project_permissions_are_on_the_whole_controller(permission):
    """projects.delete is never limited to projects: its route checks no project scope."""
    assert permission not in access_control.SCOPED_PERMISSIONS
    assert permission in access_control.SYSTEM_ROLES["admin"]
    assert {"name": permission.value, "scoped": False} in access_control.list_permissions()
    # A role holds it: it applies to the whole Controller server, whatever the projects
    role = access_control.create_role(f"Role {permission.value}", [permission])
    known_projects("shop")
    alice = web_users.create_user("alice", PASSWORD, [role["id"]], [("shop", ["reports.read"])])
    assert grants_of(alice["id"]) == {
        permission.value: None,
        "reports.read": frozenset({"shop"}),
    }


def test_a_created_project_is_read_by_its_creator_only():
    carol = creator()
    other = web_users.create_user("dave", PASSWORD)

    created = access_control.create_project(carol["id"], " mobile-app ", "user:carol")

    assert created == {"project": "mobile-app"}
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
    assert event["details"] == {"permissions": ["reports.read"], "user_id": carol["id"]}


def test_creating_a_project_never_opens_an_existing_one():
    """projects.create would otherwise let its holder read the reports of any project."""
    from security_review_mcp.auth import token_store
    from security_review_mcp.reports import services

    carol = creator()
    services.save_report("shop", "Review", [])
    known_projects("crm")
    token_store.create_token("ci-hr", Role.CI, projects=["hr"])
    access_control.approve_enrollment(enrolled("payroll"))

    for project in ("shop", "crm", "hr", "payroll"):
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

    from security_review_mcp.auth import token_store
    from security_review_mcp.connectors import registry, set_target
    from security_review_mcp.reports import services
    from security_review_mcp.storage.models import (
        ConnectorTarget,
        ExportState,
        FindingComment,
        FindingCreate,
        FindingExport,
        Severity,
    )

    finding = FindingCreate(title="SQL injection", severity=Severity.HIGH, description="Query")
    shop = services.save_report("shop", "Review", [finding])
    shop_finding = services.get_report(shop["report_id"]).findings[0]
    services.add_finding_comment(shop_finding.id, "ann", "Seen")
    set_target("shop", registry.get("jira"), "SEC", None, "user:root")
    with session_scope() as session:
        session.add(
            FindingExport(
                finding_id=shop_finding.id,
                kind="jira",
                project="shop",
                fingerprint="f" * 32,
                state=ExportState.SENT,
                external_key="SEC-1",
            )
        )
    kept = services.save_report("crm", "Review", [finding])
    carol = creator()
    access_control.create_project(carol["id"], "shop-mobile")
    make_user("alice", PASSWORD, "triager", ["shop", "crm"])
    map_claim("shop-team", "reader", ["shop"])
    map_claim("leads", "triager", ["shop", "crm"])
    token_store.create_token("ci-shop", Role.CI, projects=["shop"])
    token_store.create_token("ci-both", Role.CI, projects=["shop", "crm"])

    deleted = access_control.delete_project("Shop", "user:root")

    assert deleted == {
        "project": "shop",
        "reports": 1,
        "findings": 1,
        "members_removed": 1,
        "mappings_changed": ["leads", "shop-team"],
        "tokens_revoked": 1,
        "tokens_changed": 1,
    }
    assert [item["project"] for item in services.list_projects(set())] == ["crm"]
    with session_scope() as session:
        assert session.exec(select(FindingComment)).all() == []
        assert session.exec(select(FindingExport)).all() == []
        assert session.exec(select(ConnectorTarget)).all() == []
        assert not access_control.project_exists(session, "shop")
        assert access_control.project_exists(session, "shop-mobile")
    assert services.get_report(kept["report_id"]).project == "crm"
    # The mapping on "shop" alone is removed; the other one keeps "crm"
    mappings = access_control.list_oidc_mappings()
    assert [(m["claim"], [p["project"] for p in m["projects"]]) for m in mappings] == [
        ("leads", ["crm"])
    ]
    assert web_users.find_user("alice")["permissions"]["reports.read"] == ["crm"]
    tokens = {token["label"]: token for token in token_store.list_tokens()}
    assert "ci-shop" not in tokens
    assert tokens["ci-both"]["projects"] == ["crm"]
    (event,) = audit.list_events(action="project.deleted")["events"]
    assert (event["actor"], event["project"]) == ("user:root", "shop")
    with pytest.raises(NotFoundError):
        access_control.delete_project("shop")


# ── Enrollment ───────────────────────────────────────────────────────────────


def test_a_requested_project_waits_for_an_approval_that_gives_its_user_access():
    """A user without projects.create requests a project: it waits, its approval creates it
    with that user as its member, and the answer never tells whether the project existed."""
    from security_review_mcp.reports import services

    alice = web_users.create_user("alice", PASSWORD)
    services.save_report("shop", "Review", [])
    requested = access_control.request_project(
        " Mobile-App ", "alice", "10.0.0.1", "token:alice:agent"
    )
    known = access_control.request_project("shop", "alice")

    assert (requested["project"], requested["status"]) == ("mobile-app", "requested")
    assert {key: str(value).replace("shop", "P") for key, value in known.items()} == {
        key: str(value).replace("mobile-app", "P") for key, value in requested.items()
    }
    pending, _ = access_control.list_enrollments()
    assert (pending["project"], pending["requested_by"], pending["requested_from"]) == (
        "mobile-app",
        "alice",
        "10.0.0.1",
    )
    assert pending["existing"] is False
    with session_scope() as session:
        # Pending: not a project yet, and alice reads nothing
        assert not access_control.project_exists(session, "mobile-app")
    assert grants_of(alice["id"]) == {}

    approved = access_control.approve_enrollment(pending["id"], "user:root")

    assert approved["granted_to"] == "alice"
    assert [item["project"] for item in access_control.list_enrollments()] == ["shop"]
    assert grants_of(alice["id"])["reports.read"] == frozenset({"mobile-app"})
    events = audit.list_events(project="mobile-app")["events"]
    approved_event = next(e for e in events if e["action"] == "enrollment.approved")
    assert (approved_event["actor"], approved_event["details"]["granted_to"]) == (
        "user:root",
        "alice",
    )
    requested_event = next(e for e in events if e["action"] == "enrollment.requested")
    assert (requested_event["actor"], requested_event["details"]["requested_by"]) == (
        "token:alice:agent",
        "alice",
    )
    with pytest.raises(NotFoundError):
        access_control.reject_enrollment(pending["id"])


def test_a_creator_gets_a_new_requested_project_at_once():
    """projects.create creates a new project on request, never opens an existing one."""
    from security_review_mcp.reports import services

    carol = creator()
    services.save_report("shop", "Review", [])

    created = access_control.request_project("Mobile-App", "carol", actor="token:carol:agent")
    existing = access_control.request_project("shop", "carol")

    assert (created["project"], created["status"]) == ("mobile-app", "created")
    assert existing["status"] == "requested"
    assert grants_of(carol["id"])["reports.read"] == frozenset({"mobile-app"})
    assert [item["project"] for item in access_control.list_enrollments()] == ["shop"]
    (event,) = audit.list_events(action="project.created")["events"]
    assert (event["project"], event["actor"]) == ("mobile-app", "token:carol:agent")


def test_a_user_asks_to_join_an_existing_project():
    """An existing project is requested like a new one, once per user, and its approval gives
    the user the reader role on it; nothing is recorded for a user who already reaches it."""
    from security_review_mcp.reports import services

    alice = web_users.create_user("alice", PASSWORD)
    dave = web_users.create_user("dave", PASSWORD)
    services.save_report("shop", "Review", [])
    make_user("bob", PASSWORD, "reader", ["shop"])

    for owner in ("alice", "alice", "dave", "bob", None):
        assert access_control.request_project("shop", owner)["status"] == "requested"
    pending = access_control.list_enrollments()
    assert [(item["requested_by"], item["existing"]) for item in pending] == [
        ("alice", True),
        ("dave", True),
    ]

    # projects.create alone never opens an existing project
    with pytest.raises(access_control.AccessGrantDenied):
        access_control.approve_enrollment(pending[0]["id"], "user:carol")
    approved = access_control.approve_enrollment(
        pending[0]["id"], "user:root", may_grant_access=True
    )

    assert approved["granted_to"] == "alice"
    assert grants_of(alice["id"])["reports.read"] == frozenset({"shop"})
    assert grants_of(dave["id"]) == {}
    assert [item["requested_by"] for item in access_control.list_enrollments()] == ["dave"]


def test_enrollments_are_bounded_and_expire(monkeypatch):
    from datetime import timedelta

    from security_review_mcp.config import get_settings
    from security_review_mcp.reports import services
    from security_review_mcp.storage.models import ProjectEnrollment, utcnow

    monkeypatch.setattr(access_control, "MAX_PENDING_PROJECTS", 2)
    monkeypatch.setattr(access_control, "MAX_ENROLLMENTS_PER_REQUESTER", 3)
    access_control.request_project("first", "u1")
    access_control.request_project("second", "u2")

    with pytest.raises(ValueError, match="Too many projects"):
        access_control.request_project("third", "u3")
    # The same refusal for a known project, so that a full queue does not tell it exists
    services.save_report("shop", "Review", [])
    with pytest.raises(ValueError, match="Too many projects"):
        access_control.request_project("shop", "u3")
    # A pending project is never refused by the limit, nor requested twice
    access_control.request_project("first", "u3")
    access_control.request_project("first", "u1")
    access_control.request_project("first", "u1")
    with pytest.raises(access_control.EnrollmentThrottled, match="retry later"):
        access_control.request_project("first", "u1")
    assert [item["project"] for item in access_control.list_enrollments()] == ["first", "second"]
    # Rejected: deleted, no project; "first", nobody approved it in time, is deleted too
    second = access_control.list_enrollments()[1]
    access_control.reject_enrollment(second["id"], "user:root")
    monkeypatch.setattr(get_settings(), "project_enrollment_ttl_days", 3)
    with session_scope() as session:
        for row in session.exec(select(ProjectEnrollment)).all():
            row.created_at = utcnow() - timedelta(days=3, minutes=1)
            session.add(row)
    access_control.request_project("third", "u4")

    assert [item["project"] for item in access_control.list_enrollments()] == ["third"]
    with session_scope() as session:
        assert not access_control.project_exists(session, "first")
    rejected = audit.list_events(action="enrollment.rejected")["events"]
    assert [(event["project"], event["actor"]) for event in rejected] == [
        ("first", "enrollment"),
        ("second", "user:root"),
    ]


def test_an_autojoin_holder_joins_an_existing_project_unless_it_is_blocked(monkeypatch):
    """projects.autojoin joins a known project at once as a reader, never creates one, and
    waits for an approval as the others do on a project whose autojoin is blocked."""
    from security_review_mcp.reports import services

    monkeypatch.setattr(access_control, "MAX_ENROLLMENTS_PER_REQUESTER", 10)
    role = access_control.create_role("Joiner", [Permission.PROJECTS_AUTOJOIN])
    joe = web_users.create_user("joe", PASSWORD)
    for project in ("shop", "crm", "vault"):
        services.save_report(project, "Review", [])
    # Requested before it held the permission
    access_control.request_project("shop", "joe")
    web_users.update_user(joe["id"], [role["id"]])
    access_control.set_autojoin_blocked("vault", True, "user:root")

    joined = access_control.request_project("shop", "joe", actor="token:joe:agent")
    new = access_control.request_project("mobile-app", "joe")
    blocked = access_control.request_project("vault", "joe")

    assert (joined["project"], joined["status"]) == ("shop", "joined")
    assert (new["status"], blocked["status"]) == ("requested", "requested")
    grants = grants_of(joe["id"])
    assert grants["reports.read"] == frozenset({"shop"})
    assert "findings.triage" not in grants
    # Its pending request of the joined project is settled
    assert [item["project"] for item in access_control.list_enrollments()] == [
        "mobile-app",
        "vault",
    ]
    (event,) = audit.list_events(action="project.joined")["events"]
    assert (event["project"], event["actor"]) == ("shop", "token:joe:agent")
    (changed,) = audit.list_events(action="project.autojoin_changed")["events"]
    assert (changed["project"], changed["details"]) == ("vault", {"blocked": True})
    # Allowed again: joined at once; an unknown project cannot be blocked
    access_control.set_autojoin_blocked("vault", False, "user:root")
    assert access_control.request_project("vault", "joe")["status"] == "joined"
    with pytest.raises(NotFoundError):
        access_control.set_autojoin_blocked("unknown", True)
    # Never beyond the projects one session may reach
    monkeypatch.setattr(access_control, "MAX_SESSION_PROJECTS", 2)
    with pytest.raises(ValueError, match="already reads 2 projects"):
        access_control.request_project("crm", "joe")
    assert grants_of(joe["id"])["reports.read"] == frozenset({"shop", "vault"})


def test_creating_a_project_settles_its_pending_request():
    carol = creator()
    access_control.request_project("mobile-app")

    access_control.create_project(carol["id"], "mobile-app", "user:carol")

    assert access_control.list_enrollments() == []
    assert grants_of(carol["id"])["reports.read"] == frozenset({"mobile-app"})


def test_giving_a_project_in_reading_only_is_audited_once():
    alice = web_users.create_user("alice", PASSWORD)
    known_projects("shop")
    for _ in range(2):
        with session_scope() as session:
            access_control.add_user_project(session, alice["id"], "shop", "user:root")

    assert grants_of(alice["id"]) == {"reports.read": frozenset({"shop"})}
    (event,) = audit.list_events(action="user.projects_changed")["events"]
    assert (event["actor"], event["target_id"]) == ("user:root", str(alice["id"]))
    assert event["details"]["projects"] == ["shop=reports.read"]


# ── The last holder of users.manage ──────────────────────────────────────────


def test_no_change_removes_the_last_holder_of_users_manage():
    root = make_user("root", PASSWORD, "admin")
    managers = access_control.create_role("Managers", ["users.manage"])

    with pytest.raises(ValueError, match="keep the users.manage"):
        web_users.update_user(root["id"], [])
    # Another holder through a custom role: the change is accepted
    web_users.update_user(root["id"], [managers["id"]])
    with pytest.raises(ValueError, match="keep the users.manage"):
        access_control.update_role(managers["id"], ["audit.read"])
    with pytest.raises(ValueError, match="keep the users.manage"):
        access_control.delete_role(managers["id"])
    assert [role["name"] for role in web_users.find_user("root")["roles"]] == ["Managers"]


def test_the_guard_does_not_block_a_database_without_any_manager():
    auditor = access_control.create_role("Auditor", ["audit.read"])
    alice = web_users.create_user("alice", PASSWORD, [auditor["id"]])
    web_users.update_user(alice["id"], [])


# ── Audit ────────────────────────────────────────────────────────────────────


def test_access_changes_are_audited():
    make_user("root", PASSWORD, "admin")
    known_projects("shop")
    role = access_control.create_role("Auditor", ["audit.read"], actor="user:root")
    alice = web_users.create_user("alice", PASSWORD)
    web_users.update_user(alice["id"], [role["id"]], [("shop", ["reports.read"])], "user:root")
    access_control.set_oidc_mappings([("devs", [role["id"]], ["reports.read"], [])], "user:root")
    access_control.delete_role(role["id"], actor="user:root")

    events = audit.list_events(actor="user:root")["events"]
    assert [event["action"] for event in reversed(events)] == [
        "role.created",
        "user.roles_changed",
        "user.projects_changed",
        "oidc.mappings_changed",
        "role.deleted",
    ]
    roles = next(e for e in events if e["action"] == "user.roles_changed")
    assert roles["details"] == {"added": [role["id"]], "removed": []}
    # The mapping loses the role; it still gives the reading of every project
    mappings = access_control.list_oidc_mappings()
    assert [(m["claim"], m["roles"], m["all_projects_permissions"]) for m in mappings] == [
        ("devs", [], ["reports.read"])
    ]


def _settings(**values):
    """Settings that ignore the developer's .env file."""
    from security_review_mcp.config import Settings

    return Settings(_env_file=None, **values)
