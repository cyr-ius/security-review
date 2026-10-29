"""Roles hold the permissions on the whole controller; each project of a user holds its own
per-project permissions: the groups are removed.

- A role keeps only its permissions on the whole controller; its per-project permissions
  (``reports.read``, ``findings.triage``) move to where it was given. The built-in role
  ``reader`` (per-project permissions only) is removed.
- Each local member of a group gets the roles of the group (``webuserrole``) and, for each
  project of a role of the group, the per-project permissions of that role on that project
  (``userproject.permissions``), or on every project (``webuser.all_projects_permissions``) for a
  role given on every project: the rights of a user stay exactly the same.
- ``oidcclaimmapping`` replaces the groups with ``sso`` the same way: one mapping of the group name
  (a value of the roles claim) to its roles, its per-project permissions on every project and
  its projects with their permissions. ``useroidcclaim`` keeps the values of the claim of each
  OIDC user at its last login: its OIDC memberships of these groups become claims, so that it
  keeps its rights until its next login. An OIDC membership of a group without ``sso``
  (SECREVIEW_OIDC_DEFAULT_GROUP, which is removed with its stored setting) is lost.
- An api token of a role keeps its role and gets the per-project permissions of the role on its
  projects (``apitoken.project_permissions``). A role left without any permission is deleted,
  unless a token uses it.
- The ordinary roles ``triager`` and ``mcp-user`` are deleted with their bindings; the api tokens
  of these roles are revoked (each revocation is audited).
- ``usergroup``, ``grouprole`` and ``groupmember`` are dropped.

Downgrading is refused: the groups cannot be rebuilt from the roles of the users.

Revision ID: 0039
Revises: 0038
Create Date: 2026-10-29
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0039"
down_revision: str | None = "0038"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTOR = "migration"
_REMOVED_ROLES = ("triager", "mcp-user")
_OLD_TABLES = ("groupmember", "grouprole", "usergroup")

_SCOPED = frozenset({"reports.read", "findings.triage"})
# Permissions of the built-in admin role at this revision
_ADMIN = frozenset(
    {
        "reports.read",
        "findings.triage",
        "rules.manage",
        "standards.manage",
        "tokens.manage",
        "settings.manage",
        "users.manage",
        "audit.read",
        "projects.create",
        "projects.delete",
        "projects.autojoin",
    }
)
_user_roles = sa.table(
    "webuserrole",
    sa.column("user_id", sa.Integer),
    sa.column("role_id", sa.Integer),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("created_by", sa.String),
)
_user_projects = sa.table(
    "userproject",
    sa.column("user_id", sa.Integer),
    sa.column("project_id", sa.Integer),
    sa.column("permissions", sa.String),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("created_by", sa.String),
)
_mappings = sa.table(
    "oidcclaimmapping",
    sa.column("claim", sa.String),
    sa.column("role_ids", sa.String),
    sa.column("all_projects_permissions", sa.String),
    sa.column("projects", sa.String),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("created_by", sa.String),
)
_claims = sa.table(
    "useroidcclaim",
    sa.column("user_id", sa.Integer),
    sa.column("claim", sa.String),
    sa.column("created_at", sa.DateTime(timezone=True)),
)
_audit = sa.table(
    "auditevent",
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("action", sa.String),
    sa.column("actor", sa.String),
    sa.column("target_type", sa.String),
    sa.column("target_id", sa.String),
    sa.column("project", sa.String),
    sa.column("details", sa.String),
)


def _create_tables(inspector: sa.Inspector) -> None:
    """Create the tables and the column of this revision (each one kept when it exists)."""
    if not inspector.has_table("webuserrole"):
        op.create_table(
            "webuserrole",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("webuser.id"), nullable=False),
            sa.Column("role_id", sa.Integer(), sa.ForeignKey("accessrole.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.String(200), nullable=True),
            sa.UniqueConstraint("user_id", "role_id"),
        )
        op.create_index("ix_webuserrole_user_id", "webuserrole", ["user_id"])
        op.create_index("ix_webuserrole_role_id", "webuserrole", ["role_id"])
    if not inspector.has_table("userproject"):
        op.create_table(
            "userproject",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("webuser.id"), nullable=False),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("project.id"), nullable=False),
            sa.Column("permissions", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.String(200), nullable=True),
            sa.UniqueConstraint("user_id", "project_id"),
        )
        op.create_index("ix_userproject_user_id", "userproject", ["user_id"])
        op.create_index("ix_userproject_project_id", "userproject", ["project_id"])
    if not inspector.has_table("oidcclaimmapping"):
        op.create_table(
            "oidcclaimmapping",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("claim", sa.String(200), nullable=False),
            sa.Column("role_ids", sa.String(), nullable=False),
            sa.Column("all_projects_permissions", sa.String(), nullable=False),
            sa.Column("projects", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.String(200), nullable=True),
        )
        op.create_index("ix_oidcclaimmapping_claim", "oidcclaimmapping", ["claim"], unique=True)
    if not inspector.has_table("useroidcclaim"):
        op.create_table(
            "useroidcclaim",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("webuser.id"), nullable=False),
            sa.Column("claim", sa.String(200), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("user_id", "claim"),
        )
        op.create_index("ix_useroidcclaim_user_id", "useroidcclaim", ["user_id"])
        op.create_index("ix_useroidcclaim_claim", "useroidcclaim", ["claim"])
    columns = {column["name"] for column in inspector.get_columns("webuser")}
    if "all_projects_permissions" not in columns:
        with op.batch_alter_table("webuser") as batch:
            batch.add_column(
                sa.Column(
                    "all_projects_permissions", sa.String(), nullable=False, server_default="[]"
                )
            )
    columns = {column["name"] for column in inspector.get_columns("apitoken")}
    if "project_permissions" not in columns:
        with op.batch_alter_table("apitoken") as batch:
            batch.add_column(
                sa.Column("project_permissions", sa.String(), nullable=False, server_default="[]")
            )


def _remove_roles(connection: sa.Connection, now: datetime, groups: bool) -> None:
    """Delete ``triager`` and ``mcp-user`` (ordinary roles) with their group bindings, and
    revoke the api tokens of these roles."""
    roles = connection.execute(
        sa.text("SELECT id, name FROM accessrole WHERE system = :no AND name IN :names").bindparams(
            sa.bindparam("names", expanding=True)
        ),
        {"no": False, "names": list(_REMOVED_ROLES)},
    ).all()
    for role_id, name in roles:
        tokens = connection.execute(
            sa.text("SELECT id, label, project FROM apitoken WHERE access_role_id = :role"),
            {"role": role_id},
        ).all()
        for token_id, label, project in tokens:
            projects = [
                row[0]
                for row in connection.execute(
                    sa.text("SELECT project FROM apitokenproject WHERE token_id = :token"),
                    {"token": token_id},
                )
            ]
            connection.execute(
                sa.text("DELETE FROM apitokenproject WHERE token_id = :token"), {"token": token_id}
            )
            connection.execute(
                sa.text("DELETE FROM apitoken WHERE id = :token"), {"token": token_id}
            )
            connection.execute(
                _audit.insert().values(
                    created_at=now,
                    action="token.revoked",
                    actor=_ACTOR,
                    target_type="token",
                    target_id=token_id,
                    project=project,
                    details=json.dumps(
                        {
                            "label": label,
                            "role": "api",
                            "projects": projects or None,
                            "reason": f"the role {name} is removed",
                        }
                    ),
                )
            )
        if groups:
            connection.execute(
                sa.text("DELETE FROM grouprole WHERE role_id = :role"), {"role": role_id}
            )
        connection.execute(sa.text("DELETE FROM accessrole WHERE id = :role"), {"role": role_id})


def _permissions(connection: sa.Connection) -> dict[int, frozenset[str]]:
    """Permissions of each role (those of the code for a built-in role)."""
    permissions: dict[int, frozenset[str]] = {}
    for role_id, name, system, stored in connection.execute(
        sa.text("SELECT id, name, system, permissions FROM accessrole")
    ):
        if system and name == "admin":
            permissions[role_id] = frozenset(_ADMIN)
        elif system and name == "reader":
            permissions[role_id] = frozenset({"reports.read"})
        else:
            permissions[role_id] = frozenset(json.loads(stored))
    return permissions


class _Access:
    """Roles, per-project permissions on every project and per project of one user or group."""

    def __init__(self) -> None:
        self.roles: set[int] = set()
        self.every: set[str] = set()
        self.projects: dict[str, set[str]] = {}

    def add(self, role_id: int, projects: list[str], permissions: frozenset[str]) -> None:
        """Add a role given on ``projects`` (empty: every project), with its permissions."""
        if permissions - _SCOPED:
            self.roles.add(role_id)
        scoped = permissions & _SCOPED
        if not projects:
            self.every |= scoped
        for project in projects:
            if scoped:
                self.projects.setdefault(project, set()).update(scoped)


def _move_groups(connection: sa.Connection, now: datetime) -> None:
    """Give each local member the roles and per-project permissions of its groups; turn the
    ``sso`` groups into mappings and the OIDC memberships of these groups into claims."""
    project_ids = dict(connection.execute(sa.text("SELECT name, id FROM project")).all())
    permissions = _permissions(connection)
    groups = {
        group_id: (name, bool(sso))
        for group_id, name, sso in connection.execute(
            sa.text("SELECT id, name, sso FROM usergroup")
        )
    }
    group_bindings: dict[int, list[tuple[int, list[str]]]] = {}
    for group_id, role_id, projects in connection.execute(
        sa.text("SELECT group_id, role_id, projects FROM grouprole ORDER BY id")
    ):
        group_bindings.setdefault(group_id, []).append((role_id, json.loads(projects)))
    users: dict[int, _Access] = {}
    claims: set[tuple[int, str]] = set()
    for group_id, user_id, source in connection.execute(
        sa.text("SELECT group_id, user_id, source FROM groupmember")
    ):
        if source == "local":
            access = users.setdefault(user_id, _Access())
            for role_id, projects in group_bindings.get(group_id, []):
                access.add(role_id, projects, permissions.get(role_id, frozenset()))
        elif groups[group_id][1]:
            claims.add((user_id, groups[group_id][0]))
    for user_id, access in sorted(users.items()):
        for role_id in sorted(access.roles):
            connection.execute(
                _user_roles.insert().values(
                    user_id=user_id, role_id=role_id, created_at=now, created_by=_ACTOR
                )
            )
        if access.every:
            connection.execute(
                sa.text("UPDATE webuser SET all_projects_permissions = :every WHERE id = :user"),
                {"every": json.dumps(sorted(access.every)), "user": user_id},
            )
        for name, scoped in sorted(access.projects.items()):
            if name in project_ids and scoped - access.every:
                connection.execute(
                    _user_projects.insert().values(
                        user_id=user_id,
                        project_id=project_ids[name],
                        permissions=json.dumps(sorted(scoped)),
                        created_at=now,
                        created_by=_ACTOR,
                    )
                )
    for group_id, (name, sso) in sorted(groups.items()):
        if not sso:
            continue
        access = _Access()
        for role_id, projects in group_bindings.get(group_id, []):
            access.add(role_id, projects, permissions.get(role_id, frozenset()))
        connection.execute(
            _mappings.insert().values(
                claim=name,
                role_ids=json.dumps(sorted(access.roles)),
                all_projects_permissions=json.dumps(sorted(access.every)),
                projects=json.dumps(
                    [
                        {"project": project, "permissions": sorted(scoped)}
                        for project, scoped in sorted(access.projects.items())
                    ]
                ),
                created_at=now,
                created_by=_ACTOR,
            )
        )
    for user_id, claim in sorted(claims):
        connection.execute(_claims.insert().values(user_id=user_id, claim=claim, created_at=now))


def _split_roles(connection: sa.Connection) -> None:
    """Keep only the permissions on the whole controller in the roles: the api tokens of a role
    get its per-project permissions on their projects; a role left without any permission (the
    built-in ``reader`` among them) is deleted, unless a token uses it."""
    permissions = _permissions(connection)
    used = {
        role_id
        for (role_id,) in connection.execute(
            sa.text("SELECT DISTINCT access_role_id FROM apitoken WHERE access_role_id IS NOT NULL")
        )
    }
    for role_id, held in permissions.items():
        connection.execute(
            sa.text(
                "UPDATE apitoken SET project_permissions = :scoped WHERE access_role_id = :role"
            ),
            {"scoped": json.dumps(sorted(held & _SCOPED)), "role": role_id},
        )
        system, name = connection.execute(
            sa.text("SELECT system, name FROM accessrole WHERE id = :role"), {"role": role_id}
        ).one()
        if system and name == "admin":
            continue
        site = sorted(held - _SCOPED)
        if site or role_id in used:
            connection.execute(
                sa.text("UPDATE accessrole SET permissions = :site, system = :no WHERE id = :role"),
                {"site": json.dumps(site), "no": False, "role": role_id},
            )
        else:
            connection.execute(
                sa.text("DELETE FROM accessrole WHERE id = :role"), {"role": role_id}
            )


def upgrade() -> None:
    """Create the new tables, move the groups into them and drop the groups."""
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    _create_tables(inspector)
    now = datetime.now(UTC)
    groups = all(inspector.has_table(table) for table in _OLD_TABLES)
    _remove_roles(connection, now, groups)
    if groups:
        _move_groups(connection, now)
    for table in _OLD_TABLES:
        if inspector.has_table(table):
            op.drop_table(table)
    _split_roles(connection)
    connection.execute(sa.text("DELETE FROM appsetting WHERE key = 'oidc_default_group'"))


def downgrade() -> None:
    """Refused: the groups cannot be rebuilt from the roles of the users."""
    raise RuntimeError(
        "Revision 0039 cannot be downgraded: restore a backup of the database taken before it"
    )
