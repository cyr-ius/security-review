"""Roles and projects are given to the users: the groups are removed.

A user now holds roles (``webuserrole``) and projects (``userproject``, or every project with
``webuser.all_projects``): the permissions of its roles limited to projects apply to its
projects, the others to the whole controller; a project in ``read_only`` is only read.

- Each local member of a group gets the roles of the group. A role given on every project stays
  a role (``all_projects`` when it holds a permission limited to projects). Roles given on
  projects become roles of the user with these projects when they all share the same projects
  and the user has no role on every project limited to projects; otherwise their projects are
  only read (``read_only``) and the triage limited to some projects is dropped. A conversion
  never widens a right.
- ``oidcclaimmapping`` replaces the groups with ``sso``: each one becomes a mapping of its name (a
  value of the roles claim) to its roles and projects, by the same rules (projects shared by its
  roles given on projects, the others dropped). ``useroidcclaim`` keeps the values of the claim
  of each OIDC user at its last login: its OIDC memberships of these groups become claims, so
  that it keeps its rights until its next login. An OIDC membership of a group without ``sso``
  (SECREVIEW_OIDC_DEFAULT_GROUP, which is removed with its stored setting) is lost.
- The ordinary roles ``triager`` and ``mcp-user`` are deleted with their bindings; the api
  tokens of these roles are revoked (each revocation is audited).
- ``usergroup``, ``grouprole`` and ``groupmember`` are dropped.

Downgrading is refused: the groups cannot be rebuilt from the roles of the users.

Revision ID: 0039
Revises: 0038
Create Date: 2026-10-29
"""

import json
from collections import Counter
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
    sa.column("read_only", sa.Boolean),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("created_by", sa.String),
)
_mappings = sa.table(
    "oidcclaimmapping",
    sa.column("claim", sa.String),
    sa.column("role_ids", sa.String),
    sa.column("all_projects", sa.Boolean),
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
            sa.Column("read_only", sa.Boolean(), nullable=False),
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
            sa.Column("all_projects", sa.Boolean(), nullable=False),
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
    if "all_projects" not in columns:
        with op.batch_alter_table("webuser") as batch:
            batch.add_column(
                sa.Column("all_projects", sa.Boolean(), nullable=False, server_default=sa.false())
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
    every = {"reports.read", "findings.triage", "users.manage"}  # enough to tell scoped ones
    permissions: dict[int, frozenset[str]] = {}
    for role_id, name, system, stored in connection.execute(
        sa.text("SELECT id, name, system, permissions FROM accessrole")
    ):
        if system and name == "admin":
            permissions[role_id] = frozenset(every)
        elif system and name == "reader":
            permissions[role_id] = frozenset({"reports.read"})
        else:
            permissions[role_id] = frozenset(json.loads(stored))
    return permissions


def _convert(
    bindings: list[tuple[int, list[str]]], permissions: dict[int, frozenset[str]]
) -> tuple[set[int], bool, set[str], set[str]]:
    """Roles, every project, projects and read-only projects of the bindings (role, projects or
    an empty list for every project) of one user or group, never wider than they were."""
    roles = {role_id for role_id, projects in bindings if not projects}
    every = any(permissions.get(role_id, frozenset()) & _SCOPED for role_id in roles)
    bound: dict[int, set[str]] = {}
    for role_id, projects in bindings:
        if projects:
            bound.setdefault(role_id, set()).update(projects)
    if every or not bound:
        return roles, every, set(), set()
    shared = Counter(frozenset(projects) for projects in bound.values()).most_common(1)[0][0]
    if all(projects == shared for projects in bound.values()):
        return roles | set(bound), False, set(shared), set()
    # Different projects per role: they are only read
    read = {
        project
        for role_id, projects in bound.items()
        if "reports.read" in permissions.get(role_id, frozenset())
        for project in projects
    }
    return roles, False, set(), read


def _move_groups(connection: sa.Connection, now: datetime) -> None:
    """Give each local member the roles and projects of its groups; turn the ``sso`` groups into
    mappings and the OIDC memberships of these groups into claims."""
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
    user_bindings: dict[int, list[tuple[int, list[str]]]] = {}
    claims: set[tuple[int, str]] = set()
    for group_id, user_id, source in connection.execute(
        sa.text("SELECT group_id, user_id, source FROM groupmember")
    ):
        if source == "local":
            user_bindings.setdefault(user_id, []).extend(group_bindings.get(group_id, []))
        elif groups[group_id][1]:
            claims.add((user_id, groups[group_id][0]))
    for user_id, bindings in sorted(user_bindings.items()):
        roles, every, projects, read = _convert(bindings, permissions)
        for role_id in sorted(roles):
            connection.execute(
                _user_roles.insert().values(
                    user_id=user_id, role_id=role_id, created_at=now, created_by=_ACTOR
                )
            )
        if every:
            connection.execute(
                sa.text("UPDATE webuser SET all_projects = :yes WHERE id = :user"),
                {"yes": True, "user": user_id},
            )
        for name in sorted(projects | read):
            if name in project_ids:
                connection.execute(
                    _user_projects.insert().values(
                        user_id=user_id,
                        project_id=project_ids[name],
                        read_only=name not in projects,
                        created_at=now,
                        created_by=_ACTOR,
                    )
                )
    for group_id, (name, sso) in sorted(groups.items()):
        if not sso:
            continue
        roles, every, projects, _ = _convert(group_bindings.get(group_id, []), permissions)
        connection.execute(
            _mappings.insert().values(
                claim=name,
                role_ids=json.dumps(sorted(roles)),
                all_projects=every,
                projects=json.dumps(sorted(projects)),
                created_at=now,
                created_by=_ACTOR,
            )
        )
    for user_id, claim in sorted(claims):
        connection.execute(_claims.insert().values(user_id=user_id, claim=claim, created_at=now))


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
    connection.execute(sa.text("DELETE FROM appsetting WHERE key = 'oidc_default_group'"))


def downgrade() -> None:
    """Refused: the groups cannot be rebuilt from the roles of the users."""
    raise RuntimeError(
        "Revision 0039 cannot be downgraded: restore a backup of the database taken before it"
    )
