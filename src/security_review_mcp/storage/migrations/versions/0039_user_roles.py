"""Roles are given to the users, on every project or on one project: the groups are removed.

- ``userglobalrole`` (a role on every project) and ``userproject`` (a role on one project)
  replace the groups: each local member of a group gets the roles of the group, a role on every
  project as a ``userglobalrole``, a role on projects as one ``userproject`` per project. The
  rights of a user stay the same.
- ``oidcclaimmapping`` replaces the groups with ``sso``: each role of such a group becomes a
  mapping of the group name (a value of the roles claim) to the role, on every project or on its
  projects. ``useroidcclaim`` keeps the values of the claim of each OIDC user at its last login:
  its OIDC memberships of these groups become claims, so that it keeps its rights until its
  next login. An OIDC membership of a group without ``sso`` (SECREVIEW_OIDC_DEFAULT_GROUP, which
  is removed with its stored setting) is lost.
- The ordinary roles ``triager`` and ``mcp-user`` are deleted with their bindings; the api
  tokens of these roles are revoked (each revocation is audited).
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

_global_roles = sa.table(
    "userglobalrole",
    sa.column("user_id", sa.Integer),
    sa.column("role_id", sa.Integer),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("created_by", sa.String),
)
_project_roles = sa.table(
    "userproject",
    sa.column("user_id", sa.Integer),
    sa.column("project_id", sa.Integer),
    sa.column("role_id", sa.Integer),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("created_by", sa.String),
)
_mappings = sa.table(
    "oidcclaimmapping",
    sa.column("claim", sa.String),
    sa.column("role_id", sa.Integer),
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
    """Create the tables of this revision (each one kept when it exists)."""
    if not inspector.has_table("userglobalrole"):
        op.create_table(
            "userglobalrole",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("webuser.id"), nullable=False),
            sa.Column("role_id", sa.Integer(), sa.ForeignKey("accessrole.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.String(200), nullable=True),
            sa.UniqueConstraint("user_id", "role_id"),
        )
        op.create_index("ix_userglobalrole_user_id", "userglobalrole", ["user_id"])
        op.create_index("ix_userglobalrole_role_id", "userglobalrole", ["role_id"])
    if not inspector.has_table("userproject"):
        op.create_table(
            "userproject",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("webuser.id"), nullable=False),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("project.id"), nullable=False),
            sa.Column("role_id", sa.Integer(), sa.ForeignKey("accessrole.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.String(200), nullable=True),
            sa.UniqueConstraint("user_id", "project_id", "role_id"),
        )
        op.create_index("ix_userproject_user_id", "userproject", ["user_id"])
        op.create_index("ix_userproject_project_id", "userproject", ["project_id"])
        op.create_index("ix_userproject_role_id", "userproject", ["role_id"])
    if not inspector.has_table("oidcclaimmapping"):
        op.create_table(
            "oidcclaimmapping",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("claim", sa.String(200), nullable=False),
            sa.Column("role_id", sa.Integer(), sa.ForeignKey("accessrole.id"), nullable=False),
            sa.Column("all_projects", sa.Boolean(), nullable=False),
            sa.Column("projects", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.String(200), nullable=True),
            sa.UniqueConstraint("claim", "role_id"),
        )
        op.create_index("ix_oidcclaimmapping_claim", "oidcclaimmapping", ["claim"])
        op.create_index("ix_oidcclaimmapping_role_id", "oidcclaimmapping", ["role_id"])
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


def _move_groups(connection: sa.Connection, now: datetime) -> None:
    """Give each local member the roles of its groups; turn the ``sso`` groups into mappings
    and the OIDC memberships of these groups into claims."""
    project_ids = dict(connection.execute(sa.text("SELECT name, id FROM project")).all())
    bindings = connection.execute(
        sa.text(
            "SELECT g.id, g.name, g.sso, r.role_id, r.projects "
            "FROM grouprole r JOIN usergroup g ON g.id = r.group_id ORDER BY r.id"
        )
    ).all()
    user_roles: set[tuple[int, int]] = set()
    user_projects: set[tuple[int, int, int]] = set()
    claims: set[tuple[int, str]] = set()
    sso_groups: dict[int, str] = {}
    for group_id, group_name, sso, role_id, projects_json in bindings:
        projects = json.loads(projects_json)
        members = connection.execute(
            sa.text("SELECT user_id, source FROM groupmember WHERE group_id = :group"),
            {"group": group_id},
        ).all()
        for user_id, source in members:
            if source != "local":
                continue
            if not projects:
                user_roles.add((user_id, role_id))
            for project in projects:
                if project in project_ids:
                    user_projects.add((user_id, project_ids[project], role_id))
        if sso:
            sso_groups[group_id] = group_name
            connection.execute(
                _mappings.insert().values(
                    claim=group_name,
                    role_id=role_id,
                    all_projects=not projects,
                    projects=json.dumps(projects),
                    created_at=now,
                    created_by=_ACTOR,
                )
            )
    for group_id, group_name in sso_groups.items():
        for (user_id,) in connection.execute(
            sa.text("SELECT user_id FROM groupmember WHERE group_id = :group AND source = 'oidc'"),
            {"group": group_id},
        ):
            claims.add((user_id, group_name))
    for user_id, role_id in sorted(user_roles):
        connection.execute(
            _global_roles.insert().values(
                user_id=user_id, role_id=role_id, created_at=now, created_by=_ACTOR
            )
        )
    for user_id, project_id, role_id in sorted(user_projects):
        connection.execute(
            _project_roles.insert().values(
                user_id=user_id,
                project_id=project_id,
                role_id=role_id,
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
