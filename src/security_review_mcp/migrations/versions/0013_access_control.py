"""Access control: roles made of permissions, groups of users, roles given to groups.

Creates the ``accessrole``, ``usergroup``, ``grouprole`` and ``groupmember`` tables, with the
system roles ``reader``, ``triager`` and ``admin`` and the group ``administrators`` (role
``admin``, not matched against the OIDC groups claim). The former access is moved into groups:

- each OIDC role mapping becomes a group named after its claim value (matched against the OIDC
  groups claim) that has the role of the mapping, on the same projects;
- each web user with a role of its own joins ``administrators``, ``triagers`` or ``readers``
  (groups not matched against the OIDC groups claim) when it reached every project, or else a
  personal group ``user:<username>`` with that role on its projects.

The access an OIDC user got from its groups at its last login is not moved: it is computed again
at its next login. The ``oidcrolemapping`` table and the role columns of ``webuser`` are then
dropped.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-17
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Permissions of the system roles at the time of this revision (the code is the reference)
_SYSTEM_ROLES = {
    "reader": ["reports.read"],
    "triager": ["reports.read", "findings.triage"],
    "admin": [
        "reports.read",
        "findings.triage",
        "rules.manage",
        "standards.manage",
        "tokens.manage",
        "settings.manage",
        "users.manage",
        "audit.read",
    ],
}
_SHARED_GROUPS = {"admin": "administrators", "triager": "triagers", "reader": "readers"}
_PERSONAL_PREFIX = "user:"

_roles = sa.table(
    "accessrole",
    sa.column("id", sa.Integer),
    sa.column("name", sa.String),
    sa.column("description", sa.String),
    sa.column("permissions", sa.String),
    sa.column("system", sa.Boolean),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("updated_at", sa.DateTime(timezone=True)),
    sa.column("created_by", sa.String),
)
_groups = sa.table(
    "usergroup",
    sa.column("id", sa.Integer),
    sa.column("name", sa.String),
    sa.column("description", sa.String),
    sa.column("sso", sa.Boolean),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("updated_at", sa.DateTime(timezone=True)),
    sa.column("created_by", sa.String),
)
_group_roles = sa.table(
    "grouprole",
    sa.column("group_id", sa.Integer),
    sa.column("role_id", sa.Integer),
    sa.column("projects", sa.String),
)
_members = sa.table(
    "groupmember",
    sa.column("group_id", sa.Integer),
    sa.column("user_id", sa.Integer),
    sa.column("source", sa.String),
    sa.column("created_at", sa.DateTime(timezone=True)),
)


def _create_tables() -> None:
    """Create the four tables of this revision."""
    op.create_table(
        "accessrole",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.String(500), nullable=False),
        sa.Column("permissions", sa.String(), nullable=False),
        sa.Column("system", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=True),
    )
    op.create_index("ix_accessrole_name", "accessrole", ["name"], unique=True)
    op.create_table(
        "usergroup",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.String(500), nullable=False),
        sa.Column("sso", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=True),
    )
    op.create_index("ix_usergroup_name", "usergroup", ["name"], unique=True)
    op.create_table(
        "grouprole",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("usergroup.id"), nullable=False),
        sa.Column("role_id", sa.Integer(), sa.ForeignKey("accessrole.id"), nullable=False),
        sa.Column("projects", sa.String(), nullable=False),
        sa.UniqueConstraint("group_id", "role_id"),
    )
    op.create_index("ix_grouprole_group_id", "grouprole", ["group_id"])
    op.create_index("ix_grouprole_role_id", "grouprole", ["role_id"])
    op.create_table(
        "groupmember",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("usergroup.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("webuser.id"), nullable=False),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("group_id", "user_id", "source"),
    )
    op.create_index("ix_groupmember_group_id", "groupmember", ["group_id"])
    op.create_index("ix_groupmember_user_id", "groupmember", ["user_id"])


class _Writer:
    """Insert the roles, groups and bindings of the migration, once each."""

    def __init__(self, connection: sa.Connection) -> None:
        self.connection = connection
        self.now = datetime.now(UTC)
        self.roles: dict[str, int] = {}
        self.groups: dict[str, int] = {}
        self.bindings: set[tuple[int, int]] = set()

    def role(self, name: str) -> int:
        """Id of a system role, inserted at the first use."""
        if name not in self.roles:
            self.connection.execute(
                _roles.insert().values(
                    name=name,
                    description="",
                    permissions=json.dumps(_SYSTEM_ROLES[name]),
                    system=True,
                    created_at=self.now,
                    updated_at=self.now,
                    created_by="migration",
                )
            )
            self.roles[name] = self.connection.execute(
                sa.select(_roles.c.id).where(_roles.c.name == name)
            ).scalar_one()
        return self.roles[name]

    def group(self, name: str, sso: bool) -> int:
        """Id of a group, inserted at the first use (``sso`` is set once any use asks for it)."""
        if name not in self.groups:
            self.connection.execute(
                _groups.insert().values(
                    name=name,
                    description="",
                    sso=sso,
                    created_at=self.now,
                    updated_at=self.now,
                    created_by="migration",
                )
            )
            self.groups[name] = self.connection.execute(
                sa.select(_groups.c.id).where(_groups.c.name == name)
            ).scalar_one()
        elif sso:
            self.connection.execute(
                _groups.update().where(_groups.c.id == self.groups[name]).values(sso=True)
            )
        return self.groups[name]

    def bind(self, group_id: int, role: str, projects: list[str]) -> None:
        """Give a role to a group (the first binding of a role to a group wins)."""
        role_id = self.role(role)
        if (group_id, role_id) in self.bindings:
            return
        self.bindings.add((group_id, role_id))
        self.connection.execute(
            _group_roles.insert().values(
                group_id=group_id, role_id=role_id, projects=json.dumps(projects)
            )
        )

    def join(self, group_id: int, user_id: int) -> None:
        """Add a user to a group as a local member."""
        self.connection.execute(
            _members.insert().values(
                group_id=group_id, user_id=user_id, source="local", created_at=self.now
            )
        )


def _move_access(connection: sa.Connection) -> None:
    """Create the system roles and move the role mappings and user roles into groups."""
    writer = _Writer(connection)
    for name in _SYSTEM_ROLES:
        writer.role(name)
    writer.bind(writer.group(_SHARED_GROUPS["admin"], sso=False), "admin", [])
    if sa.inspect(connection).has_table("oidcrolemapping"):
        rows = connection.execute(
            sa.text("SELECT claim_value, role, projects FROM oidcrolemapping ORDER BY id")
        ).mappings()
        for row in rows:
            if row["role"] in _SYSTEM_ROLES:
                group_id = writer.group(row["claim_value"], sso=True)
                projects = [] if row["role"] == "admin" else json.loads(row["projects"])
                writer.bind(group_id, row["role"], projects)
    users = connection.execute(
        sa.text("SELECT id, username, role, projects FROM webuser WHERE role IS NOT NULL")
    ).mappings()
    for user in users:
        role = user["role"]
        if role not in _SYSTEM_ROLES:
            continue
        projects = [] if role == "admin" else json.loads(user["projects"] or "[]")
        if projects:
            group_id = writer.group(f"{_PERSONAL_PREFIX}{user['username']}", sso=False)
        else:
            group_id = writer.group(_SHARED_GROUPS[role], sso=False)
        writer.bind(group_id, role, projects)
        writer.join(group_id, user["id"])


def upgrade() -> None:
    """Create the access control tables, move the former access into them, drop the old one."""
    connection = op.get_bind()
    if not sa.inspect(connection).has_table("accessrole"):
        _create_tables()
        _move_access(connection)
    if sa.inspect(connection).has_table("oidcrolemapping"):
        op.drop_table("oidcrolemapping")
    existing = {column["name"] for column in sa.inspect(connection).get_columns("webuser")}
    dropped = [
        name for name in ("sso_projects", "sso_role", "projects", "role") if name in existing
    ]
    if dropped:
        with op.batch_alter_table("webuser") as batch:
            for name in dropped:
                batch.drop_column(name)


def downgrade() -> None:
    """Drop the access control tables; restore the (empty) former columns and mappings table.

    The roles of the users are not restored: an administrator gives them again.
    """
    with op.batch_alter_table("webuser") as batch:
        batch.add_column(sa.Column("role", sa.String(20), nullable=True))
        batch.add_column(sa.Column("projects", sa.String(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("sso_role", sa.String(20), nullable=True))
        batch.add_column(
            sa.Column("sso_projects", sa.String(), nullable=False, server_default="[]")
        )
    op.create_table(
        "oidcrolemapping",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("claim_value", sa.String(200), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("projects", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.UniqueConstraint("claim_value", "role"),
    )
    op.create_index("ix_oidcrolemapping_claim_value", "oidcrolemapping", ["claim_value"])
    for table in ("groupmember", "grouprole", "usergroup", "accessrole"):
        op.drop_table(table)
