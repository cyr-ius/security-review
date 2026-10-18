"""Roles given directly to a web user, on every project or on a list of projects.

Creates the ``userrole`` table. The personal groups ``user:<username>`` (created by revision
0013 and by the approval of an enrollment, not open to SSO) whose only members are that user,
added locally, become roles of the user: their roles move to ``userrole`` with the same
projects, then the group is deleted. Any other group is left as it is.

Downgrading moves the direct roles back into personal groups, then drops the table.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-18
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PERSONAL_PREFIX = "user:"

_users = sa.table("webuser", sa.column("id", sa.Integer), sa.column("username", sa.String))
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
_user_roles = sa.table(
    "userrole",
    sa.column("user_id", sa.Integer),
    sa.column("role_id", sa.Integer),
    sa.column("projects", sa.String),
)


def _merge(current: str | None, added: str) -> str:
    """Projects of two bindings of the same role: empty (every project) wins."""
    if current is None:
        return added
    if current == "[]" or added == "[]":
        return "[]"
    return json.dumps(list(dict.fromkeys([*json.loads(current), *json.loads(added)])))


def _move_personal_groups(connection: sa.Connection) -> None:
    """Turn each personal group whose only member is its user into roles of that user."""
    users = {
        name: user_id
        for user_id, name in connection.execute(sa.select(_users.c.id, _users.c.username))
    }
    groups = connection.execute(
        sa.select(_groups.c.id, _groups.c.name).where(
            _groups.c.name.like(f"{_PERSONAL_PREFIX}%"), _groups.c.sso.is_(False)
        )
    ).all()
    for group_id, name in groups:
        user_id = users.get(name.removeprefix(_PERSONAL_PREFIX))
        members = connection.execute(
            sa.select(_members.c.user_id, _members.c.source).where(_members.c.group_id == group_id)
        ).all()
        if user_id is None or {tuple(member) for member in members} != {(user_id, "local")}:
            continue
        current: dict[int, str] = dict(
            connection.execute(
                sa.select(_user_roles.c.role_id, _user_roles.c.projects).where(
                    _user_roles.c.user_id == user_id
                )
            ).all()
        )
        bindings = connection.execute(
            sa.select(_group_roles.c.role_id, _group_roles.c.projects).where(
                _group_roles.c.group_id == group_id
            )
        ).all()
        for role_id, projects in bindings:
            merged = _merge(current.get(role_id), projects)
            if role_id in current:
                connection.execute(
                    _user_roles.update()
                    .where(_user_roles.c.user_id == user_id, _user_roles.c.role_id == role_id)
                    .values(projects=merged)
                )
            else:
                connection.execute(
                    _user_roles.insert().values(user_id=user_id, role_id=role_id, projects=merged)
                )
            current[role_id] = merged
        connection.execute(_members.delete().where(_members.c.group_id == group_id))
        connection.execute(_group_roles.delete().where(_group_roles.c.group_id == group_id))
        connection.execute(_groups.delete().where(_groups.c.id == group_id))


def upgrade() -> None:
    """Create ``userrole`` and move the personal groups into it."""
    if sa.inspect(op.get_bind()).has_table("userrole"):
        return
    op.create_table(
        "userrole",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("webuser.id"), nullable=False),
        sa.Column("role_id", sa.Integer(), sa.ForeignKey("accessrole.id"), nullable=False),
        sa.Column("projects", sa.String(), nullable=False),
        sa.UniqueConstraint("user_id", "role_id"),
    )
    op.create_index("ix_userrole_user_id", "userrole", ["user_id"])
    op.create_index("ix_userrole_role_id", "userrole", ["role_id"])
    _move_personal_groups(op.get_bind())


def downgrade() -> None:
    """Move the direct roles back into personal groups, then drop ``userrole``."""
    connection = op.get_bind()
    now = datetime.now(UTC)
    rows = connection.execute(
        sa.select(_users.c.id, _users.c.username, _user_roles.c.role_id, _user_roles.c.projects)
        .join(_user_roles, _user_roles.c.user_id == _users.c.id)
        .order_by(_users.c.id)
    ).all()
    personal: dict[int, int] = {}
    for user_id, username, role_id, projects in rows:
        if user_id not in personal:
            name = f"{_PERSONAL_PREFIX}{username}"
            group_id = connection.execute(
                sa.select(_groups.c.id).where(_groups.c.name == name)
            ).scalar()
            if group_id is None:
                connection.execute(
                    _groups.insert().values(
                        name=name,
                        description="",
                        sso=False,
                        created_at=now,
                        updated_at=now,
                        created_by="migration",
                    )
                )
                group_id = connection.execute(
                    sa.select(_groups.c.id).where(_groups.c.name == name)
                ).scalar_one()
                connection.execute(
                    _members.insert().values(
                        group_id=group_id, user_id=user_id, source="local", created_at=now
                    )
                )
            personal[user_id] = group_id
        group_id = personal[user_id]
        exists = connection.execute(
            sa.select(_group_roles.c.projects).where(
                _group_roles.c.group_id == group_id, _group_roles.c.role_id == role_id
            )
        ).first()
        if exists is None:
            connection.execute(
                _group_roles.insert().values(group_id=group_id, role_id=role_id, projects=projects)
            )
        else:
            connection.execute(
                _group_roles.update()
                .where(_group_roles.c.group_id == group_id, _group_roles.c.role_id == role_id)
                .values(projects=_merge(exists[0], projects))
            )
    op.drop_index("ix_userrole_role_id", table_name="userrole")
    op.drop_index("ix_userrole_user_id", table_name="userrole")
    op.drop_table("userrole")
