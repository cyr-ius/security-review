"""No role of its own for a web user: every permission comes from a group.

Each role given directly to a user (``userrole``) becomes the local membership of a group
without OIDC that holds the same role on the same projects, so that nobody loses or gains any
access (the last administrator included):

- a role on a list of projects gives one group per project: ``project:<project>`` for
  ``reader`` (the project group also joined at the approval of an enrollment), otherwise
  ``project:<project>:<role>``;
- a role on every project gives the group ``role:<role>``.

An existing group without OIDC whose only role is that same binding is reused; a name already
taken by another group gets a number (`` (2)``). Then the ``userrole`` table is dropped.

Downgrading creates the ``userrole`` table again, empty: the groups and their members are kept.

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-18
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Same length as access_control.MAX_GROUP_NAME_CHARS
_MAX_GROUP_NAME_CHARS = 200

_roles = sa.table("accessrole", sa.column("id", sa.Integer), sa.column("name", sa.String))
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


def _base_name(role: str, project: str | None) -> str:
    """Name of the group of a role on one project (None: every project)."""
    if project is None:
        return f"role:{role}"
    return f"project:{project}" if role == "reader" else f"project:{project}:{role}"


def _find_group(connection: sa.Connection, role_id: int, projects: str) -> int | None:
    """A group without OIDC whose only role is ``role_id`` on ``projects``, or None."""
    candidates = connection.execute(
        sa.select(_groups.c.id)
        .join(_group_roles, _group_roles.c.group_id == _groups.c.id)
        .where(
            _group_roles.c.role_id == role_id,
            _group_roles.c.projects == projects,
            _groups.c.sso.is_(False),
        )
        .order_by(_groups.c.id)
    ).scalars()
    for group_id in candidates.all():
        count = connection.execute(
            sa.select(sa.func.count())
            .select_from(_group_roles)
            .where(_group_roles.c.group_id == group_id)
        ).scalar_one()
        if count == 1:
            return group_id
    return None


def _free_name(connection: sa.Connection, base: str) -> str:
    """``base`` cut to the length of a group name, with a number when the name is taken."""
    number = 1
    while True:
        suffix = "" if number == 1 else f" ({number})"
        name = base[: _MAX_GROUP_NAME_CHARS - len(suffix)] + suffix
        taken = connection.execute(sa.select(_groups.c.id).where(_groups.c.name == name)).first()
        if taken is None:
            return name
        number += 1


def _group_of(
    connection: sa.Connection, role_id: int, role: str, project: str | None, now: datetime
) -> int:
    """Id of the group that holds ``role`` on ``project`` alone, created when missing."""
    projects = json.dumps([] if project is None else [project])
    group_id = _find_group(connection, role_id, projects)
    if group_id is not None:
        return group_id
    name = _free_name(connection, _base_name(role, project))
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
        _group_roles.insert().values(group_id=group_id, role_id=role_id, projects=projects)
    )
    return group_id


def _join(connection: sa.Connection, group_id: int, user_id: int, now: datetime) -> None:
    """Add a user to a group as a local member (no change when it already is one)."""
    exists = connection.execute(
        sa.select(_members.c.user_id).where(
            _members.c.group_id == group_id,
            _members.c.user_id == user_id,
            _members.c.source == "local",
        )
    ).first()
    if exists is None:
        connection.execute(
            _members.insert().values(
                group_id=group_id, user_id=user_id, source="local", created_at=now
            )
        )


def upgrade() -> None:
    """Move every direct role into a group, then drop ``userrole``."""
    connection = op.get_bind()
    if not sa.inspect(connection).has_table("userrole"):
        return
    now = datetime.now(UTC)
    rows = connection.execute(
        sa.select(
            _user_roles.c.user_id, _user_roles.c.role_id, _roles.c.name, _user_roles.c.projects
        )
        .join(_roles, _roles.c.id == _user_roles.c.role_id)
        .order_by(_user_roles.c.user_id, _roles.c.name)
    ).all()
    for user_id, role_id, role, projects in rows:
        for project in json.loads(projects) or [None]:
            _join(connection, _group_of(connection, role_id, role, project, now), user_id, now)
    op.drop_index("ix_userrole_role_id", table_name="userrole")
    op.drop_index("ix_userrole_user_id", table_name="userrole")
    op.drop_table("userrole")


def downgrade() -> None:
    """Create ``userrole`` again, empty (the groups and their members are kept)."""
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
