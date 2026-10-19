"""The ``mcp-user`` role: create a personal MCP token.

A web user needs the new permission ``mcp_tokens.create`` to create a personal ``mcp`` token
(My account): before, every logged-in user could. The ordinary role ``mcp-user`` (only that
permission) is created when missing, so that an administrator gives it to a group. No group
receives it here: the personal ``mcp`` tokens already created keep working.

Downgrading deletes the role when no group holds it and no token uses it.

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-19
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MCP_USER = "mcp-user"
_MCP_USER_PERMISSIONS = json.dumps(["mcp_tokens.create"])

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
_group_roles = sa.table("grouprole", sa.column("role_id", sa.Integer))
_tokens = sa.table("apitoken", sa.column("access_role_id", sa.Integer))


def upgrade() -> None:
    """Create the ordinary ``mcp-user`` role when missing (a role of that name is kept)."""
    connection = op.get_bind()
    existing = connection.execute(
        sa.select(_roles.c.id).where(_roles.c.name == _MCP_USER)
    ).scalar_one_or_none()
    if existing is None:
        now = datetime.now(UTC)
        connection.execute(
            _roles.insert().values(
                name=_MCP_USER,
                description="",
                permissions=_MCP_USER_PERMISSIONS,
                system=False,
                created_at=now,
                updated_at=now,
                created_by="migration",
            )
        )


def downgrade() -> None:
    """Delete the ``mcp-user`` role, unless a group holds it or a token uses it."""
    connection = op.get_bind()
    role_id = connection.execute(
        sa.select(_roles.c.id).where(
            _roles.c.name == _MCP_USER, _roles.c.permissions == _MCP_USER_PERMISSIONS
        )
    ).scalar_one_or_none()
    if role_id is None:
        return
    for column in (_group_roles.c.role_id, _tokens.c.access_role_id):
        if connection.execute(sa.select(column).where(column == role_id).limit(1)).first():
            return
    connection.execute(_roles.delete().where(_roles.c.id == role_id))
