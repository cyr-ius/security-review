"""The ``mcp_tokens.create`` permission is replaced by SECREVIEW_PERSONAL_TOKENS_ENABLED.

Every web user may create a personal ``mcp`` or ``ci`` token while the variable is true: the
permission is removed from every role. A role left without any permission (``mcp-user``, created
by 0024) is deleted with the groups bindings that give it, unless a token uses it: it is then
kept, empty, for an administrator to change or delete.

Downgrading creates the ``mcp-user`` role again, held by no group: which roles held the
permission is not known any more.

Revision ID: 0036
Revises: 0035
Create Date: 2026-10-29
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0036"
down_revision: str | None = "0035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PERMISSION = "mcp_tokens.create"
_MCP_USER = "mcp-user"

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
    """Remove the permission from every role; delete the roles it leaves empty."""
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(_roles.c.id, _roles.c.permissions).where(
            _roles.c.permissions.contains(f'"{_PERMISSION}"')
        )
    ).all()
    for role_id, permissions in rows:
        kept = [name for name in json.loads(permissions) if name != _PERMISSION]
        used = connection.execute(
            sa.select(_tokens.c.access_role_id).where(_tokens.c.access_role_id == role_id).limit(1)
        ).first()
        if kept or used:
            connection.execute(
                _roles.update().where(_roles.c.id == role_id).values(permissions=json.dumps(kept))
            )
            continue
        connection.execute(_group_roles.delete().where(_group_roles.c.role_id == role_id))
        connection.execute(_roles.delete().where(_roles.c.id == role_id))


def downgrade() -> None:
    """Create the ``mcp-user`` role again when missing (a role of that name is kept)."""
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
                permissions=json.dumps([_PERMISSION]),
                system=False,
                created_at=now,
                updated_at=now,
                created_by="migration",
            )
        )
