"""Agents seen lately by each MCP server.

The heartbeat of an MCP server (``serverinstance``, revision 0047) carries the agents that sent it
a request lately, for the activity diagram of the Scan engines page: an opaque key, the name and
version of their MCP client, their last request and their scan_code calls running, as JSON.

Revision ID: 0048
Revises: 0047
Create Date: 2026-11-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0048"
down_revision: str | None = "0047"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "serverinstance"
_COLUMN = "agents"


def upgrade() -> None:
    """Add the agents of the MCP servers (kept when the column exists)."""
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns(_TABLE)}
    if _COLUMN not in existing:
        with op.batch_alter_table(_TABLE) as batch:
            batch.add_column(
                sa.Column(_COLUMN, sa.String(length=16000), nullable=False, server_default="[]")
            )


def downgrade() -> None:
    """Drop the agents of the MCP servers."""
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_column(_COLUMN)
