"""The holders of ``projects.autojoin`` may be kept from joining a project at once.

Creates the ``projectautojoinblock`` table: one row per project whose autojoin is blocked. The
new permission itself needs no change: the permissions of a role are stored as text.

Revision ID: 0037
Revises: 0036
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0037"
down_revision: str | None = "0036"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "projectautojoinblock"
_INDEX = "ix_projectautojoinblock_project"


def upgrade() -> None:
    """Create the table (kept when it exists)."""
    if sa.inspect(op.get_bind()).has_table(_TABLE):
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project", sa.String(200), nullable=False),
        sa.Column("blocked_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(_INDEX, _TABLE, ["project"], unique=True)


def downgrade() -> None:
    """Drop the table: every project may be joined again."""
    op.drop_table(_TABLE)
