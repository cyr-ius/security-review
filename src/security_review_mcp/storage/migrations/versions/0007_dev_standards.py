"""Development standards: per-technology guidance served to the developer's AI.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the devstandard table (kept when it already exists)."""
    if sa.inspect(op.get_bind()).has_table("devstandard"):
        return
    op.create_table(
        "devstandard",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slug", sa.String(50), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.String(500), nullable=False),
        sa.Column("technologies", sa.String(), nullable=False),
        sa.Column("file_patterns", sa.String(), nullable=False),
        sa.Column("content", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(64), nullable=True),
    )
    op.create_index("ix_devstandard_slug", "devstandard", ["slug"], unique=True)


def downgrade() -> None:
    """Drop the table of this revision."""
    op.drop_table("devstandard")
