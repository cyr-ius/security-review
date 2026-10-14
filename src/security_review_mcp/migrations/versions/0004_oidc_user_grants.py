"""OIDC user grants: projects an identity provider user reads, granted by name.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the oidcusergrant table (kept when it already exists)."""
    if sa.inspect(op.get_bind()).has_table("oidcusergrant"):
        return
    op.create_table(
        "oidcusergrant",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(200), nullable=False),
        sa.Column("projects", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=True),
    )
    op.create_index("ix_oidcusergrant_username", "oidcusergrant", ["username"], unique=True)


def downgrade() -> None:
    """Drop the table of this revision."""
    op.drop_table("oidcusergrant")
