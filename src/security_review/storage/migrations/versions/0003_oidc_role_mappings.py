"""OIDC role mapping: identity provider groups or roles mapped to web roles and projects.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the oidcrolemapping table (kept when it already exists)."""
    if sa.inspect(op.get_bind()).has_table("oidcrolemapping"):
        return
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


def downgrade() -> None:
    """Drop the table of this revision."""
    op.drop_table("oidcrolemapping")
