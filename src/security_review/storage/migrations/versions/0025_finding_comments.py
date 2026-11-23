"""Comments of the findings.

Creates the ``findingcomment`` table: the comments people write on a finding, mostly on its
risk acceptance (web interface). They are append-only.

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEX = "ix_findingcomment_finding_id"


def upgrade() -> None:
    """Create the comment table (kept when it exists)."""
    if sa.inspect(op.get_bind()).has_table("findingcomment"):
        return
    op.create_table(
        "findingcomment",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("finding.id"), nullable=False),
        sa.Column("author", sa.String(200), nullable=False),
        sa.Column("body", sa.String(2000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(_INDEX, "findingcomment", ["finding_id"])


def downgrade() -> None:
    """Drop the comment table."""
    op.drop_table("findingcomment")
