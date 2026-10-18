"""Rate limiting shared by the processes of the controller.

Creates the ``ratelimitcounter`` table: the events of a key (failed logins, API requests of
an address) in fixed time windows, so that every worker and replica applies the same limits.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the counter table (kept when it exists)."""
    if sa.inspect(op.get_bind()).has_table("ratelimitcounter"):
        return
    op.create_table(
        "ratelimitcounter",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("window_start", sa.BigInteger(), primary_key=True),
        sa.Column("hits", sa.Integer(), nullable=False),
    )
    op.create_index("ix_ratelimitcounter_window_start", "ratelimitcounter", ["window_start"])


def downgrade() -> None:
    """Drop the counter table."""
    op.drop_table("ratelimitcounter")
