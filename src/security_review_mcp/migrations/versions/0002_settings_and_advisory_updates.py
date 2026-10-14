"""Settings changed in the web interface and history of the OSV updates.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the appsetting and advisoryupdate tables (kept when they already exist)."""
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("appsetting"):
        _create_appsetting()
    if not inspector.has_table("advisoryupdate"):
        _create_advisoryupdate()


def _create_appsetting() -> None:
    """Create the table of the settings changed in the web interface."""
    op.create_table(
        "appsetting",
        sa.Column("key", sa.String(50), primary_key=True),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(64), nullable=True),
    )


def _create_advisoryupdate() -> None:
    """Create the history of the OSV updates."""
    op.create_table(
        "advisoryupdate",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("trigger", sa.String(20), nullable=False),
        sa.Column("triggered_by", sa.String(64), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("source", sa.String(500), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("results", sa.String(), nullable=False),
    )
    op.create_index("ix_advisoryupdate_status", "advisoryupdate", ["status"])
    op.create_index("ix_advisoryupdate_started_at", "advisoryupdate", ["started_at"])


def downgrade() -> None:
    """Drop the tables of this revision."""
    op.drop_table("advisoryupdate")
    op.drop_table("appsetting")
