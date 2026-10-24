"""Tickets of the findings in Jira and ServiceNow.

Creates ``findingticket`` (the ticket of a finding in a ticketing system, one per finding and
kind) and ``tickettarget`` (where the findings of a project go, and its automatic sending).

Revision ID: 0030
Revises: 0029
Create Date: 2026-10-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the ticket tables (kept when they exist)."""
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("findingticket"):
        op.create_table(
            "findingticket",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("finding_id", sa.Integer(), sa.ForeignKey("finding.id"), nullable=False),
            sa.Column("kind", sa.String(20), nullable=False),
            sa.Column("project", sa.String(200), nullable=False),
            sa.Column("fingerprint", sa.String(64), nullable=False),
            sa.Column("state", sa.String(20), nullable=False),
            sa.Column("external_key", sa.String(100), nullable=True),
            sa.Column("url", sa.String(1000), nullable=True),
            sa.Column("error", sa.String(500), nullable=True),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("created_by", sa.String(200), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("finding_id", "kind"),
        )
        for column in ("finding_id", "project", "fingerprint", "state", "updated_at"):
            op.create_index(f"ix_findingticket_{column}", "findingticket", [column])
    if not inspector.has_table("tickettarget"):
        op.create_table(
            "tickettarget",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("project", sa.String(200), nullable=False),
            sa.Column("kind", sa.String(20), nullable=False),
            sa.Column("destination", sa.String(200), nullable=False),
            sa.Column("auto_min_severity", sa.String(10), nullable=True),
            sa.Column("auto_since", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_by", sa.String(200), nullable=True),
            sa.UniqueConstraint("project", "kind"),
        )
        op.create_index("ix_tickettarget_project", "tickettarget", ["project"])


def downgrade() -> None:
    """Drop the ticket tables."""
    op.drop_table("tickettarget")
    op.drop_table("findingticket")
