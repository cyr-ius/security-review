"""OpenGrep rules proposed by an agent, waiting for a person: ``opengrepruleproposal``.

An agent proposes a rule during a review (MCP tool propose_opengrep_rule); a person logged in
to the web interface approves it (the controller installs the rule file) or rejects it.

Revision ID: 0042
Revises: 0041
Create Date: 2026-11-01
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0042"
down_revision: str | None = "0041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "opengrepruleproposal"


def upgrade() -> None:
    """Create the table of the proposed OpenGrep rules (kept when it exists)."""
    if sa.inspect(op.get_bind()).has_table(_TABLE):
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_id", sa.String(80), nullable=False),
        sa.Column("content", sa.String(), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("test_code", sa.String(), nullable=True),
        sa.Column("project", sa.String(200), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("proposed_by", sa.String(200), nullable=False),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(200), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.String(1000), nullable=True),
    )
    for column in ("rule_id", "project", "status"):
        op.create_index(f"ix_{_TABLE}_{column}", _TABLE, [column])


def downgrade() -> None:
    """Drop the proposed OpenGrep rules."""
    op.drop_table(_TABLE)
