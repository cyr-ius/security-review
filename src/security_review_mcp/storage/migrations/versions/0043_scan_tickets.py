"""Single-use tickets of the codebase scans started by an MCP agent: ``scanticket``.

The MCP tool start_codebase_scan asks the controller for a ticket that lets
``security-review-ci`` send the files of the workstation to the scans of one project. Nothing is
copied: the table starts empty.

Revision ID: 0043
Revises: 0042
Create Date: 2026-11-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0043"
down_revision: str | None = "0042"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "scanticket"


def upgrade() -> None:
    """Create the table of the scan tickets (kept when it exists)."""
    if sa.inspect(op.get_bind()).has_table(_TABLE):
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("ticket_hash", sa.String(64), nullable=False),
        sa.Column("project", sa.String(200), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("webuser.id"), nullable=True),
        sa.Column("token_id", sa.String(64), nullable=True),
        sa.Column("issued_to", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("code_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deps_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(f"ix_{_TABLE}_ticket_hash", _TABLE, ["ticket_hash"], unique=True)
    op.create_index(f"ix_{_TABLE}_user_id", _TABLE, ["user_id"])
    op.create_index(f"ix_{_TABLE}_expires_at", _TABLE, ["expires_at"])


def downgrade() -> None:
    """Drop the scan tickets (the pending ones stop working)."""
    op.drop_table(_TABLE)
