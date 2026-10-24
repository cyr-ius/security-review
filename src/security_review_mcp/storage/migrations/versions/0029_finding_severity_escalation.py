"""Severity of a finding raised by a security analyst.

Adds to ``finding`` the severity given by the report (``original_severity``, empty while the
severity was never raised), the justification of the analyst who raised it, their name and
the date.

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    sa.Column("original_severity", sa.String(10), nullable=True),
    sa.Column("severity_reason", sa.String(1000), nullable=True),
    sa.Column("severity_changed_by", sa.String(200), nullable=True),
    sa.Column("severity_changed_at", sa.DateTime(timezone=True), nullable=True),
)


def upgrade() -> None:
    """Add the escalation columns (kept when they exist)."""
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("finding")}
    missing = [column for column in _COLUMNS if column.name not in existing]
    if missing:
        with op.batch_alter_table("finding") as batch:
            for column in missing:
                batch.add_column(column)


def downgrade() -> None:
    """Drop the escalation columns."""
    with op.batch_alter_table("finding") as batch:
        for column in reversed(_COLUMNS):
            batch.drop_column(column.name)
