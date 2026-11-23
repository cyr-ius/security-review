"""Review of the whole repository asked of the MCP agent.

Adds to ``project``:

- ``codebase_review_requested_at``: date a person asked for a codebase review (None: not asked);
- ``codebase_review_interval_days``: days after the latest codebase review when the next one is
  due (None: no periodic review).

Revision ID: 0056
Revises: 0055
Create Date: 2026-11-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0056"
down_revision: str | None = "0055"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "project"
_COLUMNS = (
    sa.Column("codebase_review_requested_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("codebase_review_interval_days", sa.Integer(), nullable=True),
)


def upgrade() -> None:
    """Add the columns (kept when they exist)."""
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns(_TABLE)}
    missing = [column for column in _COLUMNS if column.name not in existing]
    if missing:
        with op.batch_alter_table(_TABLE) as batch:
            for column in missing:
                batch.add_column(column)


def downgrade() -> None:
    """Drop the columns."""
    with op.batch_alter_table(_TABLE) as batch:
        for column in reversed(_COLUMNS):
            batch.drop_column(column.name)
