"""File coverage of a codebase review.

Adds to ``securityreport``:

- ``scan_summary``: JSON counts of the files of a code or dependency scan, shown by the reports
  linked to it (None for a review and for the existing reports);
- ``files_reviewed``: JSON list of the files an agent declares it read for its review;
- ``unreviewed_leads``: JSON list of the files with leads of the code scan of its review group
  that the agent did not read, computed when the review is saved.

Revision ID: 0055
Revises: 0054
Create Date: 2026-11-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0055"
down_revision: str | None = "0054"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "securityreport"
_COLUMNS = (
    sa.Column("scan_summary", sa.String(), nullable=True),
    sa.Column("files_reviewed", sa.String(), nullable=False, server_default="[]"),
    sa.Column("unreviewed_leads", sa.String(), nullable=False, server_default="[]"),
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
