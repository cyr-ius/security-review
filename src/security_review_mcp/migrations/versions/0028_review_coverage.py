"""Review coverage of a report: checklist results and rules that raised scan leads.

Adds ``securityreport.checklist_results`` (JSON list of the checklist items walked through,
with their outcome) and ``securityreport.scan_rules`` (JSON list of the rule ids returned by
``scan_code``). Both are empty lists for the existing reports.

Revision ID: 0028
Revises: 0027
Create Date: 2026-10-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    sa.Column("checklist_results", sa.String(), nullable=False, server_default="[]"),
    sa.Column("scan_rules", sa.String(), nullable=False, server_default="[]"),
)


def upgrade() -> None:
    """Add the coverage columns (kept when they exist)."""
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("securityreport")}
    missing = [column for column in _COLUMNS if column.name not in existing]
    if missing:
        with op.batch_alter_table("securityreport") as batch:
            for column in missing:
                batch.add_column(column)


def downgrade() -> None:
    """Drop the coverage columns."""
    with op.batch_alter_table("securityreport") as batch:
        for column in reversed(_COLUMNS):
            batch.drop_column(column.name)
