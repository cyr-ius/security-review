"""Review group of a report: the reports of one codebase review.

Adds ``securityreport.review_group``: the id of the scan ticket of start_codebase_scan, stored
with the code and dependency scans saved with that ticket and with the review the agent saves
after them, so that the Report page links them. Empty for the existing reports.

Revision ID: 0054
Revises: 0053
Create Date: 2026-11-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0054"
down_revision: str | None = "0053"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "securityreport"


def upgrade() -> None:
    """Add the column and its index (kept when they exist)."""
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns(_TABLE)}
    if "review_group" in columns:
        return
    with op.batch_alter_table(_TABLE) as batch:
        batch.add_column(sa.Column("review_group", sa.String(length=32), nullable=True))
        batch.create_index("ix_securityreport_review_group", ["review_group"])


def downgrade() -> None:
    """Drop the column: the reports of a codebase review are no longer linked."""
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_index("ix_securityreport_review_group")
        batch.drop_column("review_group")
