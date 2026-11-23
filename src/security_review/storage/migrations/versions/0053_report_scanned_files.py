"""Files of a code scan report.

Adds ``securityreport.scanned_files``: JSON list of the files of a ``security-review-ci
scan-code`` scan, scanned (language, lines, matches) or not (reason). An empty list for the
existing reports and for the reviews of an agent.

Revision ID: 0053
Revises: 0052
Create Date: 2026-11-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0053"
down_revision: str | None = "0052"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMN = sa.Column("scanned_files", sa.String(), nullable=False, server_default="[]")


def upgrade() -> None:
    """Add the column of the scanned files (kept when it exists)."""
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("securityreport")}
    if _COLUMN.name not in existing:
        with op.batch_alter_table("securityreport") as batch:
            batch.add_column(_COLUMN)


def downgrade() -> None:
    """Drop the column of the scanned files."""
    with op.batch_alter_table("securityreport") as batch:
        batch.drop_column(_COLUMN.name)
