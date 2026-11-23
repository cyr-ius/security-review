"""Requests running in each server process, by family.

The heartbeat of a server process (``serverinstance``, revision 0047) carries the requests it ran
since the previous one by family (code scans, dependency scans, reports and triage, reads), as
JSON, for the rings of the activity diagram of the Activity page.

Revision ID: 0050
Revises: 0049
Create Date: 2026-11-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0050"
down_revision: str | None = "0049"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "serverinstance"
_COLUMN = "processing"


def upgrade() -> None:
    """Add the requests by family of the server processes (kept when the column exists)."""
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns(_TABLE)}
    if _COLUMN not in existing:
        with op.batch_alter_table(_TABLE) as batch:
            batch.add_column(
                sa.Column(_COLUMN, sa.String(length=200), nullable=False, server_default="{}")
            )


def downgrade() -> None:
    """Drop the requests by family of the server processes."""
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_column(_COLUMN)
