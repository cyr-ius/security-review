"""Code scans a Controller process runs itself.

The heartbeat of a Controller process (``serverinstance``, revision 0047) carries the code scans
it runs itself by pool, their files and its OpenGrep slots, as JSON, so that the activity diagram
of the Activity page shows its slots and files without scan engines.

Revision ID: 0051
Revises: 0050
Create Date: 2026-11-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0051"
down_revision: str | None = "0050"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "serverinstance"
_COLUMN = "scans"


def upgrade() -> None:
    """Add the code scans of the server processes (kept when the column exists)."""
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns(_TABLE)}
    if _COLUMN not in existing:
        with op.batch_alter_table(_TABLE) as batch:
            batch.add_column(
                sa.Column(_COLUMN, sa.String(length=200), nullable=False, server_default="{}")
            )


def downgrade() -> None:
    """Drop the code scans of the server processes."""
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_column(_COLUMN)
