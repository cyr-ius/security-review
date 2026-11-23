"""OAuth grant of a scan ticket.

Adds ``grant_id`` to ``scanticket``: the OAuth grant whose access token asked for the ticket
(None for a stored token or a ticket issued before), checked again at each use so that revoking
the grant, or turning the OAuth login off, also invalidates its tickets.

Revision ID: 0057
Revises: 0056
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0057"
down_revision: str | None = "0056"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "scanticket"
_COLUMN = "grant_id"


def upgrade() -> None:
    """Add the column (kept when it exists)."""
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns(_TABLE)}
    if _COLUMN not in existing:
        with op.batch_alter_table(_TABLE) as batch:
            batch.add_column(sa.Column(_COLUMN, sa.String(64), nullable=True))


def downgrade() -> None:
    """Drop the column."""
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_column(_COLUMN)
