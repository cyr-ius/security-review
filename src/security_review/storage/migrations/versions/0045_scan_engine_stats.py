"""Capacity and counters of the scan engines: columns of ``scanengine``.

Each engine reports in its heartbeat its OpenGrep slots and what it did since it started (scans,
files, failures, refusals when busy), shown by the Scan engines page. The existing engines get 0
until their next heartbeat.

Revision ID: 0045
Revises: 0044
Create Date: 2026-11-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0045"
down_revision: str | None = "0044"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "scanengine"
_COLUMNS = (
    sa.Column("codebase_slots", sa.Integer(), nullable=False, server_default="0"),
    sa.Column("fragment_slots", sa.Integer(), nullable=False, server_default="0"),
    sa.Column("codebase_scans", sa.BigInteger(), nullable=False, server_default="0"),
    sa.Column("fragment_scans", sa.BigInteger(), nullable=False, server_default="0"),
    sa.Column("scanned_files", sa.BigInteger(), nullable=False, server_default="0"),
    sa.Column("failed_scans", sa.BigInteger(), nullable=False, server_default="0"),
    sa.Column("busy_refusals", sa.BigInteger(), nullable=False, server_default="0"),
)


def upgrade() -> None:
    """Add the capacity and the counters of the engines (kept when they exist)."""
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns(_TABLE)}
    missing = [column for column in _COLUMNS if column.name not in existing]
    if missing:
        with op.batch_alter_table(_TABLE) as batch:
            for column in missing:
                batch.add_column(column)


def downgrade() -> None:
    """Drop the capacity and the counters of the engines."""
    with op.batch_alter_table(_TABLE) as batch:
        for column in reversed(_COLUMNS):
            batch.drop_column(column.name)
