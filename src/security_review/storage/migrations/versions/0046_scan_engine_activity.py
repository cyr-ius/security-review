"""Live activity of the scan engines and running Controller processes.

The scan engines report in their heartbeat the scans and files they are processing now (gauges,
unlike the counters of revision 0045), and each Controller process keeps a heartbeat in
``controllerinstance``, for the activity diagram of the Scan engines page.

Revision ID: 0046
Revises: 0045
Create Date: 2026-11-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0046"
down_revision: str | None = "0045"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "scanengine"
_COLUMNS = (
    sa.Column("processing_files", sa.BigInteger(), nullable=False, server_default="0"),
    sa.Column("processing_codebase_scans", sa.BigInteger(), nullable=False, server_default="0"),
    sa.Column("processing_fragment_scans", sa.BigInteger(), nullable=False, server_default="0"),
)


def upgrade() -> None:
    """Add the gauges of the engines (kept when they exist) and the Controller processes."""
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns(_TABLE)}
    missing = [column for column in _COLUMNS if column.name not in existing]
    if missing:
        with op.batch_alter_table(_TABLE) as batch:
            for column in missing:
                batch.add_column(column)
    if not inspector.has_table("controllerinstance"):
        op.create_table(
            "controllerinstance",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_controllerinstance_heartbeat_at", "controllerinstance", ["heartbeat_at"]
        )


def downgrade() -> None:
    """Drop the Controller processes and the gauges of the engines."""
    op.drop_index("ix_controllerinstance_heartbeat_at", table_name="controllerinstance")
    op.drop_table("controllerinstance")
    with op.batch_alter_table(_TABLE) as batch:
        for column in reversed(_COLUMNS):
            batch.drop_column(column.name)
