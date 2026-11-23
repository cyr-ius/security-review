"""Running Controller and MCP server processes.

The heartbeats of the Controller processes (``controllerinstance``, revision 0046) become those
of every server process (``serverinstance``): the MCP servers of the HTTP transport keep one too,
with the scan_code calls they run now, for the activity diagram of the Scan engines page. The
rows are heartbeats only: a running process records itself again within seconds, so the old
table is dropped rather than copied.

Revision ID: 0047
Revises: 0046
Create Date: 2026-11-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0047"
down_revision: str | None = "0046"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _create_controller_instances() -> None:
    op.create_table(
        "controllerinstance",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_controllerinstance_heartbeat_at", "controllerinstance", ["heartbeat_at"])


def upgrade() -> None:
    """Replace the Controller processes by the server processes (kept when they exist)."""
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("controllerinstance"):
        op.drop_index("ix_controllerinstance_heartbeat_at", table_name="controllerinstance")
        op.drop_table("controllerinstance")
    if not inspector.has_table("serverinstance"):
        op.create_table(
            "serverinstance",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("kind", sa.String(length=20), nullable=False),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("version", sa.String(length=40), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("delegated", sa.Boolean(), nullable=False),
            sa.Column("processing_fragments", sa.Integer(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_serverinstance_kind", "serverinstance", ["kind"])
        op.create_index("ix_serverinstance_heartbeat_at", "serverinstance", ["heartbeat_at"])


def downgrade() -> None:
    """Back to the Controller processes only (they record themselves again)."""
    op.drop_index("ix_serverinstance_heartbeat_at", table_name="serverinstance")
    op.drop_index("ix_serverinstance_kind", table_name="serverinstance")
    op.drop_table("serverinstance")
    _create_controller_instances()
