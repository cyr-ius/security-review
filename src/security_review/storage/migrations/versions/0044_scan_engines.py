"""Scan engines enrolled with the controller: ``scanengine``.

The scan engines (security-review-scan-engine) no longer read the database: each one enrolls
with the shared secret of the engines and gets an OAuth client (client_credentials) to read the
rules through the REST API of the controller; the controller sends the scans to the URL it gives,
while its heartbeat is recent. Nothing is copied: the table starts empty.

Revision ID: 0044
Revises: 0043
Create Date: 2026-11-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0044"
down_revision: str | None = "0043"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "scanengine"


def upgrade() -> None:
    """Create the table of the enrolled scan engines (kept when it exists)."""
    if sa.inspect(op.get_bind()).has_table(_TABLE):
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("version", sa.String(40), nullable=False),
        sa.Column("address", sa.String(64), nullable=True),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("free_codebase_slots", sa.Integer(), nullable=False),
        sa.Column("free_fragment_slots", sa.Integer(), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("access_token_hash", sa.String(64), nullable=True),
        sa.Column("access_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(f"ix_{_TABLE}_secret_hash", _TABLE, ["secret_hash"], unique=True)
    op.create_index(f"ix_{_TABLE}_access_token_hash", _TABLE, ["access_token_hash"], unique=True)
    op.create_index(f"ix_{_TABLE}_last_seen_at", _TABLE, ["last_seen_at"])
    op.create_index(f"ix_{_TABLE}_heartbeat_at", _TABLE, ["heartbeat_at"])


def downgrade() -> None:
    """Drop the enrolled scan engines (they enroll again at their next start)."""
    op.drop_table(_TABLE)
