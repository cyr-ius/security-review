"""Triage decision and agent proposal of a finding.

Adds to ``finding`` the reason, approver and expiry date of a triage decision (made by a
person in the web interface) and the status proposed by an agent, which is never applied.
The existing ``accepted`` and ``false_positive`` decisions had no reason nor approver (an agent
could make them): they expire 30 days after the upgrade, so a person confirms them or they
block again.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-17
"""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    sa.Column("status_reason", sa.String(1000), nullable=True),
    sa.Column("status_approver", sa.String(200), nullable=True),
    sa.Column("status_expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("proposed_status", sa.String(20), nullable=True),
    sa.Column("proposed_reason", sa.String(1000), nullable=True),
    sa.Column("proposed_by", sa.String(200), nullable=True),
    sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=True),
)
_INDEX = "ix_finding_status_expires_at"

# Grace period of the decisions made before reasons and expiry dates were required
LEGACY_GRACE = timedelta(days=30)
LEGACY_REASON = (
    "Decided before a reason and an expiry date were required: confirm it or it blocks again"
)
# Stored as the names of the enum members (see 0001_baseline)
_DISMISSED = ("ACCEPTED", "FALSE_POSITIVE")

finding = sa.table(
    "finding",
    sa.column("status", sa.String),
    sa.column("status_reason", sa.String),
    sa.column("status_expires_at", sa.DateTime(timezone=True)),
)


def upgrade() -> None:
    """Add the columns and the expiry index (kept when they exist), date the old decisions."""
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("finding")}
    missing = [column for column in _COLUMNS if column.name not in existing]
    if missing:
        with op.batch_alter_table("finding") as batch:
            for column in missing:
                batch.add_column(column)
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("finding")}
    if _INDEX not in indexes:
        op.create_index(_INDEX, "finding", ["status_expires_at"])
    op.execute(
        sa.update(finding)
        .where(finding.c.status.in_(_DISMISSED), finding.c.status_expires_at.is_(None))
        .values(
            status_reason=LEGACY_REASON,
            status_expires_at=datetime.now(UTC) + LEGACY_GRACE,
        )
    )


def downgrade() -> None:
    """Drop the expiry index and the columns."""
    op.drop_index(_INDEX, "finding")
    with op.batch_alter_table("finding") as batch:
        for column in reversed(_COLUMNS):
            batch.drop_column(column.name)
