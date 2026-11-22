"""Acknowledged findings.

An ``info`` finding is an observation, not a risk: a person marks it ``acknowledged`` (read)
instead of accepting it. PostgreSQL stores the status of a finding in the native enum type
``findingstatus``, which gets the new value; SQLite stores it as text and needs no change.

Revision ID: 0052
Revises: 0051
Create Date: 2026-11-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0052"
down_revision: str | None = "0051"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the value ``ACKNOWLEDGED`` to the status of the findings (kept when it exists)."""
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TYPE findingstatus ADD VALUE IF NOT EXISTS 'ACKNOWLEDGED'")


def downgrade() -> None:
    """Reopen the acknowledged findings.

    PostgreSQL cannot drop a value from an enum type: ``ACKNOWLEDGED`` stays in the type,
    unused.
    """
    finding = sa.table(
        "finding",
        sa.column("status", sa.String()),
        sa.column("status_reason", sa.String()),
        sa.column("status_approver", sa.String()),
    )
    op.execute(
        finding.update()
        .where(finding.c.status == "ACKNOWLEDGED")
        .values(status="OPEN", status_reason=None, status_approver=None)
    )
