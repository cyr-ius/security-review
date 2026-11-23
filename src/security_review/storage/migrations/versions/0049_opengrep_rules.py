"""OpenGrep rules stored in the database.

The OpenGrep rules were files of the Controller server (SECREVIEW_OPENGREP_RULES_DIR): lost with
an ephemeral volume, and shared between replicas only by a ReadWriteMany volume. The database
becomes their source; SECREVIEW_OPENGREP_RULES_DIR only holds the copy each process gives to
OpenGrep. The files of an existing directory are imported by the Controller server at its next
start (see opengrep_rule_store.seed_defaults), not here: the migration does not read the disk.

Revision ID: 0049
Revises: 0048
Create Date: 2026-11-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0049"
down_revision: str | None = "0048"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "opengreprule"


def upgrade() -> None:
    """Create the table of the OpenGrep rules (kept when it exists)."""
    if not sa.inspect(op.get_bind()).has_table(_TABLE):
        op.create_table(
            _TABLE,
            sa.Column("id", sa.String(length=80), nullable=False),
            sa.Column("content", sa.String(), nullable=False),
            sa.Column("digest", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade() -> None:
    """Drop the OpenGrep rules (and the seeds of the default ones, reinstalled as files)."""
    op.drop_table(_TABLE)
    op.execute(sa.text("DELETE FROM defaultseed WHERE kind = 'opengrep'"))
