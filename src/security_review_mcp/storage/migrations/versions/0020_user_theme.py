"""Theme of the web interface remembered per user.

Adds ``webuser.theme``: ``light``, ``dark`` or ``auto`` (the system preference, the default).

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the column (kept when it exists)."""
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("webuser")}
    if "theme" not in columns:
        with op.batch_alter_table("webuser") as batch:
            batch.add_column(
                sa.Column(
                    "theme",
                    sa.String(10),
                    nullable=False,
                    server_default="auto",
                )
            )


def downgrade() -> None:
    """Drop the column."""
    with op.batch_alter_table("webuser") as batch:
        batch.drop_column("theme")
