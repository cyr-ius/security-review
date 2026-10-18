"""Password change required at the next login.

Adds ``webuser.must_change_password``: set by a password chosen or generated for the user
(creation, reset, first administrator), cleared when the user changes it. Existing users are
not asked to change their password.

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the column (kept when it exists)."""
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("webuser")}
    if "must_change_password" not in columns:
        with op.batch_alter_table("webuser") as batch:
            batch.add_column(
                sa.Column(
                    "must_change_password",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.false(),
                )
            )


def downgrade() -> None:
    """Drop the column."""
    with op.batch_alter_table("webuser") as batch:
        batch.drop_column("must_change_password")
