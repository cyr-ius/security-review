"""A project is requested by an authenticated user, who gets access to it once approved.

Adds to ``projectenrollment`` the web user who requested the project
(``requested_by_user_id``): the approval adds that user to the project group. The requests of
older versions have no user and stay as they are.

Revision ID: 0033
Revises: 0032
Create Date: 2026-10-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "projectenrollment"


def upgrade() -> None:
    """Add the column and its index (kept when they exist)."""
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns(_TABLE)}
    if "requested_by_user_id" in columns:
        return
    with op.batch_alter_table(_TABLE) as batch:
        batch.add_column(
            sa.Column(
                "requested_by_user_id",
                sa.Integer(),
                sa.ForeignKey("webuser.id", name="fk_projectenrollment_requested_by_user_id"),
                nullable=True,
            )
        )
        batch.create_index("ix_projectenrollment_requested_by_user_id", ["requested_by_user_id"])


def downgrade() -> None:
    """Drop the column: an older version approves a project without giving access to it."""
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_index("ix_projectenrollment_requested_by_user_id")
        batch.drop_column("requested_by_user_id")
