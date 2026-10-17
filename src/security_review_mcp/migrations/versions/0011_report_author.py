"""Author of a report: the developer declared by the client and the token that saved it.

Adds ``securityreport.author`` (indexed, the developer username given with the report: one
enrolled device may serve several people) and ``securityreport.submitted_by`` (label of the
bearer token that saved it). Both stay empty for the existing reports.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    sa.Column("author", sa.String(200), nullable=True),
    sa.Column("submitted_by", sa.String(200), nullable=True),
)
_INDEX = "ix_securityreport_author"


def upgrade() -> None:
    """Add the columns and the author index (kept when they exist)."""
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("securityreport")}
    missing = [column for column in _COLUMNS if column.name not in existing]
    if missing:
        with op.batch_alter_table("securityreport") as batch:
            for column in missing:
                batch.add_column(column)
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("securityreport")}
    if _INDEX not in indexes:
        op.create_index(_INDEX, "securityreport", ["author"])


def downgrade() -> None:
    """Drop the author index and the columns."""
    op.drop_index(_INDEX, "securityreport")
    with op.batch_alter_table("securityreport") as batch:
        for column in reversed(_COLUMNS):
            batch.drop_column(column.name)
