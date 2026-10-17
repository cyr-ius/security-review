"""Audit log, expiry and rotation of the bearer tokens.

Creates the ``auditevent`` table and adds to ``apitoken`` its expiry date and the previous
secret of a rotation (kept during a grace period). Existing tokens get no expiry date.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TOKEN_COLUMNS = (
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("previous_token_hash", sa.String(64), nullable=True),
    sa.Column("previous_expires_at", sa.DateTime(timezone=True), nullable=True),
)
_TOKEN_INDEXES = {
    "ix_apitoken_expires_at": "expires_at",
    "ix_apitoken_previous_token_hash": "previous_token_hash",
}
_AUDIT_INDEXES = {
    "ix_auditevent_created_at": "created_at",
    "ix_auditevent_action": "action",
    "ix_auditevent_actor": "actor",
    "ix_auditevent_project": "project",
}


def upgrade() -> None:
    """Add the token columns and indexes, create the audit table (kept when they exist)."""
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("apitoken")}
    missing = [column for column in _TOKEN_COLUMNS if column.name not in existing]
    if missing:
        with op.batch_alter_table("apitoken") as batch:
            for column in missing:
                batch.add_column(column)
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("apitoken")}
    for name, column in _TOKEN_INDEXES.items():
        if name not in indexes:
            op.create_index(name, "apitoken", [column])
    if sa.inspect(op.get_bind()).has_table("auditevent"):
        return
    op.create_table(
        "auditevent",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("target_type", sa.String(30), nullable=False),
        sa.Column("target_id", sa.String(200), nullable=True),
        sa.Column("project", sa.String(200), nullable=True),
        sa.Column("details", sa.String(), nullable=False),
    )
    for name, column in _AUDIT_INDEXES.items():
        op.create_index(name, "auditevent", [column])


def downgrade() -> None:
    """Drop the audit table, the token indexes and columns."""
    op.drop_table("auditevent")
    for name in _TOKEN_INDEXES:
        op.drop_index(name, "apitoken")
    with op.batch_alter_table("apitoken") as batch:
        for column in reversed(_TOKEN_COLUMNS):
            batch.drop_column(column.name)
