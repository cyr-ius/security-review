"""The enrollment requests a project, never a token.

A client without a token no longer receives a token waiting for approval: the enrollment
requests the project (``projectenrollment``, approved or rejected by an administrator) and the
developer creates a personal ``mcp`` token in the web interface. The tokens and project rows
still waiting for approval are deleted (they never authenticated anything), then the approval
columns are dropped: ``status``, ``requested_by`` and ``requested_from`` of ``apitoken`` and
``apitokenproject``.

Downgrading drops ``projectenrollment`` and adds the columns again; every remaining token and
project row is ``active``.

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = ("status", "requested_by", "requested_from")


def _columns(table: str) -> set[str]:
    """Names of the columns of ``table``."""
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


_ENROLLMENTS = "projectenrollment"


def _create_enrollments() -> None:
    """Create the table of the enrolled projects (kept when it exists)."""
    if sa.inspect(op.get_bind()).has_table(_ENROLLMENTS):
        return
    op.create_table(
        _ENROLLMENTS,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project", sa.String(200), nullable=False),
        sa.Column("requested_by", sa.String(200), nullable=True),
        sa.Column("requested_from", sa.String(64), nullable=True),
        sa.Column("requested_with", sa.String(200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(f"ix_{_ENROLLMENTS}_project", _ENROLLMENTS, ["project"], unique=True)
    op.create_index(f"ix_{_ENROLLMENTS}_created_at", _ENROLLMENTS, ["created_at"])


def upgrade() -> None:
    """Create the enrolled projects, delete the pending tokens and requests, then drop the
    approval columns."""
    _create_enrollments()
    connection = op.get_bind()
    if "status" in _columns("apitoken"):
        tokens = sa.table("apitoken", sa.column("id", sa.String), sa.column("status", sa.String))
        pending = sa.select(tokens.c.id).where(tokens.c.status == "pending")
        links = sa.table(
            "apitokenproject", sa.column("token_id", sa.String), sa.column("status", sa.String)
        )
        connection.execute(links.delete().where(links.c.token_id.in_(pending)))
        connection.execute(tokens.delete().where(tokens.c.status == "pending"))
        if "status" in _columns("apitokenproject"):
            connection.execute(links.delete().where(links.c.status == "pending"))
    inspector = sa.inspect(connection)
    for table in ("apitoken", "apitokenproject"):
        present = _columns(table)
        indexes = {index["name"] for index in inspector.get_indexes(table)}
        with op.batch_alter_table(table) as batch:
            if f"ix_{table}_status" in indexes:
                batch.drop_index(f"ix_{table}_status")
            for name in _COLUMNS:
                if name in present:
                    batch.drop_column(name)


def downgrade() -> None:
    """Drop the enrolled projects and add the approval columns again: every token and project
    row is active."""
    op.drop_index(f"ix_{_ENROLLMENTS}_created_at", table_name=_ENROLLMENTS)
    op.drop_index(f"ix_{_ENROLLMENTS}_project", table_name=_ENROLLMENTS)
    op.drop_table(_ENROLLMENTS)
    with op.batch_alter_table("apitoken") as batch:
        batch.add_column(sa.Column("status", sa.String(20), nullable=True))
        batch.add_column(sa.Column("requested_by", sa.String(200), nullable=True))
        batch.add_column(sa.Column("requested_from", sa.String(64), nullable=True))
    with op.batch_alter_table("apitokenproject") as batch:
        batch.add_column(
            sa.Column("status", sa.String(20), nullable=False, server_default="active")
        )
        batch.add_column(sa.Column("requested_by", sa.String(200), nullable=True))
        batch.add_column(sa.Column("requested_from", sa.String(64), nullable=True))
        batch.create_index("ix_apitokenproject_status", ["status"])
