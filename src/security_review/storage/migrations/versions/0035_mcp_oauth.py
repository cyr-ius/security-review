"""OAuth login of the MCP clients: registered clients, pending authorizations and grants.

Creates ``oauthclient``, ``oauthauthorization`` and ``oauthgrant`` (see models). Nothing is
copied: the tables start empty.

Revision ID: 0035
Revises: 0034
Create Date: 2026-10-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0035"
down_revision: str | None = "0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the three tables (kept when they exist)."""
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("oauthclient"):
        op.create_table(
            "oauthclient",
            sa.Column("client_id", sa.String(64), primary_key=True),
            sa.Column("client_name", sa.String(200), nullable=True),
            sa.Column("client_metadata", sa.String(8000), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_oauthclient_created_at", "oauthclient", ["created_at"])
    if not inspector.has_table("oauthauthorization"):
        op.create_table(
            "oauthauthorization",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "client_id",
                sa.String(64),
                sa.ForeignKey("oauthclient.client_id"),
                nullable=False,
            ),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("webuser.id"), nullable=True),
            sa.Column("code_hash", sa.String(64), nullable=True),
            sa.Column("redirect_uri", sa.String(2000), nullable=False),
            sa.Column("redirect_uri_explicit", sa.Boolean(), nullable=False),
            sa.Column("code_challenge", sa.String(128), nullable=False),
            sa.Column("state", sa.String(500), nullable=True),
            sa.Column("resource", sa.String(500), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_oauthauthorization_client_id", "oauthauthorization", ["client_id"])
        op.create_index("ix_oauthauthorization_user_id", "oauthauthorization", ["user_id"])
        op.create_index(
            "ix_oauthauthorization_code_hash", "oauthauthorization", ["code_hash"], unique=True
        )
        op.create_index("ix_oauthauthorization_expires_at", "oauthauthorization", ["expires_at"])
    if not inspector.has_table("oauthgrant"):
        op.create_table(
            "oauthgrant",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "client_id",
                sa.String(64),
                sa.ForeignKey("oauthclient.client_id"),
                nullable=False,
            ),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("webuser.id"), nullable=False),
            sa.Column("access_token_hash", sa.String(64), nullable=False),
            sa.Column("access_expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("refresh_token_hash", sa.String(64), nullable=False),
            sa.Column("refresh_expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("previous_refresh_hash", sa.String(64), nullable=True),
            sa.Column("resource", sa.String(500), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_oauthgrant_client_id", "oauthgrant", ["client_id"])
        op.create_index("ix_oauthgrant_user_id", "oauthgrant", ["user_id"])
        op.create_index(
            "ix_oauthgrant_access_token_hash", "oauthgrant", ["access_token_hash"], unique=True
        )
        op.create_index(
            "ix_oauthgrant_refresh_token_hash", "oauthgrant", ["refresh_token_hash"], unique=True
        )
        op.create_index("ix_oauthgrant_refresh_expires_at", "oauthgrant", ["refresh_expires_at"])
        op.create_index(
            "ix_oauthgrant_previous_refresh_hash", "oauthgrant", ["previous_refresh_hash"]
        )


def downgrade() -> None:
    """Drop the three tables (every OAuth client must log in again)."""
    op.drop_table("oauthgrant")
    op.drop_table("oauthauthorization")
    op.drop_table("oauthclient")
