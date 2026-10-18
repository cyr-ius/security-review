"""OIDC web users: the OIDC users become web users; the user grants are moved into them.

The revokedssouser table holds the names of the deleted OIDC users, never created again by a
login.

Each user grant (reader access given by name to an OIDC user) becomes an OIDC web user with the
role ``reader`` on the same projects. A grant whose name is not a valid username, or that names
an existing local account, is dropped (and logged): an OIDC login never opens a local account.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-14
"""

import json
import logging
import re
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

logger = logging.getLogger("security_review_mcp.migrations")

# Same rule as web_users.clean_username at the time of this revision
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}")


def _move_user_grants(connection: sa.Connection) -> None:
    """Copy the user grants into OIDC web users, then drop their table."""
    if not sa.inspect(connection).has_table("oidcusergrant"):
        return
    grants = sa.table(
        "oidcusergrant",
        sa.column("username", sa.String),
        sa.column("projects", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("created_by", sa.String),
    )
    users = sa.table(
        "webuser",
        sa.column("username", sa.String),
        sa.column("auth_source", sa.String),
        sa.column("role", sa.String),
        sa.column("projects", sa.String),
        sa.column("sso_projects", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
        sa.column("session_version", sa.BigInteger),
        sa.column("created_by", sa.String),
    )
    taken = set(connection.execute(sa.select(users.c.username)).scalars())
    now = datetime.now(UTC)
    for grant in connection.execute(sa.select(grants)).mappings():
        name = grant["username"]
        if not USERNAME_PATTERN.fullmatch(name) or name in taken:
            logger.warning("User grant of %r dropped: not a valid or free username", name)
            continue
        taken.add(name)
        connection.execute(
            users.insert().values(
                username=name,
                auth_source="oidc",
                role="reader",
                projects=json.dumps(json.loads(grant["projects"])),
                sso_projects="[]",
                created_at=grant["created_at"] or now,
                updated_at=now,
                session_version=0,
                created_by=grant["created_by"],
            )
        )
    op.drop_table("oidcusergrant")


def upgrade() -> None:
    """Add the OIDC columns to webuser (those it lacks) and move the user grants into it."""
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("webuser")}
    added = {
        "auth_source": sa.Column(
            "auth_source", sa.String(20), nullable=False, server_default="local"
        ),
        "oidc_subject": sa.Column("oidc_subject", sa.String(255), nullable=True),
        "sso_role": sa.Column("sso_role", sa.String(20), nullable=True),
        "sso_projects": sa.Column("sso_projects", sa.String(), nullable=False, server_default="[]"),
    }
    missing = [column for name, column in added.items() if name not in existing]
    with op.batch_alter_table("webuser") as batch:
        for column in missing:
            batch.add_column(column)
        # Dropped by revision 0013: missing from a database created from newer models
        if "role" in existing:
            batch.alter_column("role", existing_type=sa.String(20), nullable=True)
        batch.alter_column("password_hash", existing_type=sa.String(255), nullable=True)
        batch.alter_column(
            "password_changed_at", existing_type=sa.DateTime(timezone=True), nullable=True
        )
    defaults = [column.name for column in missing if column.server_default is not None]
    if defaults:
        with op.batch_alter_table("webuser") as batch:
            # The defaults only filled the existing rows: the models set the values
            for name in defaults:
                batch.alter_column(name, existing_type=added[name].type, server_default=None)
    _move_user_grants(op.get_bind())
    if not sa.inspect(op.get_bind()).has_table("revokedssouser"):
        op.create_table(
            "revokedssouser",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("username", sa.String(64), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_by", sa.String(64), nullable=True),
        )
        op.create_index("ix_revokedssouser_username", "revokedssouser", ["username"], unique=True)


def downgrade() -> None:
    """Drop the OIDC web users, their columns and revocations; recreate (empty) oidcusergrant."""
    op.drop_table("revokedssouser")
    op.execute(sa.text("DELETE FROM webuser WHERE auth_source <> 'local'"))
    with op.batch_alter_table("webuser") as batch:
        batch.alter_column(
            "password_changed_at", existing_type=sa.DateTime(timezone=True), nullable=False
        )
        batch.alter_column("password_hash", existing_type=sa.String(255), nullable=False)
        batch.alter_column("role", existing_type=sa.String(20), nullable=False)
        batch.drop_column("sso_projects")
        batch.drop_column("sso_role")
        batch.drop_column("oidc_subject")
        batch.drop_column("auth_source")
    op.create_table(
        "oidcusergrant",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(200), nullable=False),
        sa.Column("projects", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=True),
    )
    op.create_index("ix_oidcusergrant_username", "oidcusergrant", ["username"], unique=True)
