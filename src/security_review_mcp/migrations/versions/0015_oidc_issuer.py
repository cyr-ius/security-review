"""Issuer of the OIDC account of a web user.

Adds ``webuser.oidc_issuer``: an OIDC account is identified by the issuer and the ``sub``
claim, so that another identity provider cannot reuse a subject. The users bound before this
revision get the issuer of their next login.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the issuer column (kept when it exists)."""
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("webuser")}
    if "oidc_issuer" not in columns:
        with op.batch_alter_table("webuser") as batch:
            batch.add_column(sa.Column("oidc_issuer", sa.String(500), nullable=True))


def downgrade() -> None:
    """Drop the issuer column."""
    with op.batch_alter_table("webuser") as batch:
        batch.drop_column("oidc_issuer")
