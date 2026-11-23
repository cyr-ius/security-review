"""API tokens: a personal token of a web user, or a token of a role.

Adds to ``apitoken`` the owner of a personal ``api`` token (``user_id``: the token holds the
current rights of that user) and the role of a role ``api`` token (``access_role_id``: the token
holds the permissions of that role, on its projects). Both stay empty for the other tokens.

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the two columns and their indexes (kept when they exist)."""
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("apitoken")}
    with op.batch_alter_table("apitoken") as batch:
        if "user_id" not in columns:
            batch.add_column(
                sa.Column(
                    "user_id",
                    sa.Integer(),
                    sa.ForeignKey("webuser.id", name="fk_apitoken_user_id"),
                    nullable=True,
                )
            )
            batch.create_index("ix_apitoken_user_id", ["user_id"])
        if "access_role_id" not in columns:
            batch.add_column(
                sa.Column(
                    "access_role_id",
                    sa.Integer(),
                    sa.ForeignKey("accessrole.id", name="fk_apitoken_access_role_id"),
                    nullable=True,
                )
            )
            batch.create_index("ix_apitoken_access_role_id", ["access_role_id"])


def downgrade() -> None:
    """Delete the api tokens, then drop the columns (an older version knows no api token)."""
    connection = op.get_bind()
    tokens = sa.table("apitoken", sa.column("id", sa.String), sa.column("role", sa.String))
    links = sa.table("apitokenproject", sa.column("token_id", sa.String))
    api = sa.select(tokens.c.id).where(tokens.c.role == "api")
    connection.execute(links.delete().where(links.c.token_id.in_(api)))
    connection.execute(tokens.delete().where(tokens.c.role == "api"))
    with op.batch_alter_table("apitoken") as batch:
        batch.drop_index("ix_apitoken_access_role_id")
        batch.drop_column("access_role_id")
        batch.drop_index("ix_apitoken_user_id")
        batch.drop_column("user_id")
