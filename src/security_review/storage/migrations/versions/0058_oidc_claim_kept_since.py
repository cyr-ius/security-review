"""OIDC claim kept against the identity provider.

Adds ``kept_since`` to ``useroidcclaim``: set when a login kept a claim the identity provider no
longer sent, so as not to remove the last holder of ``users.manage``, and shown in the web
interface until the provider sends the claim again.

Revision ID: 0058
Revises: 0057
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0058"
down_revision: str | None = "0057"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "useroidcclaim"
_COLUMN = "kept_since"


def upgrade() -> None:
    """Add the column (kept when it exists)."""
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns(_TABLE)}
    if _COLUMN not in existing:
        with op.batch_alter_table(_TABLE) as batch:
            batch.add_column(sa.Column(_COLUMN, sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Drop the column."""
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_column(_COLUMN)
