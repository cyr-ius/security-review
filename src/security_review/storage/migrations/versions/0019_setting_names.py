"""Standard setting name: the stored setting ``oidc_scopes`` follows the renamed variable,
``oidc_scope`` (SECREVIEW_OIDC_SCOPE).

Data only: the schema does not change.

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

appsetting = sa.table("appsetting", sa.column("key", sa.String))

# Former key -> new key
RENAMED = {"oidc_scopes": "oidc_scope"}


def _rename(pairs: dict[str, str]) -> None:
    """Rename the stored keys; a row already stored under the new key is replaced."""
    connection = op.get_bind()
    for old, new in pairs.items():
        exists = connection.execute(
            sa.select(appsetting.c.key).where(appsetting.c.key == old)
        ).first()
        if exists is None:
            continue
        connection.execute(sa.delete(appsetting).where(appsetting.c.key == new))
        connection.execute(sa.update(appsetting).where(appsetting.c.key == old).values(key=new))


def upgrade() -> None:
    """Store the OIDC scope under the name of the new variable."""
    _rename(RENAMED)


def downgrade() -> None:
    """Store it under its former name again."""
    _rename({new: old for old, new in RENAMED.items()})
