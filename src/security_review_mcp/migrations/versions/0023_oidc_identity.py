"""OIDC users identified by their issuer and subject.

Adds the unique index ``ix_webuser_oidc_identity`` on ``webuser.oidc_issuer`` and
``webuser.oidc_subject``: the login opens the user bound to them, so no two users may share
them. Before, a name changed at the identity provider created a second user bound to the same
identity. Of such users, the one that logged in last keeps the identity; the others keep their
name, groups and history but are unbound to a subject that never matches (``""``, no issuer):
they can no longer log in, and an administrator deletes them.

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEX = "ix_webuser_oidc_identity"

_users = sa.table(
    "webuser",
    sa.column("id", sa.Integer()),
    sa.column("oidc_issuer", sa.String(500)),
    sa.column("oidc_subject", sa.String(255)),
    sa.column("last_login_at", sa.DateTime()),
)


def _unbind_duplicates(connection: sa.Connection) -> None:
    """Keep each bound identity on the user that logged in last; unbind the others."""
    rows = connection.execute(
        sa.select(_users.c.id, _users.c.oidc_issuer, _users.c.oidc_subject, _users.c.last_login_at)
        .where(_users.c.oidc_issuer.is_not(None), _users.c.oidc_subject.is_not(None))
        .order_by(_users.c.id)
    ).all()
    kept: dict[tuple[str, str], tuple[bool, object, int]] = {}
    for row in rows:
        key = (row.oidc_issuer, row.oidc_subject)
        # Never logged in ranks first; equal dates (or none) fall back to the id
        rank = (row.last_login_at is not None, row.last_login_at, row.id)
        if key in kept:
            older = min(kept[key], rank)
            kept[key] = max(kept[key], rank)
            connection.execute(
                sa.update(_users)
                .where(_users.c.id == older[2])
                .values(oidc_subject="", oidc_issuer=None)
            )
        else:
            kept[key] = rank


def upgrade() -> None:
    """Unbind the duplicate identities, then add the unique index (kept when it exists)."""
    connection = op.get_bind()
    indexes = {index["name"] for index in sa.inspect(connection).get_indexes("webuser")}
    if INDEX not in indexes:
        _unbind_duplicates(connection)
        op.create_index(INDEX, "webuser", ["oidc_issuer", "oidc_subject"], unique=True)


def downgrade() -> None:
    """Drop the index (the unbound users stay unbound)."""
    op.drop_index(INDEX, table_name="webuser")
