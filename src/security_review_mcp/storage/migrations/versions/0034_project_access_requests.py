"""A user may request the access to a project that already exists.

``projectenrollment`` held at most one request per project; it now holds one request per
project and per user (``requested_by_user_id``), so that several users can ask to join the
same project. The existing requests stay as they are.

Revision ID: 0034
Revises: 0033
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0034"
down_revision: str | None = "0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "projectenrollment"
_INDEX = "ix_projectenrollment_project"
_UNIQUE = "uq_projectenrollment_project_user"


def upgrade() -> None:
    """Make the project index non-unique and add the unique (project, user) constraint (kept
    when it exists)."""
    inspector = sa.inspect(op.get_bind())
    if any(item["name"] == _UNIQUE for item in inspector.get_unique_constraints(_TABLE)):
        return
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_index(_INDEX)
        batch.create_index(_INDEX, ["project"])
        batch.create_unique_constraint(_UNIQUE, ["project", "requested_by_user_id"])


def downgrade() -> None:
    """Keep the oldest request of each project, then make the project unique again."""
    bind = op.get_bind()
    table = sa.table(_TABLE, sa.column("id", sa.Integer()), sa.column("project", sa.String()))
    oldest = sa.select(sa.func.min(table.c.id)).group_by(table.c.project)
    bind.execute(sa.delete(table).where(table.c.id.not_in(oldest)))
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_constraint(_UNIQUE, type_="unique")
        batch.drop_index(_INDEX)
        batch.create_index(_INDEX, ["project"], unique=True)
