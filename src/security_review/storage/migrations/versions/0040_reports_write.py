"""``reports.write``: the tokens of a user save reports and propose a status only where it is
held, no longer wherever the user reads.

So that nothing changes at the upgrade, ``reports.write`` is added wherever ``reports.read`` is
held: on every project of a user (``webuser.all_projects_permissions``), on each project of a
user (``userproject.permissions``), and in the OIDC mappings (``oidcclaimmapping``, on every
project and on each of their projects). An administrator then removes it from the readers who
should not write. The api tokens of a role are left as they are: they save no report.

Downgrading removes ``reports.write`` everywhere.

Revision ID: 0040
Revises: 0039
Create Date: 2026-10-30
"""

import json
from collections.abc import Callable, Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0040"
down_revision: str | None = "0039"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_READ = "reports.read"
_WRITE = "reports.write"

_users = sa.table(
    "webuser", sa.column("id", sa.Integer), sa.column("all_projects_permissions", sa.String)
)
_user_projects = sa.table(
    "userproject", sa.column("id", sa.Integer), sa.column("permissions", sa.String)
)
_mappings = sa.table(
    "oidcclaimmapping",
    sa.column("id", sa.Integer),
    sa.column("all_projects_permissions", sa.String),
    sa.column("projects", sa.String),
)


def _added(permissions: list[str]) -> list[str]:
    """``reports.write`` added next to ``reports.read``."""
    return sorted({*permissions, _WRITE}) if _READ in permissions else permissions


def _removed(permissions: list[str]) -> list[str]:
    """``reports.write`` removed."""
    return [name for name in permissions if name != _WRITE]


def _rewrite(change: Callable[[list[str]], list[str]]) -> None:
    """Apply ``change`` to every stored list of per-project permissions."""
    bind = op.get_bind()
    for table, column in (
        (_users, "all_projects_permissions"),
        (_user_projects, "permissions"),
        (_mappings, "all_projects_permissions"),
    ):
        for row_id, value in bind.execute(sa.select(table.c.id, table.c[column])).all():
            held = json.loads(value or "[]")
            changed = change(held)
            if changed != held:
                bind.execute(
                    table.update().where(table.c.id == row_id).values({column: json.dumps(changed)})
                )
    for row_id, value in bind.execute(sa.select(_mappings.c.id, _mappings.c.projects)).all():
        projects = json.loads(value or "[]")
        changed = [item | {"permissions": change(item["permissions"])} for item in projects]
        if changed != projects:
            bind.execute(
                _mappings.update()
                .where(_mappings.c.id == row_id)
                .values(projects=json.dumps(changed))
            )


def upgrade() -> None:
    """Give ``reports.write`` wherever ``reports.read`` is held."""
    _rewrite(_added)


def downgrade() -> None:
    """Remove ``reports.write``."""
    _rewrite(_removed)
