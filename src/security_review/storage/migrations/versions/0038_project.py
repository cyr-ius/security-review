"""The known projects get their own table, ``project``.

A project was known through its reports, the projects of its tokens and those named by the roles
of the groups. Each of these names becomes a row of ``project``; the ``projectautojoinblock``
table becomes its ``autojoin_blocked`` column (a blocked project is known even without any other
reference).

Downgrading gives the blocked projects back to ``projectautojoinblock`` and drops ``project``:
the projects are known again through their references.

Revision ID: 0038
Revises: 0037
Create Date: 2026-10-29
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0038"
down_revision: str | None = "0037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "project"
_BLOCKS = "projectautojoinblock"
_ACTOR = "migration"

_projects = sa.table(
    _TABLE,
    sa.column("name", sa.String),
    sa.column("autojoin_blocked", sa.Boolean),
    sa.column("created_at", sa.DateTime),
    sa.column("created_by", sa.String),
)
_blocks = sa.table(
    _BLOCKS,
    sa.column("project", sa.String),
    sa.column("blocked_by", sa.String),
    sa.column("created_at", sa.DateTime),
)


def _names(connection: sa.Connection) -> set[str]:
    """Every project name referred to by a report, a token or a role of a group."""
    names: set[str] = set()
    for query in (
        "SELECT DISTINCT project FROM securityreport",
        "SELECT DISTINCT project FROM apitokenproject",
        "SELECT DISTINCT project FROM apitoken WHERE project IS NOT NULL",
    ):
        names.update(row[0] for row in connection.execute(sa.text(query)))
    if sa.inspect(connection).has_table("grouprole"):
        for (projects,) in connection.execute(
            sa.text("SELECT projects FROM grouprole WHERE projects != '[]'")
        ):
            names.update(json.loads(projects))
    return {name for name in names if name}


def upgrade() -> None:
    """Create ``project``, fill it, and drop ``projectautojoinblock`` (each step skipped when
    already done)."""
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    has_blocks = inspector.has_table(_BLOCKS)
    if inspector.has_table(_TABLE):
        if has_blocks:
            op.drop_table(_BLOCKS)
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("autojoin_blocked", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(200), nullable=True),
    )
    op.create_index("ix_project_name", _TABLE, ["name"], unique=True)
    blocked = (
        {row[0] for row in connection.execute(sa.select(_blocks.c.project))}
        if has_blocks
        else set()
    )
    now = datetime.now(UTC)
    rows = [
        {"name": name, "autojoin_blocked": name in blocked, "created_at": now, "created_by": _ACTOR}
        for name in sorted(_names(connection) | blocked)
    ]
    if rows:
        op.bulk_insert(_projects, rows)  # type: ignore[arg-type]
    if has_blocks:
        op.drop_table(_BLOCKS)


def downgrade() -> None:
    """Give the blocked projects back to ``projectautojoinblock`` and drop ``project``."""
    connection = op.get_bind()
    op.create_table(
        _BLOCKS,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project", sa.String(200), nullable=False),
        sa.Column("blocked_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_projectautojoinblock_project", _BLOCKS, ["project"], unique=True)
    now = datetime.now(UTC)
    rows = [
        {"project": row[0], "blocked_by": _ACTOR, "created_at": now}
        for row in connection.execute(
            sa.select(_projects.c.name).where(_projects.c.autojoin_blocked.is_(True))
        )
    ]
    if rows:
        op.bulk_insert(_blocks, rows)  # type: ignore[arg-type]
    op.drop_table(_TABLE)
