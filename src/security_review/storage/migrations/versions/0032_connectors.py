"""Ticketing renamed connectors: a connector may feed any external system, not only tickets.

Moves ``findingticket`` to ``findingexport`` and ``tickettarget`` to ``connectortarget`` (rows
copied, so that the indexes and constraints get the names of the new tables on every database),
and renames the connection settings stored in ``appsetting`` (``ticketing_<kind>_<field>`` to
``connector_<kind>_<field>``, ``ticketing:<kind>:enabled`` to ``connector:<kind>:enabled``).
The audit log is left as it was written.

Revision ID: 0032
Revises: 0031
Create Date: 2026-10-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_PREFIX = "ticketing"
_NEW_PREFIX = "connector"


def _export_columns() -> list[sa.Column]:
    """Columns of the export of a finding (see models.FindingExport)."""
    return [
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("finding.id"), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("project", sa.String(200), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("external_key", sa.String(100), nullable=True),
        sa.Column("url", sa.String(1000), nullable=True),
        sa.Column("error", sa.String(500), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("finding_id", "kind"),
    ]


def _target_columns() -> list[sa.Column]:
    """Columns of the destination of a project (see models.ConnectorTarget)."""
    return [
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("destination", sa.String(200), nullable=False),
        sa.Column("auto_min_severity", sa.String(10), nullable=True),
        sa.Column("auto_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(200), nullable=True),
        sa.UniqueConstraint("project", "kind"),
    ]


_EXPORT_INDEXES = ("finding_id", "project", "fingerprint", "state", "updated_at")


def _move(old: str, new: str, columns: list[sa.Column], indexes: Sequence[str]) -> None:
    """Create ``new``, copy the rows of ``old`` into it, then drop ``old`` (kept when ``new``
    already exists)."""
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table(new):
        return
    table = op.create_table(new, *columns)
    for column in indexes:
        op.create_index(f"ix_{new}_{column}", new, [column])
    if inspector.has_table(old):
        names = [column.name for column in table.columns]
        source = sa.table(old, *(sa.column(name) for name in names))
        op.execute(sa.insert(table).from_select(names, sa.select(*source.columns)))
        op.drop_table(old)


def _rename_settings(old: str, new: str) -> None:
    """Rename the stored connection settings whose key starts with ``old``."""
    setting = sa.table("appsetting", sa.column("key", sa.String))
    bind = op.get_bind()
    keys = bind.execute(
        sa.select(setting.c.key).where(
            setting.c.key.like(f"{old}\\_%", escape="\\") | setting.c.key.like(f"{old}:%")
        )
    ).scalars()
    for key in list(keys):
        bind.execute(
            sa.update(setting).where(setting.c.key == key).values(key=new + key[len(old) :])
        )


def upgrade() -> None:
    """Move the tables and the stored settings to their connector names."""
    _move("findingticket", "findingexport", _export_columns(), _EXPORT_INDEXES)
    _move("tickettarget", "connectortarget", _target_columns(), ("project",))
    _rename_settings(_OLD_PREFIX, _NEW_PREFIX)


def downgrade() -> None:
    """Move the tables and the stored settings back to their ticketing names."""
    _rename_settings(_NEW_PREFIX, _OLD_PREFIX)
    _move("connectortarget", "tickettarget", _target_columns(), ("project",))
    _move("findingexport", "findingticket", _export_columns(), _EXPORT_INDEXES)
