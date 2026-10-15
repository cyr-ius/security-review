"""General proxy: the proxy set in the web interface serves every outgoing connection.

The settings ``osv_proxy_mode`` and ``osv_proxy_url`` become ``proxy`` (a URL, or "" for a
direct connection); ``no_proxy`` is new. Data only: the schema does not change.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-15
"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

appsetting = sa.table(
    "appsetting",
    sa.column("key", sa.String),
    sa.column("value", sa.String),
    sa.column("updated_at", sa.DateTime(timezone=True)),
    sa.column("updated_by", sa.String),
)


def _read(connection: sa.Connection, *keys: str) -> dict[str, str]:
    """Return the stored values of these keys."""
    rows = connection.execute(
        sa.select(appsetting.c.key, appsetting.c.value).where(appsetting.c.key.in_(keys))
    )
    return {row.key: row.value for row in rows}


def _replace(connection: sa.Connection, old: tuple[str, ...], new: dict[str, str]) -> None:
    """Delete the ``old`` keys and store the ``new`` values."""
    connection.execute(sa.delete(appsetting).where(appsetting.c.key.in_(old + tuple(new))))
    for key, value in new.items():
        connection.execute(
            sa.insert(appsetting).values(
                key=key, value=value, updated_at=datetime.now(UTC), updated_by="migration"
            )
        )


def upgrade() -> None:
    """Turn the OSV proxy mode and URL into the general proxy setting."""
    connection = op.get_bind()
    stored = _read(connection, "osv_proxy_mode", "osv_proxy_url")
    mode = stored.get("osv_proxy_mode")
    new: dict[str, str] = {}
    if mode == "none":
        new["proxy"] = ""
    elif mode == "custom" and stored.get("osv_proxy_url"):
        new["proxy"] = stored["osv_proxy_url"]
    if stored:
        _replace(connection, ("osv_proxy_mode", "osv_proxy_url"), new)


def downgrade() -> None:
    """Turn the general proxy setting back into the OSV proxy mode and URL (no_proxy is lost)."""
    connection = op.get_bind()
    stored = _read(connection, "proxy", "no_proxy")
    proxy = stored.get("proxy")
    new: dict[str, str] = {}
    if proxy == "":
        new["osv_proxy_mode"] = "none"
    elif proxy:
        new = {"osv_proxy_mode": "custom", "osv_proxy_url": proxy}
    if stored:
        _replace(connection, ("proxy", "no_proxy"), new)
