"""The reason of a risk acceptance is its first comment.

Since this revision, accepting a risk adds its reason to the comments of the finding. The
acceptances recorded before get that comment here (author: the approver, date: the decision),
unless the finding already has comments.

Downgrading keeps the comments: they cannot be told apart from those written by a person.

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-19
"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_findings = sa.table(
    "finding",
    sa.column("id", sa.Integer),
    sa.column("status", sa.String),
    sa.column("status_reason", sa.String),
    sa.column("status_approver", sa.String),
    sa.column("status_changed_at", sa.DateTime(timezone=True)),
)
_comments = sa.table(
    "findingcomment",
    sa.column("finding_id", sa.Integer),
    sa.column("author", sa.String),
    sa.column("body", sa.String),
    sa.column("created_at", sa.DateTime(timezone=True)),
)


def upgrade() -> None:
    """Add the reason of each accepted risk without comments as its first comment."""
    connection = op.get_bind()
    commented = sa.select(_comments.c.finding_id).where(_comments.c.finding_id == _findings.c.id)
    rows = connection.execute(
        sa.select(
            _findings.c.id,
            _findings.c.status_reason,
            _findings.c.status_approver,
            _findings.c.status_changed_at,
        ).where(
            _findings.c.status == "ACCEPTED",
            _findings.c.status_reason.is_not(None),
            ~sa.exists(commented),
        )
    ).all()
    now = datetime.now(UTC)
    for finding_id, reason, approver, decided_at in rows:
        connection.execute(
            _comments.insert().values(
                finding_id=finding_id,
                author=approver or "unknown",
                body=reason,
                created_at=decided_at or now,
            )
        )


def downgrade() -> None:
    """Nothing to undo: the comments are kept."""
