"""Review type of a report: the prompt or the CLI command that produced it.

Adds ``securityreport.review_type`` (indexed text, empty for the existing reports) and fills it
for the reports saved by the CLI scans, recognized by their reviewer.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Reviewer written by the CLI scans -> review type
_CLI_REVIEWERS = {
    "security-review-controller code scan": "code-scan",
    "security-review-controller deps scan": "dependency-scan",
}

securityreport = sa.table(
    "securityreport", sa.column("reviewer", sa.String), sa.column("review_type", sa.String)
)


def upgrade() -> None:
    """Add the review_type column and its index (kept when they exist), fill the CLI scans."""
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("securityreport")}
    if "review_type" not in columns:
        with op.batch_alter_table("securityreport") as batch:
            batch.add_column(sa.Column("review_type", sa.String(40), nullable=True))
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("securityreport")}
    if "ix_securityreport_review_type" not in indexes:
        op.create_index("ix_securityreport_review_type", "securityreport", ["review_type"])
    for reviewer, review_type in _CLI_REVIEWERS.items():
        op.execute(
            sa.update(securityreport)
            .where(securityreport.c.reviewer == reviewer, securityreport.c.review_type.is_(None))
            .values(review_type=review_type)
        )


def downgrade() -> None:
    """Drop the review_type column and its index."""
    op.drop_index("ix_securityreport_review_type", "securityreport")
    with op.batch_alter_table("securityreport") as batch:
        batch.drop_column("review_type")
