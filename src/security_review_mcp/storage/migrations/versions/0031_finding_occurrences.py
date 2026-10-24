"""Occurrences of one issue across the reports of a project.

Adds to ``finding`` its ``fingerprint`` (project, rule, file and title, see sarif.fingerprint),
``superseded_by`` (the occurrence of a later report that replaces it) and ``first_seen_at``
(the date of the first occurrence, kept until the issue is fixed).

The findings stored before get them here: in each group of findings with the same
fingerprint, the findings of the latest report stay current and the older ones point to the
first finding of that report. No status changes: a decision taken on an older occurrence is
not carried to the current one.

Revision ID: 0031
Revises: 0030
Create Date: 2026-10-24
"""

import hashlib
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    sa.Column("fingerprint", sa.String(64), nullable=True),
    sa.Column("superseded_by", sa.Integer(), nullable=True),
    sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
)
_INDEXES = ("fingerprint", "superseded_by")

_findings = sa.table(
    "finding",
    sa.column("id", sa.Integer),
    sa.column("report_id", sa.Integer),
    sa.column("status", sa.String),
    sa.column("rule_id", sa.String),
    sa.column("cwe", sa.String),
    sa.column("category", sa.String),
    sa.column("file_path", sa.String),
    sa.column("title", sa.String),
    sa.column("line_start", sa.Integer),
    sa.column("fingerprint", sa.String),
    sa.column("superseded_by", sa.Integer),
    sa.column("first_seen_at", sa.DateTime(timezone=True)),
)
_reports = sa.table(
    "securityreport",
    sa.column("id", sa.Integer),
    sa.column("project", sa.String),
    sa.column("created_at", sa.DateTime(timezone=True)),
)


def _fingerprint(project: str, rule_id, cwe, category, file_path, title: str) -> str:
    """Copy of sarif.fingerprint at this revision (a migration never imports the code)."""
    rule = rule_id or cwe or f"secreview/{category}"
    raw = "|".join([project, rule, file_path or "", title.strip().lower()])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _backfill() -> None:
    """Fingerprint the stored findings and link the occurrences of each issue."""
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(
            _findings.c.id,
            _findings.c.report_id,
            _findings.c.status,
            _findings.c.rule_id,
            _findings.c.cwe,
            _findings.c.category,
            _findings.c.file_path,
            _findings.c.title,
            _reports.c.project,
            _reports.c.created_at,
        )
        .join(_reports, _reports.c.id == _findings.c.report_id)
        .order_by(
            _reports.c.created_at,
            _reports.c.id,
            _findings.c.line_start.is_(None),
            _findings.c.line_start,
            _findings.c.id,
        )
    ).all()
    # fingerprint -> report id -> findings (id, status, report date), oldest report first
    groups: dict[str, dict[int, list[tuple]]] = {}
    for fid, report_id, status, rule, cwe, category, path, title, project, created in rows:
        digest = _fingerprint(project, rule, cwe, category, path, title)
        groups.setdefault(digest, {}).setdefault(report_id, []).append((fid, status, created))

    for digest, by_report in groups.items():
        occurrences = list(by_report.values())
        current = occurrences[-1][0][0]
        first_seen = None
        previous_fixed = True
        for findings in occurrences:
            if previous_fixed:
                first_seen = findings[0][2]
            for fid, _status, _created in findings:
                connection.execute(
                    _findings.update()
                    .where(_findings.c.id == fid)
                    .values(
                        fingerprint=digest,
                        superseded_by=None if findings is occurrences[-1] else current,
                        first_seen_at=first_seen,
                    )
                )
            previous_fixed = all(status == "FIXED" for _fid, status, _created in findings)


def upgrade() -> None:
    """Add the occurrence columns (kept when they exist) and fill them."""
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("finding")}
    missing = [column for column in _COLUMNS if column.name not in existing]
    if missing:
        with op.batch_alter_table("finding") as batch:
            for column in missing:
                batch.add_column(column)
    indexes = {index["name"] for index in inspector.get_indexes("finding")}
    for name in _INDEXES:
        if f"ix_finding_{name}" not in indexes:
            op.create_index(f"ix_finding_{name}", "finding", [name])
    if missing:
        _backfill()


def downgrade() -> None:
    """Drop the occurrence columns."""
    for name in _INDEXES:
        op.drop_index(f"ix_finding_{name}", table_name="finding")
    with op.batch_alter_table("finding") as batch:
        for column in reversed(_COLUMNS):
            batch.drop_column(column.name)
