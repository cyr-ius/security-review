"""Fingerprint of the dependency findings: without their title (see sarif.issue_fingerprint).

A dependency review (written by an agent) and a dependency scan reported the same advisory
twice: the title and the file differed. The fingerprint of a dependency finding with a rule id
is now the advisory id alone, or the hygiene rule (DEP-*) and the name of the file.

The stored dependency findings get the new fingerprint, and so do their connector records
(``findingexport``). The current occurrences that now share a fingerprint are linked as in
save_report: those of the latest report stay current, the older ones point to its first finding
and pass it their comments, the date of the first occurrence is the earliest one. No status
changes.

Downgrading keeps the new fingerprints: an older version reports them again once.

Revision ID: 0041
Revises: 0040
Create Date: 2026-10-30
"""

import hashlib
from collections.abc import Sequence
from pathlib import PurePosixPath

import sqlalchemy as sa
from alembic import op

revision: str = "0041"
down_revision: str | None = "0040"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ADVISORY_PREFIXES = ("GHSA-", "PYSEC-", "CVE-", "OSV-", "RUSTSEC-", "GO-", "MAL-")

_findings = sa.table(
    "finding",
    sa.column("id", sa.Integer),
    sa.column("report_id", sa.Integer),
    sa.column("rule_id", sa.String),
    sa.column("category", sa.String),
    sa.column("file_path", sa.String),
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
_comments = sa.table(
    "findingcomment",
    sa.column("finding_id", sa.Integer),
)
_exports = sa.table(
    "findingexport",
    sa.column("finding_id", sa.Integer),
    sa.column("fingerprint", sa.String),
)


def _fingerprint(project: str, rule_id: str, file_path: str | None) -> str:
    """Copy of sarif.issue_fingerprint for a dependency finding with a rule id."""
    if rule_id.upper().startswith(_ADVISORY_PREFIXES):
        parts = [project, rule_id.upper()]
    else:
        parts = [project, rule_id, PurePosixPath((file_path or "").replace("\\", "/")).name]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]


def upgrade() -> None:
    """Fingerprint the dependency findings again and link the occurrences now merged."""
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(
            _findings.c.id,
            _findings.c.report_id,
            _findings.c.rule_id,
            _findings.c.file_path,
            _findings.c.superseded_by,
            _findings.c.first_seen_at,
            _reports.c.project,
        )
        .join(_reports, _reports.c.id == _findings.c.report_id)
        .where(
            sa.func.lower(sa.func.trim(_findings.c.category)) == "dependency",
            _findings.c.rule_id.is_not(None),
            _findings.c.rule_id != "",
        )
        .order_by(
            _reports.c.created_at,
            _reports.c.id,
            _findings.c.line_start.is_(None),
            _findings.c.line_start,
            _findings.c.id,
        )
    ).all()
    # fingerprint -> report id -> current findings (id, first seen), oldest report first
    current: dict[str, dict[int, list[tuple]]] = {}
    for fid, report_id, rule, path, superseded_by, first_seen, project in rows:
        digest = _fingerprint(project, rule, path)
        connection.execute(
            _findings.update().where(_findings.c.id == fid).values(fingerprint=digest)
        )
        connection.execute(
            _exports.update().where(_exports.c.finding_id == fid).values(fingerprint=digest)
        )
        if superseded_by is None:
            current.setdefault(digest, {}).setdefault(report_id, []).append((fid, first_seen))

    for by_report in current.values():
        if len(by_report) < 2:
            continue
        *older, latest = by_report.values()
        kept = latest[0][0]
        dates = [seen for findings in by_report.values() for _fid, seen in findings if seen]
        for findings in older:
            for fid, _seen in findings:
                connection.execute(
                    _findings.update()
                    .where(_findings.c.superseded_by == fid)
                    .values(superseded_by=kept)
                )
                connection.execute(
                    _findings.update().where(_findings.c.id == fid).values(superseded_by=kept)
                )
                connection.execute(
                    _comments.update().where(_comments.c.finding_id == fid).values(finding_id=kept)
                )
        if dates:
            connection.execute(
                _findings.update()
                .where(_findings.c.id.in_([fid for fid, _seen in latest]))
                .values(first_seen_at=min(dates))
            )


def downgrade() -> None:
    """Nothing to undo: the former fingerprints cannot be told apart from the new ones."""
