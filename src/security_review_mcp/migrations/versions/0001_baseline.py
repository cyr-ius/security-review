"""Baseline: the schema of version 1.x.

Creates the tables on an empty database. A database created by version 1.x (before Alembic,
when the server created the tables at start) is completed instead: missing tables and nullable
columns are added, and the project of the tokens created before multi-project tokens is copied
into ``apitokenproject``.

The tables are frozen here on purpose: later revisions change the schema, never this file.

Revision ID: 0001
Revises:
Create Date: 2026-10-14
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

metadata = sa.MetaData()
SEVERITY = sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severity")
FINDING_STATUS = sa.Enum("OPEN", "FIXED", "ACCEPTED", "FALSE_POSITIVE", name="findingstatus")


def _string(length: int | None = None) -> sa.String:
    """VARCHAR as created by SQLModel (no length: unbounded)."""
    return sa.String(length)


def _timestamp() -> sa.DateTime:
    """Timezone-aware timestamp."""
    return sa.DateTime(timezone=True)


sa.Table(
    "advisory",
    metadata,
    sa.Column("id", _string(100), primary_key=True),
    sa.Column("summary", _string(), nullable=False),
    sa.Column("severity", _string(10), nullable=True),
    sa.Column("aliases", _string(), nullable=False),
    sa.Column("modified", _string(40), nullable=True),
    sa.Column("imported_at", _timestamp(), nullable=False, index=True),
)
sa.Table(
    "advisoryaffected",
    metadata,
    sa.Column("id", sa.Integer(), primary_key=True),
    sa.Column(
        "advisory_id", _string(100), sa.ForeignKey("advisory.id"), nullable=False, index=True
    ),
    sa.Column("ecosystem", _string(30), nullable=False, index=True),
    sa.Column("package", _string(300), nullable=False, index=True),
    sa.Column("ranges", _string(), nullable=False),
    sa.Column("versions", _string(), nullable=False),
    sa.Column("fixed", _string(), nullable=False),
)
apitoken = sa.Table(
    "apitoken",
    metadata,
    sa.Column("id", _string(64), primary_key=True),
    sa.Column("label", _string(64), nullable=False, unique=True, index=True),
    sa.Column("role", _string(20), nullable=False),
    sa.Column("project", _string(200), nullable=True, index=True),
    sa.Column("token_hash", _string(64), nullable=False, unique=True, index=True),
    sa.Column("created_at", _timestamp(), nullable=False),
    sa.Column("status", _string(20), nullable=True),
    sa.Column("requested_by", _string(200), nullable=True),
    sa.Column("requested_from", _string(64), nullable=True),
)
apitokenproject = sa.Table(
    "apitokenproject",
    metadata,
    sa.Column("id", _string(64), primary_key=True),
    sa.Column("token_id", _string(64), sa.ForeignKey("apitoken.id"), nullable=False, index=True),
    sa.Column("project", _string(200), nullable=False, index=True),
    sa.Column("status", _string(20), nullable=False, index=True),
    sa.Column("created_at", _timestamp(), nullable=False),
    sa.Column("requested_by", _string(200), nullable=True),
    sa.Column("requested_from", _string(64), nullable=True),
    sa.UniqueConstraint("token_id", "project"),
)
sa.Table(
    "customcheckitem",
    metadata,
    sa.Column("domain", _string(31), primary_key=True),
    sa.Column("id", _string(50), primary_key=True),
    sa.Column("title", _string(300), nullable=False),
    sa.Column("what_to_look_for", _string(), nullable=False),
    sa.Column("cwe", _string(20), nullable=False),
)
sa.Table(
    "customrule",
    metadata,
    sa.Column("id", _string(50), primary_key=True),
    sa.Column("title", _string(300), nullable=False),
    sa.Column("severity", _string(10), nullable=False),
    sa.Column("cwe", _string(20), nullable=False),
    sa.Column("languages", _string(), nullable=False),
    sa.Column("pattern", _string(500), nullable=False),
    sa.Column("advice", _string(), nullable=False),
    sa.Column("ignore_case", sa.Boolean(), nullable=False),
    sa.Column("created_at", _timestamp(), nullable=False),
    sa.Column("updated_at", _timestamp(), nullable=False),
)
sa.Table(
    "defaultseed",
    metadata,
    sa.Column("kind", _string(10), primary_key=True),
    sa.Column("key", _string(90), primary_key=True),
    sa.Column("digest", _string(64), nullable=False),
    sa.Column("seeded_at", _timestamp(), nullable=False),
)
sa.Table(
    "disabledrule",
    metadata,
    sa.Column("rule_id", _string(50), primary_key=True),
    sa.Column("disabled_at", _timestamp(), nullable=False),
)
sa.Table(
    "rulesetrevision",
    metadata,
    sa.Column("id", sa.Integer(), primary_key=True),
    sa.Column("revision", sa.Integer(), nullable=False),
)
sa.Table(
    "securityreport",
    metadata,
    sa.Column("project", _string(200), nullable=False, index=True),
    sa.Column("repository", _string(500), nullable=True),
    sa.Column("branch", _string(200), nullable=True),
    sa.Column("commit_sha", _string(64), nullable=True, index=True),
    sa.Column("reviewer", _string(200), nullable=True),
    sa.Column("scope", _string(), nullable=True),
    sa.Column("summary", _string(), nullable=False),
    sa.Column("id", sa.Integer(), primary_key=True),
    sa.Column("risk_level", SEVERITY, nullable=False, index=True),
    sa.Column("created_at", _timestamp(), nullable=False, index=True),
)
sa.Table(
    "finding",
    metadata,
    sa.Column("title", _string(200), nullable=False),
    sa.Column("severity", SEVERITY, nullable=False, index=True),
    sa.Column("rule_id", _string(60), nullable=True),
    sa.Column("category", _string(50), nullable=False),
    sa.Column("cwe", _string(20), nullable=True),
    sa.Column("owasp", _string(60), nullable=True),
    sa.Column("file_path", _string(500), nullable=True),
    sa.Column("line_start", sa.Integer(), nullable=True),
    sa.Column("line_end", sa.Integer(), nullable=True),
    sa.Column("description", _string(), nullable=False),
    sa.Column("evidence", _string(), nullable=True),
    sa.Column("recommendation", _string(), nullable=True),
    sa.Column("id", sa.Integer(), primary_key=True),
    sa.Column(
        "report_id", sa.Integer(), sa.ForeignKey("securityreport.id"), nullable=False, index=True
    ),
    sa.Column("status", FINDING_STATUS, nullable=False, index=True),
    sa.Column("status_changed_at", _timestamp(), nullable=True),
)


def _add_missing_columns(bind: sa.Connection) -> None:
    """Add the nullable columns that a 1.x database created by an older release lacks."""
    inspector = sa.inspect(bind)
    for table in metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {column["name"] for column in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            if not column.nullable:
                raise RuntimeError(
                    f"Cannot add required column {table.name}.{column.name} automatically; "
                    "migrate the database manually."
                )
            op.add_column(table.name, sa.Column(column.name, column.type, nullable=True))


def _move_legacy_project_tokens(bind: sa.Connection) -> None:
    """Copy the single project of the tokens created before multi-project tokens."""
    linked = sa.select(apitokenproject.c.token_id)
    rows = bind.execute(
        sa.select(apitoken).where(apitoken.c.project.is_not(None), apitoken.c.id.not_in(linked))
    ).all()
    for row in rows:
        bind.execute(
            apitokenproject.insert().values(
                id=str(uuid.uuid4()),
                token_id=row.id,
                project=row.project,
                status="pending" if row.status == "pending" else "active",
                created_at=row.created_at,
                requested_by=row.requested_by,
                requested_from=row.requested_from,
            )
        )


def upgrade() -> None:
    """Create the missing tables, complete a 1.x database and move its legacy tokens."""
    bind = op.get_bind()
    _add_missing_columns(bind)
    metadata.create_all(bind, checkfirst=True)
    _move_legacy_project_tokens(bind)


def downgrade() -> None:
    """Drop every table (the database is emptied)."""
    metadata.drop_all(op.get_bind())
