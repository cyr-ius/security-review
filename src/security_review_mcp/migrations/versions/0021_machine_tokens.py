"""Tokens are for machines; ``triager`` becomes an ordinary role.

- The ``reader`` and ``triager`` tokens are revoked (deleted with their project rows, each
  revocation written to the audit log with the actor ``migration``): a person reaches the web
  API through a session, whose rights come from its groups. The ``mcp``, ``ci``, ``metrics`` and
  ``admin`` tokens are kept.
- The ``triager`` role is no longer built in: an administrator may change or delete it. It is
  created (read and triage) when missing, so that every database starts with it.

Downgrading makes ``triager`` built in again (with its permissions); the revoked tokens are not
restored.

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-18
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REMOVED_TOKEN_ROLES = ("reader", "triager")
_TRIAGER = "triager"
_TRIAGER_PERMISSIONS = json.dumps(["findings.triage", "reports.read"])

_tokens = sa.table(
    "apitoken",
    sa.column("id", sa.String),
    sa.column("label", sa.String),
    sa.column("role", sa.String),
    sa.column("project", sa.String),
)
_token_projects = sa.table(
    "apitokenproject",
    sa.column("token_id", sa.String),
    sa.column("project", sa.String),
    sa.column("status", sa.String),
)
_roles = sa.table(
    "accessrole",
    sa.column("id", sa.Integer),
    sa.column("name", sa.String),
    sa.column("description", sa.String),
    sa.column("permissions", sa.String),
    sa.column("system", sa.Boolean),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("updated_at", sa.DateTime(timezone=True)),
    sa.column("created_by", sa.String),
)
_audit = sa.table(
    "auditevent",
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("action", sa.String),
    sa.column("actor", sa.String),
    sa.column("target_type", sa.String),
    sa.column("target_id", sa.String),
    sa.column("project", sa.String),
    sa.column("details", sa.String),
)


def _revoke_person_tokens(connection: sa.Connection, now: datetime) -> None:
    """Delete the ``reader`` and ``triager`` tokens and audit each revocation."""
    rows = connection.execute(
        sa.select(_tokens.c.id, _tokens.c.label, _tokens.c.role, _tokens.c.project).where(
            _tokens.c.role.in_(_REMOVED_TOKEN_ROLES)
        )
    ).all()
    for token_id, label, role, project in rows:
        projects = (
            connection.execute(
                sa.select(_token_projects.c.project).where(
                    _token_projects.c.token_id == token_id, _token_projects.c.status == "active"
                )
            )
            .scalars()
            .all()
        )
        connection.execute(_token_projects.delete().where(_token_projects.c.token_id == token_id))
        connection.execute(_tokens.delete().where(_tokens.c.id == token_id))
        details = {
            "label": label,
            "role": role,
            "projects": projects or ([project] if project else None),
            "reason": "tokens are for machines: use a web user and its groups",
        }
        connection.execute(
            _audit.insert().values(
                created_at=now,
                action="token.revoked",
                actor="migration",
                target_type="token",
                target_id=token_id,
                project=project,
                details=json.dumps(details),
            )
        )


def upgrade() -> None:
    """Revoke the person tokens, then make ``triager`` an ordinary role (created if missing)."""
    connection = op.get_bind()
    now = datetime.now(UTC)
    _revoke_person_tokens(connection, now)
    triager = connection.execute(
        sa.select(_roles.c.id).where(_roles.c.name == _TRIAGER)
    ).scalar_one_or_none()
    if triager is None:
        connection.execute(
            _roles.insert().values(
                name=_TRIAGER,
                description="",
                permissions=_TRIAGER_PERMISSIONS,
                system=False,
                created_at=now,
                updated_at=now,
                created_by="migration",
            )
        )
    else:
        # The permissions of a built-in role came from the code: store them in the row
        connection.execute(
            _roles.update()
            .where(_roles.c.id == triager, _roles.c.system.is_(True))
            .values(permissions=_TRIAGER_PERMISSIONS, system=False, updated_at=now)
        )


def downgrade() -> None:
    """Make ``triager`` built in again (the revoked tokens are not restored)."""
    connection = op.get_bind()
    connection.execute(
        _roles.update()
        .where(_roles.c.name == _TRIAGER)
        .values(permissions=_TRIAGER_PERMISSIONS, system=True, updated_at=datetime.now(UTC))
    )
