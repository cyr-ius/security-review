"""Schemas of the audit log."""

from typing import Any

from pydantic import BaseModel

# ── Audit log ────────────────────────────────────────────────────────────────


class AuditEvent(BaseModel):
    """One entry of the audit log (details never hold a secret)."""

    id: int
    created_at: str
    action: str
    # user:NAME, token:LABEL, cli, anonymous or stdio
    actor: str
    target_type: str
    target_id: str | None
    project: str | None
    details: dict[str, Any]


class AuditPage(BaseModel):
    """One page of the audit log (``total`` counts every matching event)."""

    total: int
    events: list[AuditEvent]
