"""Schemas of the connectors."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from ...connectors import api as connectors_api
from ...storage.models import (
    Severity,
)

# ── Connectors (see connectors) ──────────────────────────────────────────────

# Body of PUT /settings/connectors/{kind}: field name to value (null or "" deletes the stored
# value)
ConnectorValues = Annotated[
    dict[
        Annotated[str, StringConstraints(max_length=18)],
        Annotated[str | None, StringConstraints(max_length=connectors_api.MAX_FIELD_CHARS)],
    ],
    Field(max_length=30),
]


class ConnectorFieldInfo(BaseModel):
    """A field declared by a connector: label, help and example in English, ``translations``
    by language (``{"fr": {"label": ..., "help": ...}}``)."""

    name: str
    label: str
    help: str
    placeholder: str
    secret: bool
    required: bool
    translations: dict[str, dict[str, str]]


class ConnectorFieldState(ConnectorFieldInfo):
    """A field of a connection: its variable, stored value, variable value, whether the variable
    is set (it then takes precedence), effective value. Secrets are ``***`` when set."""

    variable: str
    value: str | None
    env: str | None
    env_set: bool
    effective: str | None


class ConnectorInfo(BaseModel):
    """A connector: its connection and what a project chooses (``destination``)."""

    kind: str
    name: str
    builtin: bool
    configured: bool
    # Switched on: findings may be sent (see connectors.connections.enabled)
    enabled: bool
    fields: list[ConnectorFieldState]
    destination: ConnectorFieldInfo


class ConnectorSettings(BaseModel):
    """Connectors: SECREVIEW_CONNECTORS_ENABLED (``false``: every connector locked off), the
    allowed third-party connectors (SECREVIEW_CONNECTORS_PLUGINS) and every available connector."""

    enabled: bool
    interval_seconds: int
    cafile: str | None
    plugins: list[str]
    connectors: list[ConnectorInfo]


class ConnectorSwitch(BaseModel):
    """Body of PUT /settings/connectors/{kind}/enabled."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool


class ConnectorTestResult(BaseModel):
    """Outcome of a connection test: ``error`` is a short code (auth, refused, unreachable...)
    and ``message`` its detail, without secret."""

    ok: bool
    error: str | None = None
    message: str | None = None


class ConnectorTargetUpdate(BaseModel):
    """Body of PUT /projects/{project}/connector-targets/{kind}.

    ``destination`` is what the system asks for (Jira project key, ServiceNow assignment
    group...). ``auto_min_severity`` sends automatically the new open findings at least that
    severe; ``null``: only by hand.
    """

    model_config = ConfigDict(extra="forbid")

    destination: str = Field(default="", max_length=connectors_api.MAX_FIELD_CHARS)
    auto_min_severity: Severity | None = None


class ConnectorTarget(BaseModel):
    """Where the findings of a project go through one connector."""

    project: str
    kind: str
    destination: str
    auto_min_severity: Severity | None
    auto_since: datetime | None
    updated_at: datetime
    updated_by: str | None


class ConnectorDestination(BaseModel):
    """A project and a connector its findings can be sent to now."""

    project: str
    kind: str


class ConnectorSystem(BaseModel):
    """A connector: kind and display name."""

    kind: str
    name: str
