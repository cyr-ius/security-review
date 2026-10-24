"""Connectors: the findings sent to external systems by the controller (optional).

A connector creates the record of a finding in an external system: a ticket (Jira, ServiceNow),
an entry in a vulnerability register, a risk in a GRC tool...

Every connector is off until switched on in the web interface, unless the operator locks them
all (SECREVIEW_CONNECTORS_ENABLED=false, see connections.enabled). Outgoing
connections of the controller, never of the MCP server. Each system has its connector (see
api): Jira and ServiceNow are built in, and a third-party package adds others through an entry
point, loaded only when the operator allows it (SECREVIEW_CONNECTORS_PLUGINS, see registry).

- api: the public API a connector implements;
- registry: the available connectors;
- connections: the values of each connection (variables, web interface, secrets);
- transport: the HTTP client every connector goes through (HTTPS, proxy, no redirect, bounds);
- core: destinations of the projects, sending, automatic sending.
"""

from .api import ConnectorError
from .core import (
    AUTO_ACTOR,
    ExportDispatcher,
    delete_target,
    destinations,
    dispatch,
    list_targets,
    pending_findings,
    send_finding,
    set_target,
    test_connection,
    validate_settings,
)

__all__ = [
    "AUTO_ACTOR",
    "ExportDispatcher",
    "ConnectorError",
    "delete_target",
    "destinations",
    "dispatch",
    "list_targets",
    "pending_findings",
    "send_finding",
    "set_target",
    "test_connection",
    "validate_settings",
]
