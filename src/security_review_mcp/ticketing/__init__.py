"""Tickets of the findings in ticketing systems, created by the controller (optional).

Disabled by default (SECREVIEW_TICKETING_ENABLED): outgoing connections of the controller, never
of the MCP server. The systems are **connectors** (see api): Jira and ServiceNow are built in,
and a third-party package adds others through an entry point, loaded only when the operator
allows it (SECREVIEW_TICKETING_PLUGINS, see registry).

- api: the public API a connector implements;
- registry: the available connectors;
- connections: the values of each connection (variables, web interface, secrets);
- transport: the HTTP client every connector goes through (HTTPS, proxy, no redirect, bounds);
- core: destinations of the projects, sending, automatic sending.
"""

from .api import TicketingError
from .core import (
    AUTO_ACTOR,
    TicketDispatcher,
    delete_target,
    destinations,
    dispatch,
    forget_project,
    list_targets,
    pending_findings,
    send_finding,
    set_target,
    test_connection,
    validate_settings,
)

__all__ = [
    "AUTO_ACTOR",
    "TicketDispatcher",
    "TicketingError",
    "delete_target",
    "destinations",
    "dispatch",
    "forget_project",
    "list_targets",
    "pending_findings",
    "send_finding",
    "set_target",
    "test_connection",
    "validate_settings",
]
