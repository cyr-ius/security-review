"""Public API of the ticketing connectors: what a connector (built-in or third party) implements.

A connector is a subclass of :class:`TicketConnector`. A third-party package publishes it under
the entry point group ``security_review_mcp.ticketing``::

    # pyproject.toml of the package
    [project.entry-points."security_review_mcp.ticketing"]
    acme = "acme_tickets:AcmeConnector"

The controller loads it only when the operator lists its entry point name in
``SECREVIEW_TICKETING_PLUGINS`` (``acme``); the MCP server never loads a connector.

What the connector does:

- it declares its ``kind`` (identifier stored with the tickets, in URLs and variables), its
  display ``name``, the ``fields`` of its connection and its ``destination`` field (what an
  administrator chooses per project);
- it gives the authentication headers of its connection (``auth_headers``);
- it creates a ticket from a :class:`TicketContent` (``create_ticket``) and checks a connection
  with a read-only request (``test_connection``).

What the controller does for it, so that every connector keeps the same guarantees:

- the ``url`` field (HTTPS only, without credentials) is added to every connector; the values of
  the fields come from the variables ``SECREVIEW_<KIND>_<FIELD>`` or from the web interface,
  checked against their declaration, the secrets never shown again;
- requests only go through :attr:`Connection.http`: to the configured URL only, HTTPS, through the
  outgoing proxy, without following redirects, with a timeout and a bounded JSON answer; the
  errors never hold a secret;
- the content of the finding is masked (secrets) before the connector receives it, the ticket is
  claimed before the request (no duplicate across replicas) and an earlier ticket of the same
  issue is reused;
- the outcome is stored, audited and retried by the automatic sending.

A connector must never open a connection by itself, log the values of its fields, nor change
anything but the ticket it creates: a ticket never changes the status of a finding.

The contract is versioned by API_VERSION: a connector built for another version is refused.
"""

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol

API_VERSION = 1
ENTRY_POINT_GROUP = "security_review_mcp.ticketing"

KIND_PATTERN = re.compile(r"[a-z][a-z0-9_]{1,19}")
FIELD_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,17}")
# Name of the field every connector gets from the controller
URL_FIELD = "url"
MAX_FIELD_CHARS = 500
MAX_NAME_CHARS = 40
MAX_KEY_CHARS = 100
MAX_TICKET_URL_CHARS = 1000
# Longest description of a ticket built by TicketContent.text (Jira refuses 32 767 characters)
MAX_DESCRIPTION_CHARS = 30_000


class TicketingError(Exception):
    """A ticket could not be created or a connection used.

    ``code`` is returned to the user, the message shown to whoever may send findings: it must
    not hold a secret. Codes raised by a connector: ``auth`` (credentials refused), ``refused``
    (request refused), ``unreachable``, ``invalid`` (unexpected answer). The controller also uses
    ``disabled``, ``not_configured``, ``no_target``, ``in_progress`` and ``superseded``.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ConnectorField:
    """A setting of a connection (or the destination of a project), as shown in the web
    interface.

    ``label``, ``help`` and ``placeholder`` are in English; ``translations`` gives them in other
    languages of the interface: ``{"fr": {"label": "...", "help": "..."}}``. A ``secret`` is
    never shown again nor logged. ``pattern`` is a regular expression the value must match
    entirely (keep it simple: it is matched against administrator input).
    """

    name: str
    label: str
    secret: bool = False
    required: bool = False
    default: str = ""
    help: str = ""
    placeholder: str = ""
    pattern: str | None = None
    max_length: int = MAX_FIELD_CHARS
    translations: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

    def check(self, value: str) -> str:
        """Return the value to store, or raise ValueError (the message names the field)."""
        text = value if self.secret else value.strip()
        if len(text) > min(self.max_length, MAX_FIELD_CHARS):
            raise ValueError(f"{self.label} too long (max {self.max_length} chars)")
        if not text.isprintable():
            raise ValueError(f"{self.label} must not contain control characters")
        if text and self.pattern and not re.fullmatch(self.pattern, text):
            raise ValueError(f"invalid {self.label}")
        return text


@dataclass(frozen=True)
class TicketContent:
    """What a ticket says about a finding. Every text is already masked (secrets).

    ``facts`` are short (name, value) pairs (project, severity, location...); ``sections`` are
    the free texts of the report, (title, text), written by an agent: a connector that renders
    markup must escape them (see the Jira connector). ``fingerprint`` identifies the issue
    across the reports of the project (to correlate in the remote system).
    """

    finding_id: int
    project: str
    severity: str
    title: str
    summary: str
    facts: tuple[tuple[str, str], ...]
    sections: tuple[tuple[str, str], ...]
    fingerprint: str
    report_url: str | None = None

    def text(self, limit: int = MAX_DESCRIPTION_CHARS) -> str:
        """Plain text description: the facts, then the sections, bounded to ``limit``."""
        lines = [f"{name}: {value}" for name, value in self.facts]
        for title, text in self.sections:
            lines += ["", f"{title}:", text]
        lines += ["", f"Sent by security-review-mcp (finding {self.finding_id})."]
        description = "\n".join(lines)
        if len(description) > limit:
            description = description[: limit - 20] + "\n[truncated]"
        return description


@dataclass(frozen=True)
class CreatedTicket:
    """A ticket created by a connector: its key (SEC-12, INC0010001) and its https:// link."""

    key: str
    url: str


class HttpClient(Protocol):
    """HTTP client of a connection, provided by the controller.

    ``path`` is relative to the configured URL (``/rest/api/2/issue``): no other host can be
    reached. The authentication headers of the connector are added. The answer is the decoded
    JSON object; any failure raises TicketingError (``auth``, ``refused``, ``unreachable``,
    ``invalid``), without secret.
    """

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        query: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a request to the system and return its JSON answer (an object)."""
        ...


@dataclass(frozen=True)
class Connection:
    """A configured connection: its URL (without final slash), the values of the fields of the
    connector (secrets included, defaults applied) and its HTTP client."""

    base_url: str
    values: Mapping[str, str]
    http: HttpClient


class TicketConnector(ABC):
    """A ticketing system. Subclass it, set the class attributes and implement the methods.

    The controller creates one instance per process: keep no state between calls.
    """

    #: Version of this API the connector is written for
    api_version: ClassVar[int] = API_VERSION
    #: Identifier: lowercase letters, digits and ``_`` (``jira``); variables SECREVIEW_<KIND>_*
    kind: ClassVar[str]
    #: Display name (``Jira``)
    name: ClassVar[str]
    #: Fields of the connection, the URL excepted (added by the controller)
    fields: ClassVar[tuple[ConnectorField, ...]] = ()
    #: What an administrator chooses per project (``name`` is ignored)
    destination: ClassVar[ConnectorField]
    #: Help and example of the URL field
    url_help: ClassVar[str] = ""
    url_placeholder: ClassVar[str] = ""
    url_translations: ClassVar[Mapping[str, Mapping[str, str]]] = {}

    def check_destination(self, value: str) -> str:
        """Return the destination to store, or raise ValueError. Override it to normalize."""
        text = self.destination.check(value)
        if self.destination.required and not text:
            raise ValueError(f"{self.destination.label} is required")
        return text

    @abstractmethod
    def auth_headers(self, values: Mapping[str, str]) -> dict[str, str]:
        """HTTP headers that authenticate a request (``Authorization``...)."""

    @abstractmethod
    def create_ticket(
        self, connection: Connection, destination: str, content: TicketContent
    ) -> CreatedTicket:
        """Create the ticket of a finding at ``destination`` and return it.

        Raises:
            TicketingError: If the system refuses it or answers unexpectedly.
        """

    @abstractmethod
    def test_connection(self, connection: Connection) -> None:
        """Check the URL and the credentials with a read-only request.

        Raises:
            TicketingError: If the connection cannot be used.
        """


__all__ = [
    "API_VERSION",
    "ENTRY_POINT_GROUP",
    "Connection",
    "ConnectorField",
    "CreatedTicket",
    "HttpClient",
    "TicketConnector",
    "TicketContent",
    "TicketingError",
]
