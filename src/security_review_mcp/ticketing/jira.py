"""Built-in connector: Jira Cloud and Data Center (REST API v2).

Jira Cloud authenticates with the e-mail address of the account and an API token (basic
authentication); a Data Center personal access token is sent as a bearer token (empty account).
The description is Jira wiki markup: the texts of the report are put in ``{noformat}`` blocks,
so that a text written by an agent is never read as markup (links, images loaded from another
site).
"""

import base64
from collections.abc import Mapping
from urllib.parse import quote

from .api import (
    MAX_DESCRIPTION_CHARS,
    MAX_KEY_CHARS,
    Connection,
    ConnectorField,
    CreatedTicket,
    TicketConnector,
    TicketContent,
    TicketingError,
)

PROJECT_KEY = r"[A-Z][A-Z0-9_]{0,49}"


def wiki_description(content: TicketContent) -> str:
    """Description of a Jira issue: the facts, then each section in a ``{noformat}`` block."""
    lines = [f"{name}: {value}" for name, value in content.facts]
    for title, text in content.sections:
        lines += ["", f"*{title}*", "{noformat}", text.replace("{noformat}", "{ noformat}")]
        lines.append("{noformat}")
    lines += ["", f"Sent by security-review-mcp (finding {content.finding_id})."]
    description = "\n".join(lines)
    if len(description) > MAX_DESCRIPTION_CHARS:
        description = description[: MAX_DESCRIPTION_CHARS - 20] + "\n[truncated]"
        if description.count("{noformat}") % 2:
            description += "\n{noformat}"
    return description


class JiraConnector(TicketConnector):
    """Jira issues, one per finding, in the project chosen per security-review project."""

    kind = "jira"
    name = "Jira"
    url_help = "Jira Cloud or Data Center address, HTTPS only."
    url_placeholder = "https://acme.atlassian.net"
    url_translations = {
        "fr": {"help": "Adresse de Jira Cloud ou Data Center, en HTTPS uniquement."},
        "es": {"help": "Dirección de Jira Cloud o Data Center, solo HTTPS."},
    }
    fields = (
        ConnectorField(
            name="username",
            label="Account",
            help=(
                "Jira Cloud: e-mail address of the account. Empty: the token is a Data Center "
                "personal access token."
            ),
            placeholder="secreview@acme.example",
            translations={
                "fr": {
                    "label": "Compte",
                    "help": (
                        "Jira Cloud : adresse e-mail du compte. Vide : le jeton est un jeton "
                        "d'accès personnel Data Center."
                    ),
                },
                "es": {
                    "label": "Cuenta",
                    "help": (
                        "Jira Cloud: dirección de correo de la cuenta. Vacía: el token es un "
                        "token de acceso personal de Data Center."
                    ),
                },
            },
        ),
        ConnectorField(
            name="api_token",
            label="API token",
            secret=True,
            required=True,
            translations={"fr": {"label": "Jeton d'API"}, "es": {"label": "Token de API"}},
        ),
        ConnectorField(
            name="issue_type",
            label="Issue type",
            default="Bug",
            max_length=100,
            placeholder="Bug",
            translations={
                "fr": {"label": "Type de ticket"},
                "es": {"label": "Tipo de incidencia"},
            },
        ),
    )
    destination = ConnectorField(
        name="destination",
        label="Jira project key",
        required=True,
        placeholder="SEC",
        pattern=PROJECT_KEY,
        max_length=50,
        translations={
            "fr": {"label": "Clé du projet Jira"},
            "es": {"label": "Clave del proyecto Jira"},
        },
    )

    def check_destination(self, value: str) -> str:
        """Project keys are uppercase."""
        return super().check_destination(value.strip().upper())

    def auth_headers(self, values: Mapping[str, str]) -> dict[str, str]:
        """Basic authentication (Cloud), or bearer token (Data Center) without account."""
        token = values.get("api_token", "")
        if not values.get("username"):
            return {"Authorization": f"Bearer {token}"}
        raw = base64.b64encode(f"{values['username']}:{token}".encode()).decode("ascii")
        return {"Authorization": f"Basic {raw}"}

    def create_ticket(
        self, connection: Connection, destination: str, content: TicketContent
    ) -> CreatedTicket:
        """Create the issue; its key is checked before it is kept."""
        body = {
            "fields": {
                "project": {"key": destination},
                "issuetype": {"name": connection.values.get("issue_type") or "Bug"},
                "summary": content.summary,
                "description": wiki_description(content),
                "labels": ["security-review", f"severity-{content.severity}"],
            }
        }
        answer = connection.http.request("POST", "/rest/api/2/issue", json_body=body)
        key = answer.get("key")
        project, _, number = key.partition("-") if isinstance(key, str) else ("", "", "")
        if not (project == destination and number.isdigit()) or len(key) > MAX_KEY_CHARS:
            raise TicketingError("invalid", "jira sent no issue key")
        return CreatedTicket(key=key, url=f"{connection.base_url}/browse/{quote(key)}")

    def test_connection(self, connection: Connection) -> None:
        """Read the account of the credentials."""
        connection.http.request("GET", "/rest/api/2/myself")
