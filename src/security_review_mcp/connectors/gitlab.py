"""Built-in connector: GitLab issues (gitlab.com or self-managed, REST API v4).

The token (personal, group or project access token with the ``api`` scope) is sent in the
``PRIVATE-TOKEN`` header. The destination is the numeric ID of the project, shown on its page:
its path would have to be sent encoded (``group%2Fproject``), which the HTTP client of the
connectors refuses. The description is Markdown in which every text of the report is a code span
or a code block (see markdown): a text written by an agent never mentions anyone, loads an image
nor runs a quick action (``/close``). The issues are confidential unless the connection says
otherwise.
"""

from collections.abc import Mapping

from .api import (
    MAX_KEY_CHARS,
    Connection,
    Connector,
    ConnectorError,
    ConnectorField,
    ExportedFinding,
    FindingContent,
)
from .markdown import markdown_description

PROJECT_ID = r"[1-9][0-9]{0,19}"


class GitLabConnector(Connector):
    """GitLab issues, one per finding, in the project chosen per security-review project."""

    kind = "gitlab"
    name = "GitLab"
    url_help = "Address of gitlab.com or of a self-managed GitLab, HTTPS only."
    url_placeholder = "https://gitlab.com"
    url_translations = {
        "fr": {"help": "Adresse de gitlab.com ou d'un GitLab autogéré, en HTTPS uniquement."},
        "es": {"help": "Dirección de gitlab.com o de un GitLab autogestionado, solo HTTPS."},
    }
    fields = (
        ConnectorField(
            name="token",
            label="Access token",
            secret=True,
            required=True,
            help="Personal, group or project access token with the api scope.",
            translations={
                "fr": {
                    "label": "Jeton d'accès",
                    "help": "Jeton d'accès personnel, de groupe ou de projet avec le scope api.",
                },
                "es": {
                    "label": "Token de acceso",
                    "help": "Token de acceso personal, de grupo o de proyecto con el scope api.",
                },
            },
        ),
        ConnectorField(
            name="confidential",
            label="Confidential issues",
            default="true",
            pattern="true|false",
            max_length=5,
            placeholder="true",
            help="true (default): only the members of the project who may see them read them.",
            translations={
                "fr": {
                    "label": "Tickets confidentiels",
                    "help": (
                        "true (par défaut) : seuls les membres du projet autorisés les lisent."
                    ),
                },
                "es": {
                    "label": "Incidencias confidenciales",
                    "help": (
                        "true (por defecto): solo las leen los miembros del proyecto autorizados."
                    ),
                },
            },
        ),
    )
    destination = ConnectorField(
        name="destination",
        label="GitLab project ID",
        required=True,
        placeholder="42",
        pattern=PROJECT_ID,
        max_length=20,
        translations={
            "fr": {"label": "ID du projet GitLab"},
            "es": {"label": "ID del proyecto de GitLab"},
        },
    )

    def auth_headers(self, values: Mapping[str, str]) -> dict[str, str]:
        """Access token in the PRIVATE-TOKEN header."""
        return {"PRIVATE-TOKEN": values.get("token", "")}

    def export_finding(
        self, connection: Connection, destination: str, content: FindingContent
    ) -> ExportedFinding:
        """Create the issue; its number and link are checked before they are kept."""
        body = {
            "title": content.summary,
            "description": markdown_description(content),
            "labels": f"security-review,severity-{content.severity}",
            "confidential": connection.values.get("confidential", "true") != "false",
        }
        answer = connection.http.request(
            "POST", f"/api/v4/projects/{destination}/issues", json_body=body
        )
        iid = answer.get("iid")
        if not isinstance(iid, int) or isinstance(iid, bool) or iid <= 0:
            raise ConnectorError("invalid", "gitlab sent no issue number")
        link = answer.get("web_url")
        if (
            not isinstance(link, str)
            or not link.startswith(f"{connection.base_url}/")
            or not link.endswith(f"/-/issues/{iid}")
        ):
            raise ConnectorError("invalid", "gitlab sent no issue link")
        references = answer.get("references")
        full = references.get("full") if isinstance(references, dict) else None
        key = full if isinstance(full, str) and full.endswith(f"#{iid}") else f"{destination}#{iid}"
        return ExportedFinding(key=key[:MAX_KEY_CHARS], url=link)

    def test_connection(self, connection: Connection) -> None:
        """Read the user of the token."""
        connection.http.request("GET", "/api/v4/user")
