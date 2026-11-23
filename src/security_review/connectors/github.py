"""Built-in connector: GitHub issues (github.com or GitHub Enterprise Server, REST API).

The token (fine-grained personal access token with the *Issues: read and write* permission on
the repositories, or a classic token with ``repo``) is sent as a bearer token. The description is
Markdown in which every text of the report is a code span or a code block (see markdown): a
text written by an agent never mentions anyone nor loads an image. GitHub issues have no
confidential flag: whoever reads the repository reads them.
"""

from collections.abc import Mapping
from urllib.parse import urlsplit

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

REPOSITORY = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}"
API_VERSION_HEADER = "2022-11-28"
GITHUB_API = "api.github.com"
ENTERPRISE_API_PATH = "/api/v3"


def web_url(base_url: str) -> str | None:
    """Address of the web pages for the API at ``base_url``, or None when it is not known."""
    parts = urlsplit(base_url)
    if parts.netloc.lower() == GITHUB_API and parts.path in ("", "/"):
        return "https://github.com"
    if parts.path.rstrip("/").endswith(ENTERPRISE_API_PATH):
        return base_url.rstrip("/")[: -len(ENTERPRISE_API_PATH)]
    return None


class GitHubConnector(Connector):
    """GitHub issues, one per finding, in the repository chosen per security-review project."""

    kind = "github"
    name = "GitHub"
    url_help = (
        "Address of the GitHub API: https://api.github.com, or https://<host>/api/v3 for "
        "GitHub Enterprise Server. HTTPS only."
    )
    url_placeholder = "https://api.github.com"
    url_translations = {
        "fr": {
            "help": (
                "Adresse de l'API GitHub : https://api.github.com, ou https://<hôte>/api/v3 pour "
                "GitHub Enterprise Server. En HTTPS uniquement."
            )
        },
        "es": {
            "help": (
                "Dirección de la API de GitHub: https://api.github.com, o https://<host>/api/v3 "
                "para GitHub Enterprise Server. Solo HTTPS."
            )
        },
    }
    fields = (
        ConnectorField(
            name="token",
            label="Access token",
            secret=True,
            required=True,
            help=(
                "Fine-grained personal access token with the Issues: read and write permission "
                "on the repositories (or a classic token with the repo scope)."
            ),
            translations={
                "fr": {
                    "label": "Jeton d'accès",
                    "help": (
                        "Jeton d'accès personnel à granularité fine avec la permission Issues : "
                        "lecture et écriture sur les dépôts (ou jeton classique avec le scope "
                        "repo)."
                    ),
                },
                "es": {
                    "label": "Token de acceso",
                    "help": (
                        "Token de acceso personal de granularidad fina con el permiso Issues: "
                        "lectura y escritura en los repositorios (o token clásico con el scope "
                        "repo)."
                    ),
                },
            },
        ),
    )
    destination = ConnectorField(
        name="destination",
        label="GitHub repository",
        required=True,
        placeholder="acme/shop",
        pattern=REPOSITORY,
        max_length=140,
        translations={
            "fr": {"label": "Dépôt GitHub"},
            "es": {"label": "Repositorio de GitHub"},
        },
    )

    def check_destination(self, value: str) -> str:
        """``owner/repository``; ``.`` and ``..`` are not repositories."""
        text = super().check_destination(value.strip())
        if text.rpartition("/")[2] in (".", ".."):
            raise ValueError(f"invalid {self.destination.label}")
        return text

    def auth_headers(self, values: Mapping[str, str]) -> dict[str, str]:
        """Bearer token, with the version of the REST API."""
        return {
            "Authorization": f"Bearer {values.get('token', '')}",
            "X-GitHub-Api-Version": API_VERSION_HEADER,
        }

    def export_finding(
        self, connection: Connection, destination: str, content: FindingContent
    ) -> ExportedFinding:
        """Create the issue; its number is checked before it is kept."""
        body = {
            "title": content.summary,
            "body": markdown_description(content, limit=60_000),
            "labels": ["security-review", f"severity-{content.severity}"],
        }
        answer = connection.http.request("POST", f"/repos/{destination}/issues", json_body=body)
        number = answer.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise ConnectorError("invalid", "github sent no issue number")
        key = f"{destination}#{number}"
        web = web_url(connection.base_url)
        if web is not None:
            link = f"{web}/{destination}/issues/{number}"
        else:  # another API address: the link GitHub gave, once checked
            link = answer.get("html_url")
            if not isinstance(link, str) or not link.endswith(f"/issues/{number}"):
                raise ConnectorError("invalid", "github sent no issue link")
        return ExportedFinding(key=key[:MAX_KEY_CHARS], url=link)

    def test_connection(self, connection: Connection) -> None:
        """Read the rate limit of the token: refused when the token is not valid."""
        connection.http.request("GET", "/rate_limit")
