"""Example connector: each finding becomes a risk in a (fictitious) Acme register.

Copy this package to write a connector for your own tool (a vulnerability register, a GRC
platform, an internal tracker): change the kind, the fields, the destination and the two requests.

Install it next to the controller, then allow it::

    pip install ./examples/connector
    SECREVIEW_CONNECTORS_PLUGINS=acme

Its connection is then set on the Connectors screen, or with the variables SECREVIEW_ACME_URL and
SECREVIEW_ACME_API_KEY.
"""

from collections.abc import Mapping

from security_review_mcp.connectors.api import (
    Connection,
    Connector,
    ConnectorError,
    ConnectorField,
    ExportedFinding,
    FindingContent,
)

# Acme ratings of each severity
RATINGS = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


class AcmeConnector(Connector):
    """Findings as risks of an Acme register, one register per security-review project."""

    kind = "acme"
    name = "Acme Risk"
    url_help = "Address of the Acme API, HTTPS only."
    url_placeholder = "https://risk.acme.example/api"
    fields = (
        ConnectorField(
            name="api_key",
            label="API key",
            secret=True,
            required=True,
            translations={"fr": {"label": "Clé d'API"}, "es": {"label": "Clave de API"}},
        ),
    )
    destination = ConnectorField(
        name="destination",
        label="Risk register",
        required=True,
        placeholder="APPSEC",
        pattern=r"[A-Z0-9_-]{1,40}",
        translations={"fr": {"label": "Registre des risques"}},
    )

    def auth_headers(self, values: Mapping[str, str]) -> dict[str, str]:
        """The API key goes in a header; the controller never logs it."""
        return {"X-Api-Key": values["api_key"]}

    def export_finding(
        self, connection: Connection, destination: str, content: FindingContent
    ) -> ExportedFinding:
        """Create the risk. ``content`` is already masked; plain text needs no escaping."""
        answer = connection.http.request(
            "POST",
            f"/registers/{destination}/risks",
            json_body={
                "title": content.summary,
                "description": content.text(),
                "rating": RATINGS.get(content.severity, 1),
                "external_id": content.fingerprint,
            },
        )
        risk_id = answer.get("id")
        if not isinstance(risk_id, str) or not risk_id.isalnum():
            raise ConnectorError("invalid", "acme sent no risk id")
        return ExportedFinding(key=risk_id, url=f"{connection.base_url}/risks/{risk_id}")

    def test_connection(self, connection: Connection) -> None:
        """A read-only request that needs valid credentials."""
        connection.http.request("GET", "/me")
