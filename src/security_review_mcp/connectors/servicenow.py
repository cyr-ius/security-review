"""Built-in connector: ServiceNow (Table API).

One record per finding in the configured table (``incident`` by default), with the urgency and
the impact of its severity, the assignment group chosen per project and the fingerprint of the
issue as ``correlation_id``. Basic authentication.
"""

import base64
import re
from collections.abc import Mapping
from urllib.parse import urlencode

from .api import (
    MAX_KEY_CHARS,
    Connection,
    Connector,
    ConnectorError,
    ConnectorField,
    ExportedFinding,
    FindingContent,
)

TABLE = r"[a-z][a-z0-9_]{0,79}"
# Urgency and impact (1 high, 3 low) of each severity
LEVELS = {
    "critical": ("1", "1"),
    "high": ("1", "2"),
    "medium": ("2", "2"),
    "low": ("3", "3"),
    "info": ("3", "3"),
}


class ServiceNowConnector(Connector):
    """ServiceNow records, one per finding, assigned to the group chosen per project."""

    kind = "servicenow"
    name = "ServiceNow"
    url_help = "Address of the ServiceNow instance, HTTPS only."
    url_placeholder = "https://acme.service-now.com"
    url_translations = {
        "fr": {"help": "Adresse de l'instance ServiceNow, en HTTPS uniquement."},
        "es": {"help": "Dirección de la instancia de ServiceNow, solo HTTPS."},
    }
    fields = (
        ConnectorField(
            name="username",
            label="Account",
            required=True,
            translations={"fr": {"label": "Compte"}, "es": {"label": "Cuenta"}},
        ),
        ConnectorField(
            name="password",
            label="Password",
            secret=True,
            required=True,
            translations={"fr": {"label": "Mot de passe"}, "es": {"label": "Contraseña"}},
        ),
        ConnectorField(
            name="table",
            label="Table",
            default="incident",
            help="Table of the records, for example incident.",
            placeholder="incident",
            pattern=TABLE,
            max_length=80,
            translations={
                "fr": {
                    "label": "Table",
                    "help": "Table des enregistrements, par exemple incident.",
                },
                "es": {"label": "Tabla", "help": "Tabla de los registros, por ejemplo incident."},
            },
        ),
    )
    destination = ConnectorField(
        name="destination",
        label="Assignment group (optional)",
        max_length=200,
        translations={
            "fr": {"label": "Groupe d'affectation (facultatif)"},
            "es": {"label": "Grupo de asignación (opcional)"},
        },
    )

    def auth_headers(self, values: Mapping[str, str]) -> dict[str, str]:
        """Basic authentication."""
        raw = f"{values.get('username', '')}:{values.get('password', '')}"
        return {"Authorization": f"Basic {base64.b64encode(raw.encode()).decode('ascii')}"}

    def export_finding(
        self, connection: Connection, destination: str, content: FindingContent
    ) -> ExportedFinding:
        """Create the record; its id is checked before it is kept."""
        table = connection.values.get("table") or "incident"
        urgency, impact = LEVELS.get(content.severity, ("3", "3"))
        body = {
            "short_description": content.summary,
            "description": content.text(),
            "urgency": urgency,
            "impact": impact,
            "correlation_id": content.fingerprint,
            "correlation_display": "security-review-mcp",
        }
        if destination:
            body["assignment_group"] = destination
        answer = connection.http.request(
            "POST",
            f"/api/now/table/{table}",
            json_body=body,
            query={"sysparm_input_display_value": "true", "sysparm_fields": "sys_id,number"},
        )
        result = answer.get("result")
        sys_id = result.get("sys_id") if isinstance(result, dict) else None
        number = result.get("number") if isinstance(result, dict) else None
        if not isinstance(sys_id, str) or not re.fullmatch(r"[0-9a-f]{32}", sys_id):
            raise ConnectorError("invalid", "servicenow sent no record id")
        key = number if isinstance(number, str) and number.isalnum() else sys_id
        link = (
            f"{connection.base_url}/nav_to.do?{urlencode({'uri': f'{table}.do?sys_id={sys_id}'})}"
        )
        return ExportedFinding(key=key[:MAX_KEY_CHARS], url=link)

    def test_connection(self, connection: Connection) -> None:
        """Read one record of the table."""
        table = connection.values.get("table") or "incident"
        connection.http.request(
            "GET",
            f"/api/now/table/{table}",
            query={"sysparm_limit": "1", "sysparm_fields": "sys_id"},
        )
