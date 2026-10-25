# Third-party connectors

A Python package can add a connector for any other system: a vulnerability register, a GRC
platform, an internal tracker... It gets the same switch, connection, destinations and
guarantees as the built-in connectors (see [Connectors](index.md)).

## Installing a connector

A connector published by a Python package (entry point of the group
`security_review_mcp.connectors`) is installed next to the controller, then **allowed** by its
entry point name: installing a package is not enough.

```bash
uv pip install secreview-acme-connector         # in the image or the environment of the controller
SECREVIEW_CONNECTORS_PLUGINS=acme               # comma separated
SECREVIEW_ACME_URL=https://risk.acme.example/api
SECREVIEW_ACME_API_KEY=...
```

The controller loads the allowed connectors at start and refuses to start if one is missing,
written for another version of the API, or declares a variable of the server itself
(`SECREVIEW_<KIND>_<FIELD>` must not be an existing setting). The **Connectors** screen shows it
as a card marked **Third-party**, off until switched on. A connector runs in the controller with
its rights: only install and allow code you trust, like any dependency.

## Writing a connector

A connector is a subclass of `Connector` (module `security_review_mcp.connectors.api`, version
`API_VERSION = 2`). The complete example
[`examples/connector`](https://github.com/cyr-ius/security-review-mcp/tree/master/examples/connector)
is a package to copy: it turns each finding into a risk of an Acme register.

```python
from security_review_mcp.connectors.api import (
    Connection,
    Connector,
    ConnectorError,
    ConnectorField,
    ExportedFinding,
    FindingContent,
)


class AcmeConnector(Connector):
    kind = "acme"  # identifier: exports, URLs, SECREVIEW_ACME_* variables
    name = "Acme Risk"  # display name
    url_placeholder = "https://risk.acme.example/api"
    fields = (  # the URL field is added by the controller
        ConnectorField(
            name="api_key",
            label="API key",
            secret=True,
            required=True,
            translations={"fr": {"label": "Clé d'API"}},
        ),
    )
    destination = ConnectorField(
        name="destination", label="Risk register", required=True, pattern=r"[A-Z0-9_-]{1,40}"
    )

    def auth_headers(self, values):
        return {"X-Api-Key": values["api_key"]}

    def export_finding(
        self, connection: Connection, destination: str, content: FindingContent
    ) -> ExportedFinding:
        answer = connection.http.request(
            "POST",
            f"/registers/{destination}/risks",
            json_body={"title": content.summary, "description": content.text()},
        )
        if not isinstance(answer.get("id"), str):
            raise ConnectorError("invalid", "acme sent no risk id")
        return ExportedFinding(key=answer["id"], url=f"{connection.base_url}/risks/{answer['id']}")

    def test_connection(self, connection: Connection) -> None:
        connection.http.request("GET", "/me")
```

```toml
# pyproject.toml of the package
[project.entry-points."security_review_mcp.connectors"]
acme = "acme_connector:AcmeConnector"
```

| Element | Role |
|---|---|
| `kind` | Lowercase letters, digits and `_` (2 to 20 characters, not `connectors`); stored with the exports |
| `fields` | `ConnectorField`: `name`, `label`, `secret`, `required`, `default`, `help`, `placeholder`, `pattern` (full match), `max_length`, `translations` (`{"fr": {"label": ..., "help": ...}}`) |
| `destination` | What an administrator chooses per project; override `check_destination` to normalize it |
| `auth_headers(values)` | Authentication headers, added by the controller to each request |
| `export_finding(connection, destination, content)` | Creates the record of the finding and returns `ExportedFinding(key, url)` (`https://` link) |
| `test_connection(connection)` | Read-only request that needs valid credentials |

What the controller guarantees, whatever the connector:

- `connection.http.request(method, path, json_body=..., query=...)` is the only way out: `path`
  is relative to the configured URL (no other host), over HTTPS, through the outgoing proxy,
  **without following redirects**, 15 second timeout, JSON answer bounded to 1 MiB; a failure
  raises `ConnectorError` (`auth`, `refused`, `unreachable`, `invalid`) without the secrets;
- `content` is already masked: `summary`, `facts`, `sections` (texts written by an agent:
  escape them if the system renders markup), `text()` (plain description), `fingerprint`,
  `report_url`;
- the claim (no duplicate record), the reuse of the record of an issue found again, the stored
  outcome, the audit and the retries of the automatic sending;
- any other exception of the connector becomes the `invalid` error, without its message (it
  could hold a value of the connection).

A connector must never open a connection by itself, log the values of its fields, nor change
anything but the record it creates.
