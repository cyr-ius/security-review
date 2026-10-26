# Writing a connector

A third-party connector is a Python package that the controller loads to send the findings to
another system. This page is for its developers; to install and allow a connector, see
[Third-party connectors](../usage/connectors/third-party.md).

A connector is a subclass of `Connector` (module `security_review_mcp.connectors.api`, version
`API_VERSION = 2`). The complete example
[`examples/connector`](https://github.com/cyr-ius/security-review/tree/master/examples/connector)
is a package to copy: it turns each finding into a risk of an Acme register.

## Example

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

## Elements of a connector

| Element | Role |
|---|---|
| `kind` | Lowercase letters, digits and `_` (2 to 20 characters, not `connectors`); stored with the exports |
| `fields` | `ConnectorField`: `name`, `label`, `secret`, `required`, `default`, `help`, `placeholder`, `pattern` (full match), `max_length`, `translations` (`{"fr": {"label": ..., "help": ...}}`) |
| `destination` | What an administrator chooses per project; override `check_destination` to normalize it |
| `auth_headers(values)` | Authentication headers, added by the controller to each request |
| `export_finding(connection, destination, content)` | Creates the record of the finding and returns `ExportedFinding(key, url)` (`https://` link) |
| `test_connection(connection)` | Read-only request that needs valid credentials |

## Guarantees of the controller

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
