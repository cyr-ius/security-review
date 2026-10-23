# Ticketing: Jira and ServiceNow

The controller can turn a finding into a ticket in **Jira** (Cloud or Data Center) or in
**ServiceNow**: by hand, from a finding card, or automatically for the projects given a
severity threshold. Sending is **one way**: the key and the link of the ticket are kept on the
finding, and its status is never changed from the ticket (a person still decides it, see
[triage of findings](../usage/web-interface.md#triage-of-findings)).

Each system is a **connector**: Jira and ServiceNow are built in, and a third-party package
can add others (a GRC platform, an internal tracker): see
[third-party connectors](#third-party-connectors) and [writing a connector](#writing-a-connector).

Only the controller connects to these systems and loads the connectors; the MCP server never
does.

## Enabling

The **Connectors** screen (Administration, `settings.manage` permission) shows every available
connector as a card: its state, the number of projects that use it, a **switch** and a **gear**
that opens its settings (**Connection** and **Projects** tabs).

Every connector is **disabled by default**: nothing is sent through it until an administrator
switches it on. A connector can only be switched on once its connection is configured; switching
it off stops the sending by hand and the automatic sending at once. Each change is recorded in
the audit log (`ticketing.changed`, `{"enabled": true}`).

`SECREVIEW_TICKETING_ENABLED` is the lock of the operator:

| Value | Effect |
|---|---|
| unset (default) | The switches of the screen decide; every connector is off until switched on |
| `false` | Every connector is locked off: nothing is sent, the switches cannot be turned on, **Test the connection** is refused |
| `true` | A connector never switched in the screen is on (behaviour of the versions without switch); a switch turned off still applies |

```bash
SECREVIEW_TICKETING_INTERVAL_SECONDS=300   # period of the automatic sending
SECREVIEW_TICKETING_CAFILE=/etc/ssl/corp-ca.pem   # optional: internal certificate authority
```

## Connections

Each system has its connection, set by its variables or in the **Connection** tab of its gear in
the **Connectors** screen. A variable that is set takes precedence: its
field is only shown in the screen. Secrets are never shown again (`***`); sending `***` back
keeps the stored one. **Test the connection** checks the entered values with a read-only
request, without saving them, before the connector is switched on.

Every field of a connector has its variable, `SECREVIEW_<KIND>_<FIELD>`: those of the built-in
connectors are below. A secret is bound to the host of its URL: setting a URL for another host,
or a URL where there was none (after deleting it, for instance), requires entering the secrets
again in the same change. A secret set by a variable only goes to a URL set by a variable: the
screen refuses the URL (otherwise a stored token could be sent to another host).

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_JIRA_URL` | — | Jira address, `https://` only (`https://acme.atlassian.net`, or the base URL of a Data Center) |
| `SECREVIEW_JIRA_USERNAME` | — | Jira Cloud: e-mail address of the account, used with an API token. Empty: the token is a Data Center personal access token, sent as a bearer token |
| `SECREVIEW_JIRA_API_TOKEN` | — | API token (Cloud) or personal access token (Data Center) |
| `SECREVIEW_JIRA_ISSUE_TYPE` | `Bug` | Issue type of the tickets |
| `SECREVIEW_SERVICENOW_URL` | — | Address of the instance, `https://` only |
| `SECREVIEW_SERVICENOW_USERNAME` | — | Account (basic authentication) |
| `SECREVIEW_SERVICENOW_PASSWORD` | — | Its password |
| `SECREVIEW_SERVICENOW_TABLE` | `incident` | Table of the records |

The account only needs to create tickets: in Jira, the *Browse projects* and *Create issues*
permissions on the projects used; in ServiceNow, the right to create records in the table
(the `itil` role for `incident`).

## Destinations of the projects

A project needs a **destination** to send its findings to a system: the **Jira project key**
(`SEC`), or the **ServiceNow assignment group** (optional, its name). The destinations are set
in the **Projects** tab of the gear of the connector, in the **Connectors** screen.

Each destination may have an **automatic sending** threshold: every new **open** finding at
least that severe is then sent by the controller. The threshold only applies to the reports
saved **after** it was set: the findings already stored are only sent by hand.

## Sending a finding

A user who may triage the project (`findings.triage` permission) sees a **Send to Jira** /
**Send to ServiceNow** button on each finding card whose project has a destination. Once the
ticket exists, the card shows its key, linked to the ticket. A failure is shown on the card
with its reason (refused credentials, unknown project key...).

The automatic sending runs every `SECREVIEW_TICKETING_INTERVAL_SECONDS` (300 by default), at
most 20 findings per system and round, the most severe first. A failed finding is retried at
most 5 times, 15 minutes after the first failure, then with a doubled delay.

### One ticket per issue

A finding found again by a later report (same project, rule, file and title: the
[SARIF fingerprint](sarif.md)) reuses the ticket of the first occurrence: no new ticket is
created. Sending a finding that already has its ticket returns it.

## Content of a ticket

| | Jira | ServiceNow |
|---|---|---|
| Title | `[HIGH] shop-api: SQL injection` (`summary`) | same (`short_description`) |
| Description | project, severity, location, rule, CWE, OWASP, branch, commit, link to the report (with `SECREVIEW_WEB_URL`), then description, evidence and recommendation | same, as plain text |
| Other fields | labels `security-review` and `severity-<severity>` | `urgency` and `impact` from the severity, `assignment_group`, `correlation_id` (the fingerprint) |

ServiceNow urgency and impact: `critical` 1 / 1, `high` 1 / 2, `medium` 2 / 2, `low` and
`info` 3 / 3.

The texts of the report are masked again (secrets) before they leave. In Jira, they are put in
`{noformat}` blocks: written by an agent, they are never read as wiki markup (links, images
loaded from another site).

## Security

- Outgoing connections of the **controller** only, every connector disabled by default (switched
  on by an administrator, or locked off by `SECREVIEW_TICKETING_ENABLED=false`), over **HTTPS** with
  certificate verification (`SECREVIEW_TICKETING_CAFILE` for an internal authority), through the
  [outgoing proxy](../reference/configuration.md#outgoing-proxy).
- **Redirects are refused**: they would carry the credentials elsewhere. Timeout 15 seconds,
  answer bounded to 1 MiB.
- Secrets entered in the screen are stored in the database **in clear**, like the OIDC client
  secret: the API never returns them (`***`), the logs only name the changed settings, the audit
  event masks them. Prefer the variables (Kubernetes secret) if the database is not protected
  like a secret.
- A failure keeps a short code and a bounded excerpt of the error message of the system, masked
  and without the credentials.
- A secret is bound to the host of its URL: a new URL requires its secrets again, even after the
  URL was deleted, and a secret set by a variable needs its URL set by a variable, so that a
  stored token never reaches another host.
- A third-party connector is loaded only when `SECREVIEW_TICKETING_PLUGINS` names it, and
  runs with the rights of the controller: install only code you trust.
- Audit events: `ticketing.changed` (connection or switch), `ticketing.target_changed` (destination of a
  project), `finding.ticket_created` (ticket created or reused, with its key; actor `auto` for
  the automatic sending).

## Third-party connectors

A connector published by a Python package (entry point of the group
`security_review_mcp.ticketing`) is installed next to the controller, then **allowed** by its
entry point name: installing a package is not enough.

```bash
pip install secreview-acme-connector            # in the image or the environment of the controller
SECREVIEW_TICKETING_PLUGINS=acme                # comma separated
SECREVIEW_ACME_URL=https://risk.acme.example/api
SECREVIEW_ACME_API_KEY=...
```

The controller loads the allowed connectors at start and refuses to start if one is missing,
written for another version of the API, or declares a variable of the server itself
(`SECREVIEW_<KIND>_<FIELD>` must not be an existing setting). The **Connectors** screen shows it
as a card marked **Third-party**, off until switched on. A connector runs in the controller with its
rights: only install and allow code you trust, like any dependency.

## Writing a connector

A connector is a subclass of `TicketConnector` (module `security_review_mcp.ticketing.api`,
version `API_VERSION = 1`). The complete example
[`examples/ticketing-connector`](https://github.com/cyr-ius/security-review-mcp/tree/master/examples/ticketing-connector)
is a package to copy.

```python
from security_review_mcp.ticketing.api import (
    Connection,
    ConnectorField,
    CreatedTicket,
    TicketConnector,
    TicketContent,
    TicketingError,
)


class AcmeConnector(TicketConnector):
    kind = "acme"  # identifier: tickets, URLs, SECREVIEW_ACME_* variables
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

    def create_ticket(
        self, connection: Connection, destination: str, content: TicketContent
    ) -> CreatedTicket:
        answer = connection.http.request(
            "POST",
            f"/registers/{destination}/risks",
            json_body={"title": content.summary, "description": content.text()},
        )
        if not isinstance(answer.get("id"), str):
            raise TicketingError("invalid", "acme sent no risk id")
        return CreatedTicket(key=answer["id"], url=f"{connection.base_url}/risks/{answer['id']}")

    def test_connection(self, connection: Connection) -> None:
        connection.http.request("GET", "/me")
```

```toml
# pyproject.toml of the package
[project.entry-points."security_review_mcp.ticketing"]
acme = "acme_connector:AcmeConnector"
```

| Element | Role |
|---|---|
| `kind` | Lowercase letters, digits and `_` (2 to 20 characters); stored with the tickets |
| `fields` | `ConnectorField`: `name`, `label`, `secret`, `required`, `default`, `help`, `placeholder`, `pattern` (full match), `max_length`, `translations` (`{"fr": {"label": ..., "help": ...}}`) |
| `destination` | What an administrator chooses per project; override `check_destination` to normalize it |
| `auth_headers(values)` | Authentication headers, added by the controller to each request |
| `create_ticket(connection, destination, content)` | Creates the ticket and returns `CreatedTicket(key, url)` (`https://` link) |
| `test_connection(connection)` | Read-only request that needs valid credentials |

What the controller guarantees, whatever the connector:

- `connection.http.request(method, path, json_body=..., query=...)` is the only way out: `path`
  is relative to the configured URL (no other host), over HTTPS, through the outgoing proxy,
  **without following redirects**, 15 second timeout, JSON answer bounded to 1 MiB; a failure
  raises `TicketingError` (`auth`, `refused`, `unreachable`, `invalid`) without the secrets;
- `content` is already masked: `summary`, `facts`, `sections` (texts written by an agent:
  escape them if the system renders markup), `text()` (plain description), `fingerprint`,
  `report_url`;
- the claim (no duplicate ticket), the reuse of the ticket of an issue found again, the stored
  outcome, the audit and the retries of the automatic sending;
- any other exception of the connector becomes the `invalid` error, without its message (it
  could hold a value of the connection).

A connector must never open a connection by itself, log the values of its fields, nor change
anything but the ticket it creates.

## REST API

| Route | Permission | Role |
|---|---|---|
| `GET /api/v1/settings/ticketing` | `settings.manage` | Every connector with its fields and connection (secrets `***`) and its switch (`enabled`), allowed plugins, `SECREVIEW_TICKETING_ENABLED` (`enabled`: `null` when unset) |
| `GET /api/v1/ticketing/systems` | any | Available systems (`kind`, `name`) |
| `PUT /api/v1/settings/ticketing/{kind}` | `settings.manage` | Changes fields of a connection (`{"url": ..., "api_token": ...}`); `null` or `""` deletes the stored value; `404` for an unknown system |
| `PUT /api/v1/settings/ticketing/{kind}/enabled` | `settings.manage` | Switches a connector on or off (`{"enabled": true}`); `422` while its connection is not configured or when `SECREVIEW_TICKETING_ENABLED=false` |
| `POST /api/v1/settings/ticketing/{kind}/test` | `settings.manage` | Tests the stored values and those of the body, not saved, the connector switched on or not |
| `GET /api/v1/ticketing/targets` | `settings.manage` | Destinations of the projects |
| `PUT /api/v1/projects/{project}/ticket-targets/{kind}` | `settings.manage` | `{"destination": "SEC", "auto_min_severity": "high"}` (`null`: by hand only) |
| `DELETE /api/v1/projects/{project}/ticket-targets/{kind}` | `settings.manage` | Deletes a destination (the tickets are kept) |
| `GET /api/v1/ticketing/destinations` | any | Projects and systems the caller may send findings to now |
| `POST /api/v1/findings/{id}/tickets/{kind}` | `findings.triage` | Sends a finding: `201` with the ticket; `409` when the connector is switched off, or the connection or the destination is missing; `502` when the system refuses it |

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://secreview.example.com/api/v1/findings/42/tickets/jira
# {"kind": "jira", "state": "sent", "external_key": "SEC-12", "url": "https://acme.atlassian.net/browse/SEC-12", …}
```

The tickets of a finding are also in its `tickets` list, in the reports and lists of findings
(REST API and MCP tools).
