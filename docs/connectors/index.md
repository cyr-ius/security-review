# Connectors

A **connector** sends the findings of security-review-mcp to another tool of your teams: a
ticket in **Jira** or **ServiceNow**, an entry in a vulnerability register, a risk in a GRC
platform, an item in an internal tracker... Whatever the connector creates in that system is
the **record** of the finding.

| Connector | Record | Page |
|---|---|---|
| Jira (Cloud or Data Center) | Issue | [Jira](jira.md) |
| ServiceNow | Incident (or a record of another table) | [ServiceNow](servicenow.md) |
| Third party | Whatever the package creates (vulnerability, risk, item...) | [Third-party connectors](third-party.md) |

A finding is sent by hand, from its card, or automatically for the projects given a severity
threshold. Sending is **one way**: the key and the link of the record are kept on the finding,
and its status is never changed from the record (a person still decides it, see
[triage of findings](../usage/web-interface.md#triage-of-findings)).

Only the controller connects to these systems and loads the connectors; the MCP server never
does.

## Enabling

The **Connectors** screen (Administration, `settings.manage` permission) shows every available
connector as a card: its state, the number of projects that use it, a **switch** and a **gear**
that opens its settings (**Connection** and **Projects** tabs).

Every connector is **disabled by default**: nothing is sent through it until an administrator
switches it on. A connector can only be switched on once its connection is configured; switching
it off stops the sending by hand and the automatic sending at once. Each change is recorded in
the audit log (`connector.changed`, `{"enabled": true}`).

`SECREVIEW_CONNECTORS_ENABLED` is the lock of the operator:

| Value | Effect |
|---|---|
| `true` (default) | The switches of the screen decide; every connector is off until switched on |
| `false` | Every connector is locked off: nothing is sent, the switches cannot be turned on, **Test the connection** is refused |

The former `SECREVIEW_TICKETING_*` variables are not read any more: the controller refuses to
start while one of them is set, so that a lock is never lost silently.

```bash
SECREVIEW_CONNECTORS_INTERVAL_SECONDS=300   # period of the automatic sending
SECREVIEW_CONNECTORS_CAFILE=/etc/ssl/corp-ca.pem   # optional: internal certificate authority
```

## Connections

Each connector has its connection, set by its variables or in the **Connection** tab of its gear
in the **Connectors** screen. A variable that is set takes precedence: its field is only shown
in the screen. Secrets are never shown again (`***`); sending `***` back keeps the stored one.
**Test the connection** checks the entered values with a read-only request, without saving them,
before the connector is switched on.

Every field of a connector has its variable, `SECREVIEW_<KIND>_<FIELD>` (`SECREVIEW_JIRA_URL`):
see the page of each connector. A secret is bound to the host of its URL: setting a URL for
another host, or a URL where there was none (after deleting it, for instance), requires entering
the secrets again in the same change. A secret set by a variable only goes to a URL set by a
variable: the screen refuses the URL (otherwise a stored token could be sent to another host).

## Destinations of the projects

A project needs a **destination** to send its findings through a connector: what the connector
asks for, such as the **Jira project key** (`SEC`) or the **ServiceNow assignment group**. The
destinations are set in the **Projects** tab of the gear of the connector, in the
**Connectors** screen.

Each destination may have an **automatic sending** threshold: every new **open** finding at
least that severe is then sent by the controller. The threshold only applies to the reports
saved **after** it was set: the findings already stored are only sent by hand.

## Sending a finding

A user who may triage the project (`findings.triage` permission) sees a **Send to Jira** /
**Send to ServiceNow** button (one per connector) on each finding card whose project has a
destination. Once the record exists, the card shows its key, linked to the record. A failure is
shown on the card with its reason (refused credentials, unknown project key...).

The automatic sending runs every `SECREVIEW_CONNECTORS_INTERVAL_SECONDS` (300 by default), at
most 20 findings per connector and round, the most severe first. A failed finding is retried at
most 5 times, 15 minutes after the first failure, then with a doubled delay.

### One record per issue

A finding found again by a later report (same project, rule, file and title: the
[SARIF fingerprint](../advanced/sarif.md)) reuses the record of the first occurrence: no new
record is created. Sending a finding that already has its record returns it.

### Content sent

Every connector receives the same content: a title (`[HIGH] shop-api: SQL injection`), the
project, severity, location, rule, CWE, OWASP, branch, commit, link to the report (with
`SECREVIEW_WEB_URL`), then the description, evidence and recommendation, and the fingerprint of
the issue. The texts of the report are masked again (secrets) before they leave. How each field
lands in the system is described on the page of the connector.

## Security

- Outgoing connections of the **controller** only, every connector disabled by default (switched
  on by an administrator, or locked off by `SECREVIEW_CONNECTORS_ENABLED=false`), over **HTTPS**
  with certificate verification (`SECREVIEW_CONNECTORS_CAFILE` for an internal authority), through
  the [outgoing proxy](../reference/configuration.md#outgoing-proxy).
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
- A third-party connector is loaded only when `SECREVIEW_CONNECTORS_PLUGINS` names it, and runs
  with the rights of the controller: install only code you trust.
- Audit events: `connector.changed` (connection or switch), `connector.target_changed`
  (destination of a project), `finding.exported` (record created or reused, with its key; actor
  `auto` for the automatic sending).

## REST API

| Route | Permission | Role |
|---|---|---|
| `GET /api/v1/settings/connectors` | `settings.manage` | Every connector with its fields and connection (secrets `***`) and its switch (`enabled`), allowed plugins, `SECREVIEW_CONNECTORS_ENABLED` (`enabled`) |
| `GET /api/v1/connectors` | any | Available connectors (`kind`, `name`) |
| `PUT /api/v1/settings/connectors/{kind}` | `settings.manage` | Changes fields of a connection (`{"url": ..., "api_token": ...}`); `null` or `""` deletes the stored value; `404` for an unknown connector |
| `PUT /api/v1/settings/connectors/{kind}/enabled` | `settings.manage` | Switches a connector on or off (`{"enabled": true}`); `422` while its connection is not configured or when `SECREVIEW_CONNECTORS_ENABLED=false` |
| `POST /api/v1/settings/connectors/{kind}/test` | `settings.manage` | Tests the stored values and those of the body, not saved, the connector switched on or not |
| `GET /api/v1/connectors/targets` | `settings.manage` | Destinations of the projects |
| `PUT /api/v1/projects/{project}/connector-targets/{kind}` | `settings.manage` | `{"destination": "SEC", "auto_min_severity": "high"}` (`null`: by hand only) |
| `DELETE /api/v1/projects/{project}/connector-targets/{kind}` | `settings.manage` | Deletes a destination (the records are kept) |
| `GET /api/v1/connectors/destinations` | any | Projects and connectors the caller may send findings through now |
| `POST /api/v1/findings/{id}/exports/{kind}` | `findings.triage` | Sends a finding: `201` with its export; `409` when the connector is switched off, or the connection or the destination is missing; `502` when the system refuses it |

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://secreview.example.com/api/v1/findings/42/exports/jira
# {"kind": "jira", "state": "sent", "external_key": "SEC-12", "url": "https://acme.atlassian.net/browse/SEC-12", …}
```

The exports of a finding are also in its `exports` list, in the reports and lists of findings
(REST API and MCP tools).
