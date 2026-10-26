# Connectors in detail

The [connectors](../usage/connectors/index.md) page describes the connectors in the web interface.
This page gives the variables, the automatic sending, the content sent, the guarantees and the
REST API.

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

```bash
SECREVIEW_CONNECTORS_INTERVAL_SECONDS=300   # period of the automatic sending
SECREVIEW_CONNECTORS_CAFILE=/etc/ssl/corp-ca.pem   # optional: internal certificate authority
```

## Sending a finding

A user who may triage the project (`findings.triage` permission) sees a **Send to**
button (one per connector) on each finding card whose project has a destination.
Once the record exists, the card shows its key, linked to the record. A failure is
shown on the card with its reason (refused credentials, unknown project key...).

The automatic sending runs every `SECREVIEW_CONNECTORS_INTERVAL_SECONDS` (300 by default), at
most 20 findings per connector and round, the most severe first. A failed finding is retried at
most 5 times, 15 minutes after the first failure, then with a doubled delay.

### One record per issue

A finding found again by a later report (same project, rule, file and title: the
[SARIF fingerprint](reports/sarif.md)) reuses the record of the first occurrence: no new
record is created. Sending a finding that already has its record returns it.

### Content sent

Every connector receives the same content: a title (`[HIGH] shop-api: SQL injection`), the
project, severity, location, rule, CWE, OWASP, branch, commit, link to the report (with
`SECREVIEW_CONTROLLER_URL`), then the description, evidence and recommendation, and the fingerprint of
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

## Jira

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_JIRA_URL` | — | Jira address, `https://` only (`https://acme.atlassian.net`, or the base URL of a Data Center) |
| `SECREVIEW_JIRA_USERNAME` | — | Jira Cloud: e-mail address of the account, used with an API token. Empty: the token is a Data Center personal access token, sent as a bearer token |
| `SECREVIEW_JIRA_API_TOKEN` | — | API token (Cloud) or personal access token (Data Center) |
| `SECREVIEW_JIRA_ISSUE_TYPE` | `Bug` | Issue type of the issues created |

The account only needs to create issues: the *Browse projects* and *Create issues* permissions
on the projects used.

The texts of the report are put in `{noformat}` blocks: written by an agent, they are never read
as wiki markup (links, images loaded from another site).

## ServiceNow

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_SERVICENOW_URL` | — | Address of the instance, `https://` only |
| `SECREVIEW_SERVICENOW_USERNAME` | — | Account (basic authentication) |
| `SECREVIEW_SERVICENOW_PASSWORD` | — | Its password |
| `SECREVIEW_SERVICENOW_TABLE` | `incident` | Table of the records |

The account only needs the right to create records in the table (the `itil` role for
`incident`).

## Third-party connectors

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
