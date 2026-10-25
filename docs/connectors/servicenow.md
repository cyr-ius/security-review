# ServiceNow

The built-in **ServiceNow** connector (kind `servicenow`) creates a record for each finding sent,
in the `incident` table by default.

## Connection

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_SERVICENOW_URL` | — | Address of the instance, `https://` only |
| `SECREVIEW_SERVICENOW_USERNAME` | — | Account (basic authentication) |
| `SECREVIEW_SERVICENOW_PASSWORD` | — | Its password |
| `SECREVIEW_SERVICENOW_TABLE` | `incident` | Table of the records |

The account only needs the right to create records in the table (the `itil` role for
`incident`).

## Destination

The destination of a project is the **assignment group** (optional, its name).

## Content of a record

| Field | Value |
|---|---|
| `short_description` | `[HIGH] shop-api: SQL injection` |
| `description` | project, severity, location, rule, CWE, OWASP, branch, commit, link to the report, then description, evidence and recommendation, as plain text |
| `urgency`, `impact` | from the severity: `critical` 1 / 1, `high` 1 / 2, `medium` 2 / 2, `low` and `info` 3 / 3 |
| `assignment_group` | the destination of the project |
| `correlation_id` | the fingerprint of the issue |
