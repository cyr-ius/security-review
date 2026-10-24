# Jira

The built-in **Jira** connector (kind `jira`) creates an **issue** for each finding sent, in
Jira Cloud or Jira Data Center. Enabling, destinations and sending are common to every
connector: see [Connectors](index.md).

## Connection

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_JIRA_URL` | — | Jira address, `https://` only (`https://acme.atlassian.net`, or the base URL of a Data Center) |
| `SECREVIEW_JIRA_USERNAME` | — | Jira Cloud: e-mail address of the account, used with an API token. Empty: the token is a Data Center personal access token, sent as a bearer token |
| `SECREVIEW_JIRA_API_TOKEN` | — | API token (Cloud) or personal access token (Data Center) |
| `SECREVIEW_JIRA_ISSUE_TYPE` | `Bug` | Issue type of the issues created |

The account only needs to create issues: the *Browse projects* and *Create issues* permissions
on the projects used.

## Destination

The destination of a project is the **Jira project key** (`SEC`).

## Content of an issue

| Field | Value |
|---|---|
| `summary` | `[HIGH] shop-api: SQL injection` |
| `description` | project, severity, location, rule, CWE, OWASP, branch, commit, link to the report, then description, evidence and recommendation |
| `labels` | `security-review` and `severity-<severity>` |

The texts of the report are put in `{noformat}` blocks: written by an agent, they are never read
as wiki markup (links, images loaded from another site).
