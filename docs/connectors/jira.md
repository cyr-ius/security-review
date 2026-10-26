# Jira

The **Jira** connector creates an **issue** for each finding sent, in Jira Cloud or Jira Data
Center. The variables are in [Connectors in detail](../advanced/connectors.md#jira).

## Connection

| Field | Value |
|---|---|
| URL | The address of Jira, in HTTPS (`https://acme.atlassian.net`, or the address of a Data Center) |
| **Account** | Jira Cloud: the e-mail address of the account. Empty for Data Center |
| **API token** | An API token (Cloud) or a personal access token (Data Center) |
| **Issue type** | The type of the issues created (`Bug` by default) |

The account only needs to browse and create issues in the Jira projects used.

## Destination

The destination of a project is its **Jira project key** (`SEC`).

## Content of an issue

- **Summary**: `[HIGH] shop-api: SQL injection`;
- **Description**: the project, severity, location, rule, CWE, branch, commit and a link to the
  report, then the description, evidence and recommendation of the finding;
- **Labels**: `security-review` and `severity-<severity>`, to filter them in Jira.

The texts written by the agents are shown as is: never as Jira formatting (links, images).
