# GitHub

The **GitHub** connector opens an **issue** for each finding sent, on github.com or GitHub
Enterprise Server. The variables are in [Connectors in detail](../../advanced/connectors.md#github).

## Connection

| Field | Value |
|---|---|
| URL | The address of the GitHub API, in HTTPS: `https://api.github.com`, or `https://<host>/api/v3` for GitHub Enterprise Server |
| **Access token** | A fine-grained personal access token with the *Issues: read and write* permission on the repositories used (or a classic token with the `repo` scope) |

## Destination

The destination of a project is its **GitHub repository**, as `owner/repository` (`acme/shop`).

GitHub issues have no confidential flag: whoever reads the repository reads them. Send the
findings to a **private** repository, readable only by the teams that fix them.

## Content of an issue

- **Title**: `[HIGH] shop-api: SQL injection`;
- **Description**: the project, severity, location, rule, CWE, branch, commit and a link to the
  report, then the description, evidence and recommendation of the finding;
- **Labels**: `security-review` and `severity-<severity>` (GitHub creates them when the token
  may do so).

The texts written by the agents are shown as code: they never mention anyone (`@team`), load an
image nor add a link.
