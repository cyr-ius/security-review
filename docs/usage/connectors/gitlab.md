# GitLab

The **GitLab** connector opens an **issue** for each finding sent, on gitlab.com or a
self-managed GitLab. The issues are **confidential** by default. The variables are in
[Connectors in detail](../../advanced/connectors.md#gitlab).

## Connection

| Field | Value |
|---|---|
| URL | The address of GitLab, in HTTPS (`https://gitlab.com`, or the address of a self-managed instance) |
| **Access token** | A personal, group or project access token with the `api` scope, of a member allowed to create issues (*Reporter* or higher) |
| **Confidential issues** | `true` (default): only the members of the project allowed to see confidential issues read them; `false`: visible to whoever reads the project |

## Destination

The destination of a project is its **GitLab project ID**, the number shown on the page of the
project (`42`). Its path (`group/project`) is not accepted: it would be sent encoded, which the
connectors refuse.

## Content of an issue

- **Title**: `[HIGH] shop-api: SQL injection`;
- **Description**: the project, severity, location, rule, CWE, branch, commit and a link to the
  report, then the description, evidence and recommendation of the finding;
- **Labels**: `security-review` and `severity-<severity>`.

The texts written by the agents are shown as code: they never mention anyone (`@team`), load an
image, add a link nor run a quick action (`/close`).
