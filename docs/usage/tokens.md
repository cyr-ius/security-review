# Tokens

**Tokens** are for machines: the MCP agents, the CI/CD pipelines, Prometheus and the
administration scripts. **People** sign in with a [user account](user-accounts.md), the only
way to open the web interface, with the rights of its roles
([Roles and permissions](access-control.md)). There is no read-only or
triage token: to let a person read or triage, give their account a role.

The command line, the REST API and the limits are in [Bearer tokens](../advanced/bearer-tokens.md).

## Roles of a token

Every token has a fixed role, which decides what it reaches.

| Role | For | Created |
|---|---|---|
| `mcp` | An MCP agent (Claude Code, Copilot, Codex...) | **Tokens** page, or personal token |
| `ci` | The pipeline client [`security-review-ci`](../advanced/architecture/ci.md): gate, SARIF, trend, scans | **Tokens** page, always for some projects |
| `api` | Scripts and the Swagger documentation ([API tokens](#api-tokens)) | **Tokens** page, or personal token |
| `admin` | Administration scripts: the whole REST API | Command line only |
| `metrics` | [Prometheus](../reference/metrics.md) | Command line only |

No token marks a finding as **Risk accepted** or **False positive**: only a person signed in to
the interface does it ([triage](triage.md)). The agents only propose a status.

## Creating a token in the interface

On the **Tokens** page, an administrator chooses:

- the **Usage**: **MCP**, **CI/CD pipeline** or **REST API** (with the **Role** it holds);
- the **Allowed projects**, ticked in a drop-down list with a search: **All projects**
  (including the projects reviewed later, never for a CI/CD token) or some projects;
- the **Validity**: from 30 days to 1 year.

A token never grants more than its creator holds, and the page only lists the tokens of the
projects you read. **Projects** changes the projects of a token without changing its secret;
**Rotate** replaces its secret.

## API tokens

An `api` token calls the REST API, from a script or from the Swagger documentation
(**Authorize** button). It never reaches the MCP server and never opens the interface. There
are two kinds:

- **Personal token**: created by a user for themselves (see [personal tokens](#personal-tokens)).
  It holds the current rights of the account: it reaches nothing once the account loses them.
- **Role token**: created by an administrator on the **Tokens** page, with a **Role** and
  **Per-project permissions**. It holds the permissions of that role on the whole Controller
  server and these per-project permissions on its projects. A role used by a token cannot be
  deleted.

## Personal tokens

A user creates their own tokens in **My account** > **Personal tokens**:

| Usage | For |
|---|---|
| **REST API — Swagger and scripts** | The REST API, with the rights of the account |
| **MCP — your MCP agent** | Your MCP agent, on the projects your account may read |
| **CI — security-review-ci on your workstation** | `security-review-ci` (scans, gate, commit hooks), on the projects your account may read |

Each token has one usage: an MCP token does not reach the pipeline routes, a CI token does not
reach the MCP server.

A personal token follows the account: its rights are those of the account, read at each
request; it stops while the account must change a password set by an administrator, and is
deleted with the account. Only one token per usage is allowed by default: revoke it to create
another. It cannot be rotated: revoke it and create a new one.

With the [OAuth login of MCP clients](../advanced/mcp-oauth.md), the MCP agent needs no personal
token: the clients you approved are listed in **My account** > **Connected MCP clients**, where
you revoke them. An administrator sees and revokes every client in the **MCP clients (OAuth
login)** section of the **Tokens** page, where the login is also turned on or off and its MCP
endpoint set.

### Personal MCP and CI tokens

The personal **MCP** token connects your MCP agent, the personal **CI** token
`security-review-ci`. Every account may create them, unless an administrator turned them off
(`SECREVIEW_PERSONAL_TOKENS_ENABLED=false`, see below). It reaches the
projects your account may read, shown in the **Projects** column.

For a project it does not reach yet: an administrator gives you access to it, you create it
from **Projects** if it is new and you may, or your agent asks for it itself before a review;
the request then waits for an approval ([enrollment](../advanced/architecture/mcp-server.md#enrollment-personal-token-and-project-requests)).
When the token is refused (revoked or expired), the agent tells you to sign in again and create
a new one.

The personal **CI** token serves [`security-review-ci`](../advanced/architecture/ci.md) on your
workstation, for example in the [commit hooks](../getting-started/commit-hooks.md), through
`SECREVIEW_CI_TOKEN`. A report it saves shows you as its author.

When the server uses the [OAuth login of MCP clients](../advanced/mcp-oauth.md), an administrator
may turn the personal MCP tokens off (`SECREVIEW_PERSONAL_MCP_TOKENS=false`): the **MCP** usage is
then no longer offered, and the Controller server revokes the MCP tokens left at its next start. The CI
and REST API tokens stay.

An administrator may also turn off, for the whole application, the personal MCP and CI tokens
and the OAuth login (`SECREVIEW_PERSONAL_TOKENS_ENABLED=false`): the **MCP** and **CI** usages
are no longer offered, and the tokens already created, like the MCP clients already connected
with OAuth, are refused. They are kept, and work again once the variable is `true`. The REST API
tokens stay.

## Points to watch

- **The secret is shown only once**, at creation: copy it at once. Only its digest is stored.
- **After a leak**, revoke the token, or rotate it without a grace period: the leaked secret
  stops at once.
- **A token expires**: past its validity it reaches nothing. Plan its rotation.
- **A revocation or a change of projects applies at the next request.**
- **A token never opens the web interface**, even an `admin` one.
