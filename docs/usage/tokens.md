# Tokens

**Tokens** are for machines: the MCP agents, the CI/CD pipelines, Prometheus and the
administration scripts. **People** sign in with a [user account](user-accounts.md), the only
way to open the web interface, with the rights of its groups
([Roles, groups and permissions](access-control.md)). There is no read-only or
triage token: to let a person read or triage, add their account to a group.

The command line, the REST API and the limits are in [Bearer tokens](../advanced/bearer-tokens.md).

## Roles of a token

Every token has a fixed role, which decides what it reaches.

| Role | For | Created |
|---|---|---|
| `mcp` | An MCP agent (Claude Code, Copilot, Codex...) | **Tokens** screen, or personal token |
| `ci` | The pipeline client [`security-review-ci`](../advanced/architecture/ci.md): gate, SARIF, trend, scans | **Tokens** screen, always for some projects |
| `api` | Scripts and the Swagger documentation ([API tokens](#api-tokens)) | **Tokens** screen, or personal token |
| `admin` | Administration scripts: the whole REST API | Command line only |
| `metrics` | [Prometheus](../reference/metrics.md) | Command line only |

No token marks a finding as **Risk accepted** or **False positive**: only a person signed in to
the interface does it ([triage](triage.md)). The agents only propose a status.

## Creating a token in the interface

On the **Tokens** screen, an administrator chooses:

- the **Usage**: **MCP**, **CI/CD pipeline** or **REST API** (with the **Role** it holds);
- the **Allowed projects**: **All projects** (including the projects reviewed later, never for
  a CI/CD token) or **Selected projects**;
- the **Validity**: from 30 days to 1 year.

A token never grants more than its creator holds, and the screen only lists the tokens of the
projects you read. **Projects** changes the projects of a token without changing its secret;
**Rotate** replaces its secret.

## API tokens

An `api` token calls the REST API, from a script or from the Swagger documentation
(**Authorize** button). It never reaches the MCP server and never opens the interface. There
are two kinds:

- **Personal token**: created by a user for themselves (see [personal tokens](#personal-tokens)).
  It holds the current rights of the account: it reaches nothing once the account loses them.
- **Role token**: created by an administrator on the **Tokens** screen, with a **Role**. It
  holds the permissions of that role on its projects. A role used by a token cannot be deleted.

## Personal tokens

A user creates their own tokens in **My account** > **Personal tokens**:

| Usage | For |
|---|---|
| **REST API — Swagger and scripts** | The REST API, with the rights of the account |
| **MCP / CI — agent and security-review-ci** | Your MCP agent and `security-review-ci`, on the projects your account may read |

A personal token follows the account: its rights are those of the account, read at each
request; it stops while the account must change a password set by an administrator, and is
deleted with the account. Only one token per usage is allowed by default: revoke it to create
another. It cannot be rotated: revoke it and create a new one.

With the [OAuth login of MCP clients](../advanced/mcp-oauth.md), the MCP agent needs no personal
token: the clients you approved are listed in **My account** > **Connected MCP clients**, where
you revoke them. An administrator sees and revokes every client in the **MCP clients (OAuth
login)** section of the **Tokens** screen.

### Personal MCP and CI tokens

The personal **MCP / CI** token connects your MCP agent. It is offered only when your groups
allow it (role `mcp-user`, see [Roles](access-control.md#roles)). It reaches the
projects your account may read, shown in the **Projects** column.

For a project it does not reach yet: an administrator gives you access to it, you create it
from **Projects** if it is new and you may, or your agent asks for it itself before a review;
the request then waits for an approval ([enrollment](../advanced/architecture/mcp-server.md#enrollment-personal-token-and-project-requests)).
When the token is refused (revoked or expired), the agent tells you to sign in again and create
a new one.

The same token serves [`security-review-ci`](../advanced/architecture/ci.md) on your workstation, for
example in the [commit hooks](../getting-started/commit-hooks.md): one token for both. A report
it saves shows you as its author.

## Points to watch

- **The secret is shown only once**, at creation: copy it at once. Only its digest is stored.
- **After a leak**, revoke the token, or rotate it without a grace period: the leaked secret
  stops at once.
- **A token expires**: past its validity it reaches nothing. Plan its rotation.
- **A revocation or a change of projects applies at the next request.**
- **A token never opens the web interface**, even an `admin` one.
