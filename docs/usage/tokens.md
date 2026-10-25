# Tokens

**Tokens** are for machines: MCP agents, CI/CD pipelines, Prometheus, administration scripts.
**People** use a [user account](user-accounts.md), which alone opens the web interface, with the
rights of its groups ([Roles, groups and permissions](../advanced/access-control.md)). There is
no read-only or triage token: to give a person read or triage access, add their account to a
group.

## Roles of a token

Every token has a fixed role, which decides the endpoints it reaches. A token created without a
role is `mcp`.

| Role | Usage (**Tokens** screen) | `/mcp` | REST API | Status change |
|---|---|---|---|---|
| `mcp` (default) | MCP | ✅ | — (pipeline routes for a personal token) | — |
| `admin` | CLI only | ✅ | ✅ | `open`, `fixed` ¹ |
| `api` | REST API — Swagger and scripts ([API tokens](#api-tokens)) | — | ✅ with the permissions of its role or of its user | `open`, `fixed` ¹ with `findings.triage` |
| `ci` | CI/CD pipeline — gate, SARIF, trend and scans | — | pipeline routes only (`/api/v1/ci/`), including the scans that store reports | — |
| `metrics` | CLI only | — | `/metrics` only ([Prometheus](../reference/metrics.md)) | — |

¹ `accepted` and `false_positive` need a person logged in to the interface with the
`findings.triage` permission ([triage of findings](triage.md)). On `/mcp`, no role changes a
status: the agents only propose one.

An `mcp` token can be restricted to projects with `--project` (repeatable); a `ci` token always
is (see [`ci` token](../advanced/ci.md#ci-token-and-visible-projects) and
[tokens restricted to a project](../advanced/bearer-tokens.md#tokens-restricted-to-a-project)). Creation,
expiry, rotation and revocation from the CLI: [Bearer tokens](../advanced/bearer-tokens.md).

## `admin` token

An `admin` token calls the whole REST API, for example from an administration script, but
**does not open the interface** (the login page only offers the accounts):

```bash
security-review-controller token create --label ops-script --role admin
# {"id": "…", "label": "ops-script", "role": "admin", "project": null, "created_at": "…", "token": "UJB7…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/projects
```

The REST API lists the findings of a project across all its reports, open by default, worst
first (`status`, `severity` and `review_type` filter, `limit` is capped by
`SECREVIEW_MAX_LIST_LIMIT`, `total` gives the number of matching findings for paging). Without
`project`, it lists the findings of every project the caller reads (`"project": null`):

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/findings?project=shop-api&status=open&limit=50"
# {"project": "shop-api", "total": 12, "findings": [{"id": 42, "severity": "critical", "report_id": 7, "project": "shop-api", "branch": "main", "commit_sha": "abc123", "review_type": "codebase-review", "report_created_at": "…", …}, …]}
```

`GET /api/v1/reports` lists the reports (`project`, `risk_level`, `review_type` and `author`
filter), each with its `author` and `submitted_by`. The `author` is returned, filtered, searched
and sorted only for a caller holding `users.manage` or `tokens.manage`: for the others it is
`null` (in the report and its Markdown export too) and the `author` filter is ignored:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/reports?project=shop-api&author=alice@example.com"
```

Revoke it with `security-review-controller token revoke ops-script`. Every status change is
logged with the label of the token or of the account:

```
INFO security_review_mcp.web: Finding 42 set to fixed by ops-script
```

and written to the [audit log](../advanced/audit-metrics.md) (`GET /api/v1/audit`,
`audit.read` permission), with the actor `token:ops-script` or `user:<name>`.

## API tokens

An `api` token calls the REST API, from a script or from the Swagger documentation (`/api/docs`,
**Authorize** button), with the rights of the access control, read at each request. It never
reaches `/mcp` and never opens the interface. There are two kinds:

- **Personal token**: created by a user for themselves, with **Usage** **REST API — Swagger and
  scripts** (see [personal tokens](#personal-tokens)). It holds the current rights of the
  account, which come from its groups: it reaches nothing once the account loses them.
- **Role token**: created by an administrator (`tokens.manage`) on the **Tokens** screen, with
  **Usage** **REST API** and a **Role**. It holds the permissions of that role on its projects
  (every project, or a list when the role only holds permissions per project). A role used by a
  token cannot be deleted.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "swagger", "expires_in_days": 30}'
# {"id": "…", "label": "alice:swagger", "role": "api", "personal": true, "access_role_id": null, …, "token": "Zq3…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/me
# {"client": "alice:swagger", "role": "api", "permissions": {"reports.read": ["shop-api"]}, …}
```

## Tokens created from the interface

A token never grants more than its creator holds: creating a token, changing its projects,
rotating its secret or revoking it needs `reports.read` on every project of the token, before
and after a change of its projects, and, for a role `api` token, each permission of its role on
these projects. The **Tokens** screen only lists the tokens of the projects the user reads.

## Personal tokens

A user creates their own tokens in **My account** > **Personal tokens**, with one of two
usages:

| Usage | Role | Reaches | Needs |
|---|---|---|---|
| **REST API — Swagger and scripts** | `api` | the REST API, with the rights of the account | — |
| **MCP / CI — agent and security-review-ci** | `mcp` | `/mcp` and the pipeline routes, on the projects the account may read | `mcp_tokens.create` |

A personal `ci` token (pipeline routes only) is no longer offered there: the `mcp` token covers
them (see [below](#personal-mcp-and-ci-tokens)).

Every personal token follows the same rules:

- one at most per usage by default (`SECREVIEW_PERSONAL_TOKENS_PER_USER`): revoke it to create
  another;
- label `<user>:<label>`, with a `:` that no other token label may hold, and validity bounded by
  `SECREVIEW_TOKEN_MAX_DAYS`;
- its rights are those of the account, read at each request; it stops while the account must
  change a password set by an administrator, and is deleted with the account;
- nobody can rotate it nor change its projects; an administrator can revoke it from the
  **Tokens** screen.

### Personal MCP and CI tokens

A personal `mcp` token connects the MCP agent of the user. It is offered only when the groups of
the account hold `mcp_tokens.create` (role `mcp-user`, see
[Roles](../advanced/access-control.md#roles); `403` without it); a token already created keeps
working when the account loses it, and an administrator revokes it if needed. It reaches the
projects the account may read (`reports.read` of its groups): every project when one of its
groups reads every project, none when it has none. The **Projects** column shows them, and so
does the **Tokens** screen for the administrators.

For a project it does not reach, an administrator gives the account access to the project (a
group that reads it), or the user creates it from **Projects** if it is new and they hold
`projects.create` (see [Creating a project](../advanced/access-control.md#creating-a-project)).
The agent asks for it itself with `request_project` before a review: a new project is created at
once when the user holds `projects.create`, otherwise it waits for an approval, which gives the
user access to it ([enrollment](../advanced/mcp-server.md#enrollment-personal-token-and-project-requests)). When the server refuses the token (unknown, revoked or expired), the agent
receives a `401` that tells the user to sign in again and create a new one.

A personal `mcp` token also works as a personal `ci` token on the pipeline routes: one
`SECREVIEW_TOKEN` on the workstation serves both the MCP agent and
[`security-review-ci`](../advanced/ci.md), so **My account** no longer offers a personal `ci`
token. The API still creates one to keep the two uses apart (it never reaches `/mcp`), and those
already created stay listed until revoked. A report stored by either is submitted by the token
(`alice:laptop`), and its user is the author (see
[scan from a workstation](../advanced/dependencies.md#scan-from-a-workstation-commit-hook)). An
`mcp` token created by an administrator on the **Tokens** screen stays an MCP agent token only.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "mcp"}'
# {"id": "…", "label": "alice:laptop", "role": "mcp", "personal": true, …, "token": "Zq3…"}
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "ci"}'
# {"id": "…", "label": "alice:laptop", "role": "ci", "personal": true, …, "token": "Zq3…"}
```
