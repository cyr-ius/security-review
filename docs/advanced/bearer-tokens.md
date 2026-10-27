# Bearer tokens

The tokens of the [MCP server](architecture/mcp-server.md) and of the [Controller server](architecture/controller.md) are
managed from the CLI of the Controller server. What each token may reach is in
[Tokens](../usage/tokens.md); the routes each process serves are in
[What it serves](architecture/mcp-server.md#what-it-serves) (MCP server) and
[What it serves](architecture/controller.md#what-it-serves) (Controller server).

Tokens are stored in the database (`apitoken` table): only their SHA-256 digest is kept, the
secret is shown only once, at creation. Manage them with the `token` command (see the
[CLI](../reference/cli.md#security-review-controller)):

```bash
security-review-controller token create --label ci                      # mcp role by default
security-review-controller token create --label jenkins --role ci --project shop-api
security-review-controller token create --label ops-script --role admin
# {"id": "6f1c…", "label": "ci", "role": "mcp", "project": null, "created_at": "…", "token": "UJB7…"}
security-review-controller token list [--project shop-api]             # never the secret nor the digest
security-review-controller token revoke ci                              # by label or by id
```

- Give `token` to the client; the unique `label` appears in the logs.
- `--role` is `mcp` by default; `admin`, `ci` and `metrics` are the other roles of the CLI (see
  [Roles of a token](../usage/tokens.md#roles-of-a-token)). The `api` tokens are created in the
  web interface ([API tokens](../usage/tokens.md#api-tokens)).
- `--project` limits the token to one or more projects (repeat the option), for the MCP tools
  and the pipeline routes (`mcp` and `ci` roles, always for `ci`; refused for `admin` and
  `metrics`): see [tokens restricted to a project](#tokens-restricted-to-a-project).
- `--expires-in-days` sets the validity of the token: see
  [expiry and rotation](#expiry-and-rotation-of-tokens).
- The server reads the database at every request: a creation or a revocation applies
  immediately, including to the other instances sharing the same PostgreSQL database.

Developers create their own personal tokens in the web interface
([personal tokens](../usage/tokens.md#personal-tokens)). Every creation, rotation and revocation
of a token is written to the [audit log](audit-log.md), with who made it.

## Before the first token

While no token exists, the Controller server API answers `503` and the MCP server **stays closed**: a
client without a token only reaches the [enrollment server](architecture/mcp-server.md#enrollment-personal-token-and-project-requests) (no tool),
any other request gets `401`, whatever the bearer value (a warning is logged at start-up). `/mcp`
is only open in that case when the server listens on localhost (`127.0.0.1`, `::1`) or when
`SECREVIEW_ALLOW_UNAUTHENTICATED=true`, to keep for tests on an isolated network: as soon as a
token exists, it is required in every case. With the [OAuth login](mcp-oauth.md) on, `/mcp` is
never open: a client without a token gets the `401` that starts the login. `token revoke` warns on stderr when it deletes the
last token.

## Expiry and rotation of tokens

A token may expire: after its expiry date it authenticates nothing (`401`, `error="invalid_token"`,
description `The bearer token has expired`, followed on `/mcp` by how to
[get a new one](architecture/mcp-server.md#rejected-token-sign-in-again)), but it stays listed so that an administrator
rotates or revokes it. `SECREVIEW_TOKEN_MAX_DAYS` (default `0`) sets the longest validity of a
token created or rotated, and its default validity; with `0`, tokens do not expire unless a
validity is asked for.

```bash
security-review-controller token create --label shop-ci --project shop-api --expires-in-days 90
security-review-controller token rotate shop-ci --grace-hours 24     # new secret, shown once
# {"id": "6f1c…", "label": "shop-ci", …, "expires_at": "…", "rotated_at": "…", "grace_until": "…", "token": "pX4q…"}
```

A rotation replaces the secret of a token: it keeps its id, label, role and projects, and gets a
new validity (`--expires-in-days`, default as at creation). During `--grace-hours` (`0` by
default, at most `168`) the previous secret keeps working, the time to update the clients
(`grace_until` in `token list`); after that, only the new one authenticates. The previous secret
of an expired token never comes back. After a leak, rotate without a grace period (or revoke):
the leaked secret then stops at once. A personal token cannot be rotated: its user creates a
new one. In the web interface, the **Tokens** screen rotates the project tokens (button
**Rotate**, grace period chosen above the list).

Expired tokens still count as configured tokens: a server whose tokens have all expired stays
closed, it never becomes open.

## Tokens restricted to a project

On a server shared by several teams, give each pipeline a token limited to its project:

```bash
security-review-controller token create --label shop-ci --project shop-api            # mcp role
security-review-controller token create --label shop-gate --role ci --project shop-api
```

A token without `--project` reaches every project. In the web interface, the
[**Tokens**](../usage/index.md#screens) screen creates a token for some projects
or for **All projects**, and changes the projects of an existing token (except `admin` and
`metrics`; a `ci` token always keeps at least one project). A restricted token:

- only saves reports (`save_security_report`) for its project;
- only reads, lists, exports and proposes a status for (`propose_finding_status`) the
  reports and findings of its project; `list_security_reports` without a filter only returns
  those;
- gets, for any other project, report or finding, the same "not found" error as for a missing
  object, so as not to reveal the other projects;
- cannot call `reload_rules`.

The restriction also applies to the `report://` resource and to the `triage-report` prompt.
With stdio, there is no token, hence no restriction.

!!! tip
    The `token` commands run on the Controller server side (or in its container), with the same
    `SECREVIEW_DATABASE_URL` as the Controller server. Tokens are never passed as command-line
    arguments.

## Calling the REST API with a token

An `admin` token calls the whole REST API, for example from an administration script, but
**does not open the interface** (the login page only offers the accounts):

```bash
security-review-controller token create --label ops-script --role admin
# {"id": "…", "label": "ops-script", "role": "admin", "project": null, "created_at": "…", "token": "UJB7…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/projects
```

Its status changes are limited to `open` and `fixed`, like those of an `api` token with
`findings.triage`: `accepted` and `false_positive` need a session
([triage through the REST API](reports/triage-api.md)).

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

Every status change is logged with the label of the token or of the account:

```
INFO security_review_mcp.web: Finding 42 set to fixed by ops-script
```

and written to the [audit log](audit-log.md) (`GET /api/v1/audit`, `audit.read`
permission), with the actor `token:ops-script` or `user:<name>`.

An `api` token reads the access control at each request: a personal one holds the rights of its
user, a role one the permissions of its **Role** on its projects (every project, or a list when
the role only holds permissions per project).

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
these projects. The **Tokens** screen only lists the tokens of the projects the user reads. Its
**Validity** goes from 30 days to 1 year, or the default of the server
(`SECREVIEW_TOKEN_MAX_DAYS`).

## Personal tokens

Every personal token ([personal tokens](../usage/tokens.md#personal-tokens)) follows the same
rules:

- one at most per usage by default (`SECREVIEW_PERSONAL_TOKENS_PER_USER`);
- label `<user>:<label>`, with a `:` that no other token label may hold, and validity bounded by
  `SECREVIEW_TOKEN_MAX_DAYS`;
- nobody can rotate it nor change its projects; an administrator can revoke it from the
  **Tokens** screen.

A personal `mcp` token needs `mcp_tokens.create` in the groups of the account (`403` without
it); a token already created keeps working when the account loses it, and an administrator
revokes it if needed. It reaches the projects of `reports.read` of the groups of the account:
every project when one of its groups reads every project, none when it has none. When the
server refuses it (unknown, revoked or expired), the agent receives a `401` that tells the user
to sign in again and create a new one.

Each personal token has one usage: a personal `mcp` token only reaches `/mcp`, a personal `ci`
token (offered in **My account**, for `security-review-ci` through `SECREVIEW_CI_TOKEN`) only the
pipeline routes. A report stored by a personal `ci` token is submitted by the token (`alice:laptop`), and its user is the author
(see [scan from a workstation](../review/analysis/dependencies.md#scan-from-a-workstation-commit-hook)).

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "mcp"}'
# {"id": "…", "label": "alice:laptop", "role": "mcp", "personal": true, …, "token": "Zq3…"}
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "ci"}'
# {"id": "…", "label": "alice:laptop", "role": "ci", "personal": true, …, "token": "Zq3…"}
```
