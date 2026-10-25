# Bearer tokens

The tokens of the [MCP server](mcp-server.md) and of the [controller](controller.md) are
managed from the CLI of the controller. What each token may reach is in
[Tokens](../usage/tokens.md); the routes each process serves are in
[What it serves](mcp-server.md#what-it-serves) (MCP server) and
[What it serves](controller.md#what-it-serves) (controller).

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
of a token is written to the [audit log](audit-metrics.md), with who made it.

## Before the first token

While no token exists, the controller API answers `503` and the MCP server **stays closed**: a
client without a token only reaches the [enrollment](mcp-server.md#enrollment-request-the-project),
any other request gets `401`, whatever the bearer value (a warning is logged at start-up). `/mcp`
is only open in that case when the server listens on localhost (`127.0.0.1`, `::1`) or when
`SECREVIEW_ALLOW_UNAUTHENTICATED=true`, to keep for tests on an isolated network: as soon as a
token exists, it is required in every case. `token revoke` warns on stderr when it deletes the
last token.

## Expiry and rotation of tokens

A token may expire: after its expiry date it authenticates nothing (`401`, `error="invalid_token"`,
description `The bearer token has expired`, followed on `/mcp` by how to
[get a new one](mcp-server.md#rejected-token-sign-in-again)), but it stays listed so that an administrator
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
[**Tokens**](../usage/web-interface.md#screens) screen creates a token for some projects
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
    The `token` commands run on the controller side (or in its container), with the same
    `SECREVIEW_DATABASE_URL` as the controller. Tokens are never passed as command-line
    arguments.
