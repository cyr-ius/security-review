# MCP server

The **MCP server** (`security-review-mcp`) is the process of the AI agents: it gives them the
review prompts, the checklists, the pattern scan and the development standards, and saves their
reports. It never calls the [controller](controller.md): both share the database (see
[Architecture](architecture.md)).

## What it serves

| Route | Used by | Credential |
|---|---|---|
| `/mcp` | the agents: [prompts, tools and resources](../usage/prompts-tools.md) | `mcp` token (personal or not) or `admin` token |
| `/mcp` without a token | an agent not yet connected: [enrollment server](../usage/prompts-tools.md#enrollment-server), which tells how to get a token | none |
| `/healthz` | probes (Docker `HEALTHCHECK`, Kubernetes) | none |

It serves no web page, no other route of the REST API, and no route that writes without a
token.

## Two transports

| Transport | Command | Use |
|---|---|---|
| Streamable HTTP | `security-review-mcp serve` (default of the image, port `8000`) | [shared mode](../getting-started/deploy.md): every agent of the team, with a token |
| stdio | `security-review-mcp local` | [local mode](../getting-started/stdio.md): started by the host on one workstation, local SQLite database, no token |

## Start-up

In HTTP, `security-review-mcp serve`:

1. **checks** the schema of the database and refuses to start (code `2`) while the controller has
   not migrated it: it never migrates (see [Schema migrations](controller.md#schema-migrations));
2. checks the TLS settings, loads the rules of the database;
3. serves `/mcp`. While no token exists, it stays **closed**: a client only reaches the
   enrollment server, unless the server listens on localhost or
   `SECREVIEW_ALLOW_UNAUTHENTICATED=true` (see [Bearer tokens](bearer-tokens.md)).

In stdio, `security-review-mcp local` migrates its local database itself.

## What an agent gets

| Client | Answer |
|---|---|
| No token | the [enrollment server](../usage/prompts-tools.md#enrollment-server): no tool, prompts that explain how to get a token; `401` when `SECREVIEW_ENROLLMENT=false` |
| Unknown, revoked or expired token | `401` that tells the user where to create a new token ([rejected token](#rejected-token-sign-in-again)) |
| Valid `mcp` or `admin` token | every prompt, tool and resource, on the projects of the token ([tokens restricted to a project](bearer-tokens.md#tokens-restricted-to-a-project)) |

Tokens and rules are read in the database: a token created or revoked on the controller applies
to the next request, a changed rule within 5 seconds.

## What it never does

- It makes **no outgoing connection** (the OSV database is imported by the controller), and loads
  no module of the controller.
- Its tools **never read the disk** from a path given by the client: they work on the content
  sent.
- Every input is bounded (`SECREVIEW_MAX_CONTENT_CHARS`, `SECREVIEW_MAX_FINDINGS_PER_REPORT`,
  `SECREVIEW_MAX_MCP_REQUEST_MB`, 64 KiB for a client without a token), and secrets are masked
  before storage.
- It **never changes the status of a finding**: `propose_finding_status` only records a proposal,
  that a person approves in the web interface.
- In stdio, stdout is kept for the MCP protocol: the logs go to stderr.

See [Security and limits](../reference/security.md).

## Exposure and replicas

Expose the MCP server with TLS ([built-in or reverse proxy](tls.md)) to the workstations of
the developers. Behind a reverse proxy or an Ingress, set `SECREVIEW_FORWARDED_ALLOW_IPS`, otherwise
every client shares the address of the proxy in the audit log of the project requests.

The MCP sessions (streamable HTTP) live in the memory of the process that opened them: before
running several replicas, send every request of a session to the same replica (affinity on the
`Mcp-Session-Id` header, see [Kubernetes](kubernetes.md#several-replicas)).

The variables of the MCP server: [Configuration](../reference/configuration.md#mcp-server). Its
commands (`serve`, `local`): [Command line](../reference/cli.md#security-review-mcp).

## Enrollment: personal token and project requests

The MCP server **never creates a token** and writes nothing for a client without a token. It
is enabled by default (`SECREVIEW_ENROLLMENT=true`), even before the first token is created
(except on an [open server](bearer-tokens.md), which needs no token).

1. **Personal token.** An MCP client that connects **without** an `Authorization` header is
   not rejected: it reaches a restricted MCP server (same `security-review` name) **without any
   tool**, whose prompts are named like the reviews (`security-review`, `codebase-review`…).
   They tell the user to sign in to the web interface (its URL comes from
   [`SECREVIEW_WEB_URL`](../reference/configuration.md#mcp-server)), to create a
   **personal MCP token** in **My account** (see
   [personal MCP tokens](../usage/tokens.md#personal-mcp-and-ci-tokens)) and to put it in the
   [host configuration](../getting-started/host.md#getting-a-token). The token reaches the
   projects the user may read, at each request.
2. **Project of the review.** Every review prompt starts with the `request_project` tool, with
   the project name (usually the repository name):
    - the token already reaches the project: `accessible`, the review goes on;
    - the project is new and the user holds `projects.create`: it is **created** at once, with
      the user as its member (group `project:<project>`), and the review goes on;
    - otherwise the answer is `requested`, and the agent stops before reviewing, so that no
      review is lost. A new project is **pending**: it is not a project yet and gives no access.
      For a project that already exists, the user **requests access** to it the same way
      (never at once, even with `projects.create`). The answer is the same in both cases, so
      that it does not tell which projects exist. A user files one request per project; nothing
      is recorded for a token without a user on an existing project, or for a user who already
      reads it.
3. **Approval.** A user holding `projects.create` (the `admin` role among others) approves or
   rejects the request in the **Pending projects** section of the **Projects** screen, where
   each request is marked **New project** or **Access request**, or from the CLI (`existing`:
   `true` for an access request). Approving an access request also takes `users.manage`, as
   adding a member to a group does: `projects.create` alone never opens an existing project.

    ```bash
    security-review-controller project list          # requester, address, expiry
    security-review-controller project approve 3     # id of the list
    security-review-controller project reject 4
    ```

    The approval adds the **requester** to the project group `project:<project>` (see
    [access control](access-control.md#project-groups)), created for a new project: their
    personal token reaches the project from the next request, without reconfiguration. A
    request nobody approved within `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` (7 days by default)
    is deleted.

`save_security_report` refuses a project the token does not reach and points to
`request_project`. When a user with `projects.create`
[creates the project](access-control.md#creating-a-project) on the **Projects** screen, its
own pending request is settled; those of other users become access requests.

Safeguards: at most 20 requests are pending at a time, a user (or a token without a user)
requests at most 5 projects per hour, and a pending request expires after
`SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS`. Every request, approval, rejection and expiry is
written to the [audit log](audit-metrics.md) (`enrollment.requested`, `enrollment.approved`,
`enrollment.rejected`, with the token, the requesting user and the client address). To disable
the enrollment: `SECREVIEW_ENROLLMENT=false` (clients without a token then get `401`, with the
same advice, and `request_project` refuses the projects the token does not reach).

## Rejected token: sign in again

A client whose token is **unknown, revoked or expired** gets `401` on `/mcp`
(`error="invalid_token"`): the description tells the user to sign in to the web interface (with
its URL when `SECREVIEW_WEB_URL` is set) and to create a new personal MCP token, then to replace
it in the [host configuration](../getting-started/host.md#getting-a-token). Such a client never
reaches the review tools nor the enrollment server. The rejection is logged as a warning by the
MCP server (`Rejected unauthenticated request` / `Rejected expired token`).
