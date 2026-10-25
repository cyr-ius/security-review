# MCP server

The **MCP server** (`security-review-mcp`) is the process of the AI agents: it gives them the
review prompts, the checklists, the pattern scan and the development standards, and saves their
reports. It never calls the [controller](controller.md): both share the database (see
[Architecture](architecture.md)).

## What it serves

| Route | Used by | Credential |
|---|---|---|
| `/mcp` | the agents: [prompts, tools and resources](../usage/prompts-tools.md) | `mcp` token (personal or not) or `admin` token |
| `/mcp` without a token | an agent not yet connected: [enrollment server](../usage/prompts-tools.md#enrollment-server) | none |
| `POST /api/v1/enroll` | `security-review-mcp enroll` and scripts: [enrollment](#enrollment-request-the-project) | none |
| `/healthz` | probes (Docker `HEALTHCHECK`, Kubernetes) | none |

It serves no web page and no other route of the REST API.

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
   enrollment, unless the server listens on localhost or `SECREVIEW_ALLOW_UNAUTHENTICATED=true`
   (see [Bearer tokens](bearer-tokens.md)).

In stdio, `security-review-mcp local` migrates its local database itself.

## What an agent gets

| Client | Answer |
|---|---|
| No token | the [enrollment server](../usage/prompts-tools.md#enrollment-server): `request_enrollment` and prompts that explain how to get a token; `401` when `SECREVIEW_ENROLLMENT=false` |
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
every client shares the address of the proxy for the enrollment limits.

The MCP sessions (streamable HTTP) live in the memory of the process that opened them: before
running several replicas, send every request of a session to the same replica (affinity on the
`Mcp-Session-Id` header, see [Kubernetes](kubernetes.md#several-replicas)).

The variables of the MCP server: [Configuration](../reference/configuration.md#mcp-server). Its
commands (`serve`, `local`, `enroll`): [Command line](../reference/cli.md#security-review-mcp).

## Enrollment: request the project

The enrollment **never creates a token**: it requests the project, which an administrator
approves, and the developer creates a personal MCP token in the web interface. It is enabled by
default (`SECREVIEW_ENROLLMENT=true`), even before the first token is created (except on an
[open server](bearer-tokens.md), which needs no token).

1. **Request.** The client gives the name of its project (usually the repository name). A new
   project is **pending**: it is not a project yet and gives no access. A project that already
   exists, or is already pending, is unchanged, and the answer is the same in every case, so
   that it does not tell which projects exist. Three ways to enroll:
    - **From the agent, at the first review.** An MCP client that connects **without** an
      `Authorization` header is not rejected: it reaches a restricted MCP server (same
      `security-review` name) that only exposes the `request_enrollment` tool, and prompts named
      like the reviews (`security-review`, `codebase-review`…) that explain the steps. The agent
      calls `request_enrollment` with the project name.
    - **From the command line**, from the developer workstation or the CI:

        ```bash
        security-review-mcp enroll --url https://secreview.example.internal:8443 \
            --project shop-api --requested-by "alice (shop team)"
        # {"project": "shop-api", "web_url": "https://secreview.example.internal/ui", "next_steps": "…"}
        ```

    - **Through the MCP server API**: `POST /api/v1/enroll` (without a token) with
      `{"project": "shop-api"}`, answered with `202`. The controller does not serve this
      endpoint: it exposes no unauthenticated write route.
2. **Approval.** A user holding `projects.create` (the `admin` role among others) approves or
   rejects the request in the **Pending projects** section of the **Projects** screen, or from
   the CLI:

    ```bash
    security-review-controller project list          # requester, address, expiry
    security-review-controller project approve 3     # id of the list
    security-review-controller project reject 4
    ```

    The approval creates the project, with its group `project:<project>` **without any
    member**: nobody gains any access, the approver included. A request nobody approved within
    `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` (7 days by default) is deleted.
3. **Personal token.** The answer of the enrollment gives the URL of the web interface
   (`web_url`, from [`SECREVIEW_WEB_URL`](../reference/configuration.md#mcp-server)) and the next steps:
   the user signs in, creates a **personal MCP token** in **My account** (see
   [personal MCP tokens](../usage/tokens.md#personal-mcp-and-ci-tokens)) and puts it in the
   [host configuration](../getting-started/host.md#getting-a-token). The token reaches the
   projects the user may read, at each request.
4. **Access.** An administrator gives the user access to the project by adding them to the
   group `project:<project>` (**Groups** screen, see [access control](access-control.md#project-groups)); the
   personal token reaches the project from the next request, without reconfiguration.

An agent that already has a token may also call `request_enrollment` (for instance when
`save_security_report` refuses a project its token does not reach): the project is requested
the same way, and the token gains no project. When a user with `projects.create`
[creates the project](access-control.md#creating-a-project) directly, its pending request is
settled.

## Rejected token: sign in again

A client whose token is **unknown, revoked or expired** gets `401` on `/mcp`
(`error="invalid_token"`): the description tells the user to sign in to the web interface (with
its URL when `SECREVIEW_WEB_URL` is set) and to create a new personal MCP token, then to replace
it in the [host configuration](../getting-started/host.md#getting-a-token). Such a client never
reaches the review tools nor the enrollment server. The rejection is logged as a warning by the
MCP server (`Rejected unauthenticated request` / `Rejected expired token`).

Safeguards: anybody who reaches the server may enroll, so at most 20 projects are pending at a
time, a client address enrolls at most 5 times per hour (`429` beyond; behind a reverse proxy,
set [`SECREVIEW_FORWARDED_ALLOW_IPS`](../reference/configuration.md#listening-tls-and-reverse-proxy)), and a pending project
expires after `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS`. Every request, approval, rejection and
expiry is written to the [audit log](audit-metrics.md) (`enrollment.requested`,
`enrollment.approved`, `enrollment.rejected`, with the requester and the client address). To disable the enrollment: `SECREVIEW_ENROLLMENT=false`
(clients without a token then get `401`, with the same advice).

`--url` is the URL of the **MCP server** (with or without `/mcp`): it receives the requests.
