# MCP server

The **MCP server** (`security-review-mcp`) is the process of the AI agents: it gives them the
review prompts, the checklists, the pattern scan and the development standards, and saves their
reports. It never calls the [Controller server](controller.md): both share the database (see
[Architecture](index.md)).

## What it serves

| Route | Used by | Credential |
|---|---|---|
| `/mcp` | the agents: [prompts, tools and resources](../../review/prompts-tools.md) | `mcp` token (personal or not), `admin` token, or [OAuth](../mcp-oauth.md) access token |
| `/mcp` without a token | an agent not yet connected: [enrollment server](../../review/prompts-tools.md#enrollment-server), which tells how to get a token; with the [OAuth login](../mcp-oauth.md), a `401` that starts it | none |
| `/.well-known/oauth-protected-resource/mcp` | the hosts, with the [OAuth login](../mcp-oauth.md) on: protected resource metadata (RFC 9728), which names the Controller server as authorization server (404 otherwise) | none |
| `/healthz` | probes (Docker `HEALTHCHECK`, Kubernetes) | none |

It serves no web page, no other route of the REST API, and no route that writes without a
token.

## Two transports

| Transport | Command | Use |
|---|---|---|
| Streamable HTTP | `security-review-mcp serve` (default of the image, port `8000`) | [shared mode](../../getting-started/deploy.md): every agent of the team, with a token |
| stdio | `security-review-mcp local` | [local mode](../../getting-started/stdio.md): started by the host on one workstation, local SQLite database, no token |

## Start-up

In HTTP, `security-review-mcp serve`:

1. **checks** the schema of the database and refuses to start (code `2`) while the Controller server has
   not migrated it: it never migrates (see [Schema migrations](../database.md#schema-migrations));
2. checks the TLS settings, loads the rules of the database;
3. serves `/mcp`. While no token exists, it stays **closed**: a client only reaches the
   enrollment server, unless the server listens on localhost or
   `SECREVIEW_ALLOW_UNAUTHENTICATED=true` (see [Bearer tokens](../bearer-tokens.md)).

In stdio, `security-review-mcp local` migrates its local database itself.

## What an agent gets

| Client | Answer |
|---|---|
| No token | the [enrollment server](../../review/prompts-tools.md#enrollment-server): no tool, prompts that explain how to get a token; `401` when `SECREVIEW_ENROLLMENT=false` |
| Unknown, revoked or expired token | `401` that tells the user where to create a new token ([rejected token](#rejected-token-sign-in-again)) |
| Valid `mcp` or `admin` token | every prompt, tool and resource, on the projects of the token ([tokens restricted to a project](../bearer-tokens.md#tokens-restricted-to-a-project)) |

Tokens and rules are read in the database: a token created or revoked on the Controller server applies
to the next request, a changed rule within 5 seconds.

## Prompts, tools and resources

This section is the technical reference of what the MCP server exposes to a client with a valid
token (in stdio, to the local host). When to use them in a review:
[Prompts and tools](../../review/prompts-tools.md).

At connection, the server sends **instructions** that the host shows the model: which prompt
starts a review, `request_project` before reviewing, `save_security_report` once at the end,
and `propose_finding_status` that never changes a status.

### Prompts

A prompt is a command started by the user in the host: the server returns the text of the
review, which the agent then follows. Every argument is an optional string.

| Prompt | Arguments | Returns |
|---|---|---|
| `security-review` | `language` (one or more, comma separated: `python, angular`; aliases `py`, `ts` accepted), `code`, `context`, `focus`, `report_language` | Review of the code with the checklists of the languages |
| `api-security-review` | `framework` (`FastAPI`, `Spring Boot`, `Express`…), `code`, `context`, `focus`, `report_language` | Review of a REST API against the OWASP API Security Top 10 |
| `configuration-review` | `config_type` (`Dockerfile`, `GitLab CI`, `Jenkinsfile`…), `content`, `context`, `focus`, `report_language` | Review of Docker, CI/CD, Spring, YAML or properties files |
| `codebase-review` | `languages`, `scan_results` (JSON output of `security-review-ci scan-code . --project <name> --format json`), `context`, `focus`, `report_language` | Review of the whole repository, from the scan results ([files read, rules, checklists, token consumption](../../review/analysis/code-scan.md#what-codebase-review-does)) |
| `dependency-review` | `ecosystem` (`PyPI`, `npm`, `Maven`, `Go`, `crates.io`, `NuGet`; empty: all), `files`, `context`, `report_language` | Review of manifests and lockfiles |
| `triage-report` | `report_id` (required, integer), `context`, `report_language` | Re-assessment of the findings of a stored report, embedded in Markdown without its author |
| `development-standards` | `technologies`, `files` (comma or newline separated), `task`, `context` | The [development standards](../../review/standards.md) of the stack (the catalog when both lists are empty); saves nothing |

- An empty `code`, `content` or `files` asks the agent to read the files of its workspace.
- The five review prompts start with `request_project` and end with a single call to
  `save_security_report`. The content given by the user is fenced, so that it is read as data,
  not as instructions.
- `report_language`: letters, spaces, `-`, `_` and parentheses, 40 characters at most;
  without it, `SECREVIEW_REPORT_LANGUAGE`, else the **General** page
  ([report language](../../review/prompts-tools.md#report-language)).
- An invalid argument returns the MCP error `INVALID_PARAMS` with its reason: refused
  `report_language`, `scan_results` or `task` + `context` beyond
  `SECREVIEW_MAX_CONTENT_CHARS`, report outside the projects of the token, unknown standard.

### Tools

Each tool is marked **read-only** (`readOnlyHint`) or **write** (never destructive: no tool
deletes data). An expected error (invalid input, unknown object, project the token does not
reach) is returned to the model as a tool error with its reason; the message of any other
error is hidden from it.

**Checklists, scan and rules**

| Tool | Type | Parameters | Returns |
|---|---|---|---|
| `list_checklists` | read-only | none | Domains (built-in and internal) with their number of items |
| `get_review_checklist` | read-only | `domain` | The checklist in Markdown, followed by the report language when one is configured |
| `scan_code` | read-only | `content` (at most `SECREVIEW_MAX_CONTENT_CHARS`), `language` (`python`, `java`, `typescript`, `javascript`, `angular`, `go`…) | `matches` (rule, line, masked excerpt), `suppressed` (lines marked `secreview:ignore`), counts, `report_language`; leads to check, not a full SAST |
| `list_rules` | read-only | `language` (optional) | Active rules, `disabled_rules`, `load_errors` of the internal rules |
| `reload_rules` | write | none | Reads the rules of the database again at once (otherwise within 5 seconds); refused to a token restricted to projects |

**Development standards**

| Tool | Type | Parameters | Returns |
|---|---|---|---|
| `list_development_standards` | read-only | none | Slug, title, description, technologies and file patterns of each standard, without its content |
| `get_development_standards` | read-only | `technologies` (at most 50, 50 characters each), `files` (at most 500 names, 500 characters each), `format` (`markdown` or `json`) | The standards selected by technology or file name, and the technologies no standard covers; at least one technology or file is required |

**Projects and reports**

| Tool | Type | Parameters | Returns |
|---|---|---|---|
| `request_project` | write | `project` | `status`: `accessible`, `created`, `joined` or `requested` with `next_steps` ([enrollment](#enrollment-personal-token-and-project-requests)); never a token |
| `save_security_report` | write | `project`, `summary`, `findings` (at most `SECREVIEW_MAX_FINDINGS_PER_REPORT`); optional `repository`, `branch`, `commit_sha`, `reviewer`, `scope`, `risk_level` (can only raise the computed risk), `review_type`, `author`, `checklist_results` (at most 500), `scan_rules` (at most 500) | Report id, risk level, counts by severity and review coverage ([stored report](../../review/prompts-tools.md#stored-report)) |
| `get_security_report` | read-only | `report_id`, `format` (`markdown` by default, or `json`) | The report and its findings, without its author |
| `list_security_reports` | read-only | `project`, `risk_level`, `review_type`, `limit` (1 to 100, `20` by default), `offset` | Reports, newest first, without their author (`author`: deprecated, ignored) |
| `propose_finding_status` | write | `finding_id`, `status` (`fixed`, `accepted` or `false_positive`), `reason` (10 to 1,000 characters) | The finding with its proposal; its status does not change until a person decides ([status of a finding](../../review/prompts-tools.md#status-of-a-finding)) |

**Posture, gate, exports and trends**

| Tool | Type | Parameters | Returns |
|---|---|---|---|
| `get_project_security_posture` | read-only | `project` | Open findings by severity, worst open severity |
| `check_project_gate` | read-only | `project`, `fail_on` (`high` by default), `report_id` (optional) | `passed` false while an open finding reaches `fail_on` ([gate](../../review/gate.md)) |
| `export_sarif` | read-only | `report_id` **or** `project`, `include_resolved` (`false` by default) | A SARIF 2.1.0 log; for a project, each finding once (latest report) |
| `get_trend_report` | read-only | `project`, `days` (1 to 1,095, `90` by default), `granularity` (`day`, `week` by default, `month`), `format` | New and fixed findings, open backlog, risk score, MTTR |

**Dependencies**

| Tool | Type | Parameters | Returns |
|---|---|---|---|
| `scan_dependencies` | read-only | `content` (at most `SECREVIEW_MAX_DEPENDENCY_CHARS`; beyond, use `security-review-ci scan-deps`), `filename` (selects the parser: `uv.lock`, `package-lock.json`, `pom.xml`, `bom.json`…) | Vulnerable versions and hygiene findings; check `vulnerability_check` first: when it is not `performed`, an empty list does not mean safe ([dependencies](../../review/analysis/dependencies.md)) |
| `get_advisory_status` | read-only | none | Size, ecosystems and age of the last import of the vulnerability database |

**Scope of a token.** With a token restricted to projects (personal token included), every tool
that names a project, a report or a finding checks that the token reaches it, and
`list_security_reports` only returns the reports of its projects. `save_security_report`
refuses another project and points to `request_project`. The tools that take no project
(checklists, scan, standards, dependencies) answer every token. In stdio, there is no
restriction.

### Resources

The resources are read-only, in Markdown (`text/markdown`), and follow the same scope as the
tools.

| URI | Name | Content |
|---|---|---|
| `report://{report_id}` | `security-report` | A stored report and its findings, without its author (`report_id`: a number, in the projects of the token) |
| `checklist://{domain}` | `review-checklist` | The checklist of a domain, as `get_review_checklist` without the report language |
| `standards://catalog` | `development-standards` | The catalog of the development standards |
| `standard://{slug}` | `development-standard` | One development standard, with its content |

An unknown object returns a "resource not found" error, an invalid identifier a resource error.

The [enrollment server](../../review/prompts-tools.md#enrollment-server), served to a client
without a token, exposes none of these tools nor resources: only the five review prompts,
without argument, which explain how to get a token.

## What it never does

- It makes **no outgoing connection** (the OSV database is imported by the Controller server), and loads
  no module of the Controller server.
- Its tools **never read the disk** from a path given by the client: they work on the content
  sent.
- Every input is bounded (`SECREVIEW_MAX_CONTENT_CHARS`, `SECREVIEW_MAX_FINDINGS_PER_REPORT`,
  `SECREVIEW_MAX_MCP_REQUEST_MB`, 64 KiB for a client without a token), and secrets are masked
  before storage.
- It **never changes the status of a finding**: `propose_finding_status` only records a proposal,
  that a person approves in the web interface.
- In stdio, stdout is kept for the MCP protocol: the logs go to stderr.

See [Security and limits](../../reference/security.md).

## Exposure and replicas

Expose the MCP server with TLS ([built-in or reverse proxy](../tls.md)) to the workstations of
the developers. Behind a reverse proxy or an Ingress, set `SECREVIEW_FORWARDED_ALLOW_IPS`, otherwise
every client shares the address of the proxy in the audit log of the project requests.

The MCP sessions (streamable HTTP) live in the memory of the process that opened them: before
running several replicas, send every request of a session to the same replica (affinity on the
`Mcp-Session-Id` header, see [Kubernetes](../deployment/kubernetes.md#several-replicas)).

The variables of the MCP server: [Configuration](../../reference/configuration.md#mcp-server).

| Command | Role |
|---|---|
| `serve` | Starts the MCP server of the shared mode (streamable HTTP) ([manual installation](../deployment/manual-install.md#5-start-the-mcp-server)) |
| `local` | Starts the MCP server of the local mode (stdio) ([local mode](../../getting-started/stdio.md)) |

All their options: [Command line](../../reference/cli.md#security-review-mcp).

## Enrollment: personal token and project requests

The MCP server **never creates a token** and writes nothing for a client without a token. It
is enabled by default (`SECREVIEW_ENROLLMENT=true`), even before the first token is created
(except on an [open server](../bearer-tokens.md), which needs no token).

1. **Personal token.** An MCP client that connects **without** an `Authorization` header is
   not rejected: it reaches a restricted MCP server (same `security-review` name) **without any
   tool**, whose prompts are named like the reviews (`security-review`, `codebase-review`…).
   They tell the user to sign in to the web interface (its URL comes from
   the database, where the Controller server copies its
   [`SECREVIEW_PUBLIC_URL`](../../reference/configuration.md#web-interface-and-sessions), followed by `/ui`, or the
   **General** page stores it; read again at most every 30 seconds; none: no
   link), to create a
   **personal MCP token** in **My account** (see
   [personal MCP tokens](../../usage/tokens.md#personal-mcp-and-ci-tokens)) and to put it in the
   [host configuration](../../getting-started/host.md#getting-a-token). The token reaches the
   projects the user may read, at each request.
2. **Project of the review.** Every review prompt starts with the `request_project` tool, with
   the project name (usually the repository name):
    - the token already reaches the project: `accessible`, the review goes on;
    - the project is new and the user holds `projects.create`: it is **created** at once, with
      the project in read only for the user, and the review goes on;
    - the project exists and the user holds `projects.autojoin`: the user **joins** it at once
      (`joined`, project in read only), unless a user with `projects.create` has
      [blocked its autojoin](../../usage/projects.md#blocking-the-autojoin), and the review
      goes on. A user reads at most 200 projects this way;
    - otherwise the answer is `requested`, and the agent stops before reviewing, so that no
      review is lost. A new project is **pending**: it is not a project yet and gives no access.
      For a project that already exists, the user **requests access** to it the same way
      (never at once, even with `projects.create`, except with `projects.autojoin`). The answer is the same in both cases, so
      that it does not tell which projects exist. A user files one request per project; nothing
      is recorded for a token without a user on an existing project, or for a user who already
      reads it.
3. **Approval.** A user holding `projects.create` (the `admin` role among others) approves or
   rejects the request in the **Pending projects** section of the **Projects** page, where
   each request is marked **New project** or **Access request**, or from the CLI (`existing`:
   `true` for an access request). Approving an access request also takes `users.manage`, as
   giving a role does: `projects.create` alone never opens an existing project.

    ```bash
    security-review-controller project list          # requester, address, expiry
    security-review-controller project approve 3     # id of the list
    security-review-controller project reject 4
    ```

    The approval adds the project to the **requester** in read only (see
    [members](../../usage/projects.md#members)), created for a new project: their
    personal token reaches the project from the next request, without reconfiguration. A
    request nobody approved within `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` (7 days by default)
    is deleted.

`save_security_report` refuses a project the token does not reach and points to
`request_project`. When a user with `projects.create`
[creates the project](../../usage/projects.md#creating-a-project) on the **Projects** page, its
own pending request is settled; those of other users become access requests.

Safeguards: at most 20 requests are pending at a time, a user (or a token without a user)
requests at most 5 projects per hour, and a pending request expires after
`SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS`. Every request, approval, rejection and expiry is
written to the [audit log](../audit-log.md) (`enrollment.requested`, `enrollment.approved`,
`enrollment.rejected`, with the token, the requesting user and the client address). To disable
the enrollment: `SECREVIEW_ENROLLMENT=false` (clients without a token then get `401`, with the
same advice, and `request_project` refuses the projects the token does not reach).

## Rejected token: sign in again

A client whose token is **unknown, revoked or expired** gets `401` on `/mcp`
(`error="invalid_token"`): the description tells the user to sign in to the web interface (with
its URL when it is known, as above) and to create a new personal MCP token, then to replace
it in the [host configuration](../../getting-started/host.md#getting-a-token). Such a client never
reaches the review tools nor the enrollment server. The rejection is logged as a warning by the
MCP server (`Rejected unauthenticated request` / `Rejected expired token`).

With the [OAuth login](../mcp-oauth.md) on, this `401` also carries the
`resource_metadata` parameter in its `WWW-Authenticate` challenge, so that a host that supports
OAuth signs in again by itself, and a request without a token gets the same `401` (without
`error`) instead of the enrollment server.

When the Controller server offers no personal MCP token (`SECREVIEW_PERSONAL_MCP_TOKENS=false` or
`SECREVIEW_PERSONAL_TOKENS_ENABLED=false`, stored in the database at its start), the description of the `401`, the instructions and the prompts of the
enrollment server tell the user to sign in through the OAuth login, or to ask an administrator
for an MCP token, instead of creating a personal one.
