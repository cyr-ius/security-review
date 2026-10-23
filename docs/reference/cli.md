# Command line

The package installs two commands, one per process (see
[Architecture and deployment](../advanced/architecture.md)), and a pipeline client:

- `security-review-mcp`: the **MCP server** (stdio or HTTP), plus `enroll` and `scan-deps` on the client side;
- `security-review-controller`: the **controller** (REST API and web interface), the database
  and the administration;
- `security-review-ci`: the **pipeline client** of the controller REST API (`ci` token, Python
  standard library only, no database access): gate, SARIF, trend, code and dependency scans.

## `security-review-mcp`

| Command | Role | Page |
|---|---|---|
| `serve [--transport …] [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Starts the MCP server (stdio by default, `streamable-http` for a shared server) | [Installation](../getting-started/deploy.md) |
| `enroll --url URL --project P [--requested-by WHO] [--cafile CA] [--allow-http]` | Requests the project on a shared server, for an administrator to approve (unchanged when it exists or is pending; requester: `--requested-by`, by default your login name); no token is created: the answer gives the URL of the web interface where you create a personal MCP token | [Enrollment](../advanced/http.md#enrollment-request-the-project) |
| `scan-deps FILE… [--url URL] [--fail-on S] [--format json\|text] [--require-database] [--skip-unconfigured] [--token-stdin] [--cafile CA] [--allow-http] [--save --project P [--author A] [--repository R] [--branch B] [--commit C]]` | Scans manifests and lockfiles with the advisory database of a shared MCP server (token: `SECREVIEW_TOKEN`), for a commit hook; `--save` stores a report of the project on that server | [Dependencies](../advanced/dependencies.md#scan-with-a-shared-server-commit-hook) |

Without a command, `security-review-mcp` prints its usage on stderr and exits with code `2`
(`security-review-mcp --help` prints it on stdout): an MCP host must start `security-review-mcp serve`.

With stdio, the server migrates its database itself at start-up (unless
`SECREVIEW_DB_AUTO_UPGRADE=false`). With HTTP, it **only checks** the schema: it refuses to
start (code `2`) while `security-review-controller db upgrade` has not been run.

!!! note "Old subcommands"
    `security-review-mcp token|rules|advisories|db` are deprecated:
    they print a warning on stderr and run the controller command. Replace them with
    `security-review-controller …`.

## `security-review-controller`

| Command | Role | Page |
|---|---|---|
| `serve [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Serves the REST API (`/api/v1`) and the web interface (`/ui`) | [HTTP server](../advanced/http.md) |
| `db upgrade` / `db status` | Migrates the schema (Alembic) and seeds the default rules, or shows the revision | [Architecture and deployment](../advanced/architecture.md#schema-migrations) |
| `db prune [--days N]` | Deletes the reports without findings older than `N` days (default `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS`), except the latest of each project | [Retention](configuration.md#retention-of-reports-without-findings) |
| `token create --label NAME [--role ROLE] [--project P …] [--expires-in-days N]` | Creates a Bearer token, possibly limited to several projects and with a validity, and shows its secret once | [Bearer tokens](../advanced/http.md#bearer-tokens), [roles](../usage/web-interface.md#roles) |
| `token list [--project P]` / `token revoke ID\|LABEL` | Lists or revokes the tokens | [Bearer tokens](../advanced/http.md#bearer-tokens) |
| `token rotate ID\|LABEL [--grace-hours H] [--expires-in-days N]` | Replaces the secret of a token (same label, role and projects) and shows the new one once; the previous one works for `H` more hours (`0` to `168`) | [Expiry and rotation](../advanced/http.md#expiry-and-rotation-of-tokens) |
| `audit list [--action A] [--project P] [--actor WHO] [--since DATE] [--limit N] [--offset N]` / `audit prune [--days N] [--max-events N]` | Reads the audit log (JSON, newest first) or deletes the events older than `N` days (default `SECREVIEW_AUDIT_RETENTION_DAYS`), then the oldest beyond `--max-events` (default `SECREVIEW_AUDIT_MAX_EVENTS`) | [Audit log](../advanced/audit-metrics.md#audit-log) |
| `user create NAME [--sso] [--group G …] [--password-stdin]` | Creates a [web interface account](../usage/web-interface.md#user-accounts), member of the groups `G` (the only source of its permissions): local (without `--password-stdin`, the password is generated and shown once) or OIDC with `--sso` (no password; it also joins its OIDC groups at each login) | [User accounts](../usage/web-interface.md#user-accounts) |
| `user list` / `user set-groups NAME [--group G …]` / `user delete NAME` | Lists the accounts (never their digest) with their groups and permissions, replaces the groups given to an account (its OIDC groups are kept; `administrators` is created with the `admin` role when missing, to restore an administrator) or deletes it (a deleted OIDC account is no longer created again by a login); the last holder of `users.manage` is kept | [User accounts](../usage/web-interface.md#user-accounts) |
| `group list` / `group roles` | Lists the groups (roles, projects, members) or the roles (permissions); they are managed in the web interface | [Roles, groups and permissions](../advanced/access-control.md) |
| `project list` / `project approve ID` / `project reject ID` | Lists the projects requested by an enrollment (requester, address, expiry), creates one (its group `project:<project>`, without any member) or deletes the request | [Enrollment](../advanced/http.md#enrollment-request-the-project) |
| `user reset-password NAME [--password-stdin]` | Replaces the password of a local account (generated by default) and closes its sessions | [Lost password](../usage/web-interface.md#lost-password) |
| `rules list` / `rules import PATH…` / `rules export` | Lists, imports (TOML packs) or exports the rules stored in the database | [Internal rules](../advanced/rules.md#rules-command) |
| `rules enable ID…` / `rules disable ID…` / `rules delete ID…` | Enables, disables (default or custom rules) or deletes custom rules | [Internal rules](../advanced/rules.md#rules-command) |
| `advisories import PATH` / `advisories status` | Management of the offline OSV database | [Dependencies](../advanced/dependencies.md#offline-vulnerability-database-osv-format) |
| `advisories update [--ecosystem E …]` | Downloads the OSV exports (`SECREVIEW_OSV_*`, optional proxy) and imports them; code `2` if an ecosystem fails | [Automatic update](../advanced/dependencies.md#automatic-update-by-the-controller) |

`serve` and the commands that read or write the database first migrate the schema, unless
`SECREVIEW_DB_AUTO_UPGRADE=false`: they then only check that it is up to date.

The pipeline commands (gate, SARIF export, trend report, code and dependency scans) are not
controller commands: they are run by [`security-review-ci`](#security-review-ci), through the
REST API.

## `security-review-ci`

Options of every sub-command: `--project P` (required), `--url URL` (default
`SECREVIEW_CONTROLLER_URL`), `--token-stdin` (default: `SECREVIEW_TOKEN`), `--cafile CA`,
`--allow-http`, `--timeout S`. Without arguments, `security-review-ci` prints its help and
exits with code `2`.

| Command | Role | Page |
|---|---|---|
| `gate --project P [--fail-on SEV] [--report-id N]` | Deployment gate through the REST API | [Pipeline client](../usage/gate.md#pipeline-client-security-review-ci) |
| `sarif --project P [--include-resolved] [-o FILE]` | SARIF 2.1.0 export through the REST API | [SARIF](../advanced/sarif.md) |
| `trend --project P [--days N] [--granularity G] [--format markdown\|json]` | Trend report through the REST API | [Trends](../advanced/trends.md) |
| `scan-code [PATH] --project P [--exclude GLOB …] [--max-file-bytes N] [--no-git] [--fail-on SEV] [--format text\|json\|sarif] [-o FILE] [--save]` | Reads the files of the repository and has the controller scan them with its rules; `--save` stores a report | [Whole codebase scan](../advanced/code-scan.md) |
| `scan-deps FILE… --project P [--fail-on SEV] [--format text\|json] [--require-database] [--save]` | Sends manifests, lockfiles or CycloneDX SBOMs to the controller, which checks them against its advisory database; `--save` stores a report | [Dependencies](../advanced/dependencies.md#scan-in-a-pipeline-security-review-ci-scan-deps) |

`scan-code` and `scan-deps` also accept `--repository`, `--branch`, `--commit` and `--author`,
stored with the report. They need a `ci` or `admin` token.
## Exit codes

The check commands (`security-review-ci gate`, `scan-code` and `scan-deps`, `security-review-mcp scan-deps`, `db status`) share the same convention:

| Code | Meaning |
|---|---|
| `0` | Passes |
| `1` | Blocked: at least one finding reaches the `--fail-on` threshold (or, for `db status`, schema not up to date) |
| `2` | Error (project or report not found, unreadable file, schema to migrate…) |

The administration commands (`token`, `enroll`, `rules`, `advisories`, `db upgrade`,
`db prune`) return `0`
on success and `2` on error (unknown identifier, invalid pack…), with the error as JSON on
stderr.

Every command accepts `--help` for the full list of its options.
