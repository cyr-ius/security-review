# Command line

The `security-review` package installs two commands, one per process (see
[Architecture](../advanced/architecture/index.md)), and a pipeline client:

- `security-review-mcp`: the **MCP server** (stdio or HTTP);
- `security-review-controller`: the **Controller server** (REST API and web interface), the database
  and the administration;
- `security-review-ci`: the **pipeline client** of the Controller server REST API (`ci` token, Python
  standard library only, no database access): gate, SARIF, trend, code and dependency scans.
  It is published alone, without the server, on PyPI as the `security-review-ci` package
  (Python 3.14, see [Installation](../advanced/architecture/ci.md#installation)), or can be
  installed [from the Controller server](../advanced/architecture/ci.md#from-the-controller-server).

```bash
# From PyPI
uv pip install security-review-ci
```

```bash
# From the Controller server, without PyPI
uvx --no-index --find-links https://secreview.example.com/api/ci-client/ security-review-ci@latest --help
```

## `security-review-mcp`

| Command | Role | Page |
|---|---|---|
| `serve [--transport …] [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …] [--database-url …]` | Starts the MCP server (`streamable-http` by default, for the shared mode; `--transport stdio` accepts a SQLite database only); `--database-url` overrides `SECREVIEW_DATABASE_URL` | [Manual installation](../advanced/deployment/manual-install.md#5-start-the-mcp-server) |
| `local [--database-url …]` | Starts the MCP server of the local mode (stdio), on the local SQLite database: ignores `SECREVIEW_DATABASE_URL`; `--database-url` chooses another SQLite file | [Local mode](../getting-started/stdio.md) |

Without a command, `security-review-mcp` prints its usage.

The value of `--database-url` shows in the process list: put a URL with a password in
`SECREVIEW_DATABASE_URL` rather than on the command line.

With stdio, the server migrates its database itself at start-up. With HTTP, it **only checks** the schema: it refuses to
start (code `2`) while `security-review-controller db upgrade` has not been run.

## `security-review-controller`

| Command | Role | Page |
|---|---|---|
| `serve [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Serves the REST API (`/api/v1`) and the web interface (`/ui`) | [Controller server](../advanced/architecture/controller.md), [TLS](../advanced/tls.md) |
| `db upgrade` / `db status` | Migrates the schema (Alembic) and seeds the default rules, or shows the revision | [Schema migrations](../advanced/database.md#schema-migrations) |
| `db prune [--days N]` | Deletes the reports without findings older than `N` days (default `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS`), except the latest of each project | [Retention](../advanced/database.md#retention-of-reports-without-findings) |
| `token create --label NAME [--role ROLE] [--project P …] [--expires-in-days N]` | Creates a Bearer token, possibly limited to several projects and with a validity, and shows its secret once | [Bearer tokens](../advanced/bearer-tokens.md), [roles](../usage/tokens.md) |
| `token list [--project P]` / `token revoke ID\|LABEL` | Lists or revokes the tokens | [Bearer tokens](../advanced/bearer-tokens.md) |
| `token rotate ID\|LABEL [--grace-hours H] [--expires-in-days N]` | Replaces the secret of a token (same label, role and projects) and shows the new one once; the previous one works for `H` more hours (`0` to `168`) | [Expiry and rotation](../advanced/bearer-tokens.md#expiry-and-rotation-of-tokens) |
| `audit list [--action A] [--project P] [--actor WHO] [--since DATE] [--limit N] [--offset N]` / `audit prune [--days N] [--max-events N]` | Reads the audit log (JSON, newest first) or deletes the events older than `N` days (default `SECREVIEW_AUDIT_RETENTION_DAYS`), then the oldest beyond `--max-events` (default `SECREVIEW_AUDIT_MAX_EVENTS`) | [Audit log](../advanced/audit-log.md) |
| `user create NAME [--sso] [--role R …] [--project P …] [--all-projects] [--password-stdin]` | Creates a [web interface account](../usage/user-accounts.md) with the roles `R` and the known projects `P` (or every project), the only source of its permissions: local (without `--password-stdin`, the password is generated and shown once) or OIDC with `--sso` (no password; it also gets the roles and projects of its OIDC mappings at each login) | [User accounts](../usage/user-accounts.md) |
| `user list` / `user set-access NAME [--role R …] [--project P …] [--all-projects]` / `user delete NAME` | Lists the accounts (never their digest) with their roles, projects and permissions, replaces the roles and projects of an account (those of its OIDC mappings are kept; `--role admin --all-projects` restores an administrator) or deletes it (a deleted OIDC account is no longer created again by a login); the last holder of `users.manage` is kept | [User accounts](../usage/user-accounts.md) |
| `role list` / `role mappings` | Lists the roles (permissions) or the OIDC mappings (claim value, role, projects); they are managed in the web interface | [Roles and permissions](../usage/access-control.md#roles) |
| `project list` / `project approve ID` / `project reject ID` | Lists the projects requested by the MCP agents of users (requester, address, expiry; `existing`: access request to an existing project), adds the project to the requester in read only (created for a new project) or deletes the request | [Enrollment](../advanced/architecture/mcp-server.md#enrollment-personal-token-and-project-requests) |
| `user reset-password NAME [--password-stdin]` | Replaces the password of a local account (generated by default) and closes its sessions | [Lost password](../advanced/architecture/controller.md#lost-password) |
| `rules list` / `rules import PATH…` / `rules export` | Lists, imports (TOML packs) or exports the rules stored in the database | [Rules](../review/rules.md#rules-command) |
| `rules enable ID…` / `rules disable ID…` / `rules delete ID…` | Enables, disables (default or custom rules) or deletes custom rules | [Rules](../review/rules.md#rules-command) |
| `advisories import PATH` / `advisories status` | Management of the offline OSV database | [Dependencies](../review/analysis/dependencies.md#offline-vulnerability-database-osv-format) |
| `advisories update [--ecosystem E …]` | Downloads the OSV exports (`SECREVIEW_OSV_*`, optional proxy) and imports them; code `2` if an ecosystem fails | [Automatic update](../review/analysis/dependencies.md#automatic-update-by-the-controller-server) |

`serve` and the other commands migrate the schema at start-up when needed: `db upgrade` is
only useful to a [dedicated migration job](../advanced/database.md#dedicated-migration-job).

## `security-review-ci`

Options accepted by every sub-command, except `agent-review` and `guard`:

`--project P` (required), `--url URL` (default `SECREVIEW_CONTROLLER_URL`), `--token-stdin`
(default: `SECREVIEW_CI_TOKEN`), `--cafile CA`, `--allow-http`, `--timeout S`.

Without arguments, `security-review-ci` prints its help and exits with code `2`.

| Command | Role | Page |
|---|---|---|
| `gate --project P [--fail-on SEV] [--report-id N]` | Deployment gate through the REST API | [Pipeline client](../advanced/architecture/ci.md) |
| `sarif --project P [--include-resolved] [-o FILE]` | SARIF 2.1.0 export through the REST API | [SARIF](../advanced/reports/sarif.md) |
| `trend --project P [--days N] [--granularity G] [--format markdown\|json]` | Trend report through the REST API | [Trends](../advanced/architecture/ci.md#trend-report) |
| `scan-code [PATH] --project P [--exclude GLOB …] [--max-file-bytes N] [--no-git] [--fail-on SEV] [--format text\|json\|sarif] [-o FILE] [--save]` | Reads the files of the repository and has the Controller server scan them with its rules; `--save` stores a report | [Whole codebase analysis](../review/analysis/code-scan.md) |
| `scan-deps FILE… --project P [--fail-on SEV] [--format text\|json] [--require-database] [--skip-unconfigured] [--save]` | Sends manifests, lockfiles or CycloneDX SBOMs to the Controller server, which checks them against its advisory database; `--save` stores a report; `--skip-unconfigured` exits successfully even if the Controller server is unreachable | [Dependencies](../review/analysis/dependencies.md#scan-in-a-pipeline-security-review-ci-scan-deps) |
| `agent-review --project P [--agent claude\|copilot\|codex] [--mcp-config FILE] [--mcp-server NAME] [--foreground]` | Has the coding agent of the developer review the last commit with the `security-review` MCP server of its MCP configuration (post-commit hook); never contacts the Controller server; exits with `0` when the review starts or is skipped, `2` outside a git repository | [Pipeline client](../advanced/architecture/ci.md#agent-review-of-each-commit) |
| `guard [--agent claude\|copilot\|codex]` | Hook of the coding agent before a tool call: reads the event on stdin, scans the files read by the call with the `AI-*` rules, offline, and writes the decision (refuse hidden text, ask about text addressed to an assistant); never contacts the Controller server; always exits with `0` | [Read guard](../review/analysis/read-guard.md) |

`scan-code` and `scan-deps` also accept `--repository`, `--branch`, `--commit` and `--author`,
stored with the report (`--author` is not needed with a personal token, whose user is the
author).

They need a `ci` or `admin` token (on a workstation, a [personal `ci` token](../usage/tokens.md#personal-mcp-and-ci-tokens)).

`--skip-unconfigured` exits with `0` and a warning when no Controller server URL is set (commit hook).

## Exit codes

The check commands (`security-review-ci gate`, `scan-code` and `scan-deps`, `db status`) share the same convention:

| Code | Meaning |
|---|---|
| `0` | Passes |
| `1` | Blocked: at least one finding reaches the `--fail-on` threshold (or, for `db status`, schema not up to date) |
| `2` | Error (project or report not found, unreadable file, schema to migrate…) |

The administration commands (`token`, `rules`, `advisories`, `db upgrade`,
`db prune`) return `0`
on success and `2` on error (unknown identifier, invalid pack…), with the error as JSON on
stderr.

Every command accepts `--help` for the full list of its options. `security-review-mcp
--version`, `security-review-controller --version` and `security-review-ci --version` print
the installed version.
