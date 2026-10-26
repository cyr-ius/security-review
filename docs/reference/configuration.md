# Configuration

The MCP server and the controller read environment variables prefixed with `SECREVIEW_`, or a
`.env` file in the current directory (see `.env.example`). The variables are grouped below by
the process that reads them: [both](#both-processes), the [MCP server](#mcp-server)
(`security-review-mcp`), the [controller](#controller) (`security-review-controller`) or the
[clients](#clients).

Some settings can also be set in the [web interface](../usage/web-interface.md#screens): report
language, outgoing proxy, OIDC login and syslog server of the audit log. **A variable that is set always takes precedence**
over the value of the interface, which only applies when the variable is not set (the screen
then locks the field).

## Both processes

Read by the MCP server and by the controller.

### Database and logs

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_DATABASE_URL` | SQLite file of the user (see [Database](#database)) | SQLAlchemy URL of the database, **shared** by both processes |
| `SECREVIEW_DATABASE_ECHO` | `false` | Logs the SQL queries |
| `SECREVIEW_DB_AUTO_UPGRADE` | `true` | Migrates the schema at start-up of the controller, of the stdio MCP server and of the CLI commands; when `false`, they only check that it is up to date (see [migrations](../advanced/controller.md#schema-migrations)). The HTTP MCP server never migrates |
| `SECREVIEW_LOG_LEVEL` | `INFO` | Logging level (on stderr) |

### Listening, TLS and reverse proxy

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_HOST` | `127.0.0.1` (`0.0.0.0` in the Docker image) | Listening address (HTTP) of the process. With Docker, keep the value of the image and choose the address of the host in the published ports (see [Docker](../advanced/docker.md#docker-compose-with-postgresql)) |
| `SECREVIEW_PORT` | `8000` | Listening port (HTTP) |
| `SECREVIEW_TLS_CERTFILE` | — | Certificate: enables TLS |
| `SECREVIEW_TLS_KEYFILE` | — | Private key |
| `SECREVIEW_TLS_KEYFILE_PASSWORD` | — | Password of the private key |
| `SECREVIEW_TLS_CLIENT_CA` | — | Client CA: enables mutual TLS |
| `SECREVIEW_FORWARDED_ALLOW_IPS` | — | Reverse proxies (IP addresses or CIDR ranges separated by commas, `*` for any) whose `X-Forwarded-For` gives the client address, used by the login throttling, the audit log and the logs; without it, the uvicorn default (`FORWARDED_ALLOW_IPS` variable, else `127.0.0.1`). Set it behind an Ingress or a reverse proxy, or every client shares the address of the proxy |

### Shared limits

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` | `7` | Days a project requested by the MCP agent of a user (`request_project`) waits for an approval (1 to 365) before it is deleted |
| `SECREVIEW_MAX_FINDINGS_PER_REPORT` | `500` | Maximum number of findings per report |
| `SECREVIEW_MAX_DEPENDENCY_CHARS` | `1000000` | Maximum size of a manifest passed to `scan_dependencies` or sent by `security-review-ci scan-deps` |
| `SECREVIEW_MAX_LIST_LIMIT` | `100` | Maximum size of a page of results |

## MCP server

Read by `security-review-mcp` only.

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_TRANSPORT` | `streamable-http` | `streamable-http` (shared mode) or `stdio` (local mode) |
| `SECREVIEW_ALLOW_UNAUTHENTICATED` | `false` | While no token exists, accepts every request on `/mcp` even when the server does not listen on localhost (by default it then stays closed, see [Bearer tokens](../advanced/bearer-tokens.md)); only for tests on an isolated network |
| `SECREVIEW_ENROLLMENT` | `true` | [Enrollment](../advanced/mcp-server.md#enrollment-personal-token-and-project-requests): a client without a token reaches a restricted MCP server, without any tool, that tells the user to create a personal MCP token in the web interface; with a token, `request_project` creates a new project for a user holding `projects.create`, else requests it for a user with `projects.create` to approve. `false`: `401` without a token, and no project request |
| `SECREVIEW_REPORT_LANGUAGE` | — | [Report language](../usage/prompts-tools.md#report-language) asked by the review prompts (`French`, `fr`...) when the `report_language` argument is missing; when set (even empty: the agent chooses), takes precedence over the language chosen in the [**Report language**](../usage/web-interface.md#screens) screen |
| `SECREVIEW_MAX_CONTENT_CHARS` | `200000` | Maximum size of the content passed to `scan_code`, and of each text of a report (`summary`, `scope`, `description`, `evidence`, `recommendation`) |
| `SECREVIEW_MAX_MCP_REQUEST_MB` | `16` | Maximum size of a request of an authenticated MCP client on `/mcp` (`413` beyond); a client without a token, sent to the enrollment server, is bounded to 64 KiB |

## Controller

Read by `security-review-controller` only.

### Web interface and sessions

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_ADMIN_USERNAME` | `admin` | Name of the [first administrator](../advanced/controller.md#first-administrator), created at the first start while no account exists (`administrators` group), with a random password never logged: set it with `security-review-controller user reset-password` |
| `SECREVIEW_SECRET_KEY` | — | Signing secret of the web interface sessions (accounts and OIDC), at least 32 characters, identical on every replica; unset: a random secret at every start (sessions end at restart) |
| `SECREVIEW_CONTROLLER_URL` | — | Public root URL of the controller (`https://…`, without `/ui`), the same as for [`security-review-ci`](#clients). Copied to the database at each start; the MCP server reads it there (it ignores its own variable) and gives the address of the web interface (`/ui`) to the clients without a valid token (instructions and prompts of the enrollment server, `401` of `/mcp`), so that the user knows where to sign in and create a personal MCP token; the connectors use it for their links. Unset, it is set in the [**General**](../usage/web-interface.md#screens) screen; without any, no link is given |
| `SECREVIEW_SESSION_HOURS` | `8` | Lifetime of a web interface session (1 to 24 hours) |
| `SECREVIEW_WEB_UI` | `true` | Serves the [web interface](../usage/web-interface.md) on `/ui`; when `false`, only the REST API |
| `SECREVIEW_WEB_UI_DIR` | — | Folder of another build of the web interface |
| `SECREVIEW_SWAGGER_ENABLED` | `false` | Serve the Swagger documentation (`/api/docs`) and the OpenAPI schema (`/api/openapi.json`), from the files of the web interface build |
| `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED` | `true` | Serve the pipeline client on `/api/ci-client/` (public), so that developers install it with `uv --find-links`, without PyPI ([from the controller](../advanced/ci.md#from-the-controller)) |
| `SECREVIEW_UPDATE_CHECK_ENABLED` | `false` | The **About** page searches GitHub for a newer release (HTTPS, through the outgoing proxy, cached 6 hours, see [security](security.md#security-of-the-server-itself)) |

### Rate limiting

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_RATE_LIMIT_ENABLED` | `true` | Limit the requests of each client address to the REST API (`429` over the limit); counted in the database, shared by every replica |
| `SECREVIEW_RATE_LIMIT_WINDOW_SECONDS` | `60` | Window of the limits, in seconds (1 to 3600) |
| `SECREVIEW_RATE_LIMIT_MAX_REQUESTS` | `600` | Requests of an address to `/api/` per window |
| `SECREVIEW_RATE_LIMIT_AUTH_MAX_REQUESTS` | `30` | Requests of an address to the login routes (`/api/v1/auth/`) per window |

### OIDC login

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_OIDC_ENABLED` | `false` | Enables the [OpenID Connect OIDC login](../advanced/sso.md) to the web interface. Every `SECREVIEW_OIDC_*` variable except `SECREVIEW_OIDC_CAFILE` and `SECREVIEW_OIDC_ONLY` can also be set in the **OIDC** screen, whose stored values apply when the variable is not set ([configuring OIDC in the interface](../advanced/sso.md#configuring-oidc-in-the-interface)) |
| `SECREVIEW_OIDC_ISSUER` | — | URL of the issuer (HTTPS; HTTP only on localhost), whose `/.well-known/openid-configuration` is read |
| `SECREVIEW_OIDC_CLIENT_ID` | — | Identifier of the client declared at the provider |
| `SECREVIEW_OIDC_CLIENT_SECRET` | — | Secret of the client; empty for a public client (PKCE only) |
| `SECREVIEW_OIDC_REDIRECT_URI` | — | Public URL of `/api/v1/auth/oidc/callback`, declared at the provider |
| `SECREVIEW_OIDC_SCOPE` | `openid profile email` | Requested scopes (must contain `openid`) |
| `SECREVIEW_OIDC_ROLES_CLAIM` | `groups` | Claim of the groups or roles, dotted path accepted (`realm_access.roles`); its values are matched against the names of the [groups open to OIDC](../advanced/sso.md#groups-of-the-identity-provider) |
| `SECREVIEW_OIDC_ADMIN_GROUPS` | — | OIDC groups, comma separated, created open to OIDC with the `admin` role at the first login of one of their members (first administrator) |
| `SECREVIEW_OIDC_DEFAULT_GROUP` | — | Group every OIDC user joins at each login, whatever its claim (empty: none) |
| `SECREVIEW_OIDC_USERNAME_CLAIM` | `preferred_username` | Claim that names the [OIDC account](../advanced/sso.md#oidc-accounts) (exact comparison, no fallback); session label `oidc:<value>` |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Creates the OIDC account at its first login if its groups give it a role; when `false`, an administrator creates every OIDC account in **Users** |
| `SECREVIEW_OIDC_DISPLAY_NAME` | `OIDC` | Name shown on the login button (40 characters at most) |
| `SECREVIEW_OIDC_CAFILE` | — | CA bundle to reach the provider (internal CA); the proxy is the one of `HTTPS_PROXY` |
| `SECREVIEW_OIDC_ONLY` | `false` | With OIDC enabled, refuses the password login of the local accounts ([OIDC only](../advanced/sso.md#oidc-only)); a variable only, never changed in the interface |

### Outgoing proxy

| Variable | Default | Role |
|---|---|---|
| `HTTPS_PROXY` (else `HTTP_PROXY`) | — | Standard variable, without the `SECREVIEW_` prefix (lowercase name accepted): HTTP proxy of the outgoing connections of the controller, OSV download and OIDC provider (`http://[user:password@]host:port`, `host:port` meaning `http://host:port`); without it, the connection is direct, or uses the proxy chosen in the [**Outgoing proxy**](../usage/web-interface.md#screens) screen. When set (not empty), takes precedence over that screen |
| `NO_PROXY` | — | Standard variable: [hosts reached without the proxy](../advanced/dependencies.md#hosts-without-proxy), comma separated: domains (subdomains included), IP addresses, `*` (no CIDR ranges); the loopback is always direct. When set (not empty), takes precedence over the list of the **Outgoing proxy** screen |

### OSV database

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_OSV_AUTO_UPDATE` | `false` | [Daily update](../advanced/dependencies.md#automatic-update-by-the-controller) of the OSV database by `serve` |
| `SECREVIEW_OSV_UPDATE_INTERVAL_HOURS` | `24` | Age of the database beyond which `serve` updates it (minimum `1`) |
| `SECREVIEW_OSV_URL` | `https://osv-vulnerabilities.storage.googleapis.com` | Source of the `<URL>/<ecosystem>/all.zip` exports (HTTPS only, mirror possible) |
| `SECREVIEW_OSV_ECOSYSTEMS` | `PyPI,npm,Maven,Go,crates.io,NuGet` | Downloaded ecosystems, comma separated |
| `SECREVIEW_OSV_CAFILE` | — | CA bundle used instead of the system one (internal mirror, proxy that inspects TLS) |
| `SECREVIEW_OSV_MAX_DOWNLOAD_MB` | `1024` | Maximum size of a downloaded archive |

### Findings, reports and tokens

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` | `90` | Age in days beyond which `serve` deletes the [reports without findings](#retention-of-reports-without-findings); `0` keeps every report |
| `SECREVIEW_MAX_DISMISSAL_DAYS` | `365` | Longest validity in days of an `accepted` or `false_positive` [decision](../usage/triage.md): its expiry date may not be later |
| `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED` | `true` | A person may [accept a risk](../usage/triage.md) with **No expiry**: the acceptance lasts until someone reopens the finding. `false`: every acceptance needs an expiry date. A false positive never needs one |
| `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY` | `medium` | Lowest severity (`critical`, `high`, `medium`, `low`, `info`) whose [risk acceptance](../usage/triage.md) needs a reason and an expiry date. A less severe finding is accepted by a plain validation, which closes it with no reason and no date. Empty: every acceptance needs them |
| `SECREVIEW_TOKEN_MAX_DAYS` | `0` | Longest validity in days of a bearer token created or [rotated](../advanced/bearer-tokens.md#expiry-and-rotation-of-tokens) (CLI, web interface), which is also its default validity; `0`: tokens do not expire unless a validity is asked for |
| `SECREVIEW_PERSONAL_TOKENS_PER_USER` | `1` | Personal tokens a web user may hold of each role, [REST API](../usage/tokens.md#api-tokens) and [MCP](../usage/tokens.md#personal-mcp-and-ci-tokens), from `1` to `10`: revoke one to create another |

### Audit and metrics

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_AUDIT_RETENTION_DAYS` | `365` | Age in days beyond which `serve` deletes the events of the [audit log](../advanced/audit-metrics.md); `0` keeps every event |
| `SECREVIEW_AUDIT_MAX_EVENTS` | `0` | Number of [audit events](../advanced/audit-metrics.md#retention) kept at most by the same daily purge (the oldest are deleted); `0`: no limit |
| `SECREVIEW_AUDIT_SYSLOG_ADDRESS` | — | [Forwards the audit events to syslog](../advanced/audit-metrics.md#forwarding-to-syslog): `udp://host:port`, `tcp://host:port`, `tls://host:port` (RFC 5425, port 6514 by default) or `unix:///dev/log` (no proxy); disabled when unset; without it, the server set on the **Audit log** page applies. When set (not empty), takes precedence over that page |
| `SECREVIEW_AUDIT_SYSLOG_FACILITY` | `local0` | Syslog facility of these messages (`local0` to `local7`, `auth`, `authpriv`, `daemon`...); when set, takes precedence over the one chosen on the **Audit log** page |
| `SECREVIEW_AUDIT_SYSLOG_CAFILE` | — | CA bundle that verifies the certificate of a `tls://` syslog server (internal certificate authority); default: the system CA bundle. A variable only |
| `SECREVIEW_METRICS_ENABLED` | `true` | Serves the [Prometheus metrics](metrics.md) on `/metrics` (`metrics` or `admin` token); when `false`, `/metrics` answers 404 |

### Connectors

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_CONNECTORS_ENABLED` | `true` | Lock of the [connectors](../connectors/index.md#enabling) (Jira, ServiceNow, third-party; outgoing connections of the controller): `true`, each one is switched on in the **Connectors** screen (all off by default); `false`, all locked off |
| `SECREVIEW_CONNECTORS_INTERVAL_SECONDS` | `300` | Period of the [automatic sending](../connectors/index.md#sending-a-finding) (30 to 86400) |
| `SECREVIEW_CONNECTORS_CAFILE` | — | CA bundle used instead of the system one (internal authority) |
| `SECREVIEW_CONNECTORS_PLUGINS` | — | [Third-party connectors](../connectors/third-party.md) allowed, by entry point name, comma separated; one installed but not listed is never loaded |
| `SECREVIEW_JIRA_URL`, `SECREVIEW_JIRA_USERNAME`, `SECREVIEW_JIRA_API_TOKEN`, `SECREVIEW_JIRA_ISSUE_TYPE` (`Bug`) | — | [Jira connection](../connectors/jira.md#connection); when set, takes precedence over the **Connectors** screen |
| `SECREVIEW_SERVICENOW_URL`, `SECREVIEW_SERVICENOW_USERNAME`, `SECREVIEW_SERVICENOW_PASSWORD`, `SECREVIEW_SERVICENOW_TABLE` (`incident`) | — | [ServiceNow connection](../connectors/servicenow.md#connection); when set, takes precedence over the **Connectors** screen |
| `SECREVIEW_<KIND>_<FIELD>` | — | Field of the connection of a [third-party connector](../connectors/third-party.md) (`SECREVIEW_ACME_API_KEY`) |

### Pipeline scan limits

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_MAX_SCAN_REQUEST_MB` | `64` | Maximum size of a request of [`security-review-ci scan-code` or `scan-deps`](../advanced/code-scan.md#limits-of-the-controller) (`413` beyond) |
| `SECREVIEW_MAX_SCAN_FILES` | `10000` | Maximum number of files of a scan request (`422` beyond) |
| `SECREVIEW_MAX_SCAN_FILE_CHARS` | `1048576` | Size beyond which a file sent by `scan-code` is not scanned (listed as skipped) |

## Clients

Read by the pipeline client `security-review-ci` (`SECREVIEW_TOKEN` never by the servers).

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_TOKEN` | — | Bearer token sent by [`security-review-ci`](../advanced/ci.md) to the controller (`ci` token); never used by the servers |
| `SECREVIEW_CONTROLLER_URL` | — | URL of the controller used by [`security-review-ci`](../advanced/ci.md) (default of `--url`); read from the environment only, never from `.env`. The controller reads the same variable for [its public URL](#web-interface-and-sessions) |

Bearer tokens are not configured by variable: they are stored in the database and managed with
`security-review-controller token` (see
[Authentication and TLS](../advanced/bearer-tokens.md)). Neither are internal rules:
they are stored in the database and managed with `security-review-controller rules` (see
[Rules](../usage/rules.md#rules-command)).

## Database

An SQLite database is created by default in the user's data folder:
`~/.local/share/security-review-mcp/security_reports.db` when `XDG_DATA_HOME` is not set.

For PostgreSQL (`postgres` extra, shared mode only: the stdio server accepts SQLite only):

```bash
SECREVIEW_DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/secreview
```

A PostgreSQL ready to use: [Docker Compose](../advanced/docker.md#docker-compose-with-postgresql) or
[Kubernetes](../advanced/kubernetes.md#deployment).

The schema is managed by Alembic migrations embedded in the package: **security-review-controller**
 - `security-review-controller db upgrade` creates or migrates the database and seeds the default
rules,
 - `security-review-controller db status` shows the revision (code `1` if it is not up to date). See
[Schema migrations](../advanced/controller.md#schema-migrations).

### Retention of reports without findings

The controller deletes these reports once they are older than
`SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` days (default `90`): at the start, then every
day. The latest report of each project is always kept, so a project never disappears from the
list, and a report with findings is never deleted, whatever their status. `0` disables the
purge.

The same purge can be run on demand, for example from a scheduled job when the controller is
not running:

```bash
security-review-controller db prune              # retention of SECREVIEW_EMPTY_REPORT_RETENTION_DAYS
security-review-controller db prune --days 30    # another retention, for this run only
# {"retention_days": 30, "deleted": 4}
```
