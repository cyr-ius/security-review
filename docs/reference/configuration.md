# Configuration

The MCP server and the controller read environment variables prefixed with `SECREVIEW_`, or a
`.env` file in the current directory (see `.env.example`). The **Process** column says who
uses the variable: `MCP` (`security-review-mcp`), `Controller` (`security-review-controller`)
or both.

| Variable | Default | Process | Role |
|---|---|---|---|
| `SECREVIEW_DATABASE_URL` | `sqlite:///./security_reports.db` | both | SQLAlchemy URL of the database, **shared** by both processes |
| `SECREVIEW_DATABASE_ECHO` | `false` | both | Logs the SQL queries |
| `SECREVIEW_DB_AUTO_UPGRADE` | `true` | both | Migrates the schema at start-up of the controller, of the stdio MCP server and of the CLI commands; when `false`, they only check that it is up to date (see [migrations](../advanced/architecture.md#schema-migrations)). The HTTP MCP server never migrates |
| `SECREVIEW_TRANSPORT` | `stdio` | MCP | `stdio` or `streamable-http` |
| `SECREVIEW_HOST` | `127.0.0.1` | both | Listening address (HTTP) |
| `DOCKER_MCP_PORT` | `8000` | both | Listening port (HTTP) |
| `SECREVIEW_ADMIN_USERNAME` | `admin` | Controller | Name of the [first administrator](../usage/web-interface.md#first-administrator), created at the first start while no account exists (`administrators` group) |
| `SECREVIEW_ADMIN_PASSWORD` | — | Controller | Initial password of that account, to change at the first login, never logged (it must follow the password policy); unset: a random password, set with `security-review-controller user reset-password` |
| `SECREVIEW_ADMIN_PASSWORD_LOG` | `false` | Controller | Writes the random password of the first administrator once in the logs (first test only) |
| `SECREVIEW_ALLOW_UNAUTHENTICATED` | `false` | MCP | While no token exists, accepts every request on `/mcp` even when the server does not listen on localhost (by default it then stays closed, see [Bearer tokens](../advanced/http.md#bearer-tokens)); only for tests on an isolated network |
| `SECREVIEW_SECRET_KEY` | — | Controller | Signing secret of the web interface sessions (accounts and OIDC), at least 32 characters, identical on every replica; without it, read from `SECREVIEW_SECRET_KEY_FILE` |
| `SECREVIEW_SECRET_KEY_FILE` | `secret-key` | Controller | File of the session secret when `SECREVIEW_SECRET_KEY` is unset: generated at the first start (mode `0600`), read at the next ones; `""`: a random secret at every start (sessions end at restart) |
| `SECREVIEW_SESSION_HOURS` | `8` | Controller | Lifetime of a web interface session (1 to 24 hours) |
| `SECREVIEW_ENROLLMENT` | `true` | MCP | [Enrollment](../advanced/http.md#enrollment-a-project-requests-its-token): a client without a token can request a project token (restricted MCP server, `POST /api/v1/enroll`), active after approval on the controller |
| `SECREVIEW_SERVER_URL` | — | Client | URL of the shared MCP server used by [`security-review-mcp scan-deps`](../advanced/dependencies.md#scan-with-a-shared-server-commit-hook) (default of `--url`); never used by the servers |
| `SECREVIEW_TOKEN` | — | Client | Bearer token sent by `scan-deps` to that server, and by [`security-review-ci`](../usage/gate.md#pipeline-client-security-review-ci) to the controller (`ci` token); never used by the servers |
| `SECREVIEW_CONTROLLER_URL` | — | Client | URL of the controller used by [`security-review-ci`](../usage/gate.md#pipeline-client-security-review-ci) (default of `--url`); read from the environment only, never from `.env` |
| `SECREVIEW_TLS_CERTFILE` | — | both | Certificate: enables TLS |
| `SECREVIEW_TLS_KEYFILE` | — | both | Private key |
| `SECREVIEW_TLS_KEYFILE_PASSWORD` | — | both | Password of the private key |
| `SECREVIEW_TLS_CLIENT_CA` | — | both | Client CA: enables mutual TLS |
| `SECREVIEW_FORWARDED_ALLOW_IPS` | — | both | Reverse proxies (IP addresses or CIDR ranges separated by commas, `*` for any) whose `X-Forwarded-For` gives the client address, used by the login throttling, the enrollment limits and the logs; without it, the uvicorn default (`FORWARDED_ALLOW_IPS` variable, else `127.0.0.1`). Set it behind an Ingress or a reverse proxy, or every client shares the address of the proxy |
| `SECREVIEW_RATE_LIMIT_ENABLED` | `true` | Controller | Limit the requests of each client address to the REST API (`429` over the limit); counted in the database, shared by every replica |
| `SECREVIEW_RATE_LIMIT_WINDOW_SECONDS` | `60` | Controller | Window of the limits, in seconds (1 to 3600) |
| `SECREVIEW_RATE_LIMIT_MAX_REQUESTS` | `600` | Controller | Requests of an address to `/api/` per window |
| `SECREVIEW_RATE_LIMIT_AUTH_MAX_REQUESTS` | `30` | Controller | Requests of an address to the login routes (`/api/v1/auth/`) per window |
| `SECREVIEW_WEB_UI` | `true` | Controller | Serves the [web interface](../usage/web-interface.md) on `/ui`; when `false`, only the REST API |
| `SECREVIEW_WEB_UI_DIR` | — | Controller | Folder of another build of the web interface |
| `SECREVIEW_SWAGGER_ENABLED` | `false` | Controller | Serve the Swagger documentation (`/api/docs`) and the OpenAPI schema (`/api/openapi.json`), from the files of the web interface build |
| `SECREVIEW_OIDC_ENABLED` | `false` | Controller | Enables the [OpenID Connect OIDC login](../advanced/sso.md) to the web interface. Every `SECREVIEW_OIDC_*` variable except `SECREVIEW_OIDC_CAFILE` and `SECREVIEW_OIDC_ONLY` can also be changed in the **OIDC** screen, whose stored values replace them ([configuring OIDC in the interface](../advanced/sso.md#configuring-oidc-in-the-interface)) |
| `SECREVIEW_OIDC_ISSUER` | — | Controller | URL of the issuer (HTTPS; HTTP only on localhost), whose `/.well-known/openid-configuration` is read |
| `SECREVIEW_OIDC_CLIENT_ID` | — | Controller | Identifier of the client declared at the provider |
| `SECREVIEW_OIDC_CLIENT_SECRET` | — | Controller | Secret of the client; empty for a public client (PKCE only) |
| `SECREVIEW_OIDC_REDIRECT_URI` | — | Controller | Public URL of `/api/v1/auth/oidc/callback`, declared at the provider |
| `SECREVIEW_OIDC_SCOPE` | `openid profile email` | Controller | Requested scopes (must contain `openid`) |
| `SECREVIEW_OIDC_ROLES_CLAIM` | `groups` | Controller | Claim of the groups or roles, dotted path accepted (`realm_access.roles`); its values are matched against the names of the [groups open to OIDC](../advanced/sso.md#groups-of-the-identity-provider) |
| `SECREVIEW_OIDC_ADMIN_GROUPS` | — | Controller | OIDC groups, comma separated, created open to OIDC with the `admin` role at the first login of one of their members (first administrator) |
| `SECREVIEW_OIDC_DEFAULT_GROUP` | — | Controller | Group every OIDC user joins at each login, whatever its claim (empty: none) |
| `SECREVIEW_OIDC_USERNAME_CLAIM` | `preferred_username` | Controller | Claim that names the [OIDC account](../advanced/sso.md#oidc-accounts) (exact comparison, no fallback); session label `oidc:<value>` |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Controller | Creates the OIDC account at its first login if its groups give it a role; when `false`, an administrator creates every OIDC account in **Users** |
| `SECREVIEW_OIDC_DISPLAY_NAME` | `OIDC` | Controller | Name shown on the login button (40 characters at most) |
| `SECREVIEW_OIDC_CAFILE` | — | Controller | CA bundle to reach the provider (internal CA); the proxy is the one of `HTTPS_PROXY` |
| `SECREVIEW_OIDC_ONLY` | `false` | Controller | With OIDC enabled, refuses the password login of the local accounts ([OIDC only](../advanced/sso.md#oidc-only)); a variable only, never changed in the interface |
| `HTTPS_PROXY` (else `HTTP_PROXY`) | — | Controller | Standard variable, without the `SECREVIEW_` prefix (lowercase name accepted): HTTP proxy of the outgoing connections of the controller, OSV download and OIDC provider (`http://[user:password@]host:port`, `host:port` meaning `http://host:port`); without it, the connection is direct. Replaced by the proxy chosen in the [**Outgoing proxy**](../usage/web-interface.md#screens) screen (or the direct connection) |
| `NO_PROXY` | — | Controller | Standard variable: [hosts reached without the proxy](../advanced/dependencies.md#hosts-without-proxy), comma separated: domains (subdomains included), IP addresses, `*` (no CIDR ranges); the loopback is always direct. Replaced by the list of the **Outgoing proxy** screen |
| `SECREVIEW_OSV_AUTO_UPDATE` | `false` | Controller | [Daily update](../advanced/dependencies.md#automatic-update-by-the-controller) of the OSV database by `serve` |
| `SECREVIEW_OSV_UPDATE_INTERVAL_HOURS` | `24` | Controller | Age of the database beyond which `serve` updates it (minimum `1`) |
| `SECREVIEW_OSV_URL` | `https://osv-vulnerabilities.storage.googleapis.com` | Controller | Source of the `<URL>/<ecosystem>/all.zip` exports (HTTPS only, mirror possible) |
| `SECREVIEW_OSV_ECOSYSTEMS` | `PyPI,npm,Maven` | Controller | Downloaded ecosystems, comma separated |
| `SECREVIEW_OSV_CAFILE` | — | Controller | CA bundle used instead of the system one (internal mirror, proxy that inspects TLS) |
| `SECREVIEW_OSV_MAX_DOWNLOAD_MB` | `1024` | Controller | Maximum size of a downloaded archive |
| `SECREVIEW_REPORT_LANGUAGE` | — | MCP | [Report language](../usage/prompts-tools.md#report-language) asked by the review prompts (`French`, `fr`...) when the `report_language` argument is missing and no language is chosen in the [**Report language**](../usage/web-interface.md#screens) screen; empty: the agent chooses |
| `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` | `90` | Controller | Age in days beyond which `serve` deletes the [reports without findings](#retention-of-reports-without-findings); `0` keeps every report |
| `SECREVIEW_MAX_DISMISSAL_DAYS` | `365` | Controller | Longest validity in days of an `accepted` or `false_positive` [decision](../usage/web-interface.md#triage-of-findings): its expiry date may not be later |
| `SECREVIEW_TOKEN_MAX_DAYS` | `0` | Controller | Longest validity in days of a bearer token created or [rotated](../advanced/http.md#expiry-and-rotation-of-tokens) (CLI, web interface, enrollment), which is also its default validity; `0`: tokens do not expire unless a validity is asked for |
| `SECREVIEW_AUDIT_RETENTION_DAYS` | `365` | Controller | Age in days beyond which `serve` deletes the events of the [audit log](../advanced/audit-metrics.md#audit-log); `0` keeps every event |
| `SECREVIEW_AUDIT_MAX_EVENTS` | `0` | Controller | Number of [audit events](../advanced/audit-metrics.md#retention) kept at most by the same daily purge (the oldest are deleted); `0`: no limit |
| `SECREVIEW_AUDIT_SYSLOG_ADDRESS` | — | Controller | [Forwards the audit events to syslog](../advanced/audit-metrics.md#forwarding-to-syslog): `udp://host:port`, `tcp://host:port` or `unix:///dev/log` (no TLS, no proxy); disabled when unset |
| `SECREVIEW_AUDIT_SYSLOG_FACILITY` | `local0` | Controller | Syslog facility of these messages (`local0` to `local7`, `auth`, `authpriv`, `daemon`...) |
| `SECREVIEW_METRICS_ENABLED` | `true` | Controller | Serves the [Prometheus metrics](../advanced/audit-metrics.md#prometheus-metrics) on `/metrics` (`metrics` or `admin` token); when `false`, `/metrics` answers 404 |
| `SECREVIEW_UPDATE_CHECK_ENABLED` | `false` | Controller | The **About** page searches GitHub for a newer release (HTTPS, through the outgoing proxy, cached 6 hours, see [security](security.md#security-of-the-server-itself)) |
| `SECREVIEW_LOG_LEVEL` | `INFO` | both | Logging level (on stderr) |
| `SECREVIEW_MAX_CONTENT_CHARS` | `200000` | MCP | Maximum size of the content passed to `scan_code` |
| `SECREVIEW_MAX_FINDINGS_PER_REPORT` | `500` | both | Maximum number of findings per report |
| `SECREVIEW_MAX_DEPENDENCY_CHARS` | `1000000` | MCP | Maximum size of a manifest passed to `scan_dependencies` |
| `SECREVIEW_MAX_LIST_LIMIT` | `100` | both | Maximum size of a page of results |

Bearer tokens are not configured by variable: they are stored in the database and managed with
`security-review-controller token` (see
[HTTP server, authentication and TLS](../advanced/http.md)). Neither are internal rules:
they are stored in the database and managed with `security-review-controller rules` (see
[Internal rules](../advanced/rules.md)).

## Database

SQLite by default. For PostgreSQL (`postgres` extra):

```bash
SECREVIEW_DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/secreview
```

The schema is managed by Alembic migrations embedded in the package:
`security-review-controller db upgrade` creates or migrates the database and seeds the default
rules, `db status` shows the revision (code `1` if it is not up to date). See
[Schema migrations](../advanced/architecture.md#schema-migrations).

### Retention of reports without findings

A clean review (report without any finding) only proves that nothing was found at that date.
The controller deletes these reports once they are older than
`SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` days (default `90`): at the start of `serve`, then every
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
