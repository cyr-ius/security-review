# Configuration

The MCP server and the Controller server read environment variables prefixed with `SECREVIEW_`, or a
`.env` file in the current directory (see `.env.example`). The variables are grouped below by
the process that reads them: [both](#both-processes), the [MCP server](#mcp-server)
(`security-review-mcp`), the [Controller server](#controller-server) (`security-review-controller`) or the
[clients](#clients).

Some settings can also be set in the [web interface](../usage/index.md#pages): report
language, outgoing proxy, OIDC login and syslog server of the audit log. **A variable that is set always takes precedence**
over the value of the interface, which only applies when the variable is not set (the page
then locks the field).

## Both processes

Read by the MCP server and by the Controller server.

### Database and logs

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_DATABASE_URL` | SQLite file of the user (see [Database](../advanced/database.md)) | SQLAlchemy URL of the database, **shared** by both processes |
| `SECREVIEW_DATABASE_ECHO` | `false` | Logs the SQL queries |
| `SECREVIEW_DB_AUTO_UPGRADE` | `true` | Migrates the schema at start-up of the Controller server, of the stdio MCP server and of the CLI commands; leave it as is unless migrations are run by a [dedicated job](../advanced/database.md#dedicated-migration-job), where `false` makes them only check the schema. The HTTP MCP server never migrates |
| `SECREVIEW_LOG_LEVEL` | `INFO` | Logging level (on stderr) |

### Listening, TLS and reverse proxy

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_HOST` | `127.0.0.1` (`0.0.0.0` in the Docker image) | Listening address (HTTP) of the process. With Docker, keep the value of the image and choose the address of the host in the published ports (see [Docker](../advanced/deployment/docker.md#docker-compose-with-postgresql)) |
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
| `SECREVIEW_TRANSPORT` | `streamable-http` | `streamable-http` or `http` (shared mode), or `stdio` (local mode), whatever the case; mode of the `mcp` command of the [Docker image](../advanced/deployment/docker.md#choosing-the-process) |
| `SECREVIEW_ALLOW_UNAUTHENTICATED` | `false` | While no token exists, accepts every request on `/mcp` even when the server does not listen on localhost (by default it then stays closed, see [Bearer tokens](../advanced/bearer-tokens.md)); only for tests on an isolated network |
| `SECREVIEW_REPORT_LANGUAGE` | — | [Report language](../review/prompts-tools.md#report-language) asked by the review prompts (`French`, `fr`...) when the `report_language` argument is missing; when set (even empty: the agent chooses), takes precedence over the language chosen on the [**Report language**](../usage/index.md#pages) page |
| `SECREVIEW_MAX_CONTENT_CHARS` | `200000` | Maximum size of the content passed to `scan_code`, and of each text of a report (`summary`, `scope`, `description`, `evidence`, `recommendation`) |
| `SECREVIEW_MAX_MCP_REQUEST_MB` | `16` | Maximum size of a request of an authenticated MCP client on `/mcp` (`413` beyond); a client without a token, sent to the enrollment server, is bounded to 64 KiB |
| `SECREVIEW_MCP_SCAN_CONTROLLER_URL` | — | Deprecated: set [`SECREVIEW_SCANCODE_DELEGATED`](#web-interface-and-sessions) on the Controller server instead. Still read, with a warning: root URL of the Controller server to which `scan_code` delegates its scan; takes precedence over the delegation stored by the Controller server. The Controller server only answers while its own delegation is on (`SECREVIEW_SCANCODE_DELEGATED` or the web interface): without it, `scan_code` falls back to the rules of the MCP server |
| `SECREVIEW_MCP_SCAN_TIMEOUT_SECONDS` | `120` | Maximum duration of a delegated scan, OpenGrep included (1 to 7200); beyond, `scan_code` scans with the rules of the MCP server |

## Controller server

Read by `security-review-controller` only.

### Web interface and sessions

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_ADMIN_USERNAME` | `admin` | Name of the [first administrator](../advanced/architecture/controller.md#first-administrator), created at the first start while no account exists (`admin` role, with the reading, the writing and the triage of every project), with a random password never logged: set it with `security-review-controller user reset-password` |
| `SECREVIEW_SECRET_KEY` | — | Signing secret of the web interface sessions (accounts and OIDC), at least 32 characters, identical on every replica; unset: a random secret at every start (sessions end at restart) |
| `SECREVIEW_PUBLIC_URL` | — | Public root URL of the Controller server (`https://…`, without `/ui`), often the same address as `SECREVIEW_CONTROLLER_URL` of [`security-review-ci`](#clients). Copied to the database at each start; the MCP server reads it there (it ignores its own variable) and gives the address of the web interface (`/ui`) to the clients without a valid token (instructions and prompts of the enrollment server, `401` of `/mcp`), so that the user knows where to sign in and create a personal MCP token; the connectors use it for their links. Unset, it is set on the [**General**](../usage/index.md#pages) page; without any, no link is given. `SECREVIEW_CONTROLLER_URL`, its former name, is still read by the Controller server when it is not set, with a warning |
| `SECREVIEW_SCANCODE_DELEGATED` | — | [Delegation of `scan_code`](../review/analysis/opengrep.md#fragment-scans-scan_code) of the MCP server to the Controller server, with the token of the agent, to apply its rules and OpenGrep rules too: `true` to the public URL (`SECREVIEW_PUBLIC_URL`, required), a root URL to that address as seen by the MCP server (`http://controller:8080` inside Compose), `false` off. Copied to the database at each start, where the MCP server reads it (it needs no variable); set, the **General** page cannot change it, and removing a variable that gave an address turns the delegation off. Unset: the switch of the **General** page decides (off by default, no outgoing connection of the MCP server) |
| `SECREVIEW_SCAN_TICKET_TTL_SECONDS` | `600` | Validity of the single-use ticket that [`start_codebase_scan`](../review/analysis/code-scan.md#scan-started-by-the-agent-start_codebase_scan) gives the agent for `security-review-ci` (60 to 3600) |
| `SECREVIEW_SESSION_HOURS` | `8` | Lifetime of a web interface session (1 to 24 hours) |
| `SECREVIEW_WEB_UI` | `true` | Serves the [web interface](../usage/index.md) on `/ui`; when `false`, only the REST API |
| `SECREVIEW_WEB_UI_DIR` | — | Folder of another build of the web interface |
| `SECREVIEW_SWAGGER_ENABLED` | `false` | Serve the Swagger documentation (`/api/docs`) and the OpenAPI schema (`/api/openapi.json`), from the files of the web interface build |
| `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED` | `true` | Serve the pipeline client on `/api/ci-client/` (public), so that developers install it with `uv --find-links`, without PyPI ([from the Controller server](../advanced/architecture/ci.md#from-the-controller-server)) |
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
| `SECREVIEW_OIDC_ENABLED` | `false` | Enables the [OpenID Connect OIDC login](../advanced/oidc.md) to the web interface. Every `SECREVIEW_OIDC_*` variable except `SECREVIEW_OIDC_CAFILE` and `SECREVIEW_OIDC_ONLY` can also be set on the **Sign-in** page, whose stored values apply when the variable is not set ([configuring OIDC in the interface](../advanced/oidc.md#configuring-oidc-in-the-interface)) |
| `SECREVIEW_OIDC_ISSUER` | — | URL of the issuer (HTTPS; HTTP only on localhost), whose `/.well-known/openid-configuration` is read |
| `SECREVIEW_OIDC_CLIENT_ID` | — | Identifier of the client declared at the provider |
| `SECREVIEW_OIDC_CLIENT_SECRET` | — | Secret of the client; empty for a public client (PKCE only) |
| `SECREVIEW_OIDC_REDIRECT_URI` | — | Public URL of `/api/v1/auth/oidc/callback`, declared at the provider |
| `SECREVIEW_OIDC_SCOPE` | `openid profile email` | Requested scopes (must contain `openid`) |
| `SECREVIEW_OIDC_ROLES_CLAIM` | `groups` | Claim of the groups or roles, dotted path accepted (`realm_access.roles`); its values are matched against the [OIDC mappings](../advanced/oidc.md#oidc-mappings) |
| `SECREVIEW_OIDC_ADMIN_GROUPS` | — | Values of the roles claim, comma separated, mapped to `admin`, with the reading, the writing and the triage of every project, at the login of a user who holds one, when no mapping names them (first administrator); a deleted mapping comes back at the next such login |
| `SECREVIEW_OIDC_USERNAME_CLAIM` | `preferred_username` | Claim that names the [OIDC account](../advanced/oidc.md#oidc-accounts) (exact comparison, no fallback); session label `oidc:<value>` |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Creates the OIDC account at its first login if its OIDC mappings give it a permission; when `false`, an administrator creates every OIDC account in **Users** |
| `SECREVIEW_OIDC_DISPLAY_NAME` | `OIDC` | Name shown on the login button (40 characters at most) |
| `SECREVIEW_OIDC_CAFILE` | — | CA bundle to reach the provider (internal CA); the proxy is the one of `HTTPS_PROXY` |
| `SECREVIEW_OIDC_ONLY` | `false` | With OIDC enabled, refuses the password login of the local accounts ([OIDC only](../advanced/oidc.md#oidc-only)); a variable only, never changed in the interface |

### OAuth login of MCP clients

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_MCP_OAUTH_ENABLED` | `false` | Enables the [OAuth login of the MCP clients](../advanced/mcp-oauth.md): the Controller server becomes their authorization server (routes `/authorize`, `/token`, `/register`, `/revoke` at the root of `SECREVIEW_PUBLIC_URL`, which must be set, in https outside localhost) and the MCP server sends a client without a token to it. Unset, an administrator may turn it on in the web interface (**MCP clients** page) |
| `SECREVIEW_MCP_URL` | — | Public URL of the MCP endpoint (`https://…/mcp`, ASCII: punycode for a non-ASCII host), required with OAuth (the login stays suspended without it): the resource of the tokens. Stored in the database at start, where the MCP server reads it. Unset, it may be entered in the web interface (**MCP clients** page) |
| `SECREVIEW_MCP_OAUTH_ACCESS_MINUTES` | `60` | Lifetime of an access token (5 to 1440 minutes) |
| `SECREVIEW_MCP_OAUTH_REFRESH_DAYS` | `30` | Lifetime of a refresh token (1 to 365 days), extended at each refresh; `SECREVIEW_TOKEN_MAX_DAYS`, when set, bounds the whole grant from its approval |
| `SECREVIEW_MCP_OAUTH_MAX_CLIENTS` | `1000` | Clients registered at once; a client nobody approved within a day is deleted |
| `SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS` | — | Hosts reached over https accepted as redirect URI of a client, comma separated (`mcp-client.example.com`), trusted hosts only (every path is accepted); empty: the loopback interface only |
| `SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES` | — | Custom URI schemes accepted as redirect URI, comma separated (`cursor`); empty: none |

### Outgoing proxy

| Variable | Default | Role |
|---|---|---|
| `HTTPS_PROXY` (else `HTTP_PROXY`) | — | Standard variable, without the `SECREVIEW_` prefix (lowercase name accepted): HTTP proxy of the outgoing connections of the Controller server, OSV download and OIDC provider (`http://[user:password@]host:port`, `host:port` meaning `http://host:port`); without it, the connection is direct, or uses the proxy chosen on the [**General**](../usage/index.md#pages) page. When set (not empty), takes precedence over that page |
| `NO_PROXY` | — | Standard variable: [hosts reached without the proxy](../review/analysis/dependencies.md#hosts-without-proxy), comma separated: domains (subdomains included), IP addresses, `*` (no CIDR ranges); the loopback is always direct. When set (not empty), takes precedence over the list of the **General** page |

### OSV database

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_OSV_AUTO_UPDATE` | `false` | [Daily update](../review/analysis/dependencies.md#automatic-update-by-the-controller-server) of the OSV database by `serve` |
| `SECREVIEW_OSV_UPDATE_INTERVAL_HOURS` | `24` | Age of the database beyond which `serve` updates it (minimum `1`) |
| `SECREVIEW_OSV_URL` | `https://osv-vulnerabilities.storage.googleapis.com` | Source of the `<URL>/<ecosystem>/all.zip` exports (HTTPS only, mirror possible) |
| `SECREVIEW_OSV_ECOSYSTEMS` | `PyPI,npm,Maven,Go,crates.io,NuGet` | Downloaded ecosystems, comma separated; while unset, they can be chosen on the **OSV database** page |
| `SECREVIEW_OSV_CAFILE` | — | CA bundle used instead of the system one (internal mirror, proxy that inspects TLS) |
| `SECREVIEW_OSV_MAX_DOWNLOAD_MB` | `1024` | Maximum size of a downloaded archive |

### Findings, reports and tokens

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` | `90` | Age in days beyond which `serve` deletes the [reports without findings](../advanced/database.md#retention-of-reports-without-findings); `0` keeps every report |
| `SECREVIEW_MAX_DISMISSAL_DAYS` | `365` | Longest validity in days of an `accepted` or `false_positive` [decision](../usage/triage.md): its expiry date may not be later |
| `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED` | `true` | A person may [accept a risk](../usage/triage.md) with **No expiry**: the acceptance lasts until someone reopens the finding. `false`: every acceptance needs an expiry date. A false positive never needs one |
| `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY` | `medium` | Lowest severity (`critical`, `high`, `medium`, `low`, `info`) whose [risk acceptance](../usage/triage.md) needs a reason and an expiry date. A less severe finding is accepted by a plain validation, which closes it with no reason and no date. Empty: every acceptance needs them |
| `SECREVIEW_TOKEN_MAX_DAYS` | `0` | Longest validity in days of a bearer token created or [rotated](../advanced/bearer-tokens.md#expiry-and-rotation-of-tokens) (CLI, web interface), which is also its default validity; `0`: tokens do not expire unless a validity is asked for |
| `SECREVIEW_PERSONAL_TOKENS_PER_USER` | `1` | Personal tokens a web user may hold of each role, [REST API](../usage/tokens.md#api-tokens), [MCP and CI](../usage/tokens.md#personal-mcp-and-ci-tokens), from `1` to `10`: revoke one to create another |
| `SECREVIEW_PERSONAL_TOKENS_ENABLED` | `true` | Whole application: every web user may create a [personal MCP or CI token](../usage/tokens.md#personal-mcp-and-ci-tokens) and approve an MCP client with the [OAuth login](../advanced/mcp-oauth.md). `false`: none is created nor approved, and the personal MCP and CI tokens and the OAuth grants already given are refused by the MCP server and the Controller server (kept: `true` allows them again); the REST API tokens stay. Stored in the database by the Controller server, where the MCP server reads it too: either one set to `false` refuses them |
| `SECREVIEW_PERSONAL_MCP_TOKENS` | `true` | A web user may create a personal MCP token in **My account**. `false` with the [OAuth login of MCP clients](../advanced/mcp-oauth.md): none is offered nor created, and the Controller server revokes those left at start (audited); the CI and REST API tokens stay. Stored in the database, where the MCP server reads it: a client without a valid token is then told to ask an administrator (or to use the OAuth login) instead of creating a personal token |

### Audit and metrics

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_AUDIT_RETENTION_DAYS` | `365` | Age in days beyond which `serve` deletes the events of the [audit log](../advanced/audit-log.md); `0` keeps every event |
| `SECREVIEW_AUDIT_MAX_EVENTS` | `0` | Number of [audit events](../advanced/audit-log.md#retention) kept at most by the same daily purge (the oldest are deleted); `0`: no limit |
| `SECREVIEW_AUDIT_SYSLOG_ADDRESS` | — | [Forwards the audit events to syslog](../advanced/audit-log.md#forwarding-to-syslog): `udp://host:port`, `tcp://host:port`, `tls://host:port` (RFC 5425, port 6514 by default) or `unix:///dev/log` (no proxy); disabled when unset; without it, the server set on the **Audit log** page applies. When set (not empty), takes precedence over that page |
| `SECREVIEW_AUDIT_SYSLOG_FACILITY` | `local0` | Syslog facility of these messages (`local0` to `local7`, `auth`, `authpriv`, `daemon`...); when set, takes precedence over the one chosen on the **Audit log** page |
| `SECREVIEW_AUDIT_SYSLOG_CAFILE` | — | CA bundle that verifies the certificate of a `tls://` syslog server (internal certificate authority); default: the system CA bundle. A variable only |
| `SECREVIEW_METRICS_ENABLED` | `true` | Serves the [Prometheus metrics](metrics.md) on `/metrics` (`metrics` or `admin` token); when `false`, `/metrics` answers 404 |

### Connectors

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_CONNECTORS_ENABLED` | `true` | Lock of the [connectors](../advanced/connectors.md#enabling) (Jira, ServiceNow, third-party; outgoing connections of the Controller server): `true`, each one is switched on on the **Connectors** page (all off by default); `false`, all locked off |
| `SECREVIEW_CONNECTORS_INTERVAL_SECONDS` | `300` | Period of the [automatic sending](../usage/connectors/index.md#sending-a-finding) (30 to 86400) |
| `SECREVIEW_CONNECTORS_CAFILE` | — | CA bundle used instead of the system one (internal authority) |
| `SECREVIEW_CONNECTORS_PLUGINS` | — | [Third-party connectors](../usage/connectors/third-party.md) allowed, by entry point name, comma separated; one installed but not listed is never loaded |
| `SECREVIEW_JIRA_URL`, `SECREVIEW_JIRA_USERNAME`, `SECREVIEW_JIRA_API_TOKEN`, `SECREVIEW_JIRA_ISSUE_TYPE` (`Bug`) | — | [Jira connection](../advanced/connectors.md#jira); when set, takes precedence over the **Connectors** page |
| `SECREVIEW_SERVICENOW_URL`, `SECREVIEW_SERVICENOW_USERNAME`, `SECREVIEW_SERVICENOW_PASSWORD`, `SECREVIEW_SERVICENOW_TABLE` (`incident`) | — | [ServiceNow connection](../advanced/connectors.md#servicenow); when set, takes precedence over the **Connectors** page |
| `SECREVIEW_<KIND>_<FIELD>` | — | Field of the connection of a [third-party connector](../usage/connectors/third-party.md) (`SECREVIEW_ACME_API_KEY`) |

### Pipeline scan limits

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_MAX_SCAN_REQUEST_MB` | `64` | Maximum size of a request of [`security-review-ci scan-code` or `scan-deps`](../review/analysis/code-scan.md#limits-of-the-controller-server) (`413` beyond) |
| `SECREVIEW_MAX_SCAN_FILES` | `10000` | Maximum number of files of a scan request (`422` beyond) |
| `SECREVIEW_MAX_SCAN_FILE_CHARS` | `1048576` | Size beyond which a file sent by `scan-code` is not scanned (listed as skipped) |

### OpenGrep engine

Engine of the Controller server for `scan-code`, disabled by default and skipped while no rule is installed (binary shipped in the `-opengrep` Docker image, which enables it), see [OpenGrep](../review/analysis/opengrep.md).

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_OPENGREP_ENABLED` | `false` | Also run OpenGrep on the files of `scan-code` |
| `SECREVIEW_OPENGREP_BINARY` | `/usr/local/bin/opengrep` | OpenGrep executable |
| `SECREVIEW_OPENGREP_RULES_DIR` | `/var/lib/secreview/rules/opengrep` | Directory of the OpenGrep YAML rules |
| `SECREVIEW_OPENGREP_TIMEOUT_SECONDS` | `600` | Maximum duration of one scan (1 to 7200) |
| `SECREVIEW_OPENGREP_MAX_CONCURRENT_SCANS` | `1` | Scans running at the same time in one Controller server process (`503` beyond) |
| `SECREVIEW_OPENGREP_MAX_CONCURRENT_FRAGMENT_SCANS` | `1` | Fragments of `scan_code` [delegated by the MCP server](../review/analysis/opengrep.md#fragment-scans-scan_code) scanned at the same time, in their own slots (`503` beyond); `0`: rules only for the fragments |
| `SECREVIEW_OPENGREP_JOBS` | `2` | Cores used by one scan |
| `SECREVIEW_OPENGREP_MAX_MEMORY_MB` | `2048` | Memory in MiB of one scan (`0`: no limit) |
| `SECREVIEW_OPENGREP_TAINT_INTRAFILE` | `true` | Follow the data flow through the functions of a same file (`--taint-intrafile`); `false` for an older OpenGrep executable that lacks the option |
| `SECREVIEW_OPENGREP_MAX_PENDING_PROPOSALS` | `100` | MCP server: OpenGrep rules proposed by agents (`propose_opengrep_rule`) and waiting for a decision at the same time; a new proposal is refused beyond |

### Scan engines

Optional [scan engines](../advanced/architecture/scan-engine.md) (`security-review-scan-engine`) that run the rules and OpenGrep of the code scans in place of the Controller server. The `SECREVIEW_OPENGREP_*` settings then apply to the engines.

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_SCAN_ENGINE_TOKEN` | — | Controller server and engines: shared secret (at least 32 characters), required on both sides. Set on the Controller server, it turns the [scan engines](../advanced/architecture/scan-engine.md) on: they enroll with their own address and the code scans go to the active ones; unset: the Controller server scans itself |
| `SECREVIEW_SCAN_ENGINE_NETWORKS` | private and loopback networks | Controller server: networks (comma-separated CIDRs) where the engines may [advertise their address](../advanced/architecture/scan-engine.md#how-the-scans-reach-the-engines), an IP address only |
| `SECREVIEW_SCAN_ENGINE_ADVERTISE_URL` | IP of the host name, listening port | Scan engines: root URL where the Controller server sends them the scans, given at their enrollment (e.g. `http://10.42.0.17:8000`, the pod IP) |
| `SECREVIEW_SCAN_ENGINE_TIMEOUT_SECONDS` | `660` | Controller server: time limit of a scan by an engine (1 to 7200) |
| `SECREVIEW_SCAN_ENGINE_FALLBACK` | `refuse` | Controller server: when no engine answers, `refuse` the scan (`503` with `Retry-After`) or scan `local`ly |
| `SECREVIEW_SCAN_ENGINE_ACCESS_TOKEN_MINUTES` | `15` | Controller server: validity of the OAuth access token of an [enrolled engine](../advanced/architecture/scan-engine.md#enrollment-and-access-tokens) (1 to 1440) |
| `SECREVIEW_SCAN_ENGINE_RETENTION_DAYS` | `7` | Controller server: an enrolled engine not seen for this many days is deleted (1 to 365) |
| `SECREVIEW_CONTROLLER_URL` | — | Scan engines (required): internal address of the Controller server (e.g. `http://controller:8000`), where they [enroll](../advanced/architecture/scan-engine.md#enrollment-and-access-tokens) and [read the rules](../advanced/architecture/scan-engine.md#rules) before each scan, OpenGrep rules copied into their own `SECREVIEW_OPENGREP_RULES_DIR`; the engines read no database |

## Clients

Read by the pipeline client `security-review-ci` (`SECREVIEW_CI_TOKEN` never by the servers).

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_CI_TOKEN` | — | Bearer token sent by [`security-review-ci`](../advanced/architecture/ci.md) to the Controller server (`ci` token, personal or not); never used by the servers. `SECREVIEW_TOKEN`, its former name, is still read when it is not set, with a warning |
| `SECREVIEW_CONTROLLER_URL` | — | URL of the Controller server used by [`security-review-ci`](../advanced/architecture/ci.md) (default of `--url`); read from the environment only, never from `.env`. The Controller server has its own variable for [its public URL](#web-interface-and-sessions), `SECREVIEW_PUBLIC_URL` |

Bearer tokens are not configured by variable: they are stored in the database and managed with
`security-review-controller token` (see
[Authentication and TLS](../advanced/bearer-tokens.md)). Neither are internal rules:
they are stored in the database and managed with `security-review-controller rules` (see
[Rules](../review/rules.md#rules-command)).

## Database

SQLite or PostgreSQL, schema migrations, retention of the reports without findings,
backup and upgrade: see [Database](../advanced/database.md).
