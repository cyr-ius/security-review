# Controller server

The **Controller server** (`security-review-controller`) is the process of the people and of the
pipelines: it serves the web interface, the REST API and the pipeline routes, owns the database
schema and runs the background tasks. It never calls the MCP server: both share the database
(see [Architecture](index.md)).

## What it serves

| Route | Used by | Credential |
|---|---|---|
| `/ui/` | the people (browser): [web interface](../../usage/index.md) | none for the static files; the data come from the API |
| `/api/v1/auth/` | the login page: password and [OIDC](../oidc.md) login | none |
| `/api/v1/` | the web interface, scripts, Swagger | web session, `admin` or `api` token |
| `/api/v1/ci/` | [`security-review-ci`](ci.md): gate, SARIF, trend, code and dependency scans | `ci` token (personal or not) |
| `/metrics` | Prometheus ([metrics](../../reference/metrics.md)) | `metrics` or `admin` token |
| `/api/docs` | Swagger: OpenAPI documentation of the REST API, without data, only with `SECREVIEW_SWAGGER_ENABLED=true` | none (the calls need an [API token](../../usage/tokens.md#api-tokens)) |
| `/api/ci-client/` | uv: [download of `security-review-ci`](ci.md#from-the-controller-server), unless `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED=false` | none |
| `/api/health` | the web interface, which checks the liveness of the API at load (tells nothing about the version or the settings) | none |
| `/api/favicon.svg` | icon of the web interface and of Swagger | none |
| `/.well-known/oauth-authorization-server`, `/authorize`, `/token`, `/register`, `/revoke` | the MCP hosts: [OAuth login](../mcp-oauth.md), only with `SECREVIEW_MCP_OAUTH_ENABLED=true` | none (PKCE; the approval goes through a web session) |
| `/healthz` | probes (Docker `HEALTHCHECK`, Kubernetes) | none |

The roles of the tokens are described in [Roles](../../usage/tokens.md), their
management in [Bearer tokens](../bearer-tokens.md).

## Start-up

`security-review-controller serve` (port `8000` in the image, `--host` and `--port` otherwise):

1. migrates the schema (see [Schema migrations](#schema-migrations));
2. checks the settings (TLS, OIDC, OSV, syslog, connectors): an invalid value stops it with
   code `2`;
3. creates the [first administrator](#first-administrator) while no account exists;
4. starts the background tasks, then serves the routes.

## Schema migrations

The Controller server migrates the schema when it starts; the HTTP MCP server never does. Commands,
locks between replicas and dedicated migration job: see
[Database](../database.md#schema-migrations).

## Background tasks

| Task | Enabled by | Details |
|---|---|---|
| Daily update of the OSV advisories | `SECREVIEW_OSV_AUTO_UPDATE=true` (off by default) | [Automatic update by the Controller server](../../review/analysis/dependencies.md#automatic-update-by-the-controller-server) |
| Purge of the reports without findings and of the audit log | `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` (90), `SECREVIEW_AUDIT_RETENTION_DAYS` (365), `SECREVIEW_AUDIT_MAX_EVENTS` | [Retention](../database.md#retention-of-reports-without-findings), [audit retention](../audit-log.md#retention) |
| Forwarding of the audit log to syslog | a syslog server set in the environment or in the interface | [Forwarding to syslog](../audit-log.md#forwarding-to-syslog) |
| Automatic sending of the findings by the connectors | a connector switched on, a severity threshold on the project; `SECREVIEW_CONNECTORS_ENABLED=false` locks everything | [Connectors](../../usage/connectors/index.md) |

The MCP server runs none of them.

## Outgoing connections

The Controller server is the only process that may connect outside, and every connection is **off by
default**: the OSV download, the [OIDC](../oidc.md) provider, the search for a newer release on the
**About** page (`SECREVIEW_UPDATE_CHECK_ENABLED`), the syslog server and the connectors. They
use HTTPS (syslog: UDP, TCP or TLS), through the outgoing proxy (`HTTPS_PROXY`, `NO_PROXY`,
or the **Settings** screen). See [Security and limits](../../reference/security.md).

## Exposure

Expose the Controller server with TLS ([built-in or reverse proxy](../tls.md)) to the people (web
interface, personal tokens) and to the pipeline runners. Behind a reverse proxy or an Ingress:

- set `SECREVIEW_FORWARDED_ALLOW_IPS` to the address of the proxy, otherwise every client shares
  its address for the login throttling and the rate limit;
- set `SECREVIEW_PUBLIC_URL` to the public root URL of the Controller server, without `/ui` (or
  fill in the **General** screen): the Controller server copies it to the database at start and the MCP server
  reads it there, so that an agent without a valid token knows where to create one. While it is
  unknown, a banner at the top of the web interface tells the administrators (permission
  `settings.manage`) and links to the field.

## Several replicas

The Controller server can run several replicas on the same PostgreSQL database: the migrations wait
for each other (advisory lock), the sessions are shared through `SECREVIEW_SECRET_KEY`, the login
and rate limit counters are kept in the database, only one replica downloads the OSV
advisories at a time, and a syslog batch is sent once. Set the same `SECREVIEW_SECRET_KEY` on
every replica.

## Administration commands

The other commands of `security-review-controller` run where the Controller server runs (same
`SECREVIEW_DATABASE_URL`), for example `docker compose exec controller …` or
`kubectl exec deploy/secreview-controller -c controller -- …`:

| Command | Purpose |
|---|---|
| `db` | migrate the schema, show its revision, purge reports |
| `token` | create, list, rotate and revoke the tokens ([Bearer tokens](../bearer-tokens.md)) |
| `user`, `group` | accounts of the web interface and their groups ([Managing the accounts](#managing-the-accounts)) |
| `project` | approve or reject the projects requested by the MCP agents of users ([enrollment](mcp-server.md#enrollment-personal-token-and-project-requests)) |
| `rules` | import and export the internal [rules](../../review/rules.md) and checklists |
| `advisories` | import or download the [OSV database](../../review/analysis/dependencies.md#offline-vulnerability-database-osv-format) |
| `audit` | read or purge the [audit log](../audit-log.md) |

All their options: [Command line](../../reference/cli.md#security-review-controller). The
variables of the Controller server: [Configuration](../../reference/configuration.md#controller-server).

## Managing the accounts

The [user accounts](../../usage/user-accounts.md) are managed in the **Users** screen, through the
`/api/v1/users` REST API (`users.manage` permission) or with the
[CLI](../../reference/cli.md#security-review-controller). A user name holds letters, digits and
`. _ @ -`, 64 characters at most; the type of an account is its `auth_source` (`local` or
`oidc`).

```bash
security-review-controller user create alice --group shop-triagers
# {"id": 2, "username": "alice", "auth_source": "local", "groups": [{"group_id": 3, "name": "shop-triagers", "source": "local"}], "permissions": {…}, …, "password": "q3V…"}
printf '%s\n' "$PASSWORD" | security-review-controller user create bob --password-stdin
security-review-controller user create carol@example.com --sso   # OIDC groups only
security-review-controller user list
security-review-controller user set-groups alice --group readers --group auditors
security-review-controller user set-groups alice --group administrators   # created if missing
security-review-controller user reset-password alice   # local account: new password, sessions closed
security-review-controller user delete alice
security-review-controller group list    # groups, their roles and members
```

Through the API, an OIDC account is created with `"auth_source": "oidc"`, without `password`;
`group_ids` lists its groups:

```bash
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "carol@example.com", "auth_source": "oidc", "group_ids": [4]}'
```

An OIDC account is also created at its first login with `SECREVIEW_OIDC_AUTO_CREATE_USERS=true`
([OIDC accounts](../oidc.md#oidc-accounts)).

For a local account, without `--password-stdin` (or without a password in the interface), a
random 24-character password is generated and shown **only once**. A chosen password follows
the **password policy**: 12 to 256 characters, with at least a lowercase letter, an uppercase
letter, a digit and a character that is neither a letter nor a digit. The policy applies to new
passwords: a password set before keeps working until it is changed. An OIDC account never has a
password: the user name and password login, the reset and **My account** refuse it.

!!! warning "Authentication required for the web UI"
    The API of the interface refuses the requests with status `503` while no user and no token
    exist; the login form stays displayed and says that authentication must be configured.
    `security-review-controller serve` creates the [first administrator](#first-administrator)
    at its first start, so this only happens before it; an account can also be created with
    `security-review-controller user create`. This restriction concerns the web
    UI; MCP authentication stays independent (a user account never opens `/mcp`). With the
    [OIDC login](../oidc.md), the API asks for a login (`401`) even without any
    user or token in the database.

The variables of the interface are in the
[Configuration](../../reference/configuration.md#web-interface-and-sessions).

## First administrator

At its first start, while no account exists, the Controller server creates the local account
**`admin`** (`SECREVIEW_ADMIN_USERNAME`), member of the `administrators` group (`admin` role),
with a random password that nobody knows and that is never written to the logs. The only way to
a password is the CLI, which sets a new one and prints it once:

```bash
security-review-controller user reset-password admin
# {"id": 1, "username": "admin", …, "must_change_password": true, "password": "q3V…"}
```

```
WARNING security_review_mcp.controller: Initial Web UI administrator 'admin' created: set its password with `security-review-controller user reset-password admin`
```

Handle this password as a secret and log in with `admin`. The interface then **requires a new
password** before anything else: it opens **My account**, and the API refuses every other route
(`403`) until the password is changed. If it is lost, see [lost password](#lost-password).

The same applies to every password set by someone else: a local account created or reset by an
administrator (screen or CLI) changes its password at its first login. The **Users** screen shows
**password to change** until then.

### Lost password

The password is stored as a scrypt digest: it cannot be read back. Replace it with the CLI of the
Controller server, on the same database:

```bash
security-review-controller user reset-password admin
```

The command prints the account as JSON, with a generated password in the `password` field
(`| jq -r .password` to keep only it). The old password is invalidated at once, the open sessions
of the account end, and the new password must be changed at the next login. To choose it, give it
on the first line of stdin (it then stays out of the shell history and of the process list, and
the JSON has no `password` field):

```bash
printf '%s\n' "$NEW_PASSWORD" | security-review-controller user reset-password admin --password-stdin
```

Run it where the Controller server runs:

```bash
# Docker Compose
docker compose exec controller security-review-controller user reset-password admin
# Kubernetes
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller user reset-password admin
```

An OIDC account has no password (exit code `2`). If no administrator is left, create one with
`security-review-controller user create NAME --group administrators` (generated password, printed
the same way): the `admin` account is only created at start-up while no account exists.

## Login and sessions

When the Controller server no longer accepts the session while you browse (session expired, password
changed in another tab, account deleted), a **Session expired** dialog opens: **Log in again**
opens the login page and comes back to the same page afterwards.

The login page offers the user name and password of a local account and, with the
[OIDC login](../oidc.md), the button of the identity provider; it does not accept
a token. `POST /api/v1/auth/login` checks the password of a local account and returns a signed
**session token**, valid `SECREVIEW_SESSION_HOURS` hours (8 by default), that the tab uses like
a Bearer token:

```bash
curl -s -X POST https://secreview.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username": "alice", "password": "…"}'
# {"session": "eyJ…", "expires_in": 28800, "username": "alice"}
```

Every session names an account (local or OIDC); at every request, the Controller server reads it again
from the database:

- a change of its **groups**, of their roles or of a role applies immediately to the open
  sessions;
- a **deletion** or a **new password** (changed by the user or reset by an administrator)
  closes every session of the account; `PUT /api/v1/me/password` hands a new session to the tab
  that changed the password;
- a **logout** (`POST /api/v1/me/logout`) also closes every session of the account, in every
  tab and browser: a stolen session token stops working when its user logs out.

Sessions are signed with `SECREVIEW_SECRET_KEY` (at least 32 characters), shared by every
replica of the Controller server. Without it, a random secret is drawn at every start (a warning is
logged): sessions end when the Controller server restarts and are not shared between replicas. Set it
in production (in Kubernetes, from a `Secret`: see [Kubernetes](../deployment/kubernetes.md#secrets)).

Login failures are limited: after **5 failures in 15 minutes** for a user name from the same
address, or **20 failures** from an address all user names together, the login is refused
(`429`, `Retry-After` header), even with the right password. The counters are kept in the
database: every worker and replica of the Controller server shares them. Every address is also limited
on the whole REST API (by default 600 requests a minute, 30 on the login routes, see
[`SECREVIEW_RATE_LIMIT_*`](../../reference/configuration.md#rate-limiting)). Behind a reverse proxy, the address seen is the proxy's, and the limit would then
apply to every client of the proxy: list the proxy in
[`SECREVIEW_FORWARDED_ALLOW_IPS`](../../reference/configuration.md#listening-tls-and-reverse-proxy) so that the address of the
client is read from `X-Forwarded-For`. Every login and every failure is logged, without the password:

```
INFO security_review_mcp.web: Web login of alice (role triager) from 10.0.0.12
WARNING security_review_mcp.web: Failed web login of alice from 10.0.0.12
```

## Settings stored in the database

The **General** (report language, Controller server address, outgoing proxy) and **Sign-in** (OIDC) screens of the
[web interface](../../usage/index.md) store settings in the database, shared by the MCP
server and the Controller server (`settings.manage` permission; the former `/ui/settings`,
`/ui/settings/language` and `/ui/settings/proxy` addresses open **General**). **An environment variable that is set
(environment or `.env` file, not empty) always takes precedence**: its field is then locked and
shows the variable, and a value stored before the variable was set is marked as ignored, with a
**Delete** button. A change applies without restart: the MCP server reads the Controller server
address within a minute (the change is recorded in the audit log, `controller_url.changed`),
and the proxy applies to the next OSV download and the next OIDC login. **Use the current
address** fills in the address of this Controller server.

| Route | Effect |
|---|---|
| `GET /api/v1/settings` | For each setting: the stored `value`, the variable `env`, `env_set` (the variable is set and takes precedence) and the effective value |
| `PUT /api/v1/settings/controller-url` | `value` (`null` deletes it) |
| `PUT /api/v1/settings/proxy` | `url` and `no_proxy`: `null` deletes the stored value, `"url": ""` forces the direct connection, a missing field is unchanged. Passwords are never shown again (`***`): sending `***` back keeps the stored one |

A value whose variable is set is refused with `422`. The OIDC settings have their own routes
([OIDC configuration](../oidc.md#configuring-oidc-in-the-interface)). The theme chosen by a
logged-in user is kept in their account (`GET` and `PUT /api/v1/me/preferences`), for every
browser they use.

## Security of the web interface

- The static files of `/ui/` are public (they hold no data); the `/api/v1/` API requires a
  session or an `admin` or `api` token (the pipeline routes `/api/v1/ci/` take `ci` tokens, see
  [What it serves](#what-it-serves)). Only the login routes (`/api/v1/auth/…`)
  are public, and the download of the pipeline client (`/api/ci-client/`) unless disabled.
- Account passwords are never stored: only a salted **scrypt** digest (N=2¹⁴, r=8, p=5) is
  stored and no API answer returns it. The check takes the same time whether the user name
  exists or not, and the failure answer is identical. The Swagger documentation (`/api/docs`)
  and its schema (`/api/openapi.json`) are **disabled by default**
  (`SECREVIEW_SWAGGER_ENABLED=true` serves them); once enabled, they are public and give access
  to no data. Their files come with the web interface build: nothing is loaded from the
  Internet, and Swagger never sends the schema to the online validator. In Swagger, the
  padlock of a route says that it requires a token: it stays **open** while you have not entered
  a token with **Authorize**, and does not mean that the route can be reached without a token.
  Enter an [API token](../../usage/tokens.md#api-tokens) there.
- The Controller server exposes no write route without a token. A project is requested by an agent
  with a token, through the `request_project` tool of the **MCP server**
  ([enrollment](mcp-server.md#enrollment-personal-token-and-project-requests)); the Controller server
  lists and handles the requests (`GET /api/v1/projects/pending`,
  `POST /api/v1/projects/pending/{id}/approve`, `DELETE /api/v1/projects/pending/{id}`,
  `projects.create` permission).
- The token is sent in the `Authorization` header: no cookie, hence no CSRF. Only the
  [OIDC login](../oidc.md) sets a cookie, `HttpOnly`, `SameSite=Lax`, `Secure`
  over HTTPS, limited to the return URL and valid 10 minutes: it binds the return from the
  provider to the browser that started the login (protection against *login CSRF*). The session
  token is handed in the URL fragment (`#session=...`), never sent to a server, and the
  interface clears it at once from the address bar and the history.
- It is kept in the `sessionStorage` of the tab and disappears when the tab closes.
- Pages are served with a strict CSP (`script-src 'self'`, no external resource),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- Serve the interface over HTTPS ([built-in TLS or reverse proxy](../tls.md))
  as soon as it no longer listens on localhost: the token travels with every request.

The published package and the Docker image contain the application already built. If you
install from source without building it, the Controller server only serves the REST API and a warning
is logged. See [Contributing](../../contributing/web-ui.md) to build it.
