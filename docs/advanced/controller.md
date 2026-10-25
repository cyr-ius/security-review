# Controller

The **controller** (`security-review-controller`) is the process of the people and of the
pipelines: it serves the web interface, the REST API and the pipeline routes, owns the database
schema and runs the background tasks. It never calls the MCP server: both share the database
(see [Architecture](architecture.md)).

## What it serves

| Route | Used by | Credential |
|---|---|---|
| `/ui/` | the people (browser): [web interface](../usage/web-interface.md) | none for the static files; the data come from the API |
| `/api/v1/auth/` | the login page: password and [OIDC](sso.md) login | none |
| `/api/v1/` | the web interface, scripts, Swagger | web session, `admin` or `api` token |
| `/api/v1/ci/` | [`security-review-ci`](ci.md): gate, SARIF, trend, code and dependency scans | `ci` token or personal `mcp` token |
| `/metrics` | Prometheus ([metrics](../reference/metrics.md)) | `metrics` or `admin` token |
| `/api/docs` | Swagger, only with `SECREVIEW_SWAGGER_ENABLED=true` | none (the calls need an [API token](../usage/tokens.md#api-tokens)) |
| `/api/ci-client/` | uv: [download of `security-review-ci`](ci.md#from-the-controller), unless `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED=false` | none |
| `/api/health`, `/api/favicon.svg` | liveness of the API, icon | none |
| `/healthz` | probes (Docker `HEALTHCHECK`, Kubernetes) | none |

The roles of the tokens are described in [Roles](../usage/tokens.md), their
management in [Bearer tokens](bearer-tokens.md).

## Start-up

`security-review-controller serve` (port `8000` in the image, `--host` and `--port` otherwise):

1. migrates the schema, or only checks it with `SECREVIEW_DB_AUTO_UPGRADE=false` (see
   [Schema migrations](#schema-migrations));
2. checks the settings (TLS, OIDC, OSV, syslog, connectors): an invalid value stops it with
   code `2`;
3. creates the [first administrator](#first-administrator) while no account exists;
4. starts the background tasks, then serves the routes.

## Schema migrations

The schema is managed by [Alembic](https://alembic.sqlalchemy.org/) migrations, embedded in the
package (no `alembic.ini` file to provide):

```bash
security-review-controller db upgrade   # creates or migrates the schema, then seeds the default rules
security-review-controller db status    # {"current": "0032", "head": "0032", "up_to_date": true}
```

- `db status` returns code `1` if the schema is not up to date: handy for a script or a probe.
- The **HTTP MCP server never migrates**: it refuses to start (code `2`, message
  `run security-review-controller db upgrade first`) while the database is not at the expected
  revision. Under Kubernetes, the pod restarts until the migration is done.
- The controller, the stdio MCP server and the CLI commands migrate at start-up, unless
  `SECREVIEW_DB_AUTO_UPGRADE=false`. They then only check the schema. With Docker Compose, the
  controller migrates when it starts; under Kubernetes, its init container does.
- On PostgreSQL, a migration takes an advisory lock: instances that start together (several
  replicas, a `db upgrade` run by hand) wait for each other, and the next one finds the schema
  up to date. Disable the automatic migration only to keep it in a dedicated task.

## Background tasks

| Task | Enabled by | Details |
|---|---|---|
| Daily update of the OSV advisories | `SECREVIEW_OSV_AUTO_UPDATE=true` (off by default) | [Automatic update by the controller](dependencies.md#automatic-update-by-the-controller) |
| Purge of the reports without findings and of the audit log | `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` (90), `SECREVIEW_AUDIT_RETENTION_DAYS` (365), `SECREVIEW_AUDIT_MAX_EVENTS` | [Retention](../reference/configuration.md#retention-of-reports-without-findings), [audit retention](audit-metrics.md#retention) |
| Forwarding of the audit log to syslog | a syslog server set in the environment or in the interface | [Forwarding to syslog](audit-metrics.md#forwarding-to-syslog) |
| Automatic sending of the findings by the connectors | a connector switched on, a severity threshold on the project; `SECREVIEW_CONNECTORS_ENABLED=false` locks everything | [Connectors](../connectors/index.md) |

The MCP server runs none of them.

## Outgoing connections

The controller is the only process that may connect outside, and every connection is **off by
default**: the OSV download, the [OIDC](sso.md) provider, the search for a newer release on the
**About** page (`SECREVIEW_UPDATE_CHECK_ENABLED`), the syslog server and the connectors. They
use HTTPS (syslog: UDP, TCP or TLS), through the outgoing proxy (`HTTPS_PROXY`, `NO_PROXY`,
or the **Settings** screen). See [Security and limits](../reference/security.md).

## Exposure

Expose the controller with TLS ([built-in or reverse proxy](tls.md)) to the people (web
interface, personal tokens) and to the pipeline runners. Behind a reverse proxy or an Ingress:

- set `SECREVIEW_FORWARDED_ALLOW_IPS` to the address of the proxy, otherwise every client shares
  its address for the login throttling and the rate limit;
- set `SECREVIEW_WEB_URL` (read by the MCP server) to the public URL of the interface, so that
  an agent without a valid token knows where to create one.

## Several replicas

The controller can run several replicas on the same PostgreSQL database: the migrations wait
for each other (advisory lock), the sessions are shared through `SECREVIEW_SECRET_KEY`, the login
and rate limit counters are kept in the database, only one replica downloads the OSV
advisories at a time, and a syslog batch is sent once. Set the same `SECREVIEW_SECRET_KEY` on
every replica.

## Administration commands

The other commands of `security-review-controller` run where the controller runs (same
`SECREVIEW_DATABASE_URL`), for example `docker compose exec controller …` or
`kubectl exec deploy/secreview-controller -c controller -- …`:

| Command | Purpose |
|---|---|
| `db` | migrate the schema, show its revision, purge reports |
| `token` | create, list, rotate and revoke the tokens ([Bearer tokens](bearer-tokens.md)) |
| `user`, `group` | accounts of the web interface and their groups ([User accounts](../usage/user-accounts.md)) |
| `project` | approve or reject the projects requested by an [enrollment](mcp-server.md#enrollment-request-the-project) |
| `rules` | import and export the internal [rules](../usage/rules.md) and checklists |
| `advisories` | import or download the [OSV database](dependencies.md#offline-vulnerability-database-osv-format) |
| `audit` | read or purge the [audit log](audit-metrics.md) |

All their options: [Command line](../reference/cli.md#security-review-controller). The
variables of the controller: [Configuration](../reference/configuration.md#controller).

## First administrator

At its first start, while no account exists, the controller creates the local account
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
controller, on the same database:

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

Run it where the controller runs:

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

When the controller no longer accepts the session while you browse (session expired, password
changed in another tab, account deleted), a **Session expired** dialog opens: **Log in again**
opens the login page and comes back to the same page afterwards.

The login page offers the user name and password of a local account and, with the
[OIDC login](sso.md), the button of the identity provider; it does not accept
a token. `POST /api/v1/auth/login` checks the password of a local account and returns a signed
**session token**, valid `SECREVIEW_SESSION_HOURS` hours (8 by default), that the tab uses like
a Bearer token:

```bash
curl -s -X POST https://secreview.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username": "alice", "password": "…"}'
# {"session": "eyJ…", "expires_in": 28800, "username": "alice"}
```

Every session names an account (local or OIDC); at every request, the controller reads it again
from the database:

- a change of its **groups**, of their roles or of a role applies immediately to the open
  sessions;
- a **deletion** or a **new password** (changed by the user or reset by an administrator)
  closes every session of the account; `PUT /api/v1/me/password` hands a new session to the tab
  that changed the password.

Sessions are signed with `SECREVIEW_SECRET_KEY` (at least 32 characters), shared by every
replica of the controller. Without it, a random secret is drawn at every start (a warning is
logged): sessions end when the controller restarts and are not shared between replicas. Set it
in production (in Kubernetes, from a `Secret`: see [Kubernetes](kubernetes.md#secrets)).

Login failures are limited: after **5 failures in 15 minutes** for a user name from the same
address, or **20 failures** from an address all user names together, the login is refused
(`429`, `Retry-After` header), even with the right password. The counters are kept in the
database: every worker and replica of the controller shares them. Every address is also limited
on the whole REST API (by default 600 requests a minute, 30 on the login routes, see
[`SECREVIEW_RATE_LIMIT_*`](../reference/configuration.md#rate-limiting)). Behind a reverse proxy, the address seen is the proxy's, and the limit would then
apply to every client of the proxy: list the proxy in
[`SECREVIEW_FORWARDED_ALLOW_IPS`](../reference/configuration.md#listening-tls-and-reverse-proxy) so that the address of the
client is read from `X-Forwarded-For`. Every login and every failure is logged, without the password:

```
INFO security_review_mcp.web: Web login of alice (role triager) from 10.0.0.12
WARNING security_review_mcp.web: Failed web login of alice from 10.0.0.12
```

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
  Enter an [API token](../usage/tokens.md#api-tokens) there.
- The controller exposes no write route without a token. The
  [enrollment](mcp-server.md#enrollment-request-the-project) is served by the **MCP
  server** (`POST /api/v1/enroll`, public): it requests a project, never a token; the
  controller lists and handles the requests (`GET /api/v1/projects/pending`,
  `POST /api/v1/projects/pending/{id}/approve`, `DELETE /api/v1/projects/pending/{id}`,
  `projects.create` permission).
- The token is sent in the `Authorization` header: no cookie, hence no CSRF. Only the
  [OIDC login](sso.md) sets a cookie, `HttpOnly`, `SameSite=Lax`, `Secure`
  over HTTPS, limited to the return URL and valid 10 minutes: it binds the return from the
  provider to the browser that started the login (protection against *login CSRF*). The session
  token is handed in the URL fragment (`#session=...`), never sent to a server, and the
  interface clears it at once from the address bar and the history.
- It is kept in the `sessionStorage` of the tab and disappears when the tab closes.
- Pages are served with a strict CSP (`script-src 'self'`, no external resource),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- Serve the interface over HTTPS ([built-in TLS or reverse proxy](tls.md))
  as soon as it no longer listens on localhost: the token travels with every request.

The published package and the Docker image contain the application already built. If you
install from source without building it, the controller only serves the REST API and a warning
is logged. See [Contributing](../contributing/web-ui.md) to build it.
