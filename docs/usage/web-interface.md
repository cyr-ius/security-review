# Web interface

The web interface lets the security teams browse the reports saved by the agents and **triage
the findings** (fixed, accepted risk, false positive) without an MCP client. It is served by the
**controller**, a process distinct from the MCP server that shares its database (see
[Architecture and deployment](../advanced/architecture.md)):

| Path | Content |
|---|---|
| `/ui/` | Web application (Angular) |
| `/api/v1/…` | REST API used by the application |
| `/api/docs` | OpenAPI documentation of the REST API (public, no data), when `SECREVIEW_SWAGGER_ENABLED=true` |
| `/api/favicon.svg` | Icon of the web interface and of the Swagger documentation (public) |
| `/healthz` | Liveness probe (public) |

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# interface: http://127.0.0.1:8080/ui/
```

## Screens

The screens are reached from the sidebar: **Supervision** (projects, reports) for every account,
then **Reference** (rules, checklists, standards) and **Administration** (users, groups, roles,
tokens, audit log, SSO, report language, outgoing proxy, OSV database), each shown only to the
accounts that hold its [permission](../advanced/access-control.md#permissions). The bottom
of the sidebar shows the connected client, its role and the version, with the **My account** and logout buttons; on a
small screen, the sidebar opens with the menu button. The light or dark theme is chosen at the
top right, including on the login page, and is remembered by the browser.

The interface is available in **English**, **French** and **Spanish**. The language is chosen in
the picker at the top right, including on the login page. The change is immediate and is
remembered by the browser; on the first visit, the interface follows the language of the
browser, or English if it offers none of them. This choice only concerns the interface: the
language of the review reports is set in **Report language**, and the detailed error messages sent
back by the API stay in English.

- **Projects**: every project with its open findings by severity, sorted by risk,
  activity or name.
- **Project**: open findings, trend over 30 days to 1 year (chart and table), mean
  time to remediate, oldest open finding, most frequent CWEs, latest reports and SARIF export.
  The **Review open findings** button opens the next screen.
- **Findings to review**: every open finding of the project across all its reports, worst
  severity first, then newest report first, for a review by a security expert. Each finding
  shows its description, code excerpt and recommendation, and a link to its report (date, review
  type, branch, commit). Filters by status (to re-check accepted risks or false positives), by
  severity and by review type (**Security review**, **API security review**, **Codebase
  review**...: see [review type](prompts-tools.md#review-type)); **Load more** displays the next
  findings. Users with the `findings.triage` permission change the status of each finding from this
  screen and apply or reject the statuses proposed by the agents (see
  [triage of findings](#triage-of-findings)); a triaged finding stays displayed until the next
  reload.
- **Reports**: list filtered by project and risk level (the filters are in the URL,
  so a link can be shared), with the **Type** and the **Author** of each review.
- **Report**: summary, context (repository, branch, commit, review type, **Author** and
  **Sent by (token)**, see [author of a report](prompts-tools.md#author-of-a-report)), findings with
  location, CWE, code excerpt and recommendation; Markdown and SARIF download. Users with the
  `findings.triage` permission change the status of a finding directly from this screen.
- **Standards**: the [development standards](../advanced/standards.md) handed to the AI
  assistants by the `development-standards` prompt. Administrators search, read, create, edit
  (technologies, file patterns, Markdown content), disable or delete them. A change applies
  immediately. **Export** and **Import** copy them as a [TOML file](../advanced/standards.md#import-and-export).
- **Checklists**: administrators browse the check items by domain, filter the list and create,
  edit or delete the custom items. The default items can be edited, but not deleted. Every
  change is reloaded immediately by the server and included in the review prompts.
  **Export** and **Import** exchange [TOML packs](../advanced/rules.md#import-and-export-in-the-web-interface).
- **Rules**: administrators browse every [rule](../advanced/rules.md) stored in the database,
  filtered by origin (default or custom). They create, edit (in a modal window, without losing
  the position in the list), enable or disable the rules, and delete the custom rules. A default
  rule can be edited ("Par défaut, modifiée" badge: default, edited) or disabled, but not
  deleted. The **Reload** button applies immediately a change made with the
  `security-review-controller rules` CLI. **Export** and **Import** exchange
  [TOML packs](../advanced/rules.md#import-and-export-in-the-web-interface).
- **Users**: administrators manage the [accounts](#user-accounts), the only
  ones to open the interface. Each account is **Local** (user name and password, entered or
  generated and shown only once) or **SSO** (login through the identity provider, no password),
  with a badge in the list. The administrator chooses its **Groups** and its **Direct roles and
  projects** (a role on every project or on selected projects, for this account only); the
  **Groups** column shows the groups, with a shield for the SSO groups found at the last login,
  the **Direct roles and projects** column the direct roles, and **Access** sums up what they
  give. The administrator changes the groups and direct roles of an account, resets the password of a local
  account or deletes an account. A deleted SSO account is no longer created again at its login:
  the **Deleted SSO accounts** section lists them, with the **Allow again** button. The last
  holder of `users.manage` can be neither deleted nor lose it.
- **Groups**: administrators create the groups, give them roles (on every project or on some
  projects), add members and choose whether the group is **Open to SSO** (see
  [Roles, groups and permissions](../advanced/access-control.md#groups)).
- **Roles**: administrators create roles from the permissions; the system roles `reader`,
  `triager` and `admin` are shown read only.
- **My account**: shows the type of the account. A local user changes their
  password there (their other sessions are closed); the one of an SSO user is managed by the
  identity provider.
- **Tokens**: administrators create and revoke tokens for one or more projects, or for
  **All projects** (never for a CI/CD token). The **Usage** field chooses **MCP** (`mcp` role), **REST API** or **CI/CD pipeline**
  (`ci` role, for [`security-review-ci`](gate.md#pipeline-client-security-review-ci));
  for the REST API, **API rights** chooses **Read only** (`reader`) or **Read and triage**
  (`triager`). Under **Allowed projects**, **All projects** gives every project, including the
  projects reviewed later, and **Selected projects** shows the boxes of the projects the token
  sees; **Validity**
  sets its lifetime (30 days to 1 year, or the default of the server, `SECREVIEW_TOKEN_MAX_DAYS`).
  The list shows the usage of every `mcp`, `reader`, `triager` and `ci` token, its projects
  and its expiry date (**Expired** once past). **Projects** changes the projects of an existing
  token, or gives it **All projects** after a confirmation, without changing its secret: the
  change applies from the next request; a pending request for a project now granted is approved
  with it.
  **Rotate** replaces the secret of a token and shows the new one once; the previous one keeps
  working for the grace period chosen above the list (none, 1 h, 24 h or 7 days, see
  [expiry and rotation](../advanced/http.md#expiry-and-rotation-of-tokens)).
  A token never opens the web interface. The `admin` and `metrics` tokens stay unrestricted and
  are managed from the CLI only. The secret is shown only once; only its digest is stored, in the database. A
  revocation takes effect at the next request. The **Pending requests**
  section tells new tokens apart from requests for access to an additional project
  ([enrollment](../advanced/http.md#enrollment-a-project-requests-its-token)):
  **Approve** activates the new token or adds the project to the existing token;
  **Reject** only deletes the request. The allowed projects and the additions still
  pending are shown for every token. The **Read access in the portal** column
  lets you give the developer, at the same time, read access to the project in the web
  interface, on their user account (see
  [project read access at enrollment](../advanced/sso.md#project-read-access-at-enrollment)).
- **Audit log**: administrators read the [audit log](../advanced/audit-metrics.md#audit-log): triage
  decisions, agent proposals, tokens and enrollment requests, newest first, with who made
  them; filters by event and by project, **Load more** for the older events.
- **SSO**: administrators
  [configure the SSO login](../advanced/sso.md#configuring-sso-in-the-interface) (every stored value replaces its
  `SECREVIEW_OIDC_*` variable, with a connection test to the provider). What SSO users may do
  comes from the groups open to SSO named by their groups claim (see
  [groups of the identity provider](../advanced/sso.md#groups-of-the-identity-provider)).
The next three screens hold settings stored in the database, taking precedence over the
environment variables and shared by the MCP server and the controller (`settings.manage`
permission; the former `/ui/settings` address opens **Report language**).

- **Report language**: `SECREVIEW_REPORT_LANGUAGE` variable, choice
  left to the agent or language set here (`French`, `fr`, `pt-BR`…). It applies to the next
  review prompts; the `report_language` argument of a prompt still takes precedence
  ([report language](prompts-tools.md#report-language)).
- **Outgoing proxy**: proxy of the outgoing connections of the controller, used by the OSV
  download **and** by the [SSO login](../advanced/sso.md). As for the SSO
  configuration, every value set here replaces its variable (**Variable** / **Interface
  web** badges): the URL follows `SECREVIEW_PROXY` (else `HTTPS_PROXY` / `NO_PROXY`), is set
  here, or forces the direct connection; the **hosts without proxy** follow
  `SECREVIEW_NO_PROXY` or are set here (see
  [hosts without proxy](../advanced/dependencies.md#hosts-without-proxy): domains, IP addresses, CIDR
  ranges, `*`). The change applies to the next download and to the next SSO login, without
  restart. The applied proxy, its origin and the environment variables are shown; passwords
  are never shown again (`***`): sending `***` back keeps the stored one. Through the API:
  `PUT /api/v1/settings/proxy` with `url` and `no_proxy` (`null` applies the variable again,
  `"url": ""` forces the direct connection, a missing field is unchanged).
- **OSV database**: state of the OSV vulnerability database: number of advisories by
  ecosystem, date and age of the last import, download configuration, history of the last
  50 updates (scheduled, CLI or web interface, with status, duration and result by
  ecosystem) and **Update now** button, only available if
  `SECREVIEW_OSV_AUTO_UPDATE=true`
  ([update by the controller](../advanced/dependencies.md#automatic-update-by-the-controller)).

## Triage of findings

The status of a finding is decided by a **person**; an agent only proposes it (MCP tool
`propose_finding_status`, see [status of a finding](prompts-tools.md#status-of-a-finding)).

- **Proposal of an agent**: shown on the finding in a separate box, with its author (label of
  the token), its date and its reason. The reason may come from the reviewed code: check it.
  **Apply** saves `fixed` at once, or opens the form below for `accepted` and
  `false_positive`; **Reject** removes the proposal. Neither changes the status by itself.
- **Risk accepted** and **False positive**: the status select opens a form that asks for a
  **Reason** (10 to 1000 characters) and an **Expiry date** (90 days by default, at most
  `SECREVIEW_MAX_DISMISSAL_DAYS`). The logged-in user is recorded as the approver; the card shows
  the approver, the reason and the end of validity. From the expiry date, the finding counts as
  open again (status filter, posture, [gate](gate.md), SARIF, trend) and the card says
  that the decision has expired.
- **Open** and **Fixed** are saved at once (optional reason through the API). Any decision
  removes the pending proposal.

Only a session (local or SSO account) may accept a risk or mark a false positive: a bearer
token, even `triager` or `admin`, gets `403`. Through the REST API:

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42 \
  -d '{"status": "accepted", "reason": "Internal tool, not exposed to the Internet", "expires_on": "2027-01-31"}'
# {"id": 42, "status": "accepted", "status_approver": "alice", "status_expires_at": "2027-01-31T00:00:00Z", …}
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/findings/42/proposal    # reject the agent proposal
```

A reason that is missing or too short, an expiry date in the past or too far away, or an expiry
date for `open` / `fixed` gets `422`. The **Risk accepted** and **False positive** decisions
made before this feature had no reason nor approver: the database upgrade gives them an expiry
date 30 days later, with a reason that asks to confirm them. Review them with the status filters
before that date, or they block the gate again.

## Roles

**Tokens** give access to the MCP server and to the REST API (agents, CI, scripts); **users**
(local or SSO accounts) are the only ones to open the web interface. Every token has a role,
which decides the reachable endpoints:

| Role | Usage (**Tokens** screen) | `/mcp` | REST API (read) | Status change |
|---|---|---|---|---|
| `mcp` (default) | MCP | ✅ | — | — |
| `reader` | REST API — read only | — | ✅ | — |
| `triager` | REST API — read and triage | — | ✅ | `open`, `fixed` ¹ |
| `admin` | CLI only | ✅ | ✅ | `open`, `fixed` ¹ |
| `ci` | CI/CD pipeline — gate, SARIF and trend | — | pipeline routes only (`/api/v1/ci/`) | — |
| `metrics` | CLI only | — | `/metrics` only ([Prometheus](../advanced/audit-metrics.md#prometheus-metrics)) | — |

¹ With a token. `accepted` and `false_positive` need a person logged in to the interface
with the `findings.triage` permission ([triage of findings](#triage-of-findings)). On `/mcp`, no
role changes a status: the agents only propose one.

An `mcp`, `reader` or `triager` token restricted with `--project` only sees and triages the
allowed projects; a `ci` token is always restricted to its projects (see
[`ci` token](gate.md#ci-token-and-visible-projects)); the option can be repeated (see
[tokens restricted to a project](../advanced/http.md#tokens-restricted-to-a-project)).

People log in with a [user account](#user-accounts): local (user name and password) or
[SSO](../advanced/sso.md). What an account may do comes from the roles of its groups (see
[Roles, groups and permissions](../advanced/access-control.md)); an account never opens `/mcp`.
A token created without a role stays `mcp`: it serves the agents and the CI, not the web
interface. A
`reader`, `triager` or `admin` token calls the REST API, for example from a script, but **does
not open the interface** (the login page only offers the accounts):

```bash
security-review-controller token create --label triage-bot --role triager
# {"id": "…", "label": "triage-bot", "role": "triager", "project": null, "created_at": "…", "token": "UJB7…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/projects
```

The same token lists the findings of a project across all its reports, open by default, worst
first (`status`, `severity` and `review_type` filter, `limit` is capped by
`SECREVIEW_MAX_LIST_LIMIT`, `total` gives the number of matching findings for paging):

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/findings?project=shop-api&status=open&limit=50"
# {"project": "shop-api", "total": 12, "findings": [{"id": 42, "severity": "critical", "report_id": 7, "branch": "main", "commit_sha": "abc123", "review_type": "codebase-review", "report_created_at": "…", …}, …]}
```

`GET /api/v1/reports` lists the reports (`project`, `risk_level`, `review_type` and `author`
filter), each with its `author` and `submitted_by`:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/reports?project=shop-api&author=alice@example.com"
```

Revoke it with `security-review-controller token revoke triage-bot`. Every status change is
logged with the label of the token or of the account:

```
INFO security_review_mcp.web: Finding 42 set to fixed by triage-bot
```

and written to the [audit log](../advanced/audit-metrics.md#audit-log) (`GET /api/v1/audit`, `audit.read`
permission), with the actor `token:triage-bot` or `user:<name>`.

!!! warning "Authentication required for the web UI"
    The API of the interface refuses the requests with status `503` while no user and no token
    exist; the login form stays displayed and says that authentication must be configured.
    Enable `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` (the case in the Docker image), or create an
    account with `security-review-controller user create`. This restriction concerns the web
    UI; MCP authentication stays independent (a user account never opens `/mcp`). With the
    [SSO login](../advanced/sso.md), the API asks for a login (`401`) even without any
    user or token in the database.

## User accounts

An account ties a **user name** (letters, digits and `. _ @ -`, 64 characters at most), a
**type**, **groups** and **direct roles** (a role on every project or on some projects, given to
this account only): their roles give its [permissions](../advanced/access-control.md#direct-roles-and-projects-of-an-account).

| Type (`auth_source`) | Login | Creation |
|---|---|---|
| **Local** (`local`) | User name and password | By an administrator, or the initial `admin` account |
| **SSO** (`oidc`) | [Identity provider](../advanced/sso.md), no password | By an administrator, at the approval of an enrollment, or at the first login if `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` |

An SSO account also joins, at each login, the groups open to SSO named by its groups claim (see
[SSO accounts](../advanced/sso.md#sso-accounts)). Accounts are managed in the **Users** screen,
through the `/api/v1/users` REST API (`users.manage` permission) or with the
[CLI](../reference/cli.md#security-review-controller):

```bash
security-review-controller user create alice --group shop-triagers
# {"id": 2, "username": "alice", "auth_source": "local", "groups": [{"group_id": 3, "name": "shop-triagers", "source": "local"}], "permissions": {…}, "effective_role": "triager", …, "password": "q3V…"}
printf '%s\n' "$PASSWORD" | security-review-controller user create bob --password-stdin
security-review-controller user create carol@example.com --sso   # SSO groups only
security-review-controller user list
security-review-controller user set-groups alice --group readers --group auditors
security-review-controller user set-groups alice --group administrators   # created if missing
security-review-controller user set-roles alice --role triager:shop,billing   # direct roles
security-review-controller user reset-password alice   # local account: new password, sessions closed
security-review-controller user delete alice
security-review-controller group list    # groups, their roles and members
```

Through the API, an SSO account is created with `"auth_source": "oidc"`, without `password`;
`group_ids` lists its groups and `roles` its direct roles (empty `projects`: every project):

```bash
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "carol@example.com", "auth_source": "oidc", "group_ids": [4], "roles": [{"role_id": 3, "projects": ["crm"]}]}'
```

An account without any group or direct role has no permission and cannot log in.

For a local account, without `--password-stdin` (or without a password in the interface), a
random 24-character password is generated and shown **only once**. A chosen password has 12 to
256 characters. An SSO account never has a password: the user name and password login, the
reset and **My account** refuse it.

### First administrator

With `SECREVIEW_AUTH_BOOTSTRAP_ADMIN=true` (the case in the Docker image), the controller
creates at first start the **`admin`** user, member of the `administrators` group (`admin`
role), while no account exists.
Its password is shown only once in the logs of the controller:

```
WARNING security_review_mcp.controller: Initial Web UI administrator created: user 'admin', password (shown once): …
```

Handle this password as a secret: restrict access to the logs, log in with `admin` and change
it from **My account**. If it is lost, generate a new one (the old one is
invalidated at once): `security-review-controller user reset-password admin`.

!!! note "Upgrading from the `bootstrap-admin` token"
    Previous versions created a `bootstrap-admin` **token** instead of the account. On an
    existing database, this token stays valid; the `admin` account is created at the next start
    if no account exists. Once logged in with the account, revoke the old token:
    `security-review-controller token revoke bootstrap-admin`.

### Login and sessions

The login page offers the user name and password of a local account and, with the
[SSO login](../advanced/sso.md), the button of the identity provider; it does not accept
a token. `POST /api/v1/auth/login` checks the password of a local account and returns a signed
**session token**, valid `SECREVIEW_SESSION_HOURS` hours (8 by default), that the tab uses like
a Bearer token:

```bash
curl -s -X POST https://secreview.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username": "alice", "password": "…"}'
# {"session": "eyJ…", "expires_in": 28800, "username": "alice", "role": "triager"}
```

Every session names an account (local or SSO); at every request, the controller reads it again
from the database:

- a change of its **groups**, of their roles or of a role applies immediately to the open
  sessions;
- a **deletion** or a **new password** (changed by the user or reset by an administrator)
  closes every session of the account; `PUT /api/v1/me/password` hands a new session to the tab
  that changed the password.

Sessions are signed with `SECREVIEW_SESSION_SECRET` (at least 32 characters), shared by every
replica of the controller; without it, a random secret is drawn at every start and the sessions
end at restart (a warning is logged).

Login failures are limited: after **5 failures in 15 minutes** for a user name from the same
address, or **20 failures** from an address all user names together, the login is refused
(`429`, `Retry-After` header), even with the right password. The counters are kept in the
database: every worker and replica of the controller shares them. Every address is also limited
on the whole REST API (by default 600 requests a minute, 30 on the login routes, see
[`SECREVIEW_RATE_LIMIT_*`](../reference/configuration.md)). Behind a reverse proxy, the address seen is the proxy's, and the limit would then
apply to every client of the proxy: list the proxy in
[`SECREVIEW_FORWARDED_ALLOW_IPS`](../reference/configuration.md) so that the address of the
client is read from `X-Forwarded-For`. Every login and every failure is logged, without the password:

```
INFO security_review_mcp.web: Web login of alice (role triager) from 10.0.0.12
WARNING security_review_mcp.web: Failed web login of alice from 10.0.0.12
```

## Security

- The static files of `/ui/` are public (they hold no data); the `/api/v1/` API requires a
  session or a `reader`, `triager` or `admin` token. Only the login routes (`/api/v1/auth/…`)
  are public.
- Account passwords are never stored: only a salted **scrypt** digest (N=2¹⁴, r=8, p=5) is
  stored and no API answer returns it. The check takes the same time whether the user name
  exists or not, and the failure answer is identical. The Swagger documentation (`/api/docs`)
  and its schema (`/api/openapi.json`) are **disabled by default**
  (`SECREVIEW_SWAGGER_ENABLED=true` serves them); once enabled, they are public and give access
  to no data. Their files come with the web interface build: nothing is loaded from the
  Internet, and Swagger never sends the schema to the online validator. In Swagger, the
  padlock of a route says that it requires a token: it stays **open** while you have not entered
  a token with **Authorize**, and does not mean that the route can be reached without a token.
- The controller exposes no write route without a token. The
  [enrollment](../advanced/http.md#enrollment-a-project-requests-its-token) requests are
  filed on the **MCP server** (`POST /api/v1/enroll`, public); the controller lists and handles
  them (`GET /api/v1/enrollments`, `POST /api/v1/enrollments/{id}/approve`,
  `DELETE /api/v1/enrollments/{id}`, `tokens.manage` permission). It can therefore stay on an internal
  network.
- The token is sent in the `Authorization` header: no cookie, hence no CSRF. Only the
  [SSO login](../advanced/sso.md) sets a cookie, `HttpOnly`, `SameSite=Lax`, `Secure`
  over HTTPS, limited to the return URL and valid 10 minutes: it binds the return from the
  provider to the browser that started the login (protection against *login CSRF*). The session
  token is handed in the URL fragment (`#session=...`), never sent to a server, and the
  interface clears it at once from the address bar and the history.
- It is kept in the `sessionStorage` of the tab and disappears when the tab closes.
- Pages are served with a strict CSP (`script-src 'self'`, no external resource),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- Serve the interface over HTTPS ([built-in TLS or reverse proxy](../advanced/http.md#tls))
  as soon as it no longer listens on localhost: the token travels with every request.

## Configuration

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_WEB_UI` | `true` | Serves the interface on `/ui`; when `false`, the controller only serves the REST API |
| `SECREVIEW_WEB_UI_DIR` | — | Folder of another build of the application (default: the one of the package) |
| `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` | `false` | Creates the `admin` account at the first start of the controller, while no account exists; `true` in Docker |
| `SECREVIEW_SESSION_SECRET` | — | Signing secret of the sessions (at least 32 characters), identical on every replica |
| `SECREVIEW_SESSION_HOURS` | `8` | Lifetime of a session (1 to 24 hours), local account or SSO login |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Creates the [SSO account](../advanced/sso.md#sso-accounts) at the first login; otherwise an administrator creates it |
| `SECREVIEW_ENROLLMENT` | `true` | Token requests by the projects (on the MCP server), approved in the **Tokens** screen |
| `SECREVIEW_OIDC_*` | — | [SSO login](../advanced/sso.md), see the [reference](../reference/configuration.md) |

The published package and the Docker image contain the application already built. If you
install from source without building it, the controller only serves the REST API and a warning
is logged. See [Contributing](../contributing.md#web-interface) to build it.
