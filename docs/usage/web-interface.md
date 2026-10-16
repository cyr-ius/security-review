# Web interface

The web interface lets the security teams browse the reports saved by the agents and **triage
the findings** (fixed, accepted risk, false positive) without an MCP client. It is served by the
**controller**, a process distinct from the MCP server that shares its database (see
[Architecture and deployment](../getting-started/kubernetes.md)):

| Path | Content |
|---|---|
| `/ui/` | Web application (Angular) |
| `/api/v1/…` | REST API used by the application |
| `/api/docs` | OpenAPI documentation of the REST API (public, no data) |
| `/healthz` | Liveness probe (public) |

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# interface: http://127.0.0.1:8080/ui/
```

## Screens

The screens are reached from the sidebar: **Supervision** (projects, reports) for every role,
then **Reference** (rules, checklists, standards) and **Administration** (users,
tokens, SSO roles, settings) for the `admin` role. The bottom of the sidebar shows the connected
client, its role and the version, with the **My account** and logout buttons; on a
small screen, the sidebar opens with the menu button. The light or dark theme is chosen at the
top right, including on the login page, and is remembered by the browser.

The interface is available in **English**, **French** and **Spanish**. The language is chosen in
the picker at the top right, including on the login page. The change is immediate and is
remembered by the browser; on the first visit, the interface follows the language of the
browser, or English if it offers none of them. This choice only concerns the interface: the
language of the review reports is set in **Settings**, and the detailed error messages sent back
by the API stay in English.

- **Projects**: every project with its open findings by severity, sorted by risk,
  activity or name.
- **Project**: open findings, trend over 30 days to 1 year (chart and table), mean
  time to remediate, oldest open finding, most frequent CWEs, latest reports and SARIF export.
- **Reports**: list filtered by project and risk level (the filters are in the URL,
  so a link can be shared).
- **Report**: summary, context (repository, branch, commit), findings with location,
  CWE, code excerpt and recommendation; Markdown and SARIF download. Users with the `triager` or
  `admin` role change the status of a finding directly from this screen.
- **Standards**: the [development standards](standards.md) handed to the AI
  assistants by the `development-standards` prompt. Administrators search, read, create, edit
  (technologies, file patterns, Markdown content), disable or delete them. A change applies
  immediately.
- **Checklists**: administrators browse the check items by domain, filter the list and create,
  edit or delete the custom items. The default items can be edited, but not deleted. Every
  change is reloaded immediately by the server and included in the review prompts.
- **Rules**: administrators browse every [rule](rules.md) stored in the database,
  filtered by origin (default or custom). They create, edit (in a modal window, without losing
  the position in the list), enable or disable the rules, and delete the custom rules. A default
  rule can be edited ("Par défaut, modifiée" badge: default, edited) or disabled, but not
  deleted. The **Reload** button applies immediately a change made with the
  `security-review-controller rules` CLI.
- **Users**: administrators manage the [accounts](#user-accounts), the only
  ones to open the interface. Each account is **Local** (user name and password, entered or
  generated and shown only once) or **SSO** (login through the identity provider, no password),
  with a badge in the list. The administrator chooses the `reader`, `triager` or `admin` role
  and, for `reader` and `triager`, the projects. An SSO account can have no role of its own: the
  **Role of the groups** column then shows the role that its groups gave it at its
  last login. The administrator changes the role and the projects of an account, resets the
  password of a local account or deletes an account. A deleted SSO account is no longer created
  again at its login: the **Deleted SSO accounts** section lists them,
  with the **Allow again** button. The last administrator, local or SSO,
  can be neither deleted nor demoted.
- **My account**: shows the type of the account. A local user changes their
  password there (their other sessions are closed); the one of an SSO user is managed by the
  identity provider.
- **Tokens**: administrators create and revoke tokens limited to one or more
  projects. The **Usage** field chooses **MCP** (`mcp` role) or **REST API**; for the
  REST API, **API rights** chooses **Lecture seule** (read only, `reader`) or
  **Lecture et triage** (read and triage, `triager`). The list shows the usage of every token.
  A token never opens the web interface. The `admin` role stays unrestricted and is created from
  the CLI. The secret is shown only once; only its digest is stored, in the database. A
  revocation takes effect at the next request. The **Pending requests**
  section tells new tokens apart from requests for access to an additional project
  ([enrollment](../getting-started/http.md#enrollment-a-project-requests-its-token)):
  **Approve** activates the new token or adds the project to the existing token;
  **Reject** only deletes the request. The allowed projects and the additions still
  pending are shown for every token. The **Read access in the portal** column
  lets you give the developer, at the same time, read access to the project in the web
  interface, on their user account (see
  [project read access at enrollment](#project-read-access-at-enrollment)).
- **SSO roles**: administrators
  [configure the SSO login](#configuring-sso-in-the-interface) (every stored value replaces its
  `SECREVIEW_OIDC_*` variable, with a connection test to the provider) and map the groups or
  roles of the identity provider to a web role and, for `reader` and `triager`, to a list of
  projects (see [role mapping](#role-mapping)). The groups of the SSO configuration
  (`*_GROUPS`) are shown read only in the list of mappings. The SSO users themselves are managed
  in the **Users** screen.
- **Settings**: settings stored in the database, taking precedence over the
  environment variables and shared by the MCP server and the controller.
    - **Report language**: `SECREVIEW_REPORT_LANGUAGE` variable, choice
      left to the agent or language set here (`French`, `fr`, `pt-BR`…). It applies to the next
      review prompts; the `report_language` argument of a prompt still takes precedence
      ([report language](prompts-tools.md#report-language)).
    - **Outgoing proxy of the controller**: proxy of the OSV
      download **and** of the [SSO login](#openid-connect-sso-login). As for the SSO
      configuration, every value set here replaces its variable (**Variable** / **Interface
      web** badges): the URL follows `SECREVIEW_PROXY` (else `HTTPS_PROXY` / `NO_PROXY`), is set
      here, or forces the direct connection; the **hosts without proxy** follow
      `SECREVIEW_NO_PROXY` or are set here (see
      [hosts without proxy](dependencies.md#hosts-without-proxy): domains, IP addresses, CIDR
      ranges, `*`). The change applies to the next download and to the next SSO login, without
      restart. The applied proxy, its origin and the environment variables are shown; passwords
      are never shown again (`***`): sending `***` back keeps the stored one. Through the API:
      `PUT /api/v1/settings/proxy` with `url` and `no_proxy` (`null` applies the variable again,
      `"url": ""` forces the direct connection, a missing field is unchanged).
    - **OSV vulnerability database**: number of advisories by
      ecosystem, date and age of the last import, download configuration, history of the last
      50 updates (scheduled, CLI or web interface, with status, duration and result by
      ecosystem) and **Update now** button, only available if
      `SECREVIEW_OSV_AUTO_UPDATE=true`
      ([update by the controller](dependencies.md#automatic-update-by-the-controller)).

## Roles

**Tokens** give access to the MCP server and to the REST API (agents, CI, scripts); **users**
(local or SSO accounts) are the only ones to open the web interface. Every token has a role,
which decides the reachable endpoints:

| Role | Usage (**Jetons** screen) | `/mcp` | REST API (read) | Status change |
|---|---|---|---|---|
| `mcp` (default) | MCP | ✅ | — | — |
| `reader` | REST API — read only | — | ✅ | — |
| `triager` | REST API — read and triage | — | ✅ | ✅ |
| `admin` | CLI only | ✅ | ✅ | ✅ |

An `mcp`, `reader` or `triager` token restricted with `--project` only sees and triages the
allowed projects; the option can be repeated (see
[tokens restricted to a project](../getting-started/http.md#tokens-restricted-to-a-project)).

People log in with a [user account](#user-accounts): local (user name and password) or
[SSO](#openid-connect-sso-login). Accounts have the `reader`, `triager` or `admin` role, never
`mcp`, and never open `/mcp`. A token created without a role stays `mcp`: it serves the agents
and the CI, not the web interface. The `triager` role only adds the triage of the findings. A
`reader`, `triager` or `admin` token calls the REST API, for example from a script, but **does
not open the interface** (the login page only offers the accounts):

```bash
security-review-controller token create --label triage-bot --role triager
# {"id": "…", "label": "triage-bot", "role": "triager", "project": null, "created_at": "…", "token": "UJB7…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/projects
```

Revoke it with `security-review-controller token revoke triage-bot`. Every status change is
logged with the label of the token or of the account:

```
INFO security_review_mcp.web: Finding 42 set to accepted by triage-bot
```

!!! warning "Authentication required for the web UI"
    The API of the interface refuses the requests with status `503` while no user and no token
    exist; the login form stays displayed and says that authentication must be configured.
    Enable `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` (the case in the Docker image), or create an
    account with `security-review-controller user create`. This restriction concerns the web
    UI; MCP authentication stays independent (a user account never opens `/mcp`). With the
    [SSO login](#openid-connect-sso-login), the API asks for a login (`401`) even without any
    user or token in the database.

## User accounts

An account ties a **user name** (letters, digits and `. _ @ -`, 64 characters at most), a
**type** and a web role: `reader`, `triager` or `admin`. A `reader` or `triager` account can be
limited to a list of projects; an `admin` account sees every project.

| Type (`auth_source`) | Login | Creation |
|---|---|---|
| **Local** (`local`) | User name and password | By an administrator, or the initial `admin` account |
| **SSO** (`oidc`) | [Identity provider](#openid-connect-sso-login), no password | By an administrator, at the approval of an enrollment, or at the first login if `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` |

An SSO account can have **no role of its own**: only the role given by its groups applies (see
[SSO accounts](#sso-accounts)). Accounts are managed in the **Users** screen,
through the `/api/v1/users` REST API (`admin` role) or with the
[CLI](../reference/cli.md#security-review-controller):

```bash
security-review-controller user create alice --role triager --project shop-api
# {"id": 2, "username": "alice", "auth_source": "local", "role": "triager", "projects": ["shop-api"], …, "password": "q3V…"}
printf '%s\n' "$PASSWORD" | security-review-controller user create bob --password-stdin
security-review-controller user create carol@example.com --sso --role none   # group role
security-review-controller user create dave --sso --role reader --project billing
security-review-controller user list
security-review-controller user set-role alice --role reader
security-review-controller user reset-password alice   # local account: new password, sessions closed
security-review-controller user delete alice
```

Through the API, an SSO account is created with `"auth_source": "oidc"`, without `password`;
`"role": null` leaves it without a role of its own:

```bash
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "carol@example.com", "auth_source": "oidc", "role": null}'
```

For a local account, without `--password-stdin` (or without a password in the interface), a
random 24-character password is generated and shown **only once**. A chosen password has 12 to
256 characters. An SSO account never has a password: the user name and password login, the
reset and **My account** refuse it.

### First administrator

With `SECREVIEW_AUTH_BOOTSTRAP_ADMIN=true` (the case in the Docker image), the controller
creates at first start the **`admin`** user, with the `admin` role, while no account exists.
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
[SSO login](#openid-connect-sso-login), the button of the identity provider; it does not accept
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

- a change of **role or projects** applies immediately to the open sessions;
- a **deletion** or a **new password** (changed by the user or reset by an administrator)
  closes every session of the account; `PUT /api/v1/me/password` hands a new session to the tab
  that changed the password.

Sessions are signed with `SECREVIEW_SESSION_SECRET` (at least 32 characters), shared by every
replica of the controller; without it, a random secret is drawn at every start and the sessions
end at restart (a warning is logged).

Login failures are limited: after **5 failures in 15 minutes** for a user name from the same
address, or **20 failures** from an address all user names together, the login is refused
(`429`, `Retry-After` header), even with the right password. The counter is kept in memory by
every replica. Behind a reverse proxy, the address seen is the proxy's: the limit then applies
to every client of the proxy. Every login and every failure is logged, without the password:

```
INFO security_review_mcp.web: Web login of alice (role triager) from 10.0.0.12
WARNING security_review_mcp.web: Failed web login of alice from 10.0.0.12
```

## OpenID Connect SSO login

The controller can delegate the login to the interface to an OpenID Connect identity provider
(Keycloak, Microsoft Entra ID, Okta, Authentik, Dex...). The login page then shows a
**Log in with SSO** button above the form of the local accounts, which
stays available (initial `admin` account, fallback accounts).

The flow is *authorization code* with PKCE (`S256`), state and nonce:

1. `GET /api/v1/auth/oidc/login` redirects the browser to the provider;
2. the provider sends back to `GET /api/v1/auth/oidc/callback`; the controller exchanges the
   code (server-to-server call), checks the ID token (signature by the JWKS keys of the
   provider, issuer, audience, expiry, nonce), finds the [SSO account](#sso-accounts) of the
   user (or creates it) and stores the role given by its groups;
3. it hands the interface a signed **session token**, valid `SECREVIEW_SESSION_HOURS` hours,
   that the tab uses like a Bearer token.

### Declaring the client at the provider

Create a *confidential* OIDC client (or a public one, without a secret: PKCE is enough) with:

- **Redirect URL**: `https://<controller>/api/v1/auth/oidc/callback`, the exact public URL seen
  by the browser (behind a reverse proxy, the proxy's);
- a claim holding the groups or roles of the user in the ID token (or, failing that, in the
  *userinfo* answer, which the controller reads when the ID token does not contain it).

Keycloak example (realm roles):

```bash
SECREVIEW_OIDC_ENABLED=true
SECREVIEW_OIDC_ISSUER=https://sso.example.com/realms/acme
SECREVIEW_OIDC_CLIENT_ID=security-review
SECREVIEW_OIDC_CLIENT_SECRET=...            # empty for a public client
SECREVIEW_OIDC_REDIRECT_URI=https://secreview.example.com/api/v1/auth/oidc/callback
SECREVIEW_OIDC_ROLES_CLAIM=realm_access.roles   # "groups" by default
SECREVIEW_OIDC_ADMIN_GROUPS=secreview-admins
SECREVIEW_OIDC_TRIAGER_GROUPS=secreview-triagers
SECREVIEW_OIDC_READER_GROUPS=developers,qa
SECREVIEW_OIDC_AUTO_CREATE_USERS=true       # otherwise, create every SSO account in Utilisateurs
SECREVIEW_SESSION_SECRET=$(openssl rand -base64 48)
SECREVIEW_OIDC_DISPLAY_NAME=Keycloak
```

The issuer must use HTTPS (HTTP is only accepted on `localhost`, for development); its
`/.well-known/openid-configuration` document must announce the same `issuer`. If the provider
uses an internal CA, give it with `SECREVIEW_OIDC_CAFILE`. The controller reaches the provider
through its outgoing proxy (`SECREVIEW_PROXY` / `SECREVIEW_NO_PROXY`, or the **Paramètres**
(Settings) screen), else through `HTTPS_PROXY` / `NO_PROXY`.

### Configuring SSO in the interface

The same settings can be changed in the **SSO settings** section of
the **SSO roles** screen (`admin` role), without restarting the controller. As for
the **Settings** screen, a value stored in the database **replaces its
`SECREVIEW_OIDC_*` variable**, field by field; a field never changed follows its variable:

- every field has the **Variable** badge (the variable applies, its value is shown under the
  field) or **Interface web** (stored value); the **Variable** link of a stored field deletes
  the stored value and applies the variable again;
- the **client secret** is never shown again: left empty, the current secret is kept;
  **Delete** stores an empty secret (public client, PKCE only);
- **Test the connection** contacts the provider with the values of the
  form, without storing them: reading of the `/.well-known/openid-configuration` document (same
  `issuer`, HTTPS endpoints), then of the signing keys (JWKS);
- **Save** refuses (`422`) a configuration that would enable an invalid login
  (missing or non-HTTPS issuer, scopes without `openid`, unknown default role...): nothing is
  stored then. An incomplete configuration can be prepared while SSO stays disabled.

The change applies to the next login, on every replica (the controller reads the configuration
again at every login and rebuilds the OIDC flow when it changes). Sessions already open stay
valid until they expire. Still variables only: `SECREVIEW_OIDC_CAFILE` (a file of the
deployment) and the session settings (`SECREVIEW_SESSION_SECRET`, `SECREVIEW_SESSION_HOURS`).
If a variable changed later makes the combination with the stored values invalid, the
controller starts anyway: the SSO login is disabled and the error logged, to be fixed in the
screen.

Through the API (`/api/v1/oidc/settings`, `admin` role): `GET` describes every setting (stored
`value` or `null`, `env`, `effective`; a set secret reads `***`), `PUT` changes the sent fields
(`null` applies the variable again, a missing field is unchanged) and
`POST /api/v1/oidc/settings/test` tests the provider without storing anything:

```bash
curl -X PUT https://secreview.example.com/api/v1/oidc/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled": true, "issuer": "https://sso.example.com/realms/acme",
       "client_id": "security-review", "client_secret": "...",
       "redirect_uri": "https://secreview.example.com/api/v1/auth/oidc/callback",
       "display_name": null}'
```

### SSO accounts

Every SSO user is an account of the **Users** screen (**SSO** badge), named by
the value of the `SECREVIEW_OIDC_USERNAME_CLAIM` claim (`preferred_username` by default),
compared exactly, case included. There is no fallback to `email` or `sub`, and a value that is
not a valid user name (control or invisible character, space, more than 64 characters) is
refused.

At login, the controller looks for this account:

| Situation | Result |
|---|---|
| Existing SSO account | Login, with the effective role below |
| No account, `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` | The account is **created** (`created_by`: `oidc`) if its groups or the default role give it a role; otherwise refused, without creation |
| No account, `SECREVIEW_OIDC_AUTO_CREATE_USERS=false` (default) | **Refused**: an administrator must first create the SSO account |
| **Local** account with the same name | **Refused**: an SSO login never opens a local account |
| SSO account bound to another `sub` | **Refused** (see below) |
| SSO account deleted by an administrator | **Refused**, even with the automatic creation (see below) |

At the first login, the account is **bound** to the `sub` claim of the provider; a later login
with the same user name but another `sub` (provider account deleted then created again,
renamed...) is refused. To give the user name to someone else, delete then create the account
again.

The **effective role** combines the role given to the account (**Utilisateurs** screen, or
approval of an enrollment) and the role of its groups ([role mapping](#role-mapping)), stored at
every login: the highest wins, and its projects are the union of those of both accesses with
this role. An account with neither a role of its own nor a group role is refused and its open
sessions are closed. The given role applies at once; the group role, at the next login.

**Deleting an SSO account** (**Utilisateurs** screen, `DELETE /api/v1/users/{id}` or
`security-review-controller user delete NAME`) closes its sessions at once and **revokes** its
user name: an SSO login no longer creates it again, even with the automatic creation and groups
that give it a role ("compte supprimé" message, account deleted, on the login page). To give it
access back, an administrator creates the account again (by hand or at the approval of an
enrollment), or lifts the revocation (**Autoriser à nouveau**, Allow again,
`DELETE /api/v1/users/revoked/{username}`): the account is then created again at its next
login. `GET /api/v1/users/revoked` lists the revoked accounts, with the author and the date of
the deletion.

The **last administrator** can be neither deleted nor demoted. An administrator is a local or
SSO account whose given role is `admin`, or an SSO account whose groups gave it `admin` at its
last login. Preferably keep a local administrator: if the identity provider becomes
unreachable, it remains the only access, besides the CLI.

```
INFO security_review_mcp.web: SSO web user alice created at its first login
INFO security_review_mcp.web: OIDC login of oidc:alice with role reader on every project
WARNING security_review_mcp.web: OIDC login of oidc:bob refused: no web user bob
INFO security_review_mcp.web: Web user carol (oidc) deleted by admin
WARNING security_review_mcp.web: OIDC login of oidc:carol refused: web user carol was deleted
```

### Role mapping

The *role mapping* decides the web role, and the projects, of an SSO user from the values of
the `SECREVIEW_OIDC_ROLES_CLAIM` claim (list or string, dotted path accepted, exact comparison,
case sensitive). A **mapping** ties one of these values (a group or a role of the provider) to:

- a web role: `reader`, `triager` or `admin` (never `mcp`: an OIDC session only opens the web
  interface, not `/mcp`);
- for `reader` and `triager`, an optional list of projects (50 at most); without a list, every
  project. An `admin` mapping always covers every project.

Mappings have two origins:

| Origin | Management | Projects |
|---|---|---|
| Database | **SSO roles** screen or `/api/v1/oidc/role-mappings` API (`admin` role) | All or a list |
| `SECREVIEW_OIDC_ADMIN_GROUPS`, `..._TRIAGER_GROUPS`, `..._READER_GROUPS` variables | Configuration of the controller (read only in the interface) | All |

The variables are mostly used to name the first administrator, who then creates the other
mappings in the interface.

At login:

1. the **highest role** among the mappings that match the groups of the user wins
   (`admin` > `triager` > `reader`);
2. the session sees **every project** if one of the mappings of this role is not restricted;
   otherwise the **union** of their projects (200 at most: beyond that, the login is refused).
   The projects of the mappings of a lower role are not added: a user who is `triager` on
   `shop-api` and `reader` on `billing` is `triager` on `shop-api` only;
3. without any group mapping, `SECREVIEW_OIDC_DEFAULT_ROLE` applies (`reader` or `triager`,
   every project); empty (default), the groups give no role and only the role given to the
   [SSO account](#sso-accounts) still allows the login, otherwise it is **refused**. The
   `admin` role cannot be given by default.

This group role is then combined with the role given to the account (see
[SSO accounts](#sso-accounts)).

A restricted session behaves like a
[token restricted to a project](../getting-started/http.md#tokens-restricted-to-a-project): the
other projects, their reports and their findings are handled as missing. A project can be named
before it exists (the screen suggests the known projects). A change of mapping applies at the
**next login** of the user; until then, their open sessions keep the stored group role (see
[Sessions](#sessions)). Every creation, change or deletion is logged with the label of the
administrator:

```
INFO security_review_mcp.web: Role mapping payments -> triager (billing) created by oidc:alice
```

API example:

```bash
curl -X POST https://secreview.example.com/api/v1/oidc/role-mappings \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"claim_value": "payments-team", "role": "triager", "projects": ["billing"]}'
```

The label of an SSO session is `oidc:<username>`: it is the one that appears in the logs and
in the triage history.

### Project read access at enrollment

At the approval of an [enrollment](../getting-started/http.md#enrollment-a-project-requests-its-token)
request, the administrator can also give the developer read access to the project in the
portal, on their **user account**: the developer who requested an MCP token for a project then
browses its reports.

- In the **Project tokens** screen, the **Read access in the portal** column is prefilled with the requester (`requested_by`) when it is given, and
  ticked when SSO is enabled. This field is declared by the client and **is not verified**:
  check or correct it before approving, or untick the box.
- The name designates an account of the **Users** screen, local or SSO. With SSO
  enabled, an unknown name becomes an **SSO account** (`reader` on the project), ready for its
  first login; without SSO, the account must exist.
- An account without a role of its own becomes `reader` on the project; a restricted `reader`
  or `triager` account gets one more project; an account that already sees every project is
  unchanged. An approved additional request for the same user adds the project the same way.

The access then shows on the account, where it is changed like the others. It is independent of
the MCP token: revoking the token does not remove it.

```bash
# Approve a request and give the "alice" user read access to the project
curl -X POST https://secreview.example.com/api/v1/enrollments/$REQUEST_ID/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"portal_user": "alice"}'
```

The answer then contains `portal_user`, the updated account. An invalid user name, an unknown
account without SSO or a reached limit are refused (`422`) before the approval: the request
stays pending. The log of the controller records the access:

```
INFO security_review_mcp.web: Web access to shop-api given to web user alice by admin
```

!!! note "Upgrading from the named accesses"
    Previous versions stored these accesses apart ("named accesses",
    `/api/v1/oidc/user-grants` API). Schema migration `0006` turns them into `reader` SSO
    accounts on the same projects, then deletes the table. An access whose name is not a valid
    user name or that bears the name of a local account is dropped, with a warning in the log of
    the migration.

### Sessions

- The session token is signed (HMAC-SHA256) with a key derived from `SECREVIEW_SESSION_SECRET`
  (at least 32 characters), like the one of the [local accounts](#login-and-sessions), and
  names the SSO account, read again at every request: deleting the account or changing its
  given role applies at once. Every replica of the controller must share this secret; without
  it, a random secret is drawn at every start and the sessions end at restart (a warning is
  logged).
- A group change at the provider only applies at the next login. To cut every session before it
  expires, delete the account, or change `SECREVIEW_SESSION_SECRET` and restart the controller
  (every session is cut).
- **Log out** clears the session of the tab, not the one of the identity
  provider.

On failure, the login page gives the cause (access denied at the provider, no role, SSO account
not created yet or deleted, user name taken by a local account or bound to another account,
missing user name, expired state, invalid token, unreachable provider); the detail is logged by
the controller, without code or token.

## Security

- The static files of `/ui/` are public (they hold no data); the `/api/v1/` API requires a
  session or a `reader`, `triager` or `admin` token. Only the login routes (`/api/v1/auth/…`)
  are public.
- Account passwords are never stored: only a salted **scrypt** digest (N=2¹⁴, r=8, p=5) is
  stored and no API answer returns it. The check takes the same time whether the user name
  exists or not, and the failure answer is identical. The Swagger documentation (`/api/docs`)
  and its schema (`/api/openapi.json`) are public and give access to no data. In Swagger, the
  padlock of a route says that it requires a token: it stays **open** while you have not entered
  a token with **Authorize**, and does not mean that the route can be reached without a token.
- The controller exposes no write route without a token. The
  [enrollment](../getting-started/http.md#enrollment-a-project-requests-its-token) requests are
  filed on the **MCP server** (`POST /api/v1/enroll`, public); the controller lists and handles
  them (`GET /api/v1/enrollments`, `POST /api/v1/enrollments/{id}/approve`,
  `DELETE /api/v1/enrollments/{id}`, `admin` role). It can therefore stay on an internal
  network.
- The token is sent in the `Authorization` header: no cookie, hence no CSRF. Only the
  [SSO login](#openid-connect-sso-login) sets a cookie, `HttpOnly`, `SameSite=Lax`, `Secure`
  over HTTPS, limited to the return URL and valid 10 minutes: it binds the return from the
  provider to the browser that started the login (protection against *login CSRF*). The session
  token is handed in the URL fragment (`#session=...`), never sent to a server, and the
  interface clears it at once from the address bar and the history.
- It is kept in the `sessionStorage` of the tab and disappears when the tab closes.
- Pages are served with a strict CSP (`script-src 'self'`, no external resource),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- Serve the interface over HTTPS ([built-in TLS or reverse proxy](../getting-started/http.md#tls))
  as soon as it no longer listens on localhost: the token travels with every request.

## Configuration

| Variable | Default | Role |
|---|---|---|
| `SECREVIEW_WEB_UI` | `true` | Serves the interface on `/ui`; when `false`, the controller only serves the REST API |
| `SECREVIEW_WEB_UI_DIR` | — | Folder of another build of the application (default: the one of the package) |
| `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` | `false` | Creates the `admin` account at the first start of the controller, while no account exists; `true` in Docker |
| `SECREVIEW_SESSION_SECRET` | — | Signing secret of the sessions (at least 32 characters), identical on every replica |
| `SECREVIEW_SESSION_HOURS` | `8` | Lifetime of a session (1 to 24 hours), local account or SSO login |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Creates the [SSO account](#sso-accounts) at the first login; otherwise an administrator creates it |
| `SECREVIEW_ENROLLMENT` | `true` | Token requests by the projects (on the MCP server), approved in the **Tokens** screen |
| `SECREVIEW_OIDC_*` | — | [SSO login](#openid-connect-sso-login), see the [reference](../reference/configuration.md) |

The published package and the Docker image contain the application already built. If you
install from source without building it, the controller only serves the REST API and a warning
is logged. See [Contributing](../contributing.md#web-interface) to build it.
