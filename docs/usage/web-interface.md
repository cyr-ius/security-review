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
| `/api/health` | Liveness of the API, checked by the application at load (public, tells nothing about the version or settings) |
| `/healthz` | Liveness probe (public) |

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# interface: http://127.0.0.1:8080/ui/
```

## Screens

The screens are reached from the sidebar: **Supervision** (projects, reports) for every account,
then **Reference** (rules, checklists, standards) and **Administration** (users, groups, roles,
tokens, audit log, OIDC, report language, outgoing proxy, OSV database), each shown only to the
accounts that hold its [permission](../advanced/access-control.md#permissions). The bottom
of the sidebar shows the connected client (its permissions when hovered) and the version (a link to **About**), with the **My account** and logout buttons.
On a small screen, the sidebar is reduced to its icons (each one names its screen when hovered)
and the button at the top left opens it in full; on a large screen, the same button reduces it
to its icons or expands it, a choice remembered by the browser.

The theme button at the top right, also on the login page, moves from **automatic** (the theme
of the system, followed live) to **light** and **dark**. The choice of a logged-in user is kept
in its account (`GET` and `PUT /api/v1/me/preferences`), for every browser it uses; the browser
remembers the last one for the login page.

The interface is available in **English**, **French** and **Spanish**. The language is chosen in
the picker at the top right, including on the login page. The change is immediate and is
remembered by the browser; on the first visit, the interface follows the language of the
browser, or English if it offers none of them. This choice only concerns the interface: the
language of the review reports is set in **Report language**, and the detailed error messages sent
back by the API stay in English.

The **About** page gives the version of the controller, whether a **New version** is available
on GitHub (only with `SECREVIEW_UPDATE_CHECK_ENABLED=true`, see
[outgoing connections](../reference/security.md#security-of-the-server-itself)), the links of the
documentation, of the source code and to report an issue, the link of the Swagger documentation
when it is enabled, and the status of the backend (`/api/health`, checked again with **Check
again**). When the
application loads, it checks `/api/health` first: if the controller does not answer (or stops
answering later), the **Backend unavailable** page opens, and its **Retry** button goes back to
the requested page once the controller answers again.

Tables are sorted by clicking a column header: a small arrow shows the sorted column and its
direction, and a second click reverses it. Each table opens sorted by its default column (arrow
shown), and the browser remembers the chosen sort for the next visits.

- **Projects**: every project with its open findings by severity. Search by project name, sort
  by name, worst open finding or last report, and filter by worst open severity. The **Review open findings** button opens the findings to review of every
  project you can see (**Findings to review: all projects**), each with a link to its project.
  The **Risk acceptances** button lists the accepted risks of every project you can see.
  With the `projects.create` permission, **New project** creates a project that you then read
  (see [Creating a project](../advanced/access-control.md#creating-a-project)), and the
  **Pending projects** section lists the projects requested by an
  [enrollment](../advanced/http.md#enrollment-request-the-project) (requester, address, request
  and expiry dates): **Approve** creates the project without any member, **Reject** deletes the
  request; a request not approved before its expiry is deleted.
- **Project**: open findings, trend over 30 days to 1 year (chart and table), mean
  time to remediate, oldest open finding, most frequent CWEs, latest reports and SARIF export.
  The **Review open findings** button opens the next screen; **Risk acceptances** lists the
  accepted risks of the project.
- **Findings to review**: every open finding of the project across all its reports, worst
  severity first, then newest report first, for a review by a security expert. Each finding
  shows its description, code excerpt and recommendation, and a link to its report (date, review
  type, branch, commit). Filters by status (to re-check accepted risks or false positives), by
  severity and by review type (**Security review**, **API security review**, **Codebase
  review**...: see [review type](prompts-tools.md#review-type)); **Load more** displays the next
  findings. Users with the `findings.triage` permission change the status of each finding from this
  screen and apply or reject the statuses proposed by the agents (see
  [triage of findings](#triage-of-findings)); a triaged finding stays displayed until the next
  reload (**Refresh** button).
- **Risk acceptances**: the accepted risks of the project (or of every project), expired ones
  included, nearest expiry first. Search, sort and filter by state (**Active**, **Expired**) and
  severity; **Refresh** reloads the list. A click on a finding opens its details: reason,
  comments, and for the `findings.triage` permission the forms to add a comment, change the
  expiry date and remove the acceptance (see [risk acceptances](#risk-acceptances)).
- **Reports**: list filtered by project and risk level, searchable across report metadata and
  summary, and sortable by date, project, risk, type, branch, author or summary. Search and
  filters stay in the URL, so a view can be shared; the sort is remembered by the browser.
- **Report**: summary, context (repository, branch, commit, review type, **Author** and
  **Sent by (token)**, see [author of a report](prompts-tools.md#author-of-a-report)), findings with
  location, CWE, code excerpt and recommendation; Markdown and SARIF download. Users with the
  `findings.triage` permission change the status of a finding directly from this screen.
- **Standards**: the [development standards](../advanced/standards.md) handed to the AI
  assistants by the `development-standards` prompt. Search and sort by title,
  technology or file pattern, and filter by enabled state. Administrators read, create, edit
  (technologies, file patterns, Markdown content), disable or delete them. A change applies
  immediately. **Export** and **Import** copy them as a [TOML file](../advanced/standards.md#import-and-export).
- **Checklists**: administrators search and sort check items, and filter by domain and origin; they create,
  edit or delete the custom items. The default items can be edited, but not deleted. Every
  change is reloaded immediately by the server and included in the review prompts.
  **Export** and **Import** exchange [TOML packs](../advanced/rules.md#import-and-export-in-the-web-interface).
- **Rules**: administrators search and sort every [rule](../advanced/rules.md) stored in the database,
  and filter by origin (default or custom) and severity. They create, edit (in a modal window, without losing
  the position in the list), enable or disable the rules, and delete the custom rules. A default
  rule can be edited ("Par défaut, modifiée" badge: default, edited) or disabled, but not
  deleted. The **Reload** button applies immediately a change made with the
  `security-review-controller rules` CLI. **Export** and **Import** exchange
  [TOML packs](../advanced/rules.md#import-and-export-in-the-web-interface).
- **Users**: administrators manage the [accounts](#user-accounts), the only
  ones to open the interface. Each account is **Local** (user name and password, entered or
  generated and shown only once) or **OIDC** (login through the identity provider, no password),
  with a badge in the list. The account list is searchable, sortable and filterable by type.
  Deleted OIDC accounts can be searched, sorted and filtered by the revoking administrator. The administrator chooses its **Groups**, the only source of its
  permissions; the **Groups** column shows the groups, with a shield for the OIDC groups found at
  the last login, and **Access** lists the permissions they give, with their projects. The administrator changes the groups of
  an account, resets the password of a local account or deletes an account. A deleted OIDC account is no longer created again at its login:
  the **Deleted OIDC accounts** section lists them, with the **Allow again** button. The last
  holder of `users.manage` can be neither deleted nor lose it.
- **Groups**: administrators search and sort groups, and filter local groups from groups open to
  OIDC. They create the groups, give them roles (on every project or on some projects), add
  members and choose whether the group is **Open to OIDC** (see
  [Roles, groups and permissions](../advanced/access-control.md#groups)).
- **Roles**: administrators search and sort roles, and filter built-in from custom roles. They
  create roles from the permissions; the built-in roles `reader` and `admin` are shown read
  only. `triager` (read and triage) and `mcp-user` (personal MCP token), created with the
  database, are ordinary roles: they can be changed or deleted.
- **My account**: shows the type of the account and **My permissions**. A local user changes their
  password there (their other sessions are closed); the one of an OIDC user is managed by the
  identity provider. **Personal tokens** creates and revokes the personal tokens of the account:
  [REST API](#api-tokens) tokens (Swagger, scripts), which hold its rights, and
  [MCP](#personal-mcp-tokens) tokens for its agent, which reach the projects it may read.
- **Tokens**: tokens are searchable, sortable and filterable by usage. Administrators create
  and revoke tokens for one or more projects, or for
  **All projects** (never for a CI/CD token). The **Usage** field chooses **MCP** (`mcp` role),
  **CI/CD pipeline** (`ci` role, for
  [`security-review-ci`](gate.md#pipeline-client-security-review-ci)) or **REST API** (`api`
  role, with the **Role** it holds, see [API tokens](#api-tokens)): tokens are for machines, a
  person reads and triages with a [user account](#user-accounts). Under **Allowed projects**, **All projects** gives every project, including the
  projects reviewed later, and **Selected projects** shows the boxes of the projects the token
  sees; **Validity**
  sets its lifetime (30 days to 1 year, or the default of the server, `SECREVIEW_TOKEN_MAX_DAYS`).
  The list shows the usage of every `mcp` and `ci` token, its projects
  and its expiry date (**Expired** once past). **Projects** changes the projects of an existing
  token, or gives it **All projects** after a confirmation, without changing its secret: the
  change applies from the next request.
  **Rotate** replaces the secret of a token and shows the new one once; the previous one keeps
  working for the grace period chosen above the list (none, 1 h, 24 h or 7 days, see
  [expiry and rotation](../advanced/http.md#expiry-and-rotation-of-tokens)).
  A token never opens the web interface. The `admin` and `metrics` tokens stay unrestricted and
  are managed from the CLI only. The secret is shown only once; only its digest is stored, in the database. A
  revocation takes effect at the next request. The
  [enrollment](../advanced/http.md#enrollment-request-the-project) creates no token: a project
  it requests waits in **Projects**, and once approved an administrator gives a developer
  access to it by adding them to its group `project:<project>` (**Groups** screen).
- **Audit log**: administrators read the [audit log](../advanced/audit-metrics.md#audit-log): triage
  decisions, agent proposals, tokens and enrollments, newest first, with who made
  them; filter by event and project, search event details, sort by date/action/actor/target/project,
  and use **Load more** for older events. Holders of `settings.manage` also set there the
  [syslog server](../advanced/audit-metrics.md#forwarding-to-syslog) the events are forwarded to
  (**Syslog** button, next to **Refresh**).
- **OIDC**: administrators
  [configure the OIDC login](../advanced/sso.md#configuring-oidc-in-the-interface) (a value stored there applies when its
  `SECREVIEW_OIDC_*` variable is not set, with a connection test to the provider). What OIDC users may do
  comes from the groups open to OIDC named by their groups claim (see
  [groups of the identity provider](../advanced/sso.md#groups-of-the-identity-provider)).
The next three screens hold settings stored in the database and shared by the MCP server and
the controller (`settings.manage` permission; the former `/ui/settings` address opens
**Report language**). **An environment variable that is set (environment or `.env` file)
always takes precedence** over the value set in the interface: its field is then locked and
shows the variable, and a value stored before the variable was set is marked as ignored, with
a **Delete** button.

- **Report language**: choice left to the agent or language set here (`French`, `fr`,
  `pt-BR`…), when `SECREVIEW_REPORT_LANGUAGE` is not set. It applies to the next review
  prompts; the `report_language` argument of a prompt still takes precedence
  ([report language](prompts-tools.md#report-language)).
- **Outgoing proxy**: proxy of the outgoing connections of the controller, used by the OSV
  download **and** by the [OIDC login](../advanced/sso.md). When `HTTPS_PROXY` (else
  `HTTP_PROXY`) is not set, the proxy is set here (or **No proxy (direct connection)**); when
  `NO_PROXY` is not set, the **hosts without proxy** are set here (see
  [hosts without proxy](../advanced/dependencies.md#hosts-without-proxy): domains, IP
  addresses, `*`, no CIDR ranges). An empty variable counts as not set. The change applies to the next download and to the next
  OIDC login, without restart. The applied proxy, its origin and the variables are shown; passwords
  are never shown again (`***`): sending `***` back keeps the stored one. Through the API:
  `PUT /api/v1/settings/proxy` with `url` and `no_proxy` (`null` deletes the stored value,
  `"url": ""` forces the direct connection, a missing field is unchanged; a value whose
  variable is set is refused with `422`). `GET /api/v1/settings` gives, for each setting, the
  stored `value`, the variable `env`, `env_set` (the variable is set and takes precedence) and
  the effective value.
- **OSV database**: state of the OSV vulnerability database: number of advisories by
  ecosystem, date and age of the last import, download configuration, history of the last
  50 updates (scheduled, CLI or web interface, with status, duration and result by
  ecosystem), searchable and sortable with status/trigger filters, and **Update now** button, only available if
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
  that the decision has expired. For **Risk accepted**, the **No expiry** box removes the date:
  the risk stays accepted until someone reopens the finding (disabled with
  `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false`). A false positive always needs a date.
- **Open** and **Fixed** are saved at once (optional reason through the API). Any decision
  removes the pending proposal.

Only a session (local or OIDC account) may accept a risk or mark a false positive: a bearer
token, even `admin`, gets `403`. Through the REST API:

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42 \
  -d '{"status": "accepted", "reason": "Internal tool, not exposed to the Internet", "expires_on": "2027-01-31"}'
# {"id": 42, "status": "accepted", "status_approver": "alice", "status_expires_at": "2027-01-31T00:00:00Z", …}
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/findings/42/proposal    # reject the agent proposal
```

A reason that is missing or too short, an expiry date in the past or too far away, or an expiry
date for `open` / `fixed` gets `422`. Without `expires_on`, an acceptance never expires, unless
`SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false` (`422`); `GET /api/v1/me` returns
`permanent_acceptance` to tell whether the caller may do it. The **Risk accepted** and **False positive** decisions
made before this feature had no reason nor approver: the database upgrade gives them an expiry
date 30 days later, with a reason that asks to confirm them. Review them with the status filters
before that date, or they block the gate again.

### Risk acceptances

The **Risk acceptances** screen (`/ui/risk-acceptances`, or per project from the **Projects** and
**Project** screens) lists the accepted risks, expired ones included, so that they can be renewed
before or after their end of validity. In the details of an acceptance:

- **Comments**: every comment, oldest first, with its author and date. Anyone who reads the
  project sees them. A comment **can be neither edited nor deleted**: no route of the API does
  it. They stay with the finding when its acceptance is removed.
- **Add a comment** (at most 2000 characters, secrets masked) records the logged-in user as its
  author, in the audit log too (`finding.commented`).
- **Change the expiry date** saves the acceptance again with the same reason and the new date
  (same limits as above, **No expiry** included): the logged-in user becomes its approver.
- **Remove the acceptance** reopens the finding, after a confirmation.

Like an acceptance, a comment needs a session with the `findings.triage` permission: a bearer
token gets `403`. Through the REST API:

```bash
curl -H "Authorization: Bearer $SESSION" \
  "https://secreview.example.com/api/v1/risk-acceptances?project=shop-api"
# {"project": "shop-api", "total": 1, "acceptances": [{"id": 42, "status": "accepted", "expired": false, "comments_total": 1, …}]}
curl -H "Authorization: Bearer $SESSION" https://secreview.example.com/api/v1/findings/42/comments
# [{"id": 7, "finding_id": 42, "author": "alice", "body": "Renew it after the audit", "created_at": "…"}]
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42/comments -d '{"body": "Renew it after the audit"}'
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42 -d '{"status": "open"}'    # remove the acceptance
```

`GET /api/v1/risk-acceptances` takes `limit` (capped by `SECREVIEW_MAX_LIST_LIMIT`) and
`offset`; without `project`, it lists every project the caller can read.

## Roles

**Tokens** are for machines (MCP agents, CI/CD pipelines, Prometheus, administration scripts);
**users** (local or OIDC accounts) are the people: they alone open the web interface, and their
rights come from the roles of their groups. Every token has a role, which decides the reachable
endpoints:

| Role | Usage (**Tokens** screen) | `/mcp` | REST API (read) | Status change |
|---|---|---|---|---|
| `mcp` (default) | MCP | ✅ | — | — |
| `admin` | CLI only | ✅ | ✅ | `open`, `fixed` ¹ |
| `api` | REST API — Swagger and scripts ([API tokens](#api-tokens)) | — | ✅ with the permissions of its role or of its user | `open`, `fixed` ¹ with `findings.triage` |
| `ci` | CI/CD pipeline — gate, SARIF, trend and scans | — | pipeline routes only (`/api/v1/ci/`), including the scans that store reports | — |
| `metrics` | CLI only | — | `/metrics` only ([Prometheus](../advanced/audit-metrics.md#prometheus-metrics)) | — |

¹ With a token. `accepted` and `false_positive` need a person logged in to the interface
with the `findings.triage` permission ([triage of findings](#triage-of-findings)). On `/mcp`, no
role changes a status: the agents only propose one.

An `mcp` token restricted with `--project` only sees the allowed projects; a `ci` token is always restricted to its projects (see
[`ci` token](gate.md#ci-token-and-visible-projects)); the option can be repeated (see
[tokens restricted to a project](../advanced/http.md#tokens-restricted-to-a-project)).

People log in with a [user account](#user-accounts): local (user name and password) or
[OIDC](../advanced/sso.md). What an account may do comes from the roles of its groups (see
[Roles, groups and permissions](../advanced/access-control.md)); an account never opens `/mcp`.
A token created without a role stays `mcp`: it serves the agents, not the web interface. There
is no read-only or triage token: to give a person read or triage access, add their account to a
group that has the `reader` or `triager` role (on some projects or on every project). An `admin`
token calls the whole REST API, for example from an administration script, but **does not open
the interface** (the login page only offers the accounts):

```bash
security-review-controller token create --label ops-script --role admin
# {"id": "…", "label": "ops-script", "role": "admin", "project": null, "created_at": "…", "token": "UJB7…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/projects
```

The REST API lists the findings of a project across all its reports, open by default, worst
first (`status`, `severity` and `review_type` filter, `limit` is capped by
`SECREVIEW_MAX_LIST_LIMIT`, `total` gives the number of matching findings for paging). Without
`project`, it lists the findings of every project the caller reads (`"project": null`):

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/findings?project=shop-api&status=open&limit=50"
# {"project": "shop-api", "total": 12, "findings": [{"id": 42, "severity": "critical", "report_id": 7, "project": "shop-api", "branch": "main", "commit_sha": "abc123", "review_type": "codebase-review", "report_created_at": "…", …}, …]}
```

`GET /api/v1/reports` lists the reports (`project`, `risk_level`, `review_type` and `author`
filter), each with its `author` and `submitted_by`:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/reports?project=shop-api&author=alice@example.com"
```

Revoke it with `security-review-controller token revoke ops-script`. Every status change is
logged with the label of the token or of the account:

```
INFO security_review_mcp.web: Finding 42 set to fixed by ops-script
```

and written to the [audit log](../advanced/audit-metrics.md#audit-log) (`GET /api/v1/audit`, `audit.read`
permission), with the actor `token:ops-script` or `user:<name>`.

!!! warning "Authentication required for the web UI"
    The API of the interface refuses the requests with status `503` while no user and no token
    exist; the login form stays displayed and says that authentication must be configured.
    `security-review-controller serve` creates the [first administrator](#first-administrator)
    at its first start, so this only happens before it; an account can also be created with
    `security-review-controller user create`. This restriction concerns the web
    UI; MCP authentication stays independent (a user account never opens `/mcp`). With the
    [OIDC login](../advanced/sso.md), the API asks for a login (`401`) even without any
    user or token in the database.

### API tokens

An `api` token calls the REST API, from a script or from the Swagger documentation (`/api/docs`,
**Authorize** button), with the rights of the access control, read at each request. It never
reaches `/mcp`, never opens the interface and, like every token, never accepts a risk nor marks
a false positive. There are two kinds:

- **Personal token**: a user creates it for themselves in **My account** > **Personal tokens**
  with **Usage** **REST API — Swagger and scripts** (one at most by default,
  `SECREVIEW_PERSONAL_TOKENS_PER_USER`: revoke it to create another; label `<user>:<label>`, a `:` that no other token label may hold, validity bounded by `SECREVIEW_TOKEN_MAX_DAYS`). It holds the
  current rights of the account, which come from its groups: it reaches nothing once the account
  loses them, and is deleted with the account. Nobody can rotate it nor change its projects; an
  administrator can revoke it from the **Tokens** screen.
- **Role token**: an administrator (`tokens.manage`) creates it on the **Tokens** screen with
  **Usage** **REST API** and a **Role**. It holds the permissions of that role on its projects
  (every project, or a list when the role only holds permissions per project). Its creator must
  hold each of these permissions on these projects; a role used by a token cannot be deleted.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "swagger", "expires_in_days": 30}'
# {"id": "…", "label": "alice:swagger", "role": "api", "personal": true, "access_role_id": null, …, "token": "Zq3…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/me
# {"client": "alice:swagger", "role": "api", "permissions": {"reports.read": ["shop-api"]}, …}
```

### Personal MCP tokens

A user connects their own MCP agent with a personal `mcp` token, created in **My account** >
**Personal tokens** with **Usage** **MCP**, offered only when their groups hold the
`mcp_tokens.create` permission (role `mcp-user`, see
[Roles](../advanced/access-control.md#roles); 403 without it). One at most by default
(`SECREVIEW_PERSONAL_TOKENS_PER_USER`), besides the REST API token. It reaches the projects the
account may read (`reports.read` of its groups), read at each request: a project given to or
removed from the account applies at once, every project when one of its groups reads every
project, no project when it has none. The **Projects** column shows them, and so does the
**Tokens** screen for the administrators.

A token already created keeps working when the account loses `mcp_tokens.create`: an
administrator revokes it if needed. Like a personal REST API token, it stops while the account
must change a password set by an administrator, it is deleted with the account, nobody can
rotate it nor change its projects, and an administrator can revoke it. For a project it does
not reach, an administrator gives the account access to the project (a group that reads it), or
the user creates it from **Projects** if it is new and they hold `projects.create` (see
[Creating a project](../advanced/access-control.md#creating-a-project)); a project requested by an
[enrollment](../advanced/http.md#enrollment-request-the-project) waits for an approval.
When the server refuses the token (unknown, revoked or expired), the agent receives a `401` that
tells the user to sign in again and create a new one. It never reaches the REST API.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "mcp"}'
# {"id": "…", "label": "alice:laptop", "role": "mcp", "personal": true, …, "token": "Zq3…"}
```

## User accounts

An account ties a **user name** (letters, digits and `. _ @ -`, 64 characters at most), a
**type** and **groups**: the roles of its groups give its
[permissions](../advanced/access-control.md#what-a-user-may-do). An account has no role or
project of its own.

| Type (`auth_source`) | Login | Creation |
|---|---|---|
| **Local** (`local`) | User name and password | By an administrator, or the initial `admin` account |
| **OIDC** (`oidc`) | [Identity provider](../advanced/sso.md), no password | By an administrator, or at the first login if `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` |

An OIDC account also joins, at each login, the groups open to OIDC named by its groups claim (see
[OIDC accounts](../advanced/sso.md#oidc-accounts)). Accounts are managed in the **Users** screen,
through the `/api/v1/users` REST API (`users.manage` permission) or with the
[CLI](../reference/cli.md#security-review-controller):

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

An account without any group has no permission and cannot log in.

For a local account, without `--password-stdin` (or without a password in the interface), a
random 24-character password is generated and shown **only once**. A chosen password follows
the **password policy**: 12 to 256 characters, with at least a lowercase letter, an uppercase
letter, a digit and a character that is neither a letter nor a digit. The screens list these
rules under the field and tick each one while the password is typed, and **My account** says at
once whether the confirmation matches. The policy applies to new passwords: a password set
before keeps working until it is changed. An OIDC account never has a password: the user name and password login, the
reset and **My account** refuse it.

### First administrator

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

!!! note "Upgrading from the `bootstrap-admin` token"
    Previous versions created a `bootstrap-admin` **token** instead of the account. On an
    existing database, this token stays valid; the `admin` account is created at the next start
    if no account exists. Once logged in with the account, revoke the old token:
    `security-review-controller token revoke bootstrap-admin`.

#### Lost password

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

### Login and sessions

When the controller no longer accepts the session while you browse (session expired, password
changed in another tab, account deleted), a **Session expired** dialog opens: **Log in again**
opens the login page and comes back to the same page afterwards.

The login page offers the user name and password of a local account and, with the
[OIDC login](../advanced/sso.md), the button of the identity provider; it does not accept
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
replica of the controller. Without it, the secret is read from `SECREVIEW_SECRET_KEY_FILE`
(`secret-key` in the working directory, `/var/lib/secreview` in Docker), generated there at the first
start with mode `0600`: sessions survive a restart, and the replicas that share the volume share
the secret. Replicas without a shared volume must share `SECREVIEW_SECRET_KEY`.

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
  session or an `admin` or `api` token. Only the login routes (`/api/v1/auth/…`)
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
  Enter an [API token](#api-tokens) there.
- The controller exposes no write route without a token. The
  [enrollment](../advanced/http.md#enrollment-request-the-project) is served by the **MCP
  server** (`POST /api/v1/enroll`, public): it requests a project, never a token; the
  controller lists and handles the requests (`GET /api/v1/projects/pending`,
  `POST /api/v1/projects/pending/{id}/approve`, `DELETE /api/v1/projects/pending/{id}`,
  `projects.create` permission). The controller
  can therefore stay on an internal network.
- The token is sent in the `Authorization` header: no cookie, hence no CSRF. Only the
  [OIDC login](../advanced/sso.md) sets a cookie, `HttpOnly`, `SameSite=Lax`, `Secure`
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
| `SECREVIEW_ADMIN_USERNAME` | `admin` | Name of the [first administrator](#first-administrator), created at the first start of the controller while no account exists; its password is set with `user reset-password` |
| `SECREVIEW_OIDC_ONLY` | `false` | With OIDC enabled, refuses the password login of the local accounts ([OIDC only](../advanced/sso.md#oidc-only)) |
| `SECREVIEW_SECRET_KEY` | — | Signing secret of the sessions (at least 32 characters), identical on every replica |
| `SECREVIEW_SECRET_KEY_FILE` | `secret-key` | File of the secret when `SECREVIEW_SECRET_KEY` is unset, generated at the first start |
| `SECREVIEW_SESSION_HOURS` | `8` | Lifetime of a session (1 to 24 hours), local account or OIDC login |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Creates the [OIDC account](../advanced/sso.md#oidc-accounts) at the first login; otherwise an administrator creates it |
| `SECREVIEW_ENROLLMENT` | `true` | Project requests by the MCP clients without a token (on the MCP server), approved in the **Projects** screen; no token is created |
| `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` | `7` | Days a requested project waits for an approval before it is deleted |
| `SECREVIEW_WEB_URL` | — | Public URL of the web interface, given by the MCP server to the clients without a valid token |
| `SECREVIEW_OIDC_*` | — | [OIDC login](../advanced/sso.md), see the [reference](../reference/configuration.md) |

The published package and the Docker image contain the application already built. If you
install from source without building it, the controller only serves the REST API and a warning
is logged. See [Contributing](../contributing.md#web-interface) to build it.
