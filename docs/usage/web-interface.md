# Web interface

The web interface lets the security teams browse the reports saved by the agents and **triage
the findings** (fixed, accepted risk, false positive) without an MCP client. It is served by the
**controller**, a process distinct from the MCP server that shares its database (see
[Architecture](../advanced/architecture.md)):

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
tokens, audit log, OIDC, report language, outgoing proxy, OSV database, connectors), each shown only to the
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
  With the `projects.create` permission, **New project** (left of **Refresh**) opens a modal
  window that creates a project you then read (see
  [Creating a project](../advanced/access-control.md#creating-a-project)), and the
  **Pending projects** section lists the projects requested by an
  [enrollment](../advanced/mcp-server.md#enrollment-request-the-project) (requester, address, request
  and expiry dates): **Approve** creates the project without any member, **Reject** deletes the
  request; a request not approved before its expiry is deleted. With `projects.delete`, the
  trash button of a row deletes the project and everything that refers to it (see
  [Deleting a project](../advanced/access-control.md#deleting-a-project)).
- **Project**: open findings, trend over 30 days to 1 year (chart and table), mean
  time to remediate, oldest open finding, most frequent CWEs, the 20 worst open findings
  (number, severity, rule, location, report: the number opens the report at that finding) and
  SARIF export; **All reports** lists its reports. In the **Proposal** column, a blinking
  robot icon marks a finding whose status an agent proposed: hover it to read the proposed
  status, click it to open the finding and apply or reject the proposal ([triage](triage.md)).
  The **Review open findings** button opens the next screen; **Risk acceptances** lists the
  accepted risks of the project; **Refresh** reloads the trend and the open findings.
- **Findings to review**: every open finding of the project across all its reports, each issue
  once ([reported again](triage.md#finding-reported-again)), worst
  severity first, then newest report first, for a review by a security expert. Each finding
  shows its description, code excerpt and recommendation, and a link to its report (date, review
  type, branch, commit). Filters by status (to re-check accepted risks or false positives), by
  severity and by review type (**Security review**, **API security review**, **Codebase
  review**...: see [review type](prompts-tools.md#review-type)); **Load more** displays the next
  findings. Users with the `findings.triage` permission change the status of each finding from this
  screen and apply or reject the statuses proposed by the agents (see
  [triage of findings](triage.md)); a triaged finding stays displayed until the next
  reload (**Refresh** button).
- **Risk acceptances**: the accepted risks of the project (or of every project), expired ones
  included, nearest expiry first. Search, sort and filter by state (**Active**, **Expired**) and
  severity; **Refresh** reloads the list. A click on a finding opens its details: its comments
  (the first one is the reason of the acceptance), and for the `findings.triage` permission the
  forms to add a comment, change the expiry date and remove the acceptance (see [risk acceptances](triage.md#risk-acceptances)).
- **Reports**: list filtered by project and risk level, searchable across report metadata and
  summary, and sortable by date, project, risk, type, branch, token or summary. The **Token**
  column shows the label of the token that sent the report; hovering it shows the
  author to a holder of `users.manage` or `tokens.manage`. Search and
  filters stay in the URL, so a view can be shared; the sort is remembered by the browser.
- **Report**: summary, context (repository, branch, commit, review type, **Author** (for a
  holder of `users.manage` or `tokens.manage`) and
  **Sent by (token)**, see [author of a report](prompts-tools.md#author-of-a-report)),
  **Review coverage** (checklist items by outcome and rules that raised scan leads, those cited by
  no finding marked **dismissed**, see [review coverage](prompts-tools.md#review-coverage)), findings with
  location, CWE, code excerpt and recommendation; Markdown and SARIF download. Users with the
  `findings.triage` permission change the status of a finding directly from this screen, and
  raise its severity with a justification (see [severity of a finding](triage.md#severity-of-a-finding)).
- **Standards**: the [development standards](standards.md) handed to the AI
  assistants by the `development-standards` prompt. Search and sort by title,
  technology or file pattern, and filter by enabled state. Administrators read, create, edit
  (technologies, file patterns, Markdown content), disable or delete them. A change applies
  immediately. **Export** and **Import** copy them as a [TOML file](standards.md#import-and-export).
- **Checklists**: the [checklists](checklists.md) of the reviews. Administrators search and sort check items, and filter by domain and origin; they create,
  edit or delete the custom items. The default items can be edited, but not deleted. Every
  change is reloaded immediately by the server and included in the review prompts.
  **Export** and **Import** exchange [TOML packs](rules.md#import-and-export-in-the-web-interface).
- **Rules**: administrators search and sort every [rule](rules.md) stored in the database,
  and filter by origin (default or custom) and severity. They create, edit (in a modal window, without losing
  the position in the list), enable or disable the rules, and delete the custom rules. A default
  rule can be edited ("Par défaut, modifiée" badge: default, edited) or disabled, but not
  deleted. The **Reload** button applies immediately a change made with the
  `security-review-controller rules` CLI. **Export** and **Import** exchange
  [TOML packs](rules.md#import-and-export-in-the-web-interface).
- **Users**: administrators manage the [accounts](user-accounts.md), the only
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
  [REST API](tokens.md#api-tokens) tokens (Swagger, scripts), which hold its rights, and
  [MCP / CI](tokens.md#personal-mcp-and-ci-tokens) tokens for its agent and `security-review-ci`, which reach the projects it may read.
- **Tokens**: tokens are searchable, sortable and filterable by usage. Administrators create
  and revoke tokens for one or more projects, or for
  **All projects** (never for a CI/CD token). The **Usage** field chooses **MCP** (`mcp` role),
  **CI/CD pipeline** (`ci` role, for
  [`security-review-ci`](../advanced/ci.md)) or **REST API** (`api`
  role, with the **Role** it holds, see [API tokens](tokens.md#api-tokens)): tokens are for machines, a
  person reads and triages with a [user account](user-accounts.md). Under **Allowed projects**, **All projects** gives every project, including the
  projects reviewed later, and **Selected projects** shows the boxes of the projects the token
  sees; **Validity**
  sets its lifetime (30 days to 1 year, or the default of the server, `SECREVIEW_TOKEN_MAX_DAYS`).
  The list shows the usage of every `mcp` and `ci` token, its projects
  and its expiry date (**Expired** once past). **Projects** changes the projects of an existing
  token, or gives it **All projects** after a confirmation, without changing its secret: the
  change applies from the next request.
  **Rotate** replaces the secret of a token and shows the new one once; the previous one keeps
  working for the grace period chosen above the list (none, 1 h, 24 h or 7 days, see
  [expiry and rotation](../advanced/bearer-tokens.md#expiry-and-rotation-of-tokens)).
  A token never opens the web interface. The `admin` and `metrics` tokens stay unrestricted and
  are managed from the CLI only. The secret is shown only once; only its digest is stored, in the database. A
  revocation takes effect at the next request. The
  [enrollment](../advanced/mcp-server.md#enrollment-request-the-project) creates no token: a project
  it requests waits in **Projects**, and once approved an administrator gives a developer
  access to it by adding them to its group `project:<project>` (**Groups** screen).
- **Audit log**: administrators read the [audit log](../advanced/audit-metrics.md): triage
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
- **Connectors**: one card per connector (Jira, ServiceNow, third-party) with its switch and a
  gear for its settings: connection (with **Test the connection**) and destination of each
  project, with its optional automatic sending ([connectors](../connectors/index.md)).

## See also

- [Triage of findings](triage.md): decisions on the findings, severity, risk acceptances;
- [Tokens](tokens.md): roles of the tokens, API tokens, personal MCP and CI tokens;
- [User accounts](user-accounts.md): local and OIDC accounts, password policy.
