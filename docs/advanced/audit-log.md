# Audit log in detail

The [audit log](../usage/audit-metrics.md) page describes the log in the web interface. This
page gives every event, the API, the command line and the variables.

The controller keeps an **audit log** of the security-relevant changes. It reads the database
shared with the MCP server: every replica answers the same thing. The metrics of the controller
are in [Prometheus metrics](../reference/metrics.md).

Every change below writes an event in the same transaction as the change itself: an event
exists exactly when the change was committed.

| Action | Written when |
|---|---|
| `finding.status_changed` | A person records a triage decision in the web interface (`PATCH /api/v1/findings/{id}`): previous status, new status, reason, expiry date and agent proposal it settled |
| `finding.status_proposed` | An agent proposes a status with `propose_finding_status` (never applied) |
| `finding.proposal_rejected` | A triager rejects the proposal of an agent |
| `finding.commented` | A person comments a finding (`POST /api/v1/findings/{id}/comments`): the comment, secrets masked |
| `finding.severity_changed` | A security analyst raises the severity of a finding, or restores the report's one (`PATCH /api/v1/findings/{id}/severity`): previous, new and original severity, justification |
| `token.created` | A token is created (CLI `token create`, **Tokens** screen) |
| `token.rotated` | The secret of a token is replaced (`token rotate`, **Rotate** button), with the grace period |
| `token.revoked` | A token is revoked |
| `token.projects_changed` | An administrator changes the projects of a token (**Projects** button of the **Tokens** screen), with the previous projects (`null`: every project) |
| `enrollment.requested` | The agent of a user requests a project with `request_project` ([enrollment](architecture/mcp-server.md#enrollment-personal-token-and-project-requests)), with the token as actor, the requesting user, its address, whether a new request was filed (`requested`) and whether the project already existed (`existing`: an access request) |
| `enrollment.approved` | A user with `projects.create` approves a pending project (its group in the details); the requester is added to the group (`user.groups_changed`) |
| `enrollment.rejected` | A user rejects a pending project, or it expires (actor `enrollment`, `reason`: `expired`) |
| `role.created`, `role.updated`, `role.deleted` | An administrator creates, changes (with the previous permissions) or deletes a [role](../usage/access-control.md#roles) |
| `group.created`, `group.updated`, `group.deleted` | An administrator creates, renames or changes, or deletes a [group](../usage/access-control.md#groups); the approval of a project request creates a missing [project group](../usage/projects.md#project-groups) (`project` in the details) |
| `group.roles_changed`, `group.members_changed` | An administrator replaces the roles (with their projects) or the members (added and removed user ids) of a group |
| `project.created` | A user with `projects.create` [creates a project](../usage/projects.md#creating-a-project), or its agent with `request_project` (actor: the token) (its project group and the user id in the details) |
| `project.deleted` | A user with `projects.delete` [deletes a project](../usage/projects.md#deleting-a-project) (counts of reports, findings and tokens, groups deleted or changed in the details) |
| `user.groups_changed` | An administrator replaces the groups given to an account, for instance to add it to a [project group](../usage/projects.md#project-groups) (added and removed group ids) |
| `user.roles_changed` | Former direct roles of an account (`roles`: `role` or `role:project,project`): no longer recorded since accounts have no role of their own, kept in the history |
| `user.login` | A web user logs in (method `password` or `oidc`, address) |
| `user.login_failed` | A login fails: wrong password, refused OIDC login (method, address, and the user name only when it is valid) |
| `user.logout` | A web user logs out with **Log out** (address) |
| `audit_syslog.changed` | The [syslog server](#forwarding-to-syslog) is changed on the **Audit log** page (address and facility set, `null`: stored value deleted) |
| `controller_url.changed` | The public URL of the controller, whose web interface is given to the agents without a token, is changed on the **General** screen, or copied from `SECREVIEW_CONTROLLER_URL` by the controller at start (actor `environment`); `null`: stored value deleted |
| `oauth.client_registered` | An MCP client registers itself for the [OAuth login](mcp-oauth.md) (actor `anonymous`, client name) |
| `oauth.grant_approved` / `oauth.grant_denied` | A web user approves or denies an MCP client on the **Connect an MCP client** screen |
| `oauth.grant_revoked` | An OAuth grant is revoked: in **My account**, by the client (`/revoke`), or with its user |
| `oauth.refresh_reused` | A refresh token already replaced is presented again: the grant is revoked |

Each event holds its date, its **actor**, its target (`finding` and its id, `token` and its id,
`project` and its name), the project when there is one, and details as JSON. The actor
is:

- `user:<name>`: a person logged in to the web interface (local or OIDC account);
- `token:<label>`: a bearer token (agent, API client, administrator token);
- `cli`: a `security-review-controller` command;
- `anonymous`: a failed login;
- `stdio`: an agent connected to the MCP server in stdio.

The details never hold a secret: no token, no password, and the free text (reasons,
requester) is masked like the reports. Nobody edits an event: neither MCP tool nor route
changes them.

## Reading the log

Administrators read it in the **Audit log** screen of the web interface (filters by event and
project), with `GET /api/v1/audit` (`audit.read` permission; `action`, `project`, `actor`, `since`,
`limit`, `offset` parameters, newest first) or on the command line:

```bash
security-review-controller audit list --action token.rotated --since 2026-10-01
security-review-controller audit list --project shop-api --actor user:alice --limit 20
# {"total": 1, "events": [{"id": 12, "created_at": "…", "action": "finding.status_changed",
#   "actor": "user:alice", "target_type": "finding", "target_id": "42", "project": "shop-api",
#   "details": {"previous_status": "open", "status": "accepted", "reason": "…", …}}]}
```

`--limit` (and the `limit` parameter) is capped by `SECREVIEW_MAX_LIST_LIMIT`.

## Retention

`serve` deletes the events older than `SECREVIEW_AUDIT_RETENTION_DAYS` days (default `365`), at
start then every day; `0` keeps every event. With `SECREVIEW_AUDIT_MAX_EVENTS` (default `0`, no
limit), the same purge then keeps at most that many events, deleting the oldest. The same purge
runs on demand:

```bash
security-review-controller audit prune              # SECREVIEW_AUDIT_RETENTION_DAYS and SECREVIEW_AUDIT_MAX_EVENTS
security-review-controller audit prune --days 730   # another retention, for this run only
# {"retention_days": 730, "max_events": 0, "deleted": 0}
security-review-controller audit prune --max-events 100000
```

## Forwarding to syslog

The controller can also send each event to a syslog server, to keep it outside the database
(SIEM, central log). Disabled by default:

```bash
SECREVIEW_AUDIT_SYSLOG_ADDRESS=udp://syslog.example.com:514   # or tcp://host:port, tls://host:port, unix:///dev/log
SECREVIEW_AUDIT_SYSLOG_FACILITY=local0                        # default
```

To encrypt the events, use `tls://host:port` (syslog over TLS, RFC 5425, port 6514 by default):
the controller verifies the certificate of the server and its host name with the system CA
bundle, or with `SECREVIEW_AUDIT_SYSLOG_CAFILE` (internal certificate authority, a variable
only). Each message is then framed by its length (octet counting), as RFC 5425 requires: on
rsyslog, `imtcp` with `StreamDriver.Mode="1"`; on syslog-ng, the `syslog()` source with
`transport("tls")`.

Administrators (`settings.manage` permission) can also set it on the **Audit log** page of the
web interface, with the **Syslog** button next to **Refresh** (a send icon checked when the
events are forwarded, crossed out when they are not; its tooltip gives the server). It opens the
**Syslog forwarding** dialog: **No forwarding** or **Set here** (`udp://host:port`,
`tcp://host:port` or `tls://host:port`), and the facility. **A variable that is set takes
precedence**: its field is then locked, and a value set there before is ignored (**Delete**
removes it); an empty `SECREVIEW_AUDIT_SYSLOG_ADDRESS` counts as unset. A value set there
applies within about ten seconds, without restart; the change itself is written to the audit log
(`audit_syslog.changed`). When the forwarding is stopped, the pending events, this change
included, are first sent to the previous server: the SIEM sees who stopped it. A Unix socket is a
file of the deployment: it is set with the variable only, as the CA file of TLS. Through the API: `GET` and
`PUT /api/v1/settings/audit-syslog` with `address` and `facility` (`null` deletes the stored
value, a missing field is unchanged, a field whose variable is set is refused with 422).

Each event is one message with the `info` severity, tagged `secreview-audit`, its body the event
as JSON, the same fields as `audit list`:

```
<134>secreview-audit: {"action":"user.login","actor":"user:alice","created_at":"…","details":{"address":"10.0.0.8","method":"password"},"id":12,"project":null,"target_id":"2","target_type":"user"}
```

- The controller forwards the events of **every** process, MCP server and CLI included, from the
  database: the MCP server keeps making no outgoing connection. An event leaves about 5 to 15
  seconds after it is written; the history before the forwarding is enabled (at start or in
  the web interface) is not sent.
- Each event is sent **once**, even with several replicas of the controller: the id of the last
  forwarded event is kept in the database, and a replica moves it forward before sending. A batch
  whose sending fails is logged and not sent again (at most once).
- `udp://` and `tcp://` send the events in clear: use them on a trusted network or towards a
  local relay, and `tls://` otherwise. No proxy. A certificate that is refused is logged as a
  failed sending (the batch is not sent again). An invalid variable, or a missing CA file, stops
  `serve` at start; an invalid address is refused by the web interface.
