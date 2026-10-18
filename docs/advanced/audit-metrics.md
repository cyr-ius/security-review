# Audit log and metrics

The controller keeps an **audit log** of the security-relevant changes and serves
**Prometheus metrics** on `/metrics`. Both read the database shared with the MCP server: every
replica answers the same thing.

## Audit log

Every change below writes an event in the same transaction as the change itself: an event
exists exactly when the change was committed.

| Action | Written when |
|---|---|
| `finding.status_changed` | A person records a triage decision in the web interface (`PATCH /api/v1/findings/{id}`): previous status, new status, reason, expiry date and agent proposal it settled |
| `finding.status_proposed` | An agent proposes a status with `propose_finding_status` (never applied) |
| `finding.proposal_rejected` | A triager rejects the proposal of an agent |
| `token.created` | A token is created (CLI `token create`, **Tokens** screen) |
| `token.rotated` | The secret of a token is replaced (`token rotate`, **Rotate** button), with the grace period |
| `token.revoked` | A token is revoked |
| `token.projects_changed` | An administrator changes the projects of a token (**Projects** button of the **Tokens** screen), with the previous projects (`null`: every project) |
| `enrollment.requested` | A client requests a token or one more project ([enrollment](http.md#enrollment-a-project-requests-its-token)), with the requester and its address |
| `enrollment.approved` | An administrator approves a request |
| `enrollment.rejected` | An administrator rejects a request |
| `role.created`, `role.updated`, `role.deleted` | An administrator creates, changes (with the previous permissions) or deletes a [role](access-control.md#roles) |
| `group.created`, `group.updated`, `group.deleted` | An administrator creates, renames or changes, or deletes a [group](access-control.md#groups) |
| `group.roles_changed`, `group.members_changed` | An administrator replaces the roles (with their projects) or the members (added and removed user ids) of a group |
| `user.groups_changed` | An administrator replaces the groups given to an account (added and removed group ids) |
| `user.roles_changed` | An administrator replaces the direct roles of an account, or the approval of an enrollment adds a project to it (`roles`: `role` or `role:project,project`) |
| `user.login` | A web user logs in (method `password` or `oidc`, address) |
| `user.login_failed` | A login fails: wrong password, refused SSO login (method, address, and the user name only when it is valid) |
| `user.logout` | A web user logs out with **Log out** (address) |

Each event holds its date, its **actor**, its target (`finding` and its id, `token` and its id,
`enrollment` and the request id), the project when there is one, and details as JSON. The actor
is:

- `user:<name>`: a person logged in to the web interface (local or SSO account);
- `token:<label>`: a bearer token (agent, API client, administrator token);
- `cli`: a `security-review-controller` command;
- `anonymous`: the public enrollment endpoint, or a failed login;
- `stdio`: an agent connected to the MCP server in stdio.

The details never hold a secret: no token, no password, and the free text (reasons,
requester) is masked like the reports. Nobody edits an event: neither MCP tool nor route
changes them.

### Reading the log

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

### Retention

`serve` deletes the events older than `SECREVIEW_AUDIT_RETENTION_DAYS` days (default `365`), at
start then every day; `0` keeps every event. The same purge runs on demand:

```bash
security-review-controller audit prune              # retention of SECREVIEW_AUDIT_RETENTION_DAYS
security-review-controller audit prune --days 730   # another retention, for this run only
# {"retention_days": 730, "deleted": 0}
```

## Prometheus metrics

`GET /metrics` on the **controller** answers in the Prometheus text format (`0.0.4`). The MCP
server has no metrics endpoint. It needs a token of role `metrics`, which reaches nothing else
(neither the REST API nor MCP), or `admin`:

```bash
security-review-controller token create --label prometheus --role metrics --expires-in-days 365
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/metrics
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: security-review
    scheme: https
    authorization:
      credentials_file: /etc/prometheus/secreview-token
    static_configs:
      - targets: ["secreview.example.com"]
```

| Metric | Labels | Value |
|---|---|---|
| `secreview_build_info` | `version` | `1` |
| `secreview_projects` | | Projects with reports |
| `secreview_reports` | | Stored reports |
| `secreview_findings` | `status` | Findings by effective status (an expired dismissal counts as `open`) |
| `secreview_open_findings` | `severity` | Open findings by severity |
| `secreview_project_open_findings` | `project`, `severity` | Open findings of each project |
| `secreview_finding_proposals_pending` | | Agent proposals waiting for a person |
| `secreview_tokens` | `role`, `state` | Tokens by role and state (`active`, `expired`, `pending`) |
| `secreview_tokens_expiring_soon` | | Active tokens that expire within 14 days |
| `secreview_enrollment_requests_pending` | | Enrollment requests waiting for an administrator |
| `secreview_web_users` | `auth_source` | Web accounts (`local`, `oidc`) |
| `secreview_advisories` | | Advisories in the database |
| `secreview_advisory_last_update_timestamp_seconds` | | End of the latest successful OSV download (absent before the first one) |
| `secreview_auth_rejections_total` | `reason` | Requests rejected by the authentication of the process that answers, since its start: `invalid_token`, `token_expired`, `enrollment_pending`, `insufficient_scope` |

Every value except `secreview_auth_rejections_total` comes from the database. The metrics hold
counts and project names, never a finding, a token label or a secret; label values are
escaped, so a project name cannot add lines to the answer. `SECREVIEW_METRICS_ENABLED=false`
turns the endpoint off (`404`).

Examples of alerts: `secreview_tokens_expiring_soon > 0`,
`secreview_open_findings{severity="critical"} > 0`,
`time() - secreview_advisory_last_update_timestamp_seconds > 2 * 86400`,
`rate(secreview_auth_rejections_total{reason="invalid_token"}[5m]) > 1`.
