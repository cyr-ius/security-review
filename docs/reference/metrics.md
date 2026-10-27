# Prometheus metrics

The metrics are read in the database shared with the MCP server: every replica of the
Controller server answers the same thing (see also the [audit log](../advanced/audit-log.md)).

`GET /metrics` on the **Controller server** answers in the Prometheus text format (`0.0.4`). The MCP
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
| `secreview_tokens` | `role`, `state` | Tokens by role and state (`active`, `expired`) |
| `secreview_tokens_expiring_soon` | | Active tokens that expire within 14 days |
| `secreview_project_enrollments_pending` | | Projects requested by the MCP agents of users, waiting for an approval |
| `secreview_web_users` | `auth_source` | Web accounts (`local`, `oidc`) |
| `secreview_advisories` | | Advisories in the database |
| `secreview_advisory_last_update_timestamp_seconds` | | End of the latest successful OSV download (absent before the first one) |
| `secreview_auth_rejections_total` | `reason` | Requests rejected by the authentication of the process that answers, since its start: `invalid_token`, `token_expired`, `insufficient_scope` |

Every value except `secreview_auth_rejections_total` comes from the database. The metrics hold
counts and project names, never a finding, a token label or a secret; label values are
escaped, so a project name cannot add lines to the answer. `SECREVIEW_METRICS_ENABLED=false`
turns the endpoint off (`404`).

Examples of alerts: `secreview_tokens_expiring_soon > 0`,
`secreview_open_findings{severity="critical"} > 0`,
`time() - secreview_advisory_last_update_timestamp_seconds > 2 * 86400`,
`rate(secreview_auth_rejections_total{reason="invalid_token"}[5m]) > 1`.
