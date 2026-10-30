# Triage through the REST API

The [triage](../../usage/triage.md) page describes the decisions in the web interface. This page
gives the limits, the settings and the REST API calls.

## Who may decide

Only a **session** (local or OIDC account, see [user accounts](../../usage/user-accounts.md))
with the `findings.triage` permission may change a status, raise a severity or comment: a
bearer token, even `admin`, gets `403`. An agent only proposes a status with the MCP tool
`propose_finding_status` (see [status of a finding](../../review/prompts-tools.md#status-of-a-finding)).

## Limits and settings

| Element | Limit | Setting |
|---|---|---|
| **Reason** of an acceptance | 10 to 1000 characters; optional for a false positive (10 to 1000 when given) | — |
| **Expiry date** | 90 days by default, at most `SECREVIEW_MAX_DISMISSAL_DAYS` (`365`) | [configuration](../../reference/configuration.md) |
| **No expiry** | Allowed for an acceptance unless `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false`; a false positive never expires | [configuration](../../reference/configuration.md) |
| Plain validation | Below `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY` (`medium` by default), an acceptance needs no reason and no date; empty variable: every acceptance needs them | [configuration](../../reference/configuration.md) |
| **Justification** of a severity | 10 to 1000 characters | — |
| Comment | At most 2000 characters, secrets masked | — |

## Status of a finding

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42 \
  -d '{"status": "accepted", "reason": "Internal tool, not exposed to the Internet", "expires_on": "2027-01-31"}'
# {"id": 42, "status": "accepted", "status_approver": "alice", "status_expires_at": "2027-01-31T00:00:00Z", …}
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/findings/42/proposal    # reject the agent proposal
```

**Open** and **Fixed** take an optional reason. A reason that is missing or too short, an
expiry date in the past or too far away, or an expiry date for `open` / `fixed` gets `422`.
Without `expires_on`, a false positive never expires, nor does an acceptance, unless
`SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false` (`422`); `GET /api/v1/me` returns
`permanent_acceptance` to tell whether the caller may do it. Below
`SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY`, `reason` and `expires_on` are optional for
`accepted` (`{"status": "accepted"}` is enough); `GET /api/v1/me` returns this threshold as
`risk_acceptance_min_severity` (`null`: every acceptance needs them).

## Finding reported again

The server recognizes an issue by its fingerprint: project, rule or CWE, file and title,
without the line number, as in [SARIF](sarif.md). A finding of category `dependency` with a
`rule_id` ignores its title: an advisory (`GHSA-`, `CVE-`, `PYSEC-`...) is recognized by its id
alone, whatever the file (a scan reports it on the lockfile, a review on the manifest), and a
hygiene rule (`DEP-*`) by its id and the file name. When a rule matches several lines of a file,
the occurrences are paired in line order if their number is unchanged (the code moved), else
only on the same line: a new occurrence never inherits the decision taken on another one, it
is open. A pending agent proposal of an acceptance or a false positive is carried over too.

The previous occurrence can no longer be triaged (`422`) nor sent through a connector (`409`).
The trend and the time to remediate start at the first occurrence (`first_seen_at`).
`save_security_report` and the pipeline scans return `recurring_findings` (findings already
raised by a previous report) and `carried_decisions` (decisions carried to them).

## Severity of a finding

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42/severity \
  -d '{"severity": "critical", "reason": "Endpoint reachable without authentication"}'
# {"id": 42, "severity": "critical", "original_severity": "medium", "severity_changed_by": "alice", …}
```

A lower or unchanged severity, or a missing justification, gets `422`. The Markdown export and
`get_security_report` show the severity of the report, the analyst, the date and the
justification; the change is written to the audit log (`finding.severity_changed`).

## Risk acceptances and comments

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
`offset`; without `project`, it lists every project the caller can read. The page is also
reached at `/ui/risk-acceptances`.

No route of the API edits or deletes a comment. Anyone who reads the project sees the comments;
each one is written to the audit log (`finding.commented`). Accepting a risk, or accepting it
again with another reason, adds the reason to the comments; changing the expiry date adds none.
