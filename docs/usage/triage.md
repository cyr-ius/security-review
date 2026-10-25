# Triage of findings

The status of a finding is decided by a **person**; an agent only proposes it (MCP tool
`propose_finding_status`, see [status of a finding](prompts-tools.md#status-of-a-finding)).
A triager may also send a finding to Jira or ServiceNow (**Send to Jira**), when its project
has a destination: see [connectors](../connectors/index.md#sending-a-finding).

- **Proposal of an agent**: shown on the finding in a separate box, with its author (label of
  the token), its date and its reason. The reason may come from the reviewed code: check it.
  **Apply** saves `fixed` at once, or opens the form below for `accepted` and
  `false_positive`; **Reject** removes the proposal. Neither changes the status by itself.
- **Risk accepted**: the status select opens a form that asks for a
  **Reason** (10 to 1000 characters) and an **Expiry date** (90 days by default, at most
  `SECREVIEW_MAX_DISMISSAL_DAYS`). The logged-in user is recorded as the approver; the card shows
  the approver, the reason and the end of validity. From the expiry date, the finding counts as
  open again (status filter, posture, [gate](gate.md), SARIF, trend) and the card says
  that the decision has expired. For **Risk accepted**, the **No expiry** box removes the date:
  the risk stays accepted until someone reopens the finding (disabled with
  `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false`).
- **False positive**: the form only asks for an optional **Reason** (10 to 1000 characters
  when given), with no expiry date: a false positive says the code is not vulnerable, it stays until someone reopens
  the finding. The logged-in user is recorded as the approver.
- **Risk accepted** below `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY` (`medium` by default, so a
  `low` or `info` finding): a plain validation, saved at once with no reason and no expiry date.
  Empty variable: every acceptance goes through the form above.
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
date for `open` / `fixed` gets `422`. Without `expires_on`, a false positive never expires, nor
does an acceptance, unless
`SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false` (`422`); `GET /api/v1/me` returns
`permanent_acceptance` to tell whether the caller may do it. Below
`SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY`, `reason` and `expires_on` are optional for
`accepted` (`{"status": "accepted"}` is enough); `GET /api/v1/me` returns this threshold as
`risk_acceptance_min_severity` (`null`: every acceptance needs them).

## Finding reported again

A later report of the project that raises the same issue again does not add a second
finding to review: the server recognizes it by its fingerprint (project, rule or CWE, file and
title, without the line number, as in [SARIF](../advanced/sarif.md)) and the new occurrence
replaces the previous one.

- An **acceptance** or a **false positive** still valid is carried to the new occurrence, with
  its reason, approver and expiry date; so is a pending agent proposal of one of them, a
  severity raised by an analyst and the comments. The gate does not block again.
- A **fixed** finding that comes back is **open** again.
- When a rule matches several lines of a file, the occurrences are paired in line order if
  their number is unchanged (the code moved), else only on the same line: a new occurrence
  never inherits the decision taken on another one, it is open.
- The previous occurrence stays in its report, marked **Reported again: see finding #N**; it
  can no longer be triaged (`422` through the API) nor sent through a connector (`409`).
- **Findings to review**, the posture, the project [gate](gate.md), SARIF, the counters and
  the trend count the latest occurrence only; the trend and the time to remediate start at
  the first occurrence of the issue (`first_seen_at`).
- A finding that a later report no longer raises is not closed: a review of a diff does not
  see the whole code.

`save_security_report` and the pipeline scans return `recurring_findings` (findings already
raised by a previous report) and `carried_decisions` (decisions carried to them).

## Severity of a finding

A security analyst (a person with the `findings.triage` permission) may **raise** the severity
given by a report, for example when the code is exposed to the Internet or the data is
sensitive. **Raise the severity**, at the top of the card, opens a form that asks for the
**New severity** and a **Justification** (10 to 1000 characters). The card then shows the
severity of the report, the analyst, the date and the justification; the Markdown export and
`get_security_report` show them too, and the change is written to the audit log
(`finding.severity_changed`).

The raised severity counts everywhere (filters, posture, [gate](gate.md), SARIF, trend), and
the risk level of the report goes up with it. A severity never goes below the one of the
report: an analyst can only go back to it, with a justification, to undo the escalation. To
close a finding judged less serious, accept the risk. Only a session may do it: a bearer token,
even `admin`, gets `403`; a lower or unchanged severity, or a missing justification, gets `422`.

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42/severity \
  -d '{"severity": "critical", "reason": "Endpoint reachable without authentication"}'
# {"id": 42, "severity": "critical", "original_severity": "medium", "severity_changed_by": "alice", …}
```

## Risk acceptances

The **Risk acceptances** screen (`/ui/risk-acceptances`, or per project from the **Projects** and
**Project** screens) lists the accepted risks, expired ones included, so that they can be renewed
before or after their end of validity. In the details of an acceptance:

- **Comments**: every comment, oldest first, with its author and date. The reason of the
  acceptance is the first one: accepting a risk, or accepting it again with another reason,
  adds it to the comments. Anyone who reads the project sees them. A comment **can be neither edited nor deleted**: no route of the API does
  it. They stay with the finding when its acceptance is removed.
- **Add a comment** (at most 2000 characters, secrets masked) records the logged-in user as its
  author, in the audit log too (`finding.commented`).
- **Change the expiry date** saves the acceptance again with the same reason and the new date
  (same limits as above, **No expiry** included), without adding a comment: the logged-in user
  becomes its approver.
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
