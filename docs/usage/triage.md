# Triage of findings

Triaging a finding means deciding what to do with it. The decision is always taken by a
**person** signed in to the web interface: an agent can only propose a status, never apply it.
The details of the REST API, the limits and the settings are in
[Triage through the REST API](../advanced/reports/triage-api.md).

| Status | Meaning | What is asked | Expires |
|---|---|---|---|
| **Open** | To be handled | Nothing | — |
| **Fixed** | The code was corrected | Nothing | — |
| **Risk accepted** | The issue is known and tolerated | A **Reason** and an **Expiry date** (90 days by default), or **No expiry** | Yes, at its date |
| **False positive** | The code is not vulnerable | An optional **Reason** | Never |

Worth knowing:

- **Proposal of an agent**: shown on the finding in a separate box, with its author, date and
  reason. **Apply** takes it over (the form opens for an acceptance or a false positive),
  **Reject** removes it. The reason comes from an agent that read the code: check it before
  applying it.
- **Low-severity findings** (`low` and `info` by default) are accepted by a plain validation,
  with no reason and no date.
- **An expired acceptance counts as open again** everywhere: lists, posture, [gate](../review/gate.md),
  SARIF, trend. The card says that the decision has expired.
- The person who decides is recorded as the **approver**, and every decision is written to the
  [audit log](audit-metrics.md). Any decision removes the pending proposal.
- A triager may also send a finding to Jira or ServiceNow when its project has a destination
  ([connectors](connectors/index.md#sending-a-finding)).

## Finding reported again

When a later report raises the same issue again (same project, rule, file and title, whatever
the line), it does not add a second finding to review: the new occurrence **replaces** the
previous one.

- A still valid **acceptance** or **false positive** is carried over, with its reason, approver
  and expiry date, as are the comments and a raised severity. The gate does not block again.
- A **fixed** finding that comes back is **open** again.
- The previous occurrence stays in its old report, marked **Reported again: see finding #N**,
  and can no longer be triaged.
- Lists, counters, gate and trend only count the latest occurrence; the time to remediate
  starts at the first one.
- A finding that a later report no longer raises is **not** closed: the review of a diff does
  not see the whole code. Mark it **Fixed** yourself.

## Severity of a finding

An analyst may **raise** the severity given by a report, for example when the code is exposed
to the Internet or handles sensitive data: **Raise the severity**, at the top of the card, asks
for the **New severity** and a **Justification**. The raised severity then counts everywhere,
and the risk level of the report goes up with it.

A severity never goes below the one of the report: the analyst can only go back to it to undo
the escalation. To close a finding judged less serious, accept the risk.

## Risk acceptances

The **Risk acceptances** screen lists the accepted risks, expired ones included, nearest
expiry first: this is where you renew them, before or after their end.

- **Comments**: the history of the acceptance, oldest first. The reason is the first comment.
  A comment **can be neither edited nor deleted**, and stays with the finding even when the
  acceptance is removed.
- **Change the expiry date** renews the acceptance with the same reason; you become its approver.
- **Remove the acceptance** reopens the finding.

## What expires and what is deleted

| What | Behaviour |
|---|---|
| Risk acceptance | Ends at its expiry date (at most one year): the finding counts as open again, until it is renewed |
| False positive, acceptance with **No expiry** | Never expire: they last until someone reopens the finding |
| Agent proposal | Removed by any decision on the finding, or by **Reject** |
| Previous occurrence of a finding reported again | Kept in its report, but no longer counted |
| Report without findings | Deleted after 90 days by default, except the latest report of each project ([retention](../advanced/database.md#retention-of-reports-without-findings)) |
| Report with findings, comments | Never deleted automatically, whatever the status of the findings |
| Audit log | Events kept one year by default ([retention](audit-metrics.md#retention)) |

The durations above are the defaults: an administrator may change them
([configuration](../reference/configuration.md)).
