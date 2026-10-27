# Audit log

The **audit log** records who changed what in security-review-mcp: the triage decisions, the
tokens, the accounts and their rights, the projects, the logins. It answers the questions of an
audit ("who accepted this risk?", "who created this token?").

Every event, the API, the command line and the variables are in
[Audit log in detail](../advanced/audit-log.md). The Prometheus metrics are in
[Prometheus metrics](../reference/metrics.md).

## What is recorded

| Area | Examples of events |
|---|---|
| Findings | Triage decision, agent proposal, comment, raised severity, sending through a connector |
| Tokens | Creation, rotation, revocation, change of projects |
| Accounts and rights | Logins and failed logins, logouts, roles, groups and their members |
| Projects | Request by an agent, approval, refusal, creation, deletion |
| Settings | Syslog server, Controller server address, connectors |

Each event gives its date, its **author** (a person `user:<name>`, a token `token:<label>`, the
command line `cli`...), its target, its project and its details.

## Reading the log

Administrators read it in the **Audit log** screen: newest first, with filters by event and
project, a search in the details and **Load more** for the older events.

## Retention

The events are kept **one year** by default, then deleted automatically every day. An
administrator may change this duration or bound the number of events kept
([retention in detail](../advanced/audit-log.md#retention)).

## Forwarding to syslog

To keep the events outside the database (SIEM, central log), the Controller server can also send each
one to a syslog server. On the **Audit log** screen, the **Syslog** button (next to **Refresh**)
opens the **Syslog forwarding** dialog: **No forwarding**, or **Set here** with the address of
the server and its facility. The change applies within a few seconds.

Prefer an encrypted address (`tls://host:port`): `udp://` and `tcp://` send the events in clear
([syslog in detail](../advanced/audit-log.md#forwarding-to-syslog)).

## Points to watch

- **Nobody edits or deletes an event**, except the automatic purge of the retention.
- **The log never holds a secret**: no token, no password; the free texts are masked like the
  reports.
- **The events written before the syslog forwarding is enabled are not sent.**
- **A field locked in the dialog** is set by an environment variable, which always takes
  precedence.
