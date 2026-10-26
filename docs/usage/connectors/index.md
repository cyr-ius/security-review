# Connectors

A **connector** sends the findings to another tool of your teams: a ticket in **Jira** or
**ServiceNow**, an entry in a vulnerability register, an item in an internal tracker... What the
connector creates in that tool is the **record** of the finding.

| Connector | Record | Page |
|---|---|---|
| Jira (Cloud or Data Center) | Issue | [Jira](jira.md) |
| ServiceNow | Incident (or a record of another table) | [ServiceNow](servicenow.md) |
| Third party | Whatever the connector creates | [Third-party connectors](third-party.md) |

The variables, the guarantees and the REST API are in
[Connectors in detail](../../advanced/connectors.md).

## Enabling

The **Connectors** screen (Administration) shows one card per connector, with its state
(**Inactive**, **To configure**, **Active**), its number of projects, a **switch** and a
**gear** for its settings:

1. **Connection** tab: the address of the tool and the account to use, then **Test the
   connection**;
2. **Projects** tab: for each project, its **destination** in the tool (a Jira project key, a
   ServiceNow assignment group...) and its **Automatic sending** (**By hand only**, or from a
   severity: **high and above**...);
3. the switch enables the connector.

Every connector is **off by default**: nothing leaves until an administrator enables it.

## Sending a finding

- **By hand**: a person who may triage the project sees a **Send to Jira** button (one per
  connector) on each finding of a project that has a destination. Once the record exists, the
  finding shows its key, linked to the record.
- **Automatically**: the findings of the project at or above its severity are sent every few
  minutes, the most severe first.

A finding reported again by a later report reuses the record of the first occurrence: no
duplicate is created.

## Points to watch

- **Sending is one way**: the status of the finding is never changed from the record. A person
  still decides it in the [triage](../triage.md).
- **Use an account with few rights** in the tool: creating records is enough.
- **The secrets are never shown again** (`***`): leave `***` to keep the stored one. Changing
  the address of the tool asks for its secrets again.
- **A failure** (refused credentials, unknown project...) is shown on the finding with its
  reason; the automatic sending retries a few times.
- **Only the controller** connects to these tools; the operator may lock every connector off.
