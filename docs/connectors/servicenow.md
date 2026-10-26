# ServiceNow

The **ServiceNow** connector creates a record for each finding sent, an **incident** by default.
The variables are in [Connectors in detail](../advanced/connectors.md#servicenow).

## Connection

| Field | Value |
|---|---|
| URL | The address of the instance, in HTTPS |
| **Account** | The account used to create the records |
| **Password** | Its password |
| **Table** | The table of the records (`incident` by default) |

The account only needs to create records in the table (the `itil` role for `incident`).

## Destination

The destination of a project is its **Assignment group** (optional, its name).

## Content of a record

- **Short description**: `[HIGH] shop-api: SQL injection`;
- **Description**: the project, severity, location, rule, CWE, branch, commit and a link to the
  report, then the description, evidence and recommendation of the finding;
- **Urgency** and **Impact**: from the severity (`critical` gives 1 / 1, `low` and `info`
  3 / 3);
- **Assignment group**: the destination of the project.
