# Trend report

```bash
security-review-controller trend --project my-project --days 90 --granularity week --format markdown
```

Options: `--granularity day|week|month` (default `week`), `--format markdown|json`
(default `markdown`), `--days` (default 90).

The [pipeline client](../usage/gate.md#pipeline-client-security-review-ci) prints the same report
through the controller REST API, with a `ci` token and the same options:

```bash
security-review-ci trend --project my-project --days 90 --format markdown
```

For each period:

- new and fixed findings;
- open backlog;
- risk score (critical 10, high 5, medium 2, low 1) and direction (±10 % margin over the last
  two periods).

Overall: mean time to remediate (MTTR) by severity, oldest open finding, most frequent CWEs.

!!! note
    Fixes made before v1.2 have no date: they are reported in a note.

The same report is available on the MCP side with the `get_trend_report` tool.
