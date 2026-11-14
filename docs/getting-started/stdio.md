# Local mode (stdio)

In **local mode**, the host (VS Code, Claude…) starts `security-review-mcp local` itself on the
developer workstation and talks to it through stdin / stdout: no network, no token, no
Controller server.

```mermaid
flowchart LR
    dev(["Developer"]) --> agent
    subgraph ws["Developer workstation"]
        agent["AI assistant<br/>VS Code, Claude"] -- "stdio" --> mcp["MCP server<br/>security-review-mcp<br/>(process started by the assistant)"]
        mcp --> sqlite[("Local SQLite<br/>database")]
    end
```

## Configuring the host

This is the only step: with [uv](https://docs.astral.sh/uv/getting-started/installation/) on the
workstation, there is nothing to install and nothing to start by hand. At its first start, the
host downloads the `security-review` package from PyPI with `uvx` (Python 3.14 included if
needed), then starts the server itself each time it needs it.

VS Code, GitHub Copilot and Claude read the same `.mcp.json` file at the root of the
repository:

```json
{
  "mcpServers": {
    "security-review": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "security-review=={{ release_version }}", "security-review-mcp", "local"]
    }
  }
}
```

To change a setting, add `SECREVIEW_*` variables in an `env` object next to `args` (see
[Configuration](../reference/configuration.md#mcp-server)).

Then open the chat of the host and run the `security-review` prompt.

Without `uvx` (installed package, offline workstation, sources, container): see
[Installation: other cases](../advanced/deployment/installation.md).

## Database

The server creates a SQLite database on the workstation
(`~/.local/share/security-review-mcp/security_reports.db`, or under `$XDG_DATA_HOME` when it is
set). This is the only file written by the server; delete it to remove all traces.
To put it elsewhere, add `--database-url` after `local` in `args` (SQLite only, absolute path
after `sqlite:///`):

```json
"args": ["--from", "security-review=={{ release_version }}", "security-review-mcp", "local",
         "--database-url", "sqlite:////home/me/data/security_reports.db"]
```

## Findings report (SECURITY_REPORT.md)

Without a web interface, ask the assistant for the findings of the project, for example:

- *"Show me the security findings of this project"*
- *"Write the security findings to SECURITY_REPORT.md"*

The report lists the open findings, worst first, one line per finding. You can also ask for:

- **the details** of each finding (description, code excerpt, recommendation): the report is then
  much longer;
- **the resolved findings** (fixed, accepted, false positives).

The server never writes to disk: the assistant writes `SECURITY_REPORT.md`, and the host asks you
to approve the write. The file holds code excerpts: add it to `.gitignore` if it should not be
committed.

## Triage in local mode

Without a web interface, you triage the findings in the chat.

1. Tell the assistant your decision in your own words, for example:
    - *"Line 12 of app/db.py is a false positive: the query is bound"*
    - *"Accept the risk of #42 until June 30: internal tool"*
2. Your host shows a confirmation: findings, status, reason and expiry date.
3. The status changes only when you confirm. You are recorded as the approver.

!!! warning "Decline a confirmation you did not ask for."

The host must support MCP elicitation (Claude Code, VS Code). Otherwise, the assistant can only
propose a status.

Details: [decision of the developer in local mode](../review/prompts-tools.md#decision-of-the-developer-in-local-mode).
