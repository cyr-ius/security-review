# Local mode (stdio)

In **local mode**, the host (VS Code, Claude…) starts `security-review-mcp serve` itself on the
developer workstation and talks to it through stdin / stdout: no network, no token, no
controller.

!!! warning "For specific cases only"
    The reports are saved in a **local** SQLite database that nobody else sees, there is no web
    interface to triage them, and every workstation keeps its own rules. For a team, deploy the
    [shared server](../getting-started/deploy.md) instead. Local mode is useful to try the
    prompts alone, on an offline workstation, or for a personal use.

## Running

```bash
security-review-mcp serve   # started by the host, not by hand
```

The local SQLite database (`~/.local/share/security-review-mcp/security_reports.db` by default, the same file whatever
the repository open in the host, see
[`SECREVIEW_DATABASE_URL`](../reference/configuration.md#database)) is created or migrated
automatically at start-up. It is the only file the server writes: delete it to remove every
trace. The controller is not needed.

## Host configuration

With the **stdio** transport, the host (VS Code, Claude…) starts the server process itself.
Give the path of the executable, the `serve` command and, if needed, the `SECREVIEW_*` variables
(see [Configuration](../reference/configuration.md)).

VS Code, GitHub Copilot and Claude read the same `.mcp.json` file at the root of the
repository:

```json
{
  "mcpServers": {
    "security-review": {
      "type": "stdio",
      "command": "/opt/security-review-mcp/venv/bin/security-review-mcp",
      "args": ["serve"],
      "env": { "SECREVIEW_DATABASE_URL": "sqlite:////var/lib/secreview/security_reports.db" }
    }
  }
}
```

To run the server from a container, see [Docker](docker.md#developer-workstation-stdio).
