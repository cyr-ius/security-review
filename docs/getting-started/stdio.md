# Local mode (stdio)

In **local mode**, the host (VS Code, Claude…) starts `security-review-mcp serve --transport stdio` itself
on the developer workstation and talks to it through stdin / stdout: no network, no token, no
controller.

!!! warning "For specific cases only"
    The reports are saved in a **local** SQLite database that nobody else sees, there is no web
    interface to triage them, and every workstation keeps its own rules. For a team, use the
    [shared mode (HTTP)](../getting-started/deploy.md) instead. Local mode is useful to try the
    prompts alone, on an offline workstation, or for a personal use.

## Installation

The server is published on PyPI as the `security-review` package (Python 3.14). It installs the
`security-review-mcp` command started by the host, and `security-review-controller`, which local
mode does not need. Install it in a dedicated virtual environment:

```bash
uv venv --python 3.14 /opt/security-review-mcp/venv
uv pip install --python /opt/security-review-mcp/venv security-review
```

!!! note "Formerly `security-review-mcp`"
    Up to version 2.0.0, the package was published on PyPI as `security-review-mcp`. Both
    packages install the same commands and the same Python module: uninstall the old one first
    (`uv pip uninstall --python /opt/security-review-mcp/venv security-review-mcp`), then install
    `security-review`. The commands, the settings and the database stay the same.

Without Internet access, or from the sources: see [Installation: other cases](../advanced/installation.md).

## Running

```bash
security-review-mcp serve --transport stdio   # started by the host, not by hand
```

A SQLite database is created locally (`~/.local/share/security-review-mcp/security_reports.db`).
You can change its location via [`SECREVIEW_DATABASE_URL`](../reference/configuration.md#database).
This is the only file written by the server; delete it to remove all traces.

!!! note "SQLite only"
    In stdio, the server refuses to start (code `2`) when `SECREVIEW_DATABASE_URL` points to
    another database (PostgreSQL...): local mode has no token, and a shared database would let it
    write to every project and migrate the schema of the team. Unset the variable if your
    environment defines it (`env -u SECREVIEW_DATABASE_URL ...`), or use the
    [shared mode (HTTP)](../getting-started/deploy.md).

!!! note "`--transport stdio` is required"
    Without `--transport`, `serve` starts the HTTP server of the shared mode
    ([`SECREVIEW_TRANSPORT`](../reference/configuration.md#mcp-server), `streamable-http` by
    default). Up to version 3.0.0, `serve` ran in stdio by default: add `--transport stdio` to
    the existing host configurations.

## Host configuration

With the **stdio** transport, the host (VS Code, Claude…) starts the server process itself.
Give the path of the executable, the `serve --transport stdio` command and, if needed, the `SECREVIEW_*` variables
(see [Configuration](../reference/configuration.md#mcp-server)).

VS Code, GitHub Copilot and Claude read the same `.mcp.json` file at the root of the
repository:

```json
{
  "mcpServers": {
    "security-review": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from","security-review==4.0.0","security-review-mcp","serve","--transport","stdio"]
    }
  }
}
```

To run the server from a container, see [Docker](../advanced/docker.md).
