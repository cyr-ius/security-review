# Local mode (stdio)

In **local mode**, the host (VS Code, Claude…) starts `security-review-mcp serve` itself on the
developer workstation and talks to it through stdin / stdout: no network, no token, no
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
(see [Configuration](../reference/configuration.md#mcp-server)).

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

To run the server from a container, see [Docker](../advanced/docker.md).
