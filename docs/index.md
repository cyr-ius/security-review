# security-review-mcp

MCP server for **security-oriented code review** (vulnerabilities and misconfigurations).
It gives the host (VS Code, Copilot, Claude, CI/CD agent):

- structured **prompts** to start a review;
- **tools**: checklists, quick pattern scan, saving and reading reports;
- a **database** (SQLite by default, PostgreSQL possible) that stores the reports and their
  findings.

It comes with a **command line** for pipelines: whole repository scan, deployment gate, SARIF
export, dependency analysis and trend report.

## Quick start

```bash
pip install security-review-mcp
security-review-mcp            # stdio transport: the host starts the process
```

Then declare the server in your host, for example `.vscode/mcp.json`:

```json
{
  "servers": {
    "security-review": {
      "type": "stdio",
      "command": "security-review-mcp"
    }
  }
}
```

In the chat, run the `security-review` prompt (or `codebase-review` for the whole repository):
the agent reads the code, relies on the checklists and saves its report in the database with
`save_security_report`.

## Where to go next

| I want to… | Page |
|---|---|
| Install the server, including offline | [Installation](getting-started/installation.md) |
| Plug it into VS Code or Claude | [Host configuration](getting-started/host.md) |
| Run a secure shared server | [HTTP server, authentication and TLS](getting-started/http.md) |
| Deploy the MCP server and the controller separately (Docker, Kubernetes) | [Architecture and deployment](getting-started/kubernetes.md) |
| Know the exposed prompts and tools | [Prompts and tools](usage/prompts-tools.md) |
| Block a deployment on open findings | [Gate](ci-cd/gate.md) |
| Add my company's rules | [Internal rules](usage/rules.md) |
| Browse and triage the reports in a browser | [Web interface](usage/web-interface.md) |

!!! warning "This is not a SAST"
    The pattern scan produces **leads** and false positives. It replaces neither a SAST, nor a
    full SCA analysis, nor a human review. See [Security and limits](reference/security.md).
