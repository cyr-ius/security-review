# security-review-mcp

MCP server for **security-oriented code review** (vulnerabilities and misconfigurations).
It gives the host (VS Code, Copilot, Claude, CI/CD agent):

- structured **prompts** to start a review;
- **tools**: checklists, quick pattern scan, saving and reading reports;
- a **database** (SQLite by default, PostgreSQL possible) that stores the reports and their
  findings.

It comes with a **command line** for pipelines: whole repository scan, deployment gate, SARIF
export, dependency analysis and trend report.

## Two services, two roles

The product is made of **two programs** installed by the same package. They never call each
other: they share the same **database**, where the reports, rules and tokens are stored.

```text
 agents (VS Code, Claude), CI ──▶ MCP server ──┐
                                               ├──▶ database (SQLite or PostgreSQL)
 people (browser), admins ──────▶ controller ──┘
```

| | MCP server | Controller |
|---|---|---|
| Command | `security-review-mcp` | `security-review-controller` |
| Used by | the AI agents and the CI pipelines | the people: security team, developers, administrators |
| What it does | gives the agent the review prompts, the checklists, the pattern scan, and saves its reports | shows and triages the reports in the **web interface** (`/ui/`), serves the REST API, creates the schema, manages the tokens and the user accounts |
| Exposure | to the agents and to the CI (`/mcp` endpoint) | preferably on an internal network |

In short: **the agent talks to the MCP server, people use the controller.** For a team, you
deploy **both**: without the controller, nobody can read the reports in a browser, decide on a
finding, nor create the tokens of the agents.

!!! tip "Which mode to choose?"
    - **Shared server (HTTP)**, the recommended case: the MCP server and the controller run on
      a machine or in containers, every developer and every pipeline connects to it with a
      token, and the reports are centralized. Start here.
    - **Local mode (stdio)**, for specific cases only: the host (VS Code, Claude) starts
      `security-review-mcp` itself on the developer workstation, without a network, a token,
      nor a controller. Handy to try the prompts alone or offline, but the reports stay in a
      local database that nobody else sees. See
      [Local mode (stdio)](advanced/stdio.md).

## Quick start (HTTP server)

On one machine, from the **same directory** (both processes share the SQLite file
`./security_reports.db`; use PostgreSQL as soon as they run on different machines):

```bash
pip install security-review-mcp

# 1. Controller: schema, first administrator, token of the agent
security-review-controller db upgrade
security-review-controller user create admin --group administrators   # password shown once
security-review-controller token create --label alice      # mcp token, shown once

# 2. Start the two services (two terminals)
security-review-controller serve --host 127.0.0.1 --port 8080
# web interface: http://127.0.0.1:8080/ui/
security-review-mcp serve --transport streamable-http --host 127.0.0.1 --port 8000
# MCP endpoint: http://127.0.0.1:8000/mcp
```

Then declare the MCP server in your host, for example in VS Code with `.vscode/mcp.json` (the
only file where VS Code can ask for the token), and paste the token when VS Code asks for it:

```json
{
  "servers": {
    "security-review": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer ${input:secreview-token}" }
    }
  },
  "inputs": [
    { "id": "secreview-token", "type": "promptString", "description": "Token", "password": true }
  ]
}
```

In the chat, run the `security-review` prompt (or `codebase-review` for the whole repository):
the agent reads the code, relies on the checklists and saves its report with
`save_security_report`. Log in to the web interface with the `admin` account to read and
triage it.

This quick start is a test on one machine. To open the server to a team (TLS, PostgreSQL,
Docker Compose, tokens for every developer), follow [Deploying the server](getting-started/deploy.md).

## Where to go next

The documentation follows the order of a set-up. **Getting started** and **Usage** hold what
you need to work; **Advanced** gathers the details and the optional features.

| Step | Page |
|---|---|
| 1. Install the package on the server | [Installation](getting-started/installation.md) |
| 2. Start the controller and the MCP server, create the first accounts | [Deploying the server](getting-started/deploy.md) |
| 3. Connect VS Code or Claude, get a token | [Connecting the host](getting-started/host.md) |
| 4. Run a review | [Prompts and tools](usage/prompts-tools.md) |
| 5. Read and triage the reports | [Web interface](usage/web-interface.md) |
| 6. Block a deployment on open findings | [Gate](usage/gate.md) |

| Going further (Advanced) | Page |
|---|---|
| Docker, Kubernetes, PostgreSQL | [Architecture and deployment](advanced/architecture.md), [Docker](advanced/docker.md) |
| Tokens restricted to a project, enrollment, rotation, TLS | [HTTP server, authentication and TLS](advanced/http.md) |
| Log in with the company identity provider | [OIDC login](advanced/sso.md) |
| Scan a whole repository, the dependencies, add my company's rules | [Whole codebase scan](advanced/code-scan.md), [Dependency analysis](advanced/dependencies.md), [Internal rules](advanced/rules.md) |
| SARIF, trends, audit log, Prometheus | [SARIF export](advanced/sarif.md), [Trend report](advanced/trends.md), [Audit log and metrics](advanced/audit-metrics.md) |

!!! warning "This is not a SAST"
    The pattern scan produces **leads** and false positives. It replaces neither a SAST, nor a
    full SCA analysis, nor a human review. See [Security and limits](reference/security.md).
