# Security Review MCP

MCP server for **security-oriented code review** (vulnerabilities and misconfigurations), usable
from VS Code / Copilot, Claude or a CI/CD agent. It provides review prompts, checklists, a
pattern scan, an offline dependency analysis and a report database (SQLite or PostgreSQL) usable
in pipelines.

📖 **Full documentation: <https://cyr-ius.github.io/security-review-mcp/>**

🇫🇷 [Version française](README.fr.md)

## Capabilities

| | |
|---|---|
| **Prompts** | `security-review`, `api-security-review`, `configuration-review`, `codebase-review`, `dependency-review`, `triage-report`, `development-standards` |
| **Tools** | checklists, `scan_code`, `scan_dependencies`, saving / reading / triage of reports, project posture and gate, SARIF export, trends, rule management |
| **CLI** | `security-review-mcp` (MCP server, `enroll`) and `security-review-controller` (`serve`, `db`, `gate`, `sarif`, `trend`, `code scan`, `deps scan`, `advisories`, `rules`, `token`, `user`), exit codes 0 / 1 / 2 |
| **Rules** | More than 120 rules and more than 75 checklist items: Python, Java, Angular / Node.js, Docker, Kubernetes, configuration, GitLab CI, Jenkins, Spring, FastAPI, copied into the database at first start, plus your [internal rules](https://cyr-ius.github.io/security-review-mcp/usage/rules/) (TOML import/export) |
| **Development standards** | [conventions by technology](https://cyr-ius.github.io/security-review-mcp/usage/standards/) managed in the web interface and handed to the AI assistant before it codes (prompt, `get_development_standards` / `list_development_standards` tools, resources) |
| **Vulnerabilities** | OSV database (PyPI, npm, Maven) imported offline or [updated every day by the controller](https://cyr-ius.github.io/security-review-mcp/usage/dependencies/#automatic-update-by-the-controller), optional proxy |
| **Transport** | stdio or HTTP, with optional Bearer tokens stored in the database (`token` CLI) and TLS (mutual or self-signed) |
| **Deployment** | MCP server and controller (REST API, web interface) [separated](https://cyr-ius.github.io/security-review-mcp/getting-started/kubernetes/) on a shared database, Alembic migrations, Docker Compose and Kubernetes examples |
| **Enrollment** | a project [requests its token or additional access](https://cyr-ius.github.io/security-review-mcp/getting-started/http/#enrollment-a-project-requests-its-token) (`request_enrollment` MCP tool or `enroll` CLI), an administrator approves the request |
| **Web interface** | dashboard, triage, management of [rules, checklists, project tokens, report language, outgoing proxy (OSV and SSO) and OSV updates](https://cyr-ius.github.io/security-review-mcp/usage/web-interface/), local or SSO [user accounts](https://cyr-ius.github.io/security-review-mcp/usage/web-interface/#user-accounts), the only ones to open the interface (tokens serve MCP and the REST API; initial `admin` account in the logs), optional [OpenID Connect SSO login](https://cyr-ius.github.io/security-review-mcp/usage/web-interface/#openid-connect-sso-login), [configurable in the interface](https://cyr-ius.github.io/security-review-mcp/usage/web-interface/#configuring-sso-in-the-interface), with accounts created on the fly and [role mapping](https://cyr-ius.github.io/security-review-mcp/usage/web-interface/#role-mapping) by group and by project |

Details: [prompts and tools](https://cyr-ius.github.io/security-review-mcp/usage/prompts-tools/),
[whole codebase scan](https://cyr-ius.github.io/security-review-mcp/usage/code-scan/),
[dependencies](https://cyr-ius.github.io/security-review-mcp/usage/dependencies/),
[gate](https://cyr-ius.github.io/security-review-mcp/ci-cd/gate/),
[SARIF](https://cyr-ius.github.io/security-review-mcp/ci-cd/sarif/),
[trends](https://cyr-ius.github.io/security-review-mcp/ci-cd/trends/).

## Quick start

```bash
pip install security-review-mcp        # Python ≥ 3.14; [postgres] extra for PostgreSQL

security-review-mcp                    # stdio: started by the host

# shared server: two processes on the same database
security-review-controller db upgrade                              # schema (Alembic)
security-review-controller serve --port 8080                       # /ui interface and REST API
security-review-mcp --transport streamable-http --port 8000        # /mcp endpoint

security-review-controller gate --project portal --fail-on high    # block a pipeline
```

Host configuration (VS Code, `.vscode/mcp.json`):

```json
{
  "servers": {
    "security-review": {
      "type": "stdio",
      "command": "security-review-mcp",
      "env": { "SECREVIEW_DATABASE_URL": "sqlite:////data/security_reports.db" }
    }
  }
}
```

Other cases: [offline installation](https://cyr-ius.github.io/security-review-mcp/getting-started/installation/),
[Claude and other hosts](https://cyr-ius.github.io/security-review-mcp/getting-started/host/),
[HTTP, authentication and TLS](https://cyr-ius.github.io/security-review-mcp/getting-started/http/),
[Docker and Docker Compose with PostgreSQL](https://cyr-ius.github.io/security-review-mcp/getting-started/docker/),
[architecture and Kubernetes](https://cyr-ius.github.io/security-review-mcp/getting-started/kubernetes/),
[`SECREVIEW_*` variables](https://cyr-ius.github.io/security-review-mcp/reference/configuration/).

## Limits

The pattern scan produces leads, with false positives. It replaces neither a SAST, nor a full SCA
analysis, nor a human review. See
[security and limits](https://cyr-ius.github.io/security-review-mcp/reference/security/).

## Contributing

```bash
uv sync --extra dev && uv run pytest && uv run ruff check .
```

Development happens on `dev`, and a version is released by pushing a `vX.Y.Z` tag on `master`.
See the [contribution guide](https://cyr-ius.github.io/security-review-mcp/contributing/) and
[`AGENTS.md`](AGENTS.md) (instructions for AI agents).
