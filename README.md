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
| **Tools** | checklists, `scan_code`, `scan_dependencies`, saving and reading of reports, [status proposals](https://cyr-ius.github.io/security-review-mcp/usage/prompts-tools/#status-of-a-finding) (`propose_finding_status`: an agent never closes a finding), project posture and gate, SARIF export, trends, rule management |
| **CLI** | `security-review-mcp` (MCP server, `enroll`, [`scan-deps`](https://cyr-ius.github.io/security-review-mcp/advanced/dependencies/#scan-with-a-shared-server-commit-hook) for a commit hook) and `security-review-controller` (`serve`, `db`, `code scan`, `deps scan`, `advisories`, `rules`, `token`, `user`, `audit`), exit codes 0 / 1 / 2 |
| **Pipelines** | [`security-review-ci`](https://cyr-ius.github.io/security-review-mcp/usage/gate/#pipeline-client-security-review-ci) (`gate`, `sarif`, `trend`): lightweight client of the REST API for Jenkins, GitLab or GitHub, with a `ci` token restricted to the selected projects, no database driver |
| **Rules** | More than 120 rules and more than 75 checklist items: Python, Java, Angular / Node.js, Docker, Kubernetes, configuration, GitLab CI, Jenkins, Spring, FastAPI, copied into the database at first start, plus your [internal rules](https://cyr-ius.github.io/security-review-mcp/advanced/rules/) (TOML import/export) |
| **Development standards** | [conventions by technology](https://cyr-ius.github.io/security-review-mcp/advanced/standards/) managed in the web interface and handed to the AI assistant before it codes (prompt, `get_development_standards` / `list_development_standards` tools, resources) |
| **Vulnerabilities** | manifests, lockfiles and [CycloneDX SBOMs](https://cyr-ius.github.io/security-review-mcp/advanced/dependencies/#cyclonedx-sbom-transitive-dependencies) checked against an OSV database (PyPI, npm, Maven) imported offline or [updated every day by the controller](https://cyr-ius.github.io/security-review-mcp/advanced/dependencies/#automatic-update-by-the-controller), optional proxy |
| **Transport** | HTTP (shared server) or stdio (local mode), with optional Bearer tokens stored in the database (`token` CLI) with [expiry and rotation](https://cyr-ius.github.io/security-review-mcp/advanced/http/#expiry-and-rotation-of-tokens), and TLS (optionally mutual) |
| **Audit and metrics** | [audit log](https://cyr-ius.github.io/security-review-mcp/advanced/audit-metrics/#audit-log) of triage decisions, tokens and enrollments, and [Prometheus metrics](https://cyr-ius.github.io/security-review-mcp/advanced/audit-metrics/#prometheus-metrics) on `/metrics` (`metrics` token) |
| **Deployment** | MCP server and controller (REST API, web interface) [separated](https://cyr-ius.github.io/security-review-mcp/advanced/architecture/) on a shared database, Alembic migrations, Docker Compose and Kubernetes examples |
| **Enrollment** | a project [requests its token or additional access](https://cyr-ius.github.io/security-review-mcp/advanced/http/#enrollment-a-project-requests-its-token) (`request_enrollment` MCP tool or `enroll` CLI), an administrator approves the request |
| **Web interface** | in English, French or Spanish: dashboard, [triage by a person](https://cyr-ius.github.io/security-review-mcp/usage/web-interface/#triage-of-findings) (reason, approver and expiry of the accepted risks and false positives), [per-project list of open findings](https://cyr-ius.github.io/security-review-mcp/usage/web-interface/#screens) for an expert review, management of [rules, checklists, project tokens, report language, outgoing proxy (OSV and SSO) and OSV updates](https://cyr-ius.github.io/security-review-mcp/usage/web-interface/), local or SSO [user accounts](https://cyr-ius.github.io/security-review-mcp/usage/web-interface/#user-accounts), the only ones to open the interface (tokens serve MCP and the REST API; initial `admin` account in the logs), optional [OpenID Connect SSO login](https://cyr-ius.github.io/security-review-mcp/advanced/sso/), [configurable in the interface](https://cyr-ius.github.io/security-review-mcp/advanced/sso/#configuring-sso-in-the-interface), with accounts created on the fly and [role mapping](https://cyr-ius.github.io/security-review-mcp/advanced/sso/#role-mapping) by group and by project |

Details: [prompts and tools](https://cyr-ius.github.io/security-review-mcp/usage/prompts-tools/),
[whole codebase scan](https://cyr-ius.github.io/security-review-mcp/advanced/code-scan/),
[dependencies](https://cyr-ius.github.io/security-review-mcp/advanced/dependencies/),
[gate](https://cyr-ius.github.io/security-review-mcp/usage/gate/),
[SARIF](https://cyr-ius.github.io/security-review-mcp/advanced/sarif/),
[trends](https://cyr-ius.github.io/security-review-mcp/advanced/trends/).

## Quick start

The product runs as **two services** sharing one database: the **MCP server**
(`security-review-mcp`), used by the agents and the CI, and the **controller**
(`security-review-controller`), used by people: web interface, REST API, tokens and accounts.
See [two services, two roles](https://cyr-ius.github.io/security-review-mcp/#two-services-two-roles).

```bash
pip install security-review-mcp        # Python ≥ 3.14; [postgres] extra for PostgreSQL

# from the same directory (shared SQLite file)
security-review-controller db upgrade                              # schema (Alembic)
security-review-controller user create admin --role admin          # web interface account
security-review-controller token create --label alice              # token of the agent
security-review-controller serve --port 8080                       # /ui interface and REST API
security-review-mcp --transport streamable-http --port 8000        # /mcp endpoint

security-review-ci gate --url http://localhost:8080 --project portal  # block a pipeline (ci token: SECREVIEW_TOKEN)
```

Host configuration (VS Code with a token, `.vscode/mcp.json`; Claude and `.mcp.json`: see
[connecting the host](https://cyr-ius.github.io/security-review-mcp/getting-started/host/)):

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

Step by step: [deploying the server](https://cyr-ius.github.io/security-review-mcp/getting-started/deploy/),
[connecting the host](https://cyr-ius.github.io/security-review-mcp/getting-started/host/) (VS Code, Claude, enrollment).
Other cases: [offline installation](https://cyr-ius.github.io/security-review-mcp/advanced/installation/),
[local stdio mode](https://cyr-ius.github.io/security-review-mcp/advanced/stdio/),
[HTTP, authentication and TLS](https://cyr-ius.github.io/security-review-mcp/advanced/http/),
[Docker images](https://cyr-ius.github.io/security-review-mcp/advanced/docker/#published-images) (`ghcr.io/cyr-ius/security-review-mcp`, `docker.io/cyrius44/security-review-mcp`) and [Docker Compose with PostgreSQL](https://cyr-ius.github.io/security-review-mcp/advanced/docker/#docker-compose-with-postgresql),
[architecture and Kubernetes](https://cyr-ius.github.io/security-review-mcp/advanced/architecture/),
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
