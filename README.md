![Security Review MCP: a finding reported in the code](https://raw.githubusercontent.com/cyr-ius/security-review/master/docs/assets/banner.svg)

# Security Review MCP

![licence] ![Python] ![Angular] [![ci::status]][ci::github] [![pypi::version]][pypi::web] [![docker::pulls]][docker::hub] [![documentation::badge]][documentation::web]

[licence]: https://img.shields.io/github/license/cyr-ius/security-review?label=Licence&color=blue
[python]: https://img.shields.io/badge/Python-3.14%2B-blue?logo=python
[angular]: https://img.shields.io/badge/Angular-22-blue?logo=angular
[ci::status]: https://img.shields.io/github/actions/workflow/status/cyr-ius/security-review/tests.yml?branch=dev&label=Tests&color=blue&logo=github
[ci::github]: https://github.com/cyr-ius/security-review/actions
[pypi::version]: https://img.shields.io/pypi/v/security-review?color=blue&logo=pypi&logoColor=white
[pypi::web]: https://pypi.org/project/security-review/
[docker::pulls]: https://img.shields.io/docker/pulls/cyrius44/security-review.svg?logo=docker
[docker::hub]: https://hub.docker.com/r/cyrius44/security-review
[documentation::badge]: https://img.shields.io/badge/Documentation-MkDocs-green?logo=materialformkdocs
[documentation::web]: https://cyr-ius.github.io/security-review/

MCP server for **security-oriented code review** (vulnerabilities and misconfigurations), usable
from VS Code / Copilot, Claude or a CI/CD agent. It provides review prompts, checklists, a
pattern scan with focused Tree-sitter checks for request-to-SQL flows (Python, Java, Go, C#, Rust, Node.js), Angular DOM flows and unchecked message origins, an offline dependency analysis
and a report database (SQLite or PostgreSQL) usable in pipelines.

📖 **Full documentation: <https://cyr-ius.github.io/security-review/>**

🇫🇷 [Version française](README.fr.md)

## Capabilities

| | |
|---|---|
| **Prompts** | `security-review`, `api-security-review`, `configuration-review`, `codebase-review`, `dependency-review`, `triage-report`, `development-standards` |
| **Tools** | checklists, `scan_code`, `scan_dependencies`, saving and reading of reports with their [checklist coverage](https://cyr-ius.github.io/security-review/usage/prompts-tools/#review-coverage) (grouped by a [normalized project name](https://cyr-ius.github.io/security-review/usage/prompts-tools/#project-name)), [status proposals](https://cyr-ius.github.io/security-review/usage/prompts-tools/#status-of-a-finding) (`propose_finding_status`: an agent never closes a finding), project posture and gate, SARIF export, trends, rule management |
| **CLI** | `security-review-mcp` (MCP server, `enroll`) and `security-review-controller` (`serve`, `db`, `advisories`, `rules`, `token`, `user`, `audit`), exit codes 0 / 1 / 2 |
| **Pipelines** | [`security-review-ci`](https://cyr-ius.github.io/security-review/usage/gate/#pipeline-client-security-review-ci) (`gate`, `sarif`, `trend`, [`scan-code`](https://cyr-ius.github.io/security-review/advanced/code-scan/), [`scan-deps`](https://cyr-ius.github.io/security-review/advanced/dependencies/#scan-in-a-pipeline-security-review-ci-scan-deps), which store their reports through the API): lightweight client of the REST API for Jenkins, GitLab or GitHub, with a `ci` token restricted to the selected projects, no database driver, [installed alone](https://cyr-ius.github.io/security-review/usage/gate/#installation) without Python (`uv tool install security-review-ci`); on a workstation (commit hook), with a [personal `mcp` or `ci` token](https://cyr-ius.github.io/security-review/advanced/dependencies/#scan-from-a-workstation-commit-hook) |
| **Rules** | More than 200 rules and more than 120 checklist items: Python, Java, Go, C#, Rust, TypeScript / Node.js backend, Angular, Docker, Kubernetes, configuration, GitLab CI, Jenkins, Spring, FastAPI, [prompt injection aimed at AI assistants](https://cyr-ius.github.io/security-review/usage/rules/#default-rules-by-platform) (hidden characters, injected instructions; [read guard](https://cyr-ius.github.io/security-review/advanced/read-guard/) hook for Claude Code), copied into the database at first start, plus your own [rules](https://cyr-ius.github.io/security-review/usage/rules/) and [checklists](https://cyr-ius.github.io/security-review/usage/checklists/) (TOML import/export from the CLI or the web interface) |
| **Development standards** | [conventions by technology](https://cyr-ius.github.io/security-review/usage/standards/) managed in the web interface (TOML import/export) and handed to the AI assistant before it codes (prompt, `get_development_standards` / `list_development_standards` tools, resources) |
| **Vulnerabilities** | manifests, lockfiles and [CycloneDX SBOMs](https://cyr-ius.github.io/security-review/advanced/dependencies/#cyclonedx-sbom-transitive-dependencies) checked against an OSV database (PyPI, npm, Maven, Go, crates.io, NuGet) imported offline or [updated every day by the controller](https://cyr-ius.github.io/security-review/advanced/dependencies/#automatic-update-by-the-controller), optional proxy |
| **Transport** | HTTP (shared mode) or stdio (local mode), with optional Bearer tokens stored in the database (`token` CLI) with [expiry and rotation](https://cyr-ius.github.io/security-review/advanced/http/#expiry-and-rotation-of-tokens), and TLS (optionally mutual) |
| **Audit and metrics** | [audit log](https://cyr-ius.github.io/security-review/advanced/audit-metrics/#audit-log) of triage decisions, tokens and enrollments, and [Prometheus metrics](https://cyr-ius.github.io/security-review/advanced/audit-metrics/#prometheus-metrics) on `/metrics` (`metrics` token) |
| **Connectors** | [findings sent to other tools](https://cyr-ius.github.io/security-review/connectors/): Jira and ServiceNow built in, [third-party connectors](https://cyr-ius.github.io/security-review/connectors/third-party/) for any other system (vulnerability register, GRC...); each connector switched on in the web interface, by hand or automatically above a severity threshold, one record per issue |
| **Deployment** | MCP server and controller (REST API, web interface) [separated](https://cyr-ius.github.io/security-review/advanced/architecture/) on a shared database, Alembic migrations, Docker Compose and Kubernetes examples |
| **Enrollment** | an MCP client without a token [requests its project](https://cyr-ius.github.io/security-review/advanced/http/#enrollment-request-the-project) (`request_enrollment` MCP tool or `enroll` CLI), an administrator approves it, then the user creates a personal MCP token in the web interface; a refused token gets a `401` that says how to get a new one |
| **Web interface** | in English, French or Spanish: dashboard, [triage by a person](https://cyr-ius.github.io/security-review/usage/web-interface/#triage-of-findings) (approver of the accepted risks and false positives, reason and expiry of the accepted risks), [risk acceptances](https://cyr-ius.github.io/security-review/usage/web-interface/#risk-acceptances) to renew or remove, with append-only comments, [per-project list of open findings](https://cyr-ius.github.io/security-review/usage/web-interface/#screens) for an expert review, management of [rules, checklists, tokens (per project or for all projects), report language, outgoing proxy (OSV and OIDC) and OSV updates](https://cyr-ius.github.io/security-review/usage/web-interface/), local or OIDC [user accounts](https://cyr-ius.github.io/security-review/usage/web-interface/#user-accounts), the only ones to open the interface (tokens are for machines: MCP agents, pipelines, scripts; personal or role [API tokens](https://cyr-ius.github.io/security-review/usage/web-interface/#api-tokens) for the REST API and Swagger, [personal MCP tokens](https://cyr-ius.github.io/security-review/usage/web-interface/#personal-mcp-tokens) on the projects of the user, with the `mcp-user` role; initial `admin` account in the logs), optional [OpenID Connect OIDC login](https://cyr-ius.github.io/security-review/advanced/sso/), [configurable in the interface](https://cyr-ius.github.io/security-review/advanced/sso/#configuring-sso-in-the-interface), with accounts created on the fly, and [roles, groups and permissions](https://cyr-ius.github.io/security-review/advanced/access-control/) (groups matched by name with the OIDC groups claim, roles per project given to groups, never directly to accounts) |

Details: [how a review works](https://cyr-ius.github.io/security-review/usage/how-it-works/) (rules, checklists, standards, `AGENTS.md`),
[prompts and tools](https://cyr-ius.github.io/security-review/usage/prompts-tools/),
[whole codebase scan](https://cyr-ius.github.io/security-review/advanced/code-scan/),
[dependencies](https://cyr-ius.github.io/security-review/advanced/dependencies/),
[gate](https://cyr-ius.github.io/security-review/usage/gate/),
[SARIF](https://cyr-ius.github.io/security-review/advanced/sarif/),
[trends](https://cyr-ius.github.io/security-review/advanced/trends/).

## Quick start

The product runs as **two services** sharing one database: the **MCP server**
(`security-review-mcp`), used by the agents and the CI, and the **controller**
(`security-review-controller`), used by people: web interface, REST API, tokens and accounts.
See [two services, two roles](https://cyr-ius.github.io/security-review/#two-services-two-roles).

```bash
uv venv && source .venv/bin/activate
uv pip install security-review         # Python ≥ 3.14; [postgres] extra for PostgreSQL

# from the same directory (shared SQLite file)
security-review-controller db upgrade                              # schema (Alembic)
security-review-controller user create admin --group administrators   # web interface account
security-review-controller token create --label alice              # token of the agent
security-review-controller serve --port 8080                       # /ui interface and REST API
security-review-mcp serve --port 8000                              # /mcp endpoint (streamable HTTP)

security-review-ci gate --url http://localhost:8080 --project portal  # block a pipeline (ci token: SECREVIEW_TOKEN)
```

Host configuration (VS Code with a token, `.vscode/mcp.json`; Claude and `.mcp.json`: see
[connecting the host](https://cyr-ius.github.io/security-review/getting-started/host/)):

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

Step by step: [deploying the server](https://cyr-ius.github.io/security-review/getting-started/deploy/),
[connecting the host](https://cyr-ius.github.io/security-review/getting-started/host/) (VS Code, Claude, enrollment).
Other cases: [offline installation](https://cyr-ius.github.io/security-review/advanced/installation/),
[local mode (stdio)](https://cyr-ius.github.io/security-review/getting-started/stdio/),
[HTTP, authentication and TLS](https://cyr-ius.github.io/security-review/advanced/http/),
[Docker images](https://cyr-ius.github.io/security-review/advanced/docker/#published-images) (`ghcr.io/cyr-ius/security-review`, `docker.io/cyrius44/security-review`) and [Docker Compose with PostgreSQL](https://cyr-ius.github.io/security-review/advanced/docker/#docker-compose-with-postgresql),
[architecture and Kubernetes](https://cyr-ius.github.io/security-review/advanced/architecture/),
[`SECREVIEW_*` variables](https://cyr-ius.github.io/security-review/reference/configuration/).

## Limits

The scan produces leads, with false positives. Its Tree-sitter checks cover only simple local flows inside
one file. It replaces neither a full SAST or SCA analysis, nor a human review. See
[security and limits](https://cyr-ius.github.io/security-review/reference/security/).

## Contributing

```bash
uv sync --extra dev && uv run pytest && uv run ruff check .
```

Development happens on `dev`, and a version is released by pushing a `vX.Y.Z` tag on `master`.
See the [contribution guide](https://cyr-ius.github.io/security-review/contributing/) and
[`AGENTS.md`](AGENTS.md) (instructions for AI agents).

## Security and license

Report a vulnerability privately, as described in [`SECURITY.md`](SECURITY.md). The project is
distributed under the [Apache 2.0 license](LICENSE).
