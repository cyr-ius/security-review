# Security Review

**Security Review turns the AI assistants of your developers into security reviewers that
follow your rules, and gives your security team a central view of everything they find.**

Your teams already write code with AI assistants (GitHub Copilot, Claude, Cursor...). Security
Review plugs into these assistants through **MCP** (Model Context Protocol, the open standard
that lets an assistant use external tools). Every change can then be reviewed for
vulnerabilities and misconfigurations **while the code is being written**, and every result is
recorded in one place, where your security team reads it, triages it and follows it up.

## Why adopt it

- **Security from the first line of code.** Flaws are found in the editor, by the developer,
  when fixing them costs the least, not weeks later during an audit or in production.
- **Your requirements, applied by every assistant.** The security team manages the [scan
  rules](review/rules.md), the [review checklists](review/checklists.md) and the [development standards](review/standards.md) in one place; every assistant of
  every project receives the same ones, without training each developer.
- **A central and lasting view.** Reports are stored in a database (SQLite or PostgreSQL). The
  [web interface](usage/index.md) shows, for each project, the open findings, the security posture and its trend
  over time ([trend report](advanced/architecture/ci.md#trend-report)).
- **People decide, not the AI.** An assistant can only *propose* to close a finding. A risk
  acceptance or a false positive is decided by a signed-in person, recorded as the approver; a
  risk acceptance also carries a reason and an expiry date, according to your policy: every decision can be traced for an audit
  ([triage of findings](usage/triage.md)).
- **Built into your delivery chain.** A [gate](review/gate.md) blocks a deployment while serious findings remain
  open; the results are exported in [SARIF](advanced/reports/sarif.md) (GitHub code scanning, Jenkins); the [dependencies](review/analysis/dependencies.md) are
  checked against an OSV vulnerability database, even without Internet access.
- **Connected to your company tools.** [Single sign-on (OIDC)](usage/sso.md) with your identity provider,
  [groups and roles](usage/access-control.md), findings sent to
  [Jira or ServiceNow](usage/connectors/index.md),
  [audit log forwarded to syslog, Prometheus metrics](usage/audit-metrics.md).
- **Your code stays with you.** The product is self-hosted: the MCP server makes no outgoing
  connection, secrets are masked before being stored, and it installs offline. It is open
  source (Apache 2.0 license). See [Security and limits](reference/security.md).
- **A broad coverage.** Rules for Python (FastAPI), Java (Spring), TypeScript / Node.js,
  Angular, Go, C#, Rust, configuration files and CI pipelines (GitLab CI, Jenkins...), plus the
  detection of hidden instructions aimed at AI assistants.

## How it works, in three steps

1. **The developer asks for a review** ("review my changes for security"). The assistant
   follows the review method of the server: prompts, checklists, pattern scan.
2. **The assistant saves its report**: each finding with its severity, its file, its evidence
   and a recommendation.
3. **The security team triages** the findings in the web interface, and the pipeline checks
   with the gate that no serious finding remains open before deploying.

## What the product contains

An **MCP server** for **security-focused code review** (identifying vulnerabilities and misconfigurations). It provides the host (VS Code, Copilot, Claude, CI/CD agent, etc.) with:

- Structured **prompts** to initiate a review;
- **Tools**, including checklists, pattern-based quick scans, and the ability to save and retrieve reports;
- A **database** (SQLite by default, with support for PostgreSQL) to store reports and their associated findings.

Accessed via the `security-review-mcp` command.

A **Controller server** for **administration and control management** (the Controller server is optional). It provides administrators and cybersecurity analysts with:

- Access to security analysis **reports**;
- The ability to conduct **security reviews** and manage **risk acceptance**;
- Options to add, modify, or delete **rules and checklists**;
- The ability to incorporate **development standards**;
- **Management** of developer communities;
- Third-party **connectors** for tracking and integration (Jira, ServiceNow, etc.).

Accessed via the `security-review-controller` command.

A **CI command** for injection into pipelines (such as Jenkins, etc.) that enables:

- Full **repository scanning**;
- Deployment **gates** that block releases if open findings exist;
- SARIF export and **trend reporting**;
- **Dependency analysis**.

Accessed via the `security-review-ci` command.

## Quick start (shared mode)

The repository provides a ready-to-use `docker-compose.yml` file in `examples/docker/`. This
block starts everything (PostgreSQL, Controller server, MCP server), resets the password of the `admin`
account and creates a token for your agent:

```bash
mkdir security-review-mcp && cd security-review-mcp
curl -fsSLO https://raw.githubusercontent.com/cyr-ius/security-review/{{ release_tag }}/examples/docker/docker-compose.yml
(umask 077 && printf 'POSTGRES_PASSWORD=%s\nSECREVIEW_SECRET_KEY=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" > .env)
docker compose up -d --wait
docker compose exec controller security-review-controller user reset-password admin   # password shown once
docker compose exec controller security-review-controller token create --label alice   # mcp token, shown once
# web interface: http://127.0.0.1:8080/ui/   MCP endpoint: http://127.0.0.1:8000/mcp
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

In the chat, run the `security-review` prompt (or `codebase-review` for the whole repository).
The agent reads the code, relies on the checklists and saves its report with
`save_security_report`.
Log in to the web interface with the `admin` account to read and triage it.

The ports are open on every interface of the server, in plain HTTP. Before the team uses it,
remember to set up your certificates to enable HTTPS. See [Deploying the server](getting-started/deploy.md).

## Where to go next

The documentation follows the order of a set-up. **Getting started**, **Security review** and
**Application** hold what you need to work; **Advanced** gathers the details and the optional features.

| Step | Page |
|---|---|
| 1. Deploy the Controller server and the MCP server (Docker Compose or Kubernetes), create the first accounts | [Deploying the server](getting-started/deploy.md) |
| 2. Connect VS Code or Claude, get a token | [Connecting the host](getting-started/host.md) |
| 3. Run a review | [How a review works](review/index.md) (rules, checklists, `AGENTS.md`), [Prompts and tools](review/prompts-tools.md) |
| 4. Read and triage the reports | [Web interface](usage/index.md) |
| 5. Block a deployment on open findings | [Gate](review/gate.md) |

| Going further (Advanced) | Page |
|---|---|
| Docker, Kubernetes, PostgreSQL, without containers | [Architecture](advanced/architecture/index.md), [Docker](advanced/deployment/docker.md), [Kubernetes](advanced/deployment/kubernetes.md), [Manual installation](advanced/deployment/manual-install.md) |
| Tokens restricted to a project, enrollment, rotation, TLS | [Bearer tokens](advanced/bearer-tokens.md), [Enrollment](advanced/architecture/mcp-server.md#enrollment-personal-token-and-project-requests), [TLS](advanced/tls.md) |
| Log in with the company identity provider | [OIDC login](usage/sso.md) |
| Scan a whole repository, the dependencies, add my company's rules | [Whole codebase scan](review/analysis/code-scan.md), [Dependency analysis](review/analysis/dependencies.md), [Rules](review/rules.md) |
| SARIF, trends, audit log, Prometheus | [SARIF export](advanced/reports/sarif.md), [Trend report](advanced/architecture/ci.md#trend-report), [Audit log](usage/audit-metrics.md), [Prometheus metrics](reference/metrics.md) |

!!! warning "This is not a SAST"
    The pattern scan produces **leads** and false positives. It replaces neither a SAST, nor a
    full SCA analysis, nor a human review. See [Security and limits](reference/security.md).
