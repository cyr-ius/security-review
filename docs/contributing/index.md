# Contributing

## Development environment

Python 3.14, [uv](https://docs.astral.sh/uv/) and Node.js 24 are needed (the
[devcontainer](#devcontainer) provides them and installs the dependencies at creation):

```bash
git clone https://github.com/cyr-ius/security-review.git
cd security-review
uv sync --extra dev --extra docs
npm --prefix web ci                                   # Angular, Prettier (Node.js 24)
npm --prefix web run build                            # interface served by the Controller server on /ui/
uv run security-review-controller db upgrade
```

Without the Angular build, the Controller server only serves the REST API (`/api/v1`). `prek install`
(optional), linters, formatters and security reviews: see
[Checks, reviews and releases](checks-and-releases.md).

In VS Code (`.vscode/`):

| `launch.json` configuration | Role |
|---|---|
| **Controller (debug: FastAPI + Angular)** | Controller server on port 8080 and `ng serve` on port 4200 under the debugger, then Chrome on `http://localhost:4200/ui/` with the TypeScript breakpoints; hot reload of the page, restart of the Controller server on each save of `src/` (`scripts/dev_reload.py`), migrates the database and shows the password of the initial `admin` account at first start. To stay logged in across the restarts, set `SECREVIEW_SECRET_KEY` in your `.env` (ignored by git), for example to the output of `openssl rand -hex 32` |
| **MCP server (debug, port 8000)** | Runs the **Database upgrade** task, then the HTTP MCP server under the debugger |
| **Controller CLI (prompt for arguments)** | A Controller server command (`db status`, `token list`…) under the debugger |
| **Docs: MkDocs (port 8001)** | `mkdocs serve` with live reload, opens the site in the browser |

| `tasks.json` task | Command |
|---|---|
| **Build security_review_mcp** | `uv sync --extra dev --extra docs --extra postgres` |
| **Database upgrade** | `uv run security-review-controller db upgrade` (after **Build**) |
| **Tests** / **Lint** | `pytest`, then ruff and `mkdocs build --strict` |
| **Web UI: build** / **Web UI: dev server (port 4200)** | Angular build served by the Controller server, or `ng serve` with `/api` forwarded to port 8080 (stopped with the debugger by **Web UI: stop dev server**) |
| **Docker: compose up** / **down** | `docker-compose.yml` stack of the image, with its own PostgreSQL database (same ports 8000 and 8080: stop the debug configurations first) |

### Devcontainer

The repository provides a devcontainer (`.devcontainer/`) with Python, uv, Node.js, a dedicated
Docker daemon (*docker-in-docker* feature) and a **PostgreSQL 18** database. `compose.yaml`
describes two services: `app`, the development container, and `db`, the database, reachable
from `app` under the `db` name and kept in the `secreview-dev-pg` volume between two rebuilds.
`SECREVIEW_DATABASE_URL` points to it by default: the MCP server, the Controller server and the CLI use
PostgreSQL. The tests always use an in-memory SQLite database, and ignore your `.env` file and
the `SECREVIEW_*` variables of the shell.

At creation, the devcontainer installs the `psql` client, the `prek` hooks and the full
environment (`uv sync --extra dev --extra docs --extra postgres`, `npm --prefix web ci`), then migrates the database. It
forwards ports 8000 (MCP server), 8080 (Controller server), 4200 (Angular dev server), 8001 (docs) and
5432 (PostgreSQL, development credentials `secreview` / `secreview`).

```bash
psql -h db -U secreview secreview                     # password: secreview
SECREVIEW_DATABASE_URL=sqlite:///./dev.db security-review-mcp serve   # back to SQLite for once
```

The Docker daemon lets you build and run the image of the [Dockerfile](../advanced/deployment/docker.md)
without leaving the container.

## Building the image

```bash
docker build -t security-review-mcp .   # SQLite and PostgreSQL (driver included)
```

The build also compiles the [web interface](../usage/index.md) (Node.js stage); the
Controller server serves it on `/ui/`.

The image runs as a non-root user (uid `10001`), without sources nor build tools. The SQLite
database is in the `/var/lib/secreview` volume. Its `HEALTHCHECK`
(`python -m security_review_mcp.healthcheck`, every 30 seconds) requests `/healthz` of the HTTP
MCP server or of the Controller server on the loopback interface, over HTTPS when TLS is enabled
(trusting only the certificate of the container); in stdio, nothing listens and the container
stays healthy, and with mutual TLS (`SECREVIEW_TLS_CLIENT_CA`) it is not requested: rely on the
probes of the orchestrator. The `.env` file is **not** copied into the image: pass the
configuration with `-e` or `--env-file`.

## Definition of done

A contribution, human or produced by an AI agent, is only done if the behavior it adds or fixes
is checked by a relevant test, new or existing, the `docs/` documentation is up to date in both languages and the `README.md` files, which stay summaries,
are too. When the `security-review` MCP server is up, the changes are also reviewed with it
(the project reviews itself) and the report is saved. The detailed rules (conventions, security
invariants, mapping from code to doc pages) are in `AGENTS.md` at the root of the repository;
`CLAUDE.md` and `.github/copilot-instructions.md` point to it.

The test method is in [Tests](tests.md); the checks to run and the review procedure are in
[Checks, reviews and releases](checks-and-releases.md).

## Code layout

```
src/security_review_mcp/
├── server.py      # prompts, tools, resources, entry point of the MCP server
├── prompts.py     # construction of the prompts
├── standards.py   # development standards: storage, lookup by technology / file, rendering
├── controller.py  # entry point of the Controller server (serve, db and administration commands)
├── ci_client.py   # `security-review-ci`: pipeline client of the Controller server, file listing (standard library only)
├── cli.py         # Controller server commands: db, advisories, rules, token, user, role, project, audit
├── http_server.py # HTTP of both processes: Bearer tokens and roles, TLS, /healthz, uvicorn
├── healthcheck.py # HEALTHCHECK of the Docker image (/healthz of the HTTP processes)
├── config.py      # settings (SECREVIEW_*)
├── app_settings.py # settings changed in the interface (language, outgoing proxy, OIDC), in the database
├── proxy.py       # outgoing proxy of the Controller server (OSV, OIDC): URL, no_proxy, urllib handler
├── update_check.py # search for a newer release on GitHub (About page, optional)
├── storage/       # persistence
│   ├── database.py        # engine, sessions and migrations (Alembic)
│   ├── models.py          # SQLModel models (tables + schemas)
│   ├── migrations/        # Alembic environment and schema revisions (versions/)
│   ├── retention.py       # daily purge of the reports without findings and of the old audit events
│   └── project_names.py   # normalization of the project names (every input)
├── reports/       # security reports
│   ├── services.py        # persistence logic of the reports
│   ├── coverage.py        # checks the checklist results and scan rules declared with a report
│   ├── sarif.py           # SARIF 2.1.0 export
│   └── trends.py          # trend report
├── rules/         # scan rules and checklists
│   ├── scanner.py         # scan engine, inline suppression, secret masking
│   ├── syntax_analysis.py # Tree-sitter structural checks, separate from line-based rules
│   ├── codescan.py        # whole codebase scan of the files sent by security-review-ci (findings)
│   ├── default_rules.toml # default rules and checklists, copied into the database at first start
│   ├── rules_loader.py    # rule validation, reading of the TOML packs and of the default file
│   ├── rule_store.py      # rules in the database: seeding, import/export, enabling, deletion
│   ├── registry.py        # active rules/checklists (read from the database), reload
│   └── checklists.py      # structure of a checklist item
├── deps/          # dependency analysis
│   ├── dependencies.py    # manifest / lockfile parsers, hygiene
│   ├── depscan.py         # dependency scan and conversion into findings
│   ├── advisories.py      # OSV import, version matching
│   ├── advisory_sync.py   # OSV download by the Controller server (proxy, daily update, history)
│   └── versions.py        # version comparison
├── auth/          # identity and access
│   ├── access_control.py  # permissions, roles of the web accounts, OIDC mappings, project requests
│   ├── token_store.py     # Bearer tokens in the database: creation, expiry, rotation, revocation
│   ├── web_users.py       # web interface accounts, local (scrypt) or OIDC (created on the fly), sessions, initial admin
│   ├── oidc.py            # OpenID Connect OIDC login to the web interface (Controller server)
│   └── rate_limit.py      # rate limits of the REST API and of the logins (sliding window in the database)
├── observability/ # audit log and metrics
│   ├── audit.py           # audit log: events of triage decisions, proposals, tokens and project requests
│   ├── audit_syslog.py    # forwarding of the audit events to syslog by the Controller server (optional)
│   └── metrics.py         # Prometheus metrics of the Controller server (/metrics)
├── clients/       # clients of the Controller server
│   └── ci_wheel.py        # wheel of security-review-ci built and served by the Controller server (/api/ci-client/)
├── connectors/    # findings sent to external systems: api (connector API), registry,
│                  # connections, transport (HTTP client), core (sending), jira, servicenow
└── web_api/       # Controller server: REST API /api/v1 and files of the application (/ui)
    ├── __init__.py    # create_app, static files of /ui, assembly of the routers
    ├── schemas.py     # request and response models of every route
    ├── deps.py        # identity of the caller, permissions, project scope
    └── *_routes.py    # one router per domain (auth, account, report, ci, rule, token, admin, access)
tests/             # pytest (scanner, services, end-to-end MCP client)
web/               # Angular application (built into src/security_review_mcp/webui/)
```

The MCP server never imports the modules of the Controller server that open outgoing connections or
serve its routes (`controller`, `deps/advisory_sync`, `auth/oidc`,
`observability/audit_syslog`, `connectors`, `update_check`, `web_api`), not even indirectly:
`tests/test_server.py` checks it. A module shared by both processes (such as
`app_settings`) imports them inside the function that needs them, never at the top.

## Development by component

Each part of the project has its own page, with its conventions, its invariants and the way to
test it:

| Page | Code | Content |
|---|---|---|
| [MCP server](mcp-server.md) | `server.py`, `prompts.py`, `rules/` | Tools, prompts and resources, scan rules, security invariants of the MCP process |
| [Controller server (FastAPI)](controller.md) | `web_api/`, `cli.py`, `storage/` | REST routes and their schemas, permissions, settings, CLI, schema migrations |
| [Web interface (Angular)](web-ui.md) | `web/` | Build and dev server, code conventions, translations |
| [Writing a connector](connectors.md) | `connectors/api.py`, `examples/connector/` | Third-party connector: `Connector` class, entry point, guarantees of the Controller server |
| [Documentation](documentation.md) | `docs/`, `mkdocs.yml`, `README.md` | Writing and building the bilingual documentation, README, publication |
| [Tests](tests.md) | `tests/`, `tests/conftest.py` | What to test, conventions, fixtures, tests by kind of code |
| [Checks, reviews and releases](checks-and-releases.md) | `.pre-commit-config.yaml`, `.github/workflows/` | Linters, formatters, tests, security review, branches, releases |

The generic standards of each technology (Python and FastAPI, Angular, tests) are served by the
project itself: prompt `development-standards`, tool `get_development_standards` (see
[development standards](../review/standards.md)). These pages only hold what is specific to
this repository; when they conflict, they prevail.
