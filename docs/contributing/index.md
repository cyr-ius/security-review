# Contributing

## Development environment

```bash
git clone https://github.com/cyr-ius/security-review-mcp.git
uv sync --extra dev
uv run pytest
```

Linters, formatters, hooks and security reviews: see
[Checks, reviews and releases](checks-and-releases.md).

In VS Code (`.vscode/`):

| `launch.json` configuration | Role |
|---|---|
| **MCP server + controller** | Runs the **Database upgrade** task, then both processes on the same database |
| **MCP server (HTTP, port 8000)** | MCP server only; the database must already be migrated |
| **Controller (web UI and API, port 8080)** | Controller only; migrates the database and shows the password of the initial `admin` account at first start |
| **Controller CLI (prompt for arguments)** | A controller command (`db status`, `token list`…) under the debugger |
| **Controller + web UI (Angular, port 4200)** | Controller and Angular application under the debugger, hot reload |
| **Web UI + API (Angular dev server, port 4200)** | Runs the **Web UI + API: dev servers** task (controller on 8080 and `ng serve`), waits for them to be ready, then opens Chrome on `http://localhost:4200/ui/` with the TypeScript breakpoints |
| **Pytest (current file)** | Tests of the open file |

| `tasks.json` task | Command |
|---|---|
| **Build security_review_mcp** | `uv sync --extra dev --extra docs --extra postgres` |
| **Database upgrade** | `uv run security-review-controller db upgrade` (after **Build**) |
| **Tests** / **Lint** | `pytest`, then ruff and `mkdocs build --strict` |
| **Web UI: build** / **Web UI: dev server (port 4200)** | Angular build served by the controller, or `ng serve` with `/api` forwarded to port 8080 |
| **API: controller (port 8080)** / **Web UI + API: dev servers** | Controller only outside the debugger (`security-review-controller serve`), or controller and `ng serve` in parallel |
| **Docs: serve (port 8001)** | `mkdocs serve` |
| **Docker: compose up** / **down** | `docker-compose.yml` stack of the image, with its own PostgreSQL database (same ports 8000 and 8080: stop the debug configurations first) |

### Devcontainer

The repository provides a devcontainer (`.devcontainer/`) with Python, uv, Node.js, a dedicated
Docker daemon (*docker-in-docker* feature) and a **PostgreSQL 17** database. `compose.yaml`
describes two services: `app`, the development container, and `db`, the database, reachable
from `app` under the `db` name and kept in the `secreview-dev-pg` volume between two rebuilds.
`SECREVIEW_DATABASE_URL` points to it by default: the MCP server, the controller and the CLI use
PostgreSQL. The tests always use an in-memory SQLite database, and ignore your `.env` file and
the `SECREVIEW_*` variables of the shell.

At creation, the devcontainer installs the `psql` client, the `prek` hooks and the full
environment (`uv sync --extra dev --extra docs --extra postgres`), then migrates the database. It
forwards ports 8000 (MCP server), 8080 (controller), 4200 (Angular dev server), 8001 (docs) and
5432 (PostgreSQL, development credentials `secreview` / `secreview`).

```bash
psql -h db -U secreview secreview                     # password: secreview
SECREVIEW_DATABASE_URL=sqlite:///./dev.db security-review-mcp serve   # back to SQLite for once
```

The Docker daemon lets you build and run the image of the [Dockerfile](../advanced/docker.md)
without leaving the container:

```bash
docker build -t security-review-mcp .   # SQLite and PostgreSQL (driver included)
docker run --rm -p 8080:8000 -v secreview-data:/var/lib/secreview \
    --entrypoint security-review-controller security-review-mcp serve --host 0.0.0.0
docker run --rm -p 8000:8000 -v secreview-data:/var/lib/secreview security-review-mcp \
    serve --transport streamable-http --host 0.0.0.0 --port 8000
```

The ports are forwarded to the workstation: the web interface is on `http://localhost:8080/ui/`,
the REST API on `/api/v1` and the MCP endpoint on `http://localhost:8000/mcp`. Images and
volumes are kept in volumes of the devcontainer: they do not mix with those of the host.

!!! note "Why not the Docker socket of the host?"
    Mounting `/var/run/docker.sock` would give every tool of the devcontainer, AI agents
    included, root-equivalent access to the host. The dedicated daemon requires a `privileged`
    container, but stays isolated from the daemon of the host. After adding the feature, rebuild
    the container (*Dev Containers: Rebuild Container*).

## Building the image

```bash
docker build -t security-review-mcp .   # SQLite and PostgreSQL (driver included)
docker build -t security-review-mcp --build-arg EXTRAS= .   # without the PostgreSQL driver
```

The build also compiles the [web interface](../usage/web-interface.md) (Node.js stage); the
controller serves it on `/ui/`.

The image runs as a non-root user (uid `10001`), without sources nor build tools. The SQLite
database is in the `/var/lib/secreview` volume. Its `HEALTHCHECK`
(`python -m security_review_mcp.healthcheck`, every 30 seconds) requests `/healthz` of the HTTP
MCP server or of the controller on the loopback interface, over HTTPS when TLS is enabled
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
├── controller.py  # entry point of the controller (serve, db and administration commands)
├── ci_client.py   # `security-review-ci`: pipeline client of the controller, file listing (standard library only)
├── cli.py         # controller commands: db, advisories, rules, token, user, group, project, audit
├── http_server.py # HTTP of both processes: Bearer tokens and roles, TLS, /healthz, uvicorn
├── healthcheck.py # HEALTHCHECK of the Docker image (/healthz of the HTTP processes)
├── config.py      # settings (SECREVIEW_*)
├── app_settings.py # settings changed in the interface (language, outgoing proxy, OIDC), in the database
├── proxy.py       # outgoing proxy of the controller (OSV, OIDC): URL, no_proxy, urllib handler
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
│   ├── advisory_sync.py   # OSV download by the controller (proxy, daily update, history)
│   └── versions.py        # version comparison
├── auth/          # identity and access
│   ├── access_control.py  # permissions, roles, groups and members of the web accounts, project enrollment
│   ├── token_store.py     # Bearer tokens in the database: creation, expiry, rotation, revocation
│   ├── web_users.py       # web interface accounts, local (scrypt) or OIDC (created on the fly), sessions, initial admin
│   ├── oidc.py            # OpenID Connect OIDC login to the web interface (controller)
│   ├── rate_limit.py      # rate limits of the REST API and of the logins (sliding window in the database)
│   └── enrollment_api.py  # public POST /api/v1/enroll endpoint of the MCP server
├── observability/ # audit log and metrics
│   ├── audit.py           # audit log: events of triage decisions, proposals, tokens and enrollments
│   ├── audit_syslog.py    # forwarding of the audit events to syslog by the controller (optional)
│   └── metrics.py         # Prometheus metrics of the controller (/metrics)
├── clients/       # CLI clients that contact the URL given by the operator
│   ├── commands.py        # `enroll` command of security-review-mcp
│   └── enrollment.py      # `enroll` client: project enrollment on a server in shared mode
├── connectors/    # findings sent to external systems: api (connector API), registry,
│                  # connections, transport (HTTP client), core (sending), jira, servicenow
└── web_api/       # controller: REST API /api/v1 and files of the application (/ui)
    ├── __init__.py    # create_app, static files of /ui, assembly of the routers
    ├── schemas.py     # request and response models of every route
    ├── deps.py        # identity of the caller, permissions, project scope
    └── *_routes.py    # one router per domain (auth, account, report, ci, rule, token, admin, access)
tests/             # pytest (scanner, services, end-to-end MCP client)
web/               # Angular application (built into src/security_review_mcp/webui/)
```

The MCP server never imports the modules of the controller that open outgoing connections or
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
| [Controller (FastAPI)](controller.md) | `web_api/`, `cli.py`, `storage/` | REST routes and their schemas, permissions, settings, CLI, schema migrations |
| [Web interface (Angular)](web-ui.md) | `web/` | Build and dev server, code conventions, translations |
| [Documentation](documentation.md) | `docs/`, `mkdocs.yml`, `README.md` | Writing and building the bilingual documentation, README, publication |
| [Tests](tests.md) | `tests/`, `tests/conftest.py` | What to test, conventions, fixtures, tests by kind of code |
| [Checks, reviews and releases](checks-and-releases.md) | `.pre-commit-config.yaml`, `.github/workflows/` | Linters, formatters, tests, security review, branches, releases |

The generic standards of each technology (Python and FastAPI, Angular, tests) are served by the
project itself: prompt `development-standards`, tool `get_development_standards` (see
[development standards](../usage/standards.md)). These pages only hold what is specific to
this repository; when they conflict, they prevail.
