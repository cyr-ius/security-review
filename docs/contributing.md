# Contributing

## Development environment

```bash
uv sync --extra dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
pre-commit install          # optional: same checks before every commit, and the dependency
                            # scan when SECREVIEW_SERVER_URL is set
```

In VS Code (`.vscode/`):

| `launch.json` configuration | Role |
|---|---|
| **MCP server + controller** | Runs the **Database upgrade** task, then both processes on the same database |
| **MCP server (HTTP, port 8000)** | MCP server only; the database must already be migrated |
| **Controller (web UI and API, port 8080)** | Controller only; migrates the database and shows the password of the initial `admin` account at first start |
| **Controller CLI (prompt for arguments)** | A controller command (`db status`, `token list --pending`…) under the debugger |
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
PostgreSQL. The tests always use an in-memory SQLite database.

At creation, the devcontainer installs the `psql` client, the `prek` hooks and the full
environment (`uv sync --extra dev --extra docs --extra postgres`), then migrates the database. It
forwards ports 8000 (MCP server), 8080 (controller), 4200 (Angular dev server), 8001 (docs) and
5432 (PostgreSQL, development credentials `secreview` / `secreview`).

```bash
psql -h db -U secreview secreview                     # password: secreview
SECREVIEW_DATABASE_URL=sqlite:///./dev.db security-review-mcp   # back to SQLite for once
```

The Docker daemon lets you build and run the image of the [Dockerfile](advanced/docker.md)
without leaving the container:

```bash
docker build -t security-review-mcp .
docker run --rm -p 8080:8000 -v secreview-data:/data \
    --entrypoint security-review-controller security-review-mcp serve --host 0.0.0.0
docker run --rm -p 8000:8000 -v secreview-data:/data security-review-mcp \
    --transport streamable-http --host 0.0.0.0 --port 8000
```

The ports are forwarded to the workstation: the web interface is on `http://localhost:8080/ui/`,
the REST API on `/api/v1` and the MCP endpoint on `http://localhost:8000/mcp`. Images and
volumes are kept in volumes of the devcontainer: they do not mix with those of the host.

!!! note "Why not the Docker socket of the host?"
    Mounting `/var/run/docker.sock` would give every tool of the devcontainer, AI agents
    included, root-equivalent access to the host. The dedicated daemon requires a `privileged`
    container, but stays isolated from the daemon of the host. After adding the feature, rebuild
    the container (*Dev Containers: Rebuild Container*).

## Definition of done

A contribution, human or produced by an AI agent, is only done if it includes tests, the `docs/`
documentation is up to date in both languages and the `README.md` files, which stay summaries,
are too. When the `security-review` MCP server is up, the changes are also reviewed with it
(the project reviews itself) and the report is saved. The detailed rules (conventions, security
invariants, mapping from code to doc pages) are in `AGENTS.md` at the root of the repository;
`CLAUDE.md` and `.github/copilot-instructions.md` point to it.

## Code layout

```
src/security_review_mcp/
├── server.py      # prompts, tools, resources, entry point of the MCP server
├── controller.py  # entry point of the controller (serve, db and administration commands)
├── http_server.py # HTTP of both processes: Bearer tokens and roles, TLS, /healthz, uvicorn
├── oidc.py        # OpenID Connect SSO login to the web interface (controller)
├── role_mapping.py # OIDC role mapping: provider groups → web role and projects
├── token_store.py # Bearer tokens in the database: creation, expiry, rotation, revocation, enrollment
├── audit.py       # audit log: events of triage decisions, proposals, tokens and enrollments
├── metrics.py     # Prometheus metrics of the controller (/metrics)
├── web_users.py   # web interface accounts, local (scrypt) or SSO (created on the fly), sessions, initial admin
├── enrollment.py  # `enroll` client: token request to a shared server
├── remote_scan.py # `scan-deps` client: dependency scan with a shared server
├── ci_client.py   # `security-review-ci`: pipeline client of the controller (standard library only)
├── enrollment_api.py  # public POST /api/v1/enroll endpoint of the MCP server
├── web_api.py     # controller: REST API /api/v1 and files of the application (/ui)
├── prompts.py     # construction of the prompts
├── standards.py   # development standards: storage, lookup by technology / file, rendering
├── default_rules.toml  # default rules and checklists, copied into the database at first start
├── checklists.py  # structure of a checklist item
├── scanner.py     # scan engine, inline suppression, secret masking
├── rules_loader.py    # rule validation, reading of the TOML packs and of the default file
├── rule_store.py  # rules in the database: seeding, import/export, enabling, deletion
├── registry.py    # active rules/checklists (read from the database), reload
├── cli.py         # db, gate, sarif, trend, advisories, deps, code, rules, token, audit, enroll, scan-deps commands
├── codescan.py    # whole codebase scan (file list, language, findings)
├── sarif.py       # SARIF 2.1.0 export
├── trends.py      # trend report
├── versions.py    # version comparison
├── advisories.py  # OSV import, version matching
├── advisory_sync.py  # OSV download by the controller (proxy, daily update, history)
├── app_settings.py    # settings changed in the interface (language, outgoing proxy, SSO), in the database
├── proxy.py       # outgoing proxy of the controller (OSV, SSO): URL, no_proxy, urllib handler
├── dependencies.py    # manifest / lockfile parsers, hygiene
├── depscan.py     # dependency scan and conversion into findings
├── services.py    # persistence logic of the reports
├── retention.py   # daily purge of the reports without findings and of the old audit events
├── models.py      # SQLModel models (tables + schemas)
├── database.py    # engine, sessions and migrations (Alembic)
├── migrations/    # Alembic environment and schema revisions (versions/)
└── config.py      # settings (SECREVIEW_*)
tests/             # pytest (scanner, services, end-to-end MCP client)
web/               # Angular application (built into src/security_review_mcp/webui/)
```

## Web interface

The Angular 22 application (signals, zoneless, Bootstrap 5) is in `web/`. Its build is written
into `src/security_review_mcp/webui/`, from where the controller serves it on `/ui/` and the
wheel embeds it.

```bash
cd web
npm ci
npm run build                 # production build (to redo before uv build)
npm start                     # dev server on http://localhost:4200/ui/
npm run format                # Prettier
```

`npm start` forwards `/api` to `http://127.0.0.1:8080` (`web/proxy.conf.json`): start the
controller in parallel with `security-review-controller serve --port 8080`, or use the VS Code
configuration **Web UI + API (Angular dev server, port 4200)**, which starts both
(**Controller + web UI (Angular, port 4200)** if you also want to debug the Python): every save
of a file of `web/src/` reloads the page (styles and templates without a full reload), and the
breakpoints set in the `.ts` files are honored. In the devcontainer, Chrome is opened on the
local workstation and port 4200 is forwarded automatically.

### Interface translations

The interface is translated into English, French and Spanish by an in-house service
(`web/src/app/core/i18n/`), without any extra dependency. Each screen has its catalog in
`core/i18n/messages/<screen>.ts`, declared in `messages/index.ts`, with its messages in the three
languages:

```ts
export const tokens = defineMessages({
  en: { 'tokens.created': 'Token “{label}” created.' },
  fr: { 'tokens.created': 'Jeton « {label} » créé.' },
  es: { 'tokens.created': 'Token «{label}» creado.' },
});
```

- In a template: `{{ 'tokens.title' | t }}`, or with parameters
  `{{ 'tokens.created' | t: { label: name } }}`.
- In the code: `I18nService.translate(...)` (confirmations, messages of the Signal Forms
  validators through `message: () => ...`). A message shown later (success, error) is kept as
  `msg(key, parameters)` and translated in the template, so that it follows a change of language.
- The title of the routes is a key, translated by `I18nTitleStrategy`.

The keys are typed: an unknown key, or a key missing in one of the three languages, fails
`npm run build`.

## Schema migrations

Every change of a table model (`models.py`) comes with an Alembic revision in
`src/security_review_mcp/migrations/versions/`. The
`test_upgrade_creates_the_schema_of_the_models` test (`tests/test_database.py`) fails as long
as the migrations do not produce exactly the schema of the models. To generate a draft
revision to review:

```bash
uv run python - <<'PY'
from alembic import command
from security_review_mcp import database
with database.get_engine().begin() as connection:
    command.revision(
        database.alembic_config(connection), "describe the change", autogenerate=True, rev_id="0002"
    )
PY
```

Run it with `SECREVIEW_DATABASE_URL` pointing to a throwaway SQLite database already up to date
(`security-review-controller db upgrade`). Number the revisions in sequence (`0002`, `0003`…),
review the generated file and never change a revision already published.

## Documentation

The documentation is written in Markdown in `docs/`, in **English and French**, and built with
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/) and the
[mkdocs-static-i18n](https://ultrabug.github.io/mkdocs-static-i18n/) plugin.

```bash
uv sync --extra docs
uv run mkdocs serve          # preview on http://127.0.0.1:8000, hot reload
uv run mkdocs build --strict # what the CI does: a broken link fails the build
```

- Every page exists twice, side by side: `page.md` in English (default language, served at the
  root of the site) and `page.fr.md` in French (served under `/fr/`). Change both in the same
  commit.
- Links between pages target the English file (`../reference/cli.md`): the plugin points them
  to the French page from a French page. Anchors follow the headings of each language
  (`#report-language` in English, `#langue-des-rapports` in French).
- The pages follow the order of a set-up: **Getting started** (`getting-started/`) and
  **Usage** (`usage/`) only hold what is needed to work; **Advanced** (`advanced/`) gathers the
  details and the optional features. Put a detailed explanation in `advanced/`, with at most a
  line and a link from the essential pages.
- To add a page, create both files in `docs/`, declare the English one in the `nav` section of
  `mkdocs.yml`, and translate its title in `nav_translations` (French language of the `i18n`
  plugin).

### Publishing

The `.github/workflows/docs.yml` workflow:

- on a **pull request** that touches `docs/` or `mkdocs.yml`: builds the site in `--strict`
  mode (check only);
- on a **push on `master`**: builds the site and publishes it on GitHub Pages.

One-time activation in the GitHub repository: **Settings → Pages → Build and deployment →
Source: GitHub Actions**.

## Branches

- **`dev`**: development branch, the default place to code.
- **`feat/<topic>`**: only for a large break (rework, API or schema change), created from `dev`
  and merged into `dev` by pull request.
- **`master`**: production branch, only fed by merges of `dev`.

## Releasing a version

A version is a tag pushed on `master`:

1. On `dev`, update `version` in `pyproject.toml` (e.g. `uv version 1.3.0`) and commit.
2. Merge `dev` into `master`.
3. On `master`, push the matching tag: `git tag v1.3.0 && git push origin v1.3.0`.
4. The push of the tag triggers `publish.yml`: lint and tests, check that the tag matches the
   version, publication on PyPI then creation of the GitHub release.
