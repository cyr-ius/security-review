# Installation

Python 3.14 or later. The project targets the `mcp` SDK **2.x** (`MCPServer`); with an internal
mirror limited to `mcp` 1.x, the `mcp.server.mcpserver` import will not work.

## From PyPI

```bash
pip install security-review-mcp
pip install "security-review-mcp[postgres]"   # with the PostgreSQL driver
```

## From source

```bash
git clone https://github.com/cyr-ius/security-review-mcp.git
cd security-review-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # add ".[postgres]" for PostgreSQL
cp .env.example .env
pytest && ruff check .
```

The [web interface](../usage/web-interface.md) is an Angular application to build (Node.js
22.22.3+ or 24.15+, required by Angular 22); without it, the controller only serves the REST API:

```bash
cd web && npm ci && npm run build   # writes into src/security_review_mcp/webui/
```

## Offline installation

For an environment without Internet access, prepare the wheels on a connected machine, with
**the same Python version as the target** (here 3.14):

```bash
(cd web && npm ci && npm run build)   # web interface, embedded in the wheel
python3.14 -m pip wheel --no-deps -w wheels .
python3.14 -m pip download -d wheels "mcp>=2,<3" "sqlmodel>=0.0.22" "pydantic-settings>=2.2" \
    "fastapi>=0.135" "tomlkit>=0.13" "alembic>=1.13"
# PostgreSQL only: python3.14 -m pip download -d wheels psycopg2-binary
```

Then copy the `wheels/` folder to the target machine.

!!! note "Same platform"
    The target machine must have the same OS and architecture as the connected machine.
    Otherwise, add `--platform` and `--only-binary=:all:` to `pip download`.

Then, on the target machine, targeting Python 3.14 explicitly:

```bash
python3.14 -m venv /opt/security-review-mcp/venv
/opt/security-review-mcp/venv/bin/pip install --no-index --find-links wheels security-review-mcp
```

## Running

The package installs two commands: `security-review-mcp` (MCP server) and
`security-review-controller` (web interface, REST API, database and administration). See
[Architecture and deployment](kubernetes.md).

```bash
# stdio: the host starts the process itself (developer workstation); the local SQLite
# database is created or migrated automatically
security-review-mcp

# Shared server (CI/CD): two processes on the same database
security-review-controller db upgrade                                  # schema (Alembic)
security-review-controller serve --host 127.0.0.1 --port 8080          # http://127.0.0.1:8080/ui/
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
# MCP endpoint: http://127.0.0.1:8000/mcp
```

To expose the HTTP servers beyond localhost, enable
[authentication and TLS](http.md).

## Upgrading from version 1.x

Version 2 separates the MCP server from the controller, and manages the schema with Alembic:

1. Upgrade the package or the image, then run `security-review-controller db upgrade`
   **once**. A database created by version 1.x is recognized and completed (missing columns
   and tables, multi-project tokens), without data loss.
2. Run the controller (`security-review-controller serve`) next to the MCP server: the MCP
   server no longer serves `/ui/` nor the REST API, except the public enrollment
   `/api/v1/enroll`.
3. Replace `security-review-mcp token|rules|gate|sarif|trend|advisories|deps|code` with
   `security-review-controller …` in your scripts and pipelines. The old forms still work
   during version 2, with a warning.
4. The initial administrator account (`SECREVIEW_AUTH_BOOTSTRAP_ADMIN`) is now created by the
   controller: it is the [`admin` account](../usage/web-interface.md#first-administrator) of
   the web interface, and no longer a `bootstrap-admin` token.
