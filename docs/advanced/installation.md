# Installation: other cases

The usual installation is in [Installation](../getting-started/installation.md). This page
covers the installation from the sources and without Internet access.

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
