# Architecture and deployment

In shared mode, the server is made of **two independent processes** sharing the same database. They can
run in two containers, two pods or on two machines.

```text
 agents, CI ──▶ ┌──────────────────────┐            ┌──────────────────────────┐ ◀── browser,
                │ MCP server           │            │ controller               │     admins
                │ security-review-mcp  │            │ security-review-         │
                │ /mcp, /api/v1/enroll │            │ controller serve         │
                │ /healthz             │            │ /api/v1, /ui, /healthz   │
                └──────────┬───────────┘            └────────────┬─────────────┘
                           └──────────── PostgreSQL ─────────────┘
```

| | MCP server | Controller |
|---|---|---|
| Command | `security-review-mcp serve --transport streamable-http` | `security-review-controller serve` |
| Serves | `/mcp`, public enrollment `POST /api/v1/enroll`, `/healthz` | REST API `/api/v1`, interface `/ui`, `/healthz` |
| Accepted credentials | `mcp` and `admin` tokens | web sessions (users), `admin` and `api` tokens; `ci` tokens on the pipeline routes `/api/v1/ci/` only (gate, SARIF, trend, scans) |
| Routes without a token | enrollment, `/healthz` | `/ui` files, API documentation, `/healthz` (read only) |
| Database schema | only checks it | migrates it (unless `SECREVIEW_DB_AUTO_UPGRADE=false`) |
| Advised exposure | agents and CI, with TLS | internal network or access restricted to administrators |

The two processes never call each other: everything goes through the database. A token created
or revoked on the controller applies to the next request of the MCP server. A changed rule is
reloaded within a few seconds. A project requested on the MCP server waits in the **Projects**
screen of the controller, for an approval.

The enrollment is served by the MCP server because the client only knows its URL. The
controller thus exposes **no unauthenticated write route**.

!!! note "Shared database"
    With SQLite, both processes must run on the same machine and share the file. As soon as
    they are in different pods or on different machines, use PostgreSQL (`postgres` extra
    of the PyPI package, included in the image), deployed with
    [Docker Compose](docker.md#docker-compose-with-postgresql) or [Kubernetes](kubernetes.md#deployment).

With stdio (developer workstation), only `security-review-mcp` is needed: it creates and
migrates its local database itself.

## Schema migrations

The schema is managed by [Alembic](https://alembic.sqlalchemy.org/) migrations, embedded in the
package (no `alembic.ini` file to provide):

```bash
security-review-controller db upgrade   # creates or migrates the schema, then seeds the default rules
security-review-controller db status    # {"current": "0001", "head": "0001", "up_to_date": true}
```

- `db status` returns code `1` if the schema is not up to date: handy for a script or a probe.
- The **HTTP MCP server never migrates**: it refuses to start (code `2`, message
  `run security-review-controller db upgrade first`) while the database is not at the expected
  revision. Under Kubernetes, the pod restarts until the migration is done.
- The controller, the stdio MCP server and the CLI commands migrate at start-up, unless
  `SECREVIEW_DB_AUTO_UPGRADE=false`. They then only check the schema. With Docker Compose, the
  controller migrates when it starts; under Kubernetes, its init container does.
- On PostgreSQL, a migration takes an advisory lock: instances that start together (several
  replicas, a `db upgrade` run by hand) wait for each other, and the next one finds the schema
  up to date. Disable the automatic migration only to keep it in a dedicated task.
