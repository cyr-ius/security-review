# Architecture and deployment

A shared server is made of **two independent processes** sharing the same database. They can
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
| Command | `security-review-mcp --transport streamable-http` | `security-review-controller serve` |
| Serves | `/mcp`, public enrollment `POST /api/v1/enroll`, `/healthz` | REST API `/api/v1`, interface `/ui`, `/healthz` |
| Accepted tokens | `mcp` and `admin` roles | `reader`, `triager` and `admin` roles; `ci` on the pipeline routes `/api/v1/ci/` only |
| Routes without a token | enrollment, `/healthz` | `/ui` files, API documentation, `/healthz` (read only) |
| Database schema | only checks it | migrates it (unless `SECREVIEW_DB_AUTO_UPGRADE=false`) |
| Advised exposure | agents and CI, with TLS | internal network or access restricted to administrators |

The two processes never call each other: everything goes through the database. A token created
or revoked on the controller applies to the next request of the MCP server. A changed rule is
reloaded within a few seconds. An enrollment request filed on the MCP server shows up in the
**Tokens** screen of the controller.

The enrollment is served by the MCP server because the client only knows its URL. The
controller thus exposes **no unauthenticated write route**.

!!! note "Shared database"
    With SQLite, both processes must run on the same machine and share the file. As soon as
    they are in different pods or on different machines, use PostgreSQL (`postgres` extra,
    image built with `--build-arg EXTRAS=postgres`).

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
  `SECREVIEW_DB_AUTO_UPGRADE=false`. They then only check the schema. Disable the automatic
  migration when a dedicated task handles it (`migrate` service of Docker Compose, Kubernetes
  init container): one migration at a time.

## Docker Compose

`docker-compose.yml` starts PostgreSQL, the migration, the controller and the MCP server: see
[Docker](docker.md#docker-compose-with-postgresql).

## Kubernetes

The
[`examples/kubernetes/security-review.yaml`](https://github.com/cyr-ius/security-review-mcp/blob/master/examples/kubernetes/security-review.yaml)
example deploys both processes on an existing PostgreSQL database:

```bash
kubectl create namespace secreview
kubectl -n secreview create secret generic secreview-db \
    --from-literal=SECREVIEW_DATABASE_URL='postgresql+psycopg2://secreview:<password>@<host>:5432/secreview'
kubectl -n secreview create secret generic secreview-controller \
    --from-literal=SECREVIEW_SESSION_SECRET="$(openssl rand -hex 32)"
kubectl -n secreview apply -f examples/kubernetes/security-review.yaml
kubectl -n secreview logs deploy/secreview-controller -c controller   # initial admin password
```

It contains:

- a **`secreview-controller` Deployment** (one replica, `Recreate` strategy) whose init
  container runs `security-review-controller db upgrade` at every deployment;
- a **`secreview-mcp` Deployment**, which only checks the schema;
- the **`secreview-controller` Secret**, created by hand, with `SECREVIEW_SESSION_SECRET`: the
  root file system is read-only, so the controller cannot write its
  `SECREVIEW_SESSION_SECRET_FILE`; without it, the web sessions would end at every restart and
  would not be shared by the replicas (see
  [Login and sessions](../usage/web-interface.md#login-and-sessions));
- one Service per process, `readiness` and `liveness` probes on `/healthz`, non-root
  containers with a read-only file system, without any Linux capability;
- a **NetworkPolicy** that limits access to the controller to the pods of the namespace and to
  the ingress controller (adapt its label).

Replace the image (`registry.example.com/security-review-mcp:pg`) with yours, built with the
`postgres` extra. Expose the `secreview-mcp` Service to the agents and to the CI through an
Ingress with TLS. Keep the controller internal (`kubectl port-forward`, VPN or Ingress
restricted to administrators). Behind the Ingress, set `SECREVIEW_FORWARDED_ALLOW_IPS` (commented
in the ConfigMap) to the address range of the ingress controller pods: otherwise every client
shares their address for the login throttling and the enrollment limits. Administration commands run in its pod:

```bash
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token list --pending
```

For the [daily update of the OSV advisories](dependencies.md#automatic-update-by-the-controller),
uncomment `SECREVIEW_OSV_AUTO_UPDATE` (and if needed `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY`
and `NO_PROXY`, in the `secreview-controller` Secret if the proxy holds credentials) on the
`controller` container, and allow its egress to osv.dev or your mirror (or the proxy) if an
egress NetworkPolicy applies. The MCP server needs no egress. The Swagger documentation of the
REST API (`/api/docs`) stays disabled unless you uncomment `SECREVIEW_SWAGGER_ENABLED`.

!!! warning "Several replicas of the MCP server"
    MCP sessions (streamable HTTP transport) are kept in memory by the pod that opened them.
    Before raising `replicas`, configure the Ingress to send every request of a session to the
    same pod (affinity on the `Mcp-Session-Id` header, or failing that cookie or address
    affinity). The controller can have several replicas, provided the migration is done by a
    single task (`SECREVIEW_DB_AUTO_UPGRADE=false` on the replicas).
