# Manual installation (without containers)

This page installs security-review-mcp **all-in-one** on a single Linux server, without Docker:
the **Controller server**, the **MCP server** and their **SQLite database** run on the same machine,
as the same user. It suits a test, a small team or a server where containers are not allowed.

For a team deployment, prefer [Docker Compose](../../getting-started/deploy.md#with-docker-compose)
or [Kubernetes](kubernetes.md): PostgreSQL is included, and the services restart by themselves.

```text
 agents (VS Code, Claude), CI ──▶ MCP server         :8000 ──┐
                                                             ├──▶ SQLite file
 people (browser) ──────────────▶ Controller server  :8080 ──┘
                    └─────────────────── one machine ───────────────────┘
```

## 1. Install the package

Python 3.14 or later, with [uv](https://docs.astral.sh/uv/getting-started/installation/):

```bash
uv venv /opt/security-review-mcp && source /opt/security-review-mcp/bin/activate
uv pip install security-review
```

## 2. Choose the database

Both processes must use the **same database**: give them the same `SECREVIEW_DATABASE_URL`
(see [Database](../database.md#sqlite-or-postgresql)). All-in-one, SQLite is enough:
give an absolute path so that both processes open the same file whatever the directory they
start from.

```bash
sudo install -d -o "$USER" -m 700 /var/lib/secreview
export SECREVIEW_DATABASE_URL=sqlite:////var/lib/secreview/security_reports.db
# or, with an existing PostgreSQL (uv pip install "security-review[postgres]"):
# postgresql+psycopg2://secreview:<password>@db.example.internal:5432/secreview
```

## 3. Prepare the database and the first administrator

```bash
security-review-controller db upgrade                       # creates or migrates the schema
security-review-controller user create admin --group administrators   # password shown once
```

Keep the password: it opens the web interface. Change it later from **My account**.

## 4. Start the Controller server

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# web interface: http://127.0.0.1:8080/ui/
```

Log in with the `admin` account. The Controller server is meant for people and pipelines: expose it
with TLS (see [Controller server](../architecture/controller.md#exposure)).

## 5. Start the MCP server

In another terminal, with the same `SECREVIEW_DATABASE_URL`. On the machine alone (test):

```bash
security-review-mcp serve --transport streamable-http --host 127.0.0.1 --port 8000
# MCP endpoint: http://127.0.0.1:8000/mcp
```

For the developers and the CI, expose it **with TLS**, with a certificate trusted by their
workstations (see [TLS](../tls.md)):

```bash
security-review-mcp serve --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# MCP endpoint: https://secreview.example.internal:8443/mcp
```

The MCP server refuses to start while the schema is not migrated (step 3).

## 6. Give access to the agents

The MCP server requires a token, even while none exists in the database (it then only serves the
enrollment server). Create the first one now:

```bash
security-review-controller token create --label alice   # mcp token, shown once
```

!!! note "Open server on localhost"
    A server listening on localhost, without any token, accepts every request. Elsewhere, only
    `SECREVIEW_ALLOW_UNAUTHENTICATED=true` opens it (see
    [Bearer tokens](../bearer-tokens.md)).

Then, two ways to give a token to each developer and pipeline:

- **Personal token** (with the enrollment, enabled by default): the developer connects their
  host without a token, the agent sends them to the web interface at the first review, where
  they create a personal MCP token; at the next review, the agent requests the project, which an
  administrator approves (**Projects** screen), giving them access to it. Set `SECREVIEW_PUBLIC_URL` on the Controller server (or the **General** screen) so that the agent gives the link: see
  [Getting a token](../../getting-started/host.md#getting-a-token).
- **Created by the administrator**: `security-review-controller token create --label <name>`,
  for example for a pipeline, then handed to its owner.

## 7. Check and sign in

```bash
curl http://127.0.0.1:8080/healthz   # Controller server: {"status":"ok"}
curl http://127.0.0.1:8000/healthz   # MCP server: {"status":"ok"}
```

Sign in to the web interface on `http://127.0.0.1:8080/ui/` with the `admin` account, then
create an account for each person in the **Users** screen (see
[User accounts](../../usage/user-accounts.md)).

**Next step:** [connect the host](../../getting-started/host.md) of each developer to the MCP server.
