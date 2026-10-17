# Deploying the server

This page sets up a **shared server** for a team: the controller (web interface,
administration) and the MCP server (used by the agents and the CI), on the same database. See
[two services, two roles](../index.md#two-services-two-roles).

At the end, you have:

- a web interface where people read and triage the reports;
- an `/mcp` endpoint, protected by tokens, that the hosts of the developers connect to;
- an `admin` account to manage the users, the tokens and the rules.

Two ways: [with the command line](#with-the-command-line) (one machine) or
[with Docker Compose](#with-docker-compose) (containers and PostgreSQL).

## With the command line

### 1. Choose the database

Both processes must use the **same database**: give them the same `SECREVIEW_DATABASE_URL`
(see [Configuration](../reference/configuration.md#database)).

- **SQLite** (default): only when both processes run on the same machine. Give an absolute
  path so that they open the same file whatever the directory they start from.
- **PostgreSQL**: as soon as they run on different machines or containers (`postgres` extra).

```bash
export SECREVIEW_DATABASE_URL=sqlite:////var/lib/secreview/security_reports.db
# or: postgresql+psycopg2://secreview:<password>@db.example.internal:5432/secreview
```

### 2. Prepare the database and the first administrator

```bash
security-review-controller db upgrade                       # creates or migrates the schema
security-review-controller user create admin --role admin   # password shown once
```

Keep the password: it opens the web interface. Change it later from **My account**.

### 3. Start the controller

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# web interface: http://127.0.0.1:8080/ui/
```

Log in with the `admin` account. The controller is meant for people: keep it on localhost or
an internal network (see [Architecture and deployment](../advanced/architecture.md)).

### 4. Start the MCP server

On the machine alone (test):

```bash
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
# MCP endpoint: http://127.0.0.1:8000/mcp
```

For the developers and the CI, expose it **with TLS**, with a certificate trusted by their
workstations (see [TLS](../advanced/http.md#tls)):

```bash
security-review-mcp --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# MCP endpoint: https://secreview.example.internal:8443/mcp
```

The MCP server refuses to start while the schema is not migrated (step 2).

### 5. Give access to the agents

The MCP server requires a token **as soon as one token exists** in the database. Create the
first one now:

```bash
security-review-controller token create --label alice   # mcp token, shown once
```

!!! warning "While no token exists, `/mcp` is open"
    Anyone who reaches the endpoint can then use it. Create a token before exposing the server.

Then, two ways to give a token to each developer and pipeline:

- **Enrollment** (enabled by default): the developer connects their host without a token, the
  agent requests one at the first review, and an administrator approves it in the **Tokens**
  screen. Nothing to prepare: see [Getting a token](host.md#getting-a-token-enrollment).
- **Created by the administrator**: `security-review-controller token create --label <name>`,
  for example for a pipeline, then handed to its owner.

### 6. Check

```bash
curl http://127.0.0.1:8080/healthz   # controller: {"status":"ok"}
curl http://127.0.0.1:8000/healthz   # MCP server: {"status":"ok"}
```

## With Docker Compose

The `docker-compose.yml` file of the repository runs steps 1 to 4 with PostgreSQL: database,
migration, controller and MCP server. The `admin` account is created at the first start, with
its password in the logs:

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
docker compose up -d --build
docker compose logs controller                     # initial admin password
docker compose exec controller security-review-controller token create --label alice
```

The web interface answers on `http://127.0.0.1:8080/ui/`, the MCP endpoint on
`http://127.0.0.1:8000/mcp`. Both ports are only published on `127.0.0.1`: to open them to the
team, add TLS and set `PUBLISH_ADDRESS` (see
[Docker Compose with PostgreSQL](../advanced/docker.md#docker-compose-with-postgresql)).

## Next step

[Connect the host](host.md) of each developer to the MCP server. To go further:
[tokens, enrollment and TLS](../advanced/http.md), [Kubernetes](../advanced/architecture.md#kubernetes),
[SSO login](../advanced/sso.md).
