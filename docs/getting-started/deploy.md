# Deploying the server

This page sets up a **shared server** for a team: the controller (web interface,
administration) and the MCP server (used by the agents and the CI), on the same database. See
[two services, two roles](../index.md#two-services-two-roles).

At the end, you have:

- a web interface where people read and triage the reports;
- an `/mcp` endpoint, protected by tokens, that the hosts of the developers connect to;
- an `admin` account to manage the users, the tokens and the rules.

Three ways: [with the command line](#with-the-command-line) (one machine),
[with Docker Compose](#with-docker-compose) (containers and PostgreSQL) or
[with Kubernetes](#with-kubernetes) (cluster and existing PostgreSQL).

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
security-review-controller user create admin --group administrators   # password shown once
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
security-review-mcp serve --transport streamable-http --host 127.0.0.1 --port 8000
# MCP endpoint: http://127.0.0.1:8000/mcp
```

For the developers and the CI, expose it **with TLS**, with a certificate trusted by their
workstations (see [TLS](../advanced/http.md#tls)):

```bash
security-review-mcp serve --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# MCP endpoint: https://secreview.example.internal:8443/mcp
```

The MCP server refuses to start while the schema is not migrated (step 2).

### 5. Give access to the agents

The MCP server requires a token, even while none exists in the database (it then only accepts
enrollments). Create the first one now:

```bash
security-review-controller token create --label alice   # mcp token, shown once
```

!!! note "Open server on localhost"
    A server listening on localhost, without any token, accepts every request. Elsewhere, only
    `SECREVIEW_ALLOW_UNAUTHENTICATED=true` opens it (see
    [Bearer tokens](../advanced/http.md#bearer-tokens)).

Then, two ways to give a token to each developer and pipeline:

- **Personal token** (with the enrollment, enabled by default): the developer connects their
  host without a token, the agent requests the project at the first review and sends them to
  the web interface, where they create a personal MCP token; an administrator approves the
  project (**Projects** screen) and adds them to its group. Set `SECREVIEW_WEB_URL` so that the agent gives the link: see
  [Getting a token](host.md#getting-a-token).
- **Created by the administrator**: `security-review-controller token create --label <name>`,
  for example for a pipeline, then handed to its owner.

### 6. Check

```bash
curl http://127.0.0.1:8080/healthz   # controller: {"status":"ok"}
curl http://127.0.0.1:8000/healthz   # MCP server: {"status":"ok"}
```

### 7. Connectez vous

Log in to the interface

http://127.0.0.1:8080/ui/

### 8. Docker

The same operations, performed within Docker containers

A single image, with two containers sharing the same base (see [Architecture and Deployment](architecture.md)):

- the **MCP server**, the default entry point for the image (`security-review-mcp`, with a default command of `serve` using `stdio`; add `--transport streamable-http` for HTTP);
- the **controller** (REST API, web interface, administration), launched using
`--entrypoint security-review-controller`. With [built-in authentication and TLS](http.md) (or behind a reverse proxy that handles these)


```bash
DB=postgresql+psycopg2://user:pass@db:5432/secreview

# 1. Schema (Alembic): must be run again after every image update
docker run --rm -e SECREVIEW_DATABASE_URL=$DB \
--entrypoint security-review-controller security-review-mcp:pg db upgrade

# 2. Controller: web interface and API, preferably on an internal network
docker run -d --name secreview-controller -p 127.0.0.1:8080:8000 \
-e SECREVIEW_DATABASE_URL=$DB -e SECREVIEW_DB_AUTO_UPGRADE=false \
--entrypoint security-review-controller \
security-review-mcp:pg serve --host 0.0.0.0 --port 8000

# 3. MCP Server: exposed to agents and CI
docker run -d --name secreview-mcp -p 8443:8443 \
-e SECREVIEW_DATABASE_URL=$DB \
-v ./tls:/etc/secreview/tls:ro \
-e SECREVIEW_TLS_CERTFILE=/etc/secreview/tls/cert.pem \
-e SECREVIEW_TLS_KEYFILE=/etc/secreview/tls/key.pem \
security-review-mcp:pg serve --transport streamable-http --host 0.0.0.0 --port 8443
```

Mounted files must be readable by the container user (UID `10001`). The
MCP server will refuse to start until the schema has been migrated—which happens upon the
first startup of the controller. Set the password for the `admin` account using the following command:
`docker exec secreview-controller security-review-controller user reset-password admin`

Log in to the interface (`/ui/`) using the `admin` username, then set your own password under **My Account**.
Next, create an individual account for each person via the **Users** screen
(see [User Accounts](../usage/web-interface.md#comptes-utilisateurs)).

!!! warning "The CLI is the only way to obtain the initial password"
    It is not defined by any variable, nor does it ever appear in the logs: run
    `user reset-password admin` inside the container, and treat the output as a secret.
    If you lose it, simply run the command again (the previous password will be invalidated immediately).

## With Docker Compose

The `docker-compose.yml` file of the repository runs steps 1 to 4 with PostgreSQL: database,
migration, controller and MCP server. The `admin` account is created at the first start; set
its password with the CLI, which prints it once:

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
docker compose up -d --build
docker compose exec controller security-review-controller user reset-password admin   # initial admin password
docker compose exec controller security-review-controller token create --label alice
```

The web interface answers on `http://127.0.0.1:8080/ui/`, the MCP endpoint on
`http://127.0.0.1:8000/mcp`. Both ports are only published on `127.0.0.1`: to open them to the
team, add TLS and set `DOCKER_PUBLISH_ADDRESS` (see
[Docker Compose with PostgreSQL](../advanced/docker.md#docker-compose-with-postgresql)).

## With Kubernetes

The
[`examples/kubernetes/security-review.yaml`](https://github.com/cyr-ius/security-review-mcp/blob/master/examples/kubernetes/security-review.yaml)
manifest runs steps 2 to 4 on an existing PostgreSQL database: an init container migrates the
schema, then the controller and the MCP server start in two Deployments. The `admin` account is
created at the first start; set its password with the CLI, which prints it once.

Before applying it, replace the image `registry.example.com/security-review-mcp:pg` with an
image that contains the PostgreSQL driver, for example `ghcr.io/cyr-ius/security-review-mcp:latest-pg`
(see [Installation](installation.md)). The `secreview-controller` Secret holds the signing
secret of the web sessions: without it, the controller draws a random one at every start and
the sessions end at every restart (manifest of the Secret: see
[Kubernetes](../advanced/architecture.md#kubernetes)).

```bash
kubectl create namespace secreview
kubectl -n secreview create secret generic secreview-db \
    --from-literal=SECREVIEW_DATABASE_URL='postgresql+psycopg2://secreview:<password>@<host>:5432/secreview'
kubectl -n secreview create secret generic secreview-controller \
    --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
kubectl -n secreview apply -f examples/kubernetes/security-review.yaml
kubectl -n secreview exec deploy/secreview-controller -c controller -- security-review-controller user reset-password admin   # initial admin password
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token create --label alice
```

The controller stays internal: reach the web interface with
`kubectl -n secreview port-forward svc/secreview-controller 8080:80`, then
`http://127.0.0.1:8080/ui/`. Expose the `secreview-mcp` Service to the developers and the CI
through an Ingress with TLS, and set `SECREVIEW_FORWARDED_ALLOW_IPS` to the address range of
the ingress controller pods. Content of the manifest, OSV update and several replicas: see
[Kubernetes](../advanced/architecture.md#kubernetes).

## Next step

[Connect the host](host.md) of each developer to the MCP server. To go further:
[tokens, enrollment and TLS](../advanced/http.md), [OIDC login](../advanced/sso.md).
