# Docker

## Building the image

```bash
docker build -t security-review-mcp .
docker build -t security-review-mcp:pg --build-arg EXTRAS=postgres .   # PostgreSQL driver
```

The build also compiles the [web interface](../usage/web-interface.md) (Node.js stage); the
controller serves it on `/ui/`.

The image runs as a non-root user (uid `10001`), without sources nor build tools. The SQLite
database is in the `/data` volume. The `.env` file is **not** copied into the image: pass the
configuration with `-e` or `--env-file`.

## Developer workstation (stdio)

The host starts the container. `.vscode/mcp.json`:

```json
{
  "servers": {
    "security-review": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "--rm", "-v", "secreview-data:/data", "security-review-mcp"]
    }
  }
}
```

!!! warning "`-i` but not `-t`"
    `-i` is essential (the protocol goes through stdin); do not add `-t`.

For Claude (`.mcp.json`), same `command` / `args` under `mcpServers`.

## Shared server (HTTP)

A single image, two containers sharing the database (see
[Architecture and deployment](kubernetes.md)):

- the **MCP server**, default entry point of the image (`security-review-mcp`);
- the **controller** (REST API, web interface, administration), started with
  `--entrypoint security-review-controller`.

With the [built-in authentication and TLS](http.md) (or behind a reverse proxy that handles
them):

```bash
DB=postgresql+psycopg2://user:pass@db:5432/secreview

# 1. Schema (Alembic): run again after every image upgrade
docker run --rm -e SECREVIEW_DATABASE_URL=$DB \
    --entrypoint security-review-controller security-review-mcp:pg db upgrade

# 2. Controller: web interface and API, preferably on an internal network
docker run -d --name secreview-controller -p 127.0.0.1:8080:8000 \
    -e SECREVIEW_DATABASE_URL=$DB -e SECREVIEW_DB_AUTO_UPGRADE=false \
    --entrypoint security-review-controller \
    security-review-mcp:pg serve --host 0.0.0.0 --port 8000

# 3. MCP server: exposed to the agents and to the CI
docker run -d --name secreview-mcp -p 8443:8443 \
    -e SECREVIEW_DATABASE_URL=$DB \
    -v ./tls:/etc/secreview/tls:ro \
    -e SECREVIEW_TLS_CERTFILE=/etc/secreview/tls/cert.pem \
    -e SECREVIEW_TLS_KEYFILE=/etc/secreview/tls/key.pem \
    security-review-mcp:pg --transport streamable-http --host 0.0.0.0 --port 8443
```

Mounted files must be readable by the container user (uid `10001`). The MCP server refuses to
start while the schema is not migrated. At the first start of the controller, the `admin`
account is created with a random password shown only once in its logs; only its digest is
kept, in the database. Get it with `docker logs secreview-controller`, log in to the interface
(`/ui/`) with the `admin` user name, then change the password from **Mon compte** (My account). Then create
one account per person in the **Utilisateurs** (Users) screen (see the
[user accounts](../usage/web-interface.md#user-accounts)).

The project tokens created from the **Jetons** (Tokens) screen are also stored as digests in the
database, like every token (see [Bearer tokens](http.md#bearer-tokens)).

!!! warning "Protect the logs"
    The initial password is a secret: restrict access to the Docker logs and to their central
    collection. If you lose it, generate a new one (the old one is invalidated at once):
    `docker exec secreview-controller security-review-controller user reset-password admin`.

## Docker Compose with PostgreSQL

The `docker-compose.yml` file at the root of the repository starts both processes with a
PostgreSQL database:

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
docker compose up -d --build
docker compose logs controller   # initial admin password
```

| Service | Role | Listens on |
|---|---|---|
| `db` | PostgreSQL, only reachable on the internal `backend` network | — |
| `migrate` | `security-review-controller db upgrade`, then stops | — |
| `controller` | REST API and web interface (`/ui/`) | `127.0.0.1:8080` (`PUBLISH_ADDRESS`, `SECREVIEW_CONTROLLER_PORT`) |
| `mcp` | MCP server (`/mcp`) and public enrollment | `127.0.0.1:8000` (`PUBLISH_ADDRESS`, `SECREVIEW_PORT`) |

- The image is built with the `postgres` extra (`security-review-mcp:pg`). `migrate` waits
  for the database to be ready (`pg_isready`); `controller` and `mcp` wait for `migrate` to
  succeed. Only `migrate` changes the schema (`SECREVIEW_DB_AUTO_UPGRADE=false` elsewhere).
- `POSTGRES_PASSWORD` is required and read from `.env` (never committed). It is inserted as
  is in `SECREVIEW_DATABASE_URL`: use hexadecimal characters, or encode the special characters
  (`@`, `:`, `/`...).
- The ports are only published on `127.0.0.1` by default. To expose them, enable the
  [built-in TLS](http.md) or put them behind a reverse proxy, then give the host address to use
  in `.env`: `PUBLISH_ADDRESS=192.168.1.10` (one interface) or `PUBLISH_ADDRESS=0.0.0.0`
  (every interface). This variable is only used by Compose. The controller exposes no write
  route without a token: it can stay internal.
- For an HTTPS trial without a file to mount, add `SECREVIEW_TLS_SELF_SIGNED=true` and
  `SECREVIEW_TLS_SELF_SIGNED_HOSTS` (the address or the name through which the clients reach
  the Docker host) to `.env`: the Compose file passes these variables to both servers, which
  generate a [self-signed certificate](http.md#self-signed-certificate) at every start (in the
  `/tmp` `tmpfs`). The other variables of `.env` are only used by Compose: add them under
  `environment` so that they reach the containers.
- The vulnerability advisory database is **empty** at first start: the dependency analysis then
  answers that no database is loaded. To let the controller download it at start-up, then every
  24 h, add `SECREVIEW_OSV_AUTO_UPDATE=true` to `.env` (and, if needed,
  `SECREVIEW_OSV_ECOSYSTEMS`, `SECREVIEW_PROXY` and `SECREVIEW_NO_PROXY`), which the Compose
  file passes to the controller only, then `docker compose up -d`. Follow the import with
  `docker compose logs -f controller` or in the settings of the web interface. Without
  Internet access, import an archive with `advisories import` (see
  [Dependencies](../usage/dependencies.md)).
- The containers run with a read-only file system, without any Linux capability. The
  `secreview-pg` volume holds the reports, the web interface accounts and the tokens: back it
  up.

To add TLS or internal rules, complete `environment` and `volumes` of the service concerned.
CLI commands run in the controller container:

```bash
docker compose exec controller security-review-controller gate --project portal --fail-on high
```

## Internal rules and CLI

[Internal rules](../usage/rules.md) are stored in the database: import a folder of TOML packs
with the controller CLI (the running servers apply them within a few seconds):

```bash
docker run --rm -v secreview-data:/data -v ./rules.d:/rules:ro \
    --entrypoint security-review-controller security-review-mcp rules import /rules
```

The other commands work the same way:

```bash
docker run --rm -v secreview-data:/data \
    --entrypoint security-review-controller security-review-mcp gate --project portal --fail-on high
```
