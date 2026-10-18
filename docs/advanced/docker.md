# Docker

## Published images

Each version is published for `linux/amd64` and `linux/arm64` on GitHub Container Registry and
Docker Hub, in two variants: SQLite only, and `-pg` with the PostgreSQL driver.

```bash
docker pull ghcr.io/cyr-ius/security-review-mcp:latest-pg   # or docker.io/cyrius44/security-review-mcp
```

| Tag | Content |
|---|---|
| `X.Y.Z`, `X.Y`, `X`, `latest` | Version `X.Y.Z` (the last stable version for `latest`) |
| `X.Y.Z-pg`, `X.Y-pg`, `X-pg`, `latest-pg` | Same, with the PostgreSQL driver |
| `X.Y.ZrcN` (`a`, `b`, `rc`) | Pre-release: only this tag, never `latest` |

Pin a version (`1.2.3-pg`) in production. The images carry an SBOM and a provenance
attestation (`docker buildx imagetools inspect --format '{{ json .Provenance }}' IMAGE`). In
the examples of this page, replace `security-review-mcp` and `security-review-mcp:pg` with the
published image, or build it.

## Building the image

```bash
docker build -t security-review-mcp .
docker build -t security-review-mcp:pg --build-arg EXTRAS=postgres .   # PostgreSQL driver
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

## Shared server (HTTP)

A single image, two containers sharing the database (see
[Architecture and deployment](architecture.md)):

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
account is created with a random password that nobody knows and that is never logged; only its
digest is kept, in the database. Set it with
`docker exec secreview-controller security-review-controller user reset-password admin`
(printed once), log in to the interface (`/ui/`) with the `admin` user name, then choose your
own password in **My account**. Then create
one account per person in the **Users** screen (see the
[user accounts](../usage/web-interface.md#user-accounts)).

The project tokens created from the **Tokens** screen are also stored as digests in the
database, like every token (see [Bearer tokens](http.md#bearer-tokens)).

!!! warning "The CLI is the only way to the initial password"
    No variable sets it and the logs never show it: run `user reset-password admin` in the
    container, and handle what it prints as a secret. If you lose it, run the command again (the
    old one is invalidated at once).

## Docker Compose with PostgreSQL

The `docker-compose.yml` file at the root of the repository starts both processes with a
PostgreSQL database:

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
docker compose up -d --build
docker compose exec controller security-review-controller user reset-password admin   # initial admin password
```

| Service | Role | Listens on |
|---|---|---|
| `db` | PostgreSQL, only reachable on the internal `backend` network | — |
| `migrate` | `security-review-controller db upgrade`, then stops | — |
| `controller` | REST API and web interface (`/ui/`) | `127.0.0.1:8080` (`DOCKER_PUBLISH_ADDRESS`, `DOCKER_CONTROLLER_PORT`) |
| `mcp` | MCP server (`/mcp`) and public enrollment | `127.0.0.1:8000` (`DOCKER_PUBLISH_ADDRESS`, `DOCKER_MCP_PORT`) |

- The image is built with the `postgres` extra (`security-review-mcp:pg`). `migrate` waits
  for the database to be ready (`pg_isready`); `controller` and `mcp` wait for `migrate` to
  succeed. Only `migrate` changes the schema (`SECREVIEW_DB_AUTO_UPGRADE=false` elsewhere).
- `POSTGRES_PASSWORD` is required and read from `.env` (never committed). It is inserted as
  is in `SECREVIEW_DATABASE_URL`: use hexadecimal characters, or encode the special characters
  (`@`, `:`, `/`...).
- The ports are only published on `127.0.0.1` by default. To expose them, enable the
  [built-in TLS](http.md) or put them behind a reverse proxy, then give the host address to use
  in `.env`: `DOCKER_PUBLISH_ADDRESS=192.168.1.10` (one interface) or `DOCKER_PUBLISH_ADDRESS=0.0.0.0`
  (every interface). This variable is only used by Compose. The controller exposes no write
  route without a token: it can stay internal.
- The variables of `.env` are only used by Compose: add them under `environment` so that they
  reach the containers (for example `SECREVIEW_TLS_CERTFILE` and `SECREVIEW_TLS_KEYFILE`, with
  the certificate files mounted read-only, see [Certificate authority](http.md#certificate-authority)).
- The vulnerability advisory database is **empty** at first start: the dependency analysis then
  answers that no database is loaded. To let the controller download it at start-up, then every
  24 h, add `SECREVIEW_OSV_AUTO_UPDATE=true` to `.env` (and, if needed,
  `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY` and `NO_PROXY`), which the Compose
  file passes to the controller only, then `docker compose up -d`. Follow the import with
  `docker compose logs -f controller` or in the settings of the web interface. Without
  Internet access, import an archive with `advisories import` (see
  [Dependencies](dependencies.md)).
- The containers run with a read-only file system, without any Linux capability. The
  `secreview-pg` volume holds the reports, the web interface accounts and the tokens: back it
  up.
- The `db` service uses PostgreSQL 18, whose image stores the data in a major-version
  directory: the `secreview-pg` volume is mounted on `/var/lib/postgresql` (not
  `/var/lib/postgresql/data`). A volume created by PostgreSQL 17 does not start with this image
  (`Error: in 18+, these Docker images are configured to store database data in a format...`):
  see [Upgrading PostgreSQL](#upgrading-postgresql).

To add TLS or internal rules, complete `environment` and `volumes` of the service concerned.
CLI commands run in the controller container:

```bash
docker compose exec controller security-review-controller token list
```

## Upgrading PostgreSQL

A PostgreSQL major version does not read the data files of the previous one. To move a
`secreview-pg` volume from PostgreSQL 17 to 18, dump the database with the old image, recreate
the volume and restore the dump:

```bash
# 1. With the previous Compose file (postgres:17-alpine, mount on /var/lib/postgresql/data)
docker compose stop mcp controller
(umask 077 && docker compose exec -T db pg_dump -U secreview -d secreview -Fc > ~/secreview.dump)
docker compose down

# 2. Check the dump (it lists the tables), then recreate the volume: the dump is the only copy
#    of the data from now on
docker compose run --rm -T --no-deps --entrypoint pg_restore db --list < ~/secreview.dump | grep 'TABLE DATA'
docker volume rm security-review-mcp_secreview-pg

# 3. With the current Compose file (postgres:18-alpine, mount on /var/lib/postgresql)
docker compose up -d db
docker compose exec -T db pg_restore -U secreview -d secreview --clean --if-exists --no-owner < ~/secreview.dump
docker compose up -d
```

The `migrate` service then applies the pending Alembic revisions, if any. The dump holds the
reports, the password hashes and the token fingerprints: keep it out of the repository (readable
by you only, `umask 077`) and delete it once the restore is checked.

## Developer workstation (stdio)

The host starts the container. `.mcp.json` at the root of the repository (VS Code, GitHub
Copilot and Claude):

```json
{
  "mcpServers": {
    "security-review": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "--rm", "-v", "secreview-data:/var/lib/secreview", "security-review-mcp"]
    }
  }
}
```

!!! warning "`-i` but not `-t`"
    `-i` is essential (the protocol goes through stdin); do not add `-t`.

## Internal rules and CLI

[Internal rules](rules.md) are stored in the database: import a folder of TOML packs
with the controller CLI (the running servers apply them within a few seconds):

```bash
docker run --rm -v secreview-data:/var/lib/secreview -v ./rules.d:/rules:ro \
    --entrypoint security-review-controller security-review-mcp rules import /rules
```

The other commands work the same way:

```bash
docker run --rm -v secreview-data:/var/lib/secreview \
    --entrypoint security-review-controller security-review-mcp token list
```
