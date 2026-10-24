# Docker

## Published Images

Each version is published for `linux/amd64` and `linux/arm64` on the GitHub Container Registry and
Docker Hub, in two variants: SQLite-only, and a `-pg` version that includes the PostgreSQL driver.

```bash
docker pull ghcr.io/cyr-ius/security-review-mcp:latest-pg   # or docker.io/cyrius44/security-review-mcp
```

| Tag | Content |
|---|---|
| `X.Y.Z`, `X.Y`, `X`, `latest` | Version `X.Y.Z` (the latest stable version for `latest`) |
| `X.Y.Z-pg`, `X.Y-pg`, `X-pg`, `latest-pg` | Same as above, with the PostgreSQL driver |
| `X.Y.ZrcN` (`a`, `b`, `rc`) | Pre-release: applies only to this specific tag; never used for `latest` |

The images include an SBOM and a provenance attestation (accessible via `docker buildx imagetools inspect --format '{{ json .Provenance }}' IMAGE`).
In the examples on this page, replace `security-review-mcp` and `security-review-mcp:pg` with
the actual published image name.

## Docker Compose with PostgreSQL

The `docker-compose.yml` file in the repository root starts both processes along with a
PostgreSQL database:

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
docker compose up -d --build
docker compose exec controller security-review-controller user reset-password admin   # initial admin password
```

| Service | Role | Listens on |
|---|---|---|
| `db` | PostgreSQL; accessible only via the internal `backend` network | — |
| `migrate` | Runs `security-review-controller db upgrade`, then exits | — |
| `controller` | REST API and web interface (`/ui/`) | `127.0.0.1:8080` (`DOCKER_PUBLISH_ADDRESS`, `DOCKER_CONTROLLER_PORT`) |
| `mcp` | MCP server (`/mcp`) and public enrollment | `127.0.0.1:8000` (`DOCKER_PUBLISH_ADDRESS`, `DOCKER_MCP_PORT`) |

- The image is built with the `postgres` extra (`security-review-mcp:pg`). `migrate` waits
  for the database to be ready (`pg_isready`); `controller` and `mcp` wait for `migrate` to
  complete successfully. Only `migrate` modifies the schema (`SECREVIEW_DB_AUTO_UPGRADE=false` elsewhere).
- `POSTGRES_PASSWORD` is mandatory and is read from `.env` (which should never be committed).   It is inserted
  as-is into `SECREVIEW_DATABASE_URL`: use hexadecimal characters or encode any
  special characters (e.g., `@`, `:`, `/`, etc.).
- By default, ports are published only on `127.0.0.1`. To expose them, enable the
  [built-in TLS](http.md) or place them behind a reverse proxy, then specify the host
  address to be used in `.env`: `DOCKER_PUBLISH_ADDRESS=192.168.1.10` (for a specific interface)
  or `DOCKER_PUBLISH_ADDRESS=0.0.0.0` (for all interfaces). Additionally, set the host ports
  using `DOCKER_MCP_PORT` and `DOCKER_CONTROLLER_PORT`. These variables are only used by Compose: within the containers, both servers listen on port 8000. The controller does not expose any write routes without a token, so it can remain internal.
- Variables in `.env` are only for Compose; add them under `environment` so they are passed to
   the containers (for example, `SECREVIEW_TLS_CERTFILE` and `SECREVIEW_TLS_KEYFILE`, with the certificate files mounted as read-only—see [Certificate Authority](http.md#autorite-de-certification)).
- The vulnerability advisory database is **empty** upon initial startup; consequently,
  dependency analysis will indicate that no database is loaded. To have the controller download the database at startup—and subsequently every 24 hours—add `SECREVIEW_OSV_AUTO_UPDATE=true` to your `.env` file (along with `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY`, and `NO_PROXY` if needed). The Compose file will pass these to the controller; then, run `docker compose up -d`. You can monitor the import process using `docker compose logs -f controller` or via the web interface settings. If there is no Internet access, you can import an archive using the `advisories import` command (see [Dependencies](dependencies.md)).
- The containers run with a read-only file system and no Linux capabilities. The
  `secreview-pg` volume contains reports, web interface accounts, and tokens—be sure to back it up.
- The `db` service uses PostgreSQL 18. The corresponding image organizes data into a directory
  based on the major version; therefore, the `secreview-pg` volume is mounted at `/var/lib/postgresql` (rather than `/var/lib/postgresql/data`). A volume created by PostgreSQL 17 will not work with this image
  (`Error: in 18+, these Docker images are configured to store database data in a format...`) :
  see [Upgrading PostgreSQL](#upgrading-postgresql).

To add TLS or internal rules, update the `environment` and `volumes` sections for the
relevant service. CLI commands are executed within the controller container:

```bash
docker compose exec controller security-review-controller token list
```

## Upgrading PostgreSQL

A major version of PostgreSQL cannot read data files created by a previous version. To
upgrade a `secreview-pg` volume from PostgreSQL 17 to 18, export the database using the
old image, recreate the volume, and then restore the export:

```bash
# 1. Using the previous Compose file (postgres:17-alpine, mounted at /var/lib/postgresql/data)
docker compose stop mcp controller
(umask 077 && docker compose exec -T db pg_dump -U secreview -d secreview -Fc > ~/secreview.dump)
docker compose down

# 2. Verify the export (it should list the tables), then recreate the volume: the export
#    is now the only copy of your data
docker compose run --rm -T --no-deps --entrypoint pg_restore db --list < ~/secreview.dump | grep 'TABLE DATA'
docker volume rm security-review-mcp_secreview-pg

# 3. Using the current Compose file (postgres:18-alpine, mounted at /var/lib/postgresql)
docker compose up -d db
docker compose exec -T db pg_restore -U secreview -d secreview --clean --if-exists --no-owner < ~/secreview.dump
docker compose up -d
```

The `migrate` service then applies any pending Alembic revisions. The export
contains reports, password hashes, and tokens; keep it outside the repository
(ensuring it is readable only by you, using `umask 077`) and delete it once the
restoration has been verified.

## Internal Rules and CLI

[Rules](../usage/rules.md) are stored in the database; you can import a
directory of TOML packs using the controller CLI (running servers will
apply them within seconds):

```bash
docker run --rm -v secreview-data:/var/lib/secreview -v ./rules.d:/rules:ro \
--entrypoint security-review-controller security-review-mcp rules import /rules
```

Other commands can be executed in the same way:

```bash
docker run --rm -v secreview-data:/var/lib/secreview \
--entrypoint security-review-controller security-review-mcp token list
```
