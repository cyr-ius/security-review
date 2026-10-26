# Docker

## Published Images

Each version is published for `linux/amd64` and `linux/arm64` on the GitHub Container Registry and
Docker Hub. The same image works with SQLite and PostgreSQL: it includes the PostgreSQL driver.

```bash
docker pull ghcr.io/cyr-ius/security-review:latest   # or docker.io/cyrius44/security-review
```

| Tag | Content |
|---|---|
| `X.Y.Z`, `X.Y`, `X`, `latest` | Version `X.Y.Z` (the latest stable version for `latest`) |
| `X.Y.Z-pg`, `X.Y-pg`, `X-pg`, `latest-pg` | Deprecated: aliases of the same image, kept until the next major version (former PostgreSQL variant) |
| `X.Y.ZrcN` (`a`, `b`, `rc`) | Pre-release: applies only to this specific tag; never used for `latest` |

The images include an SBOM and a provenance attestation (accessible via `docker buildx imagetools inspect --format '{{ json .Provenance }}' IMAGE`).

## Docker Compose with PostgreSQL

One file,
[`examples/docker/docker-compose.yml`](https://github.com/cyr-ius/security-review/blob/{{ release_tag }}/examples/docker/docker-compose.yml),
starts everything with the published image: PostgreSQL, the migration of the schema, the
controller and the MCP server. The commands that download it and start it are in
[Deploying the server](../../getting-started/deploy.md#with-docker-compose).

The command `printf` writes the `.env` file, readable by you only: the password of PostgreSQL
and the secret of the web sessions, generated at random. `docker compose up -d --wait` returns
once every service is ready. The web interface answers on `http://127.0.0.1:8080/ui/`, the MCP
endpoint on `http://127.0.0.1:8000/mcp`.

Content of the files of version `{{ release_tag }}`:

=== "docker-compose.yml"

    ```yaml
    --8<-- "docker/docker-compose.yml"
    ```

=== ".env"

    ```bash
    POSTGRES_PASSWORD=<48 hexadecimal characters>
    SECREVIEW_SECRET_KEY=<64 hexadecimal characters>
    ```

| Service | Role | Listens on |
|---|---|---|
| `db` | PostgreSQL, reachable by the other services only | — |
| `controller` | Web interface (`/ui/`) and REST API, for people; creates or updates the tables at start | `8080` |
| `mcp` | MCP server (`/mcp`), for the agents | `8000` |

Good to know:

- **Order of start-up.** `controller` waits until PostgreSQL is ready, then creates or updates
  the tables; `mcp`, which only checks them, waits until `controller` is healthy. After an image
  update, `docker compose up -d` is enough: the controller applies the new migrations.
- **Keep `.env`.** It holds the password of the database and the secret of the sessions; never
  commit it. The password is inserted as is in the connection URL: keep hexadecimal characters,
  as generated above.
- **Open to the team.** The ports are published on every interface of the server, in plain
  HTTP: enable the [built-in TLS](../tls.md) or put a reverse proxy in front before the team
  connects. To keep a port on the server only (behind a reverse proxy on the same machine, for
  example), prefix it with `127.0.0.1` (`"127.0.0.1:8000:8000"`). Only the `ports` choose the exposure: inside its container, each process
  listens on every interface (`SECREVIEW_HOST=0.0.0.0`, set by the image, not to be changed).
  For the built-in TLS, uncomment in `controller` and `mcp` the TLS variables
  (`SECREVIEW_TLS_CERTFILE`, `SECREVIEW_TLS_KEYFILE`) and the `volumes` that mounts the
  certificate files read-only from `./tls` (see [Certificate Authority](../tls.md#certificate-authority)).
  The controller exposes no write route without a token: it can stay internal.
  Add to `.env` the public root URL of the controller (`SECREVIEW_CONTROLLER_URL=https://…`):
  the controller copies it to the database at start, so that the MCP server gives the link of
  the web interface (`/ui`) to an agent without a token, and the connectors link their tickets to the reports. Without it, set
  it in the **General** screen.
- **Vulnerability advisories.** The OSV database is **empty** at the first start: the dependency
  analysis answers that no database is loaded. To let the controller download it at start-up,
  then every 24 hours, uncomment `SECREVIEW_OSV_AUTO_UPDATE` (and `SECREVIEW_OSV_ECOSYSTEMS`) in
  the `controller` service, then run `docker compose up -d`. Follow the import with
  `docker compose logs -f controller`. Without Internet access, import an archive with
  `advisories import` (see [Dependencies](../../review/analysis/dependencies.md#manual-import)).
- **Hardening.** The containers of security-review-mcp run with a read-only file system and
  without any Linux capability.
- **Data.** The `secreview-pg` volume holds the reports, the accounts and the tokens: back it up
  (see [Backing up PostgreSQL](#backing-up-postgresql)). It is mounted on `/var/lib/postgresql`,
  where PostgreSQL 18 keeps its data; a volume created by PostgreSQL 17 does not start with this
  image (see [Upgrading PostgreSQL](#upgrading-postgresql)).

The administration commands run in the controller container:

```bash
docker compose exec controller security-review-controller token list
```

## Without Docker Compose

The same image runs each process in its own container, on an existing PostgreSQL database (see
[Architecture](../architecture/index.md)):

- the **MCP server** is the default entry point of the image (`security-review-mcp`, default
  command `serve`, in streamable HTTP; add `--transport stdio` for the local mode);
- the **controller** (REST API, web interface, administration) is started with
  `--entrypoint security-review-controller`, with the built-in [tokens](../bearer-tokens.md) and [TLS](../tls.md)
  or behind a reverse proxy that handles them.

```bash
DB=postgresql+psycopg2://user:pass@db:5432/secreview

# 1. Controller: web interface and API, preferably on an internal network; creates or
#    updates the schema (Alembic) at start, so start it first
docker run -d --name secreview-controller -p 127.0.0.1:8080:8000 \
    -e SECREVIEW_DATABASE_URL=$DB \
    --entrypoint security-review-controller \
    ghcr.io/cyr-ius/security-review serve

# 2. MCP server: exposed to the agents and the CI
docker run -d --name secreview-mcp -p 8443:8443 \
    -e SECREVIEW_DATABASE_URL=$DB \
    -v ./tls:/etc/secreview/tls:ro \
    -e SECREVIEW_TLS_CERTFILE=/etc/secreview/tls/cert.pem \
    -e SECREVIEW_TLS_KEYFILE=/etc/secreview/tls/key.pem \
    ghcr.io/cyr-ius/security-review serve --port 8443

# 3. Password of the admin account, created at the first start of the controller
docker exec secreview-controller security-review-controller user reset-password admin
```

In the image, both processes listen on every interface of the container (`SECREVIEW_HOST=0.0.0.0`),
port `8000` unless `--port` is given: the `-p` option chooses the address and the port of the
host (`-p 127.0.0.1:8080:8000`: this machine only). Mounted files must be readable by the user of
the container (UID `10001`). The MCP server
refuses to start while the schema is not migrated (step 1).

## Backing up PostgreSQL

The `secreview-pg` volume holds the reports, the accounts and the token digests. Export it
regularly (cron, systemd timer) and keep the files away from the server, readable by you only:

```bash
(umask 077 && docker compose exec -T db pg_dump -U secreview -d secreview -Fc > ~/secreview-$(date +%F).dump)
# Restore an export (the services are stopped during the restore)
docker compose stop mcp controller
docker compose exec -T db pg_restore -U secreview -d secreview --clean --if-exists --no-owner < ~/secreview-2026-10-25.dump
docker compose start controller mcp
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

The controller then applies any pending Alembic revisions at start. The export
contains reports, password hashes, and tokens; keep it outside the repository
(ensuring it is readable only by you, using `umask 077`) and delete it once the
restoration has been verified.

## Internal Rules and CLI

[Rules](../../review/rules.md#rules-command) are stored in the database; you can import a
directory of TOML packs using the controller CLI (running servers will
apply them within seconds):

```bash
docker run --rm -v secreview-data:/var/lib/secreview -v ./rules.d:/rules:ro \
--entrypoint security-review-controller ghcr.io/cyr-ius/security-review rules import /rules
```

Other commands can be executed in the same way:

```bash
docker run --rm -v secreview-data:/var/lib/secreview \
--entrypoint security-review-controller ghcr.io/cyr-ius/security-review token list
```
