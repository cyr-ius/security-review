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
In the examples on this page, replace `security-review-mcp` with
the actual published image name.

## Docker Compose with PostgreSQL

One file,
[`examples/docker/docker-compose.yml`](https://github.com/cyr-ius/security-review-mcp/blob/{{ release_tag }}/examples/docker/docker-compose.yml),
starts everything with the published image: PostgreSQL, the migration of the schema, the
controller and the MCP server. Copy and paste the block in an empty folder:

```bash
mkdir security-review-mcp && cd security-review-mcp
curl -fsSLO https://raw.githubusercontent.com/cyr-ius/security-review-mcp/{{ release_tag }}/examples/docker/docker-compose.yml
(umask 077 && printf 'POSTGRES_PASSWORD=%s\nSECREVIEW_SECRET_KEY=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" > .env)
docker compose up -d --wait
docker compose exec controller security-review-controller user reset-password admin   # initial admin password
docker compose exec controller security-review-controller token create --label alice   # token of an agent
```

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
| `migrate` | Creates or updates the tables (`security-review-controller db upgrade`), then stops | — |
| `controller` | Web interface (`/ui/`) and REST API, for people | `127.0.0.1:8080` |
| `mcp` | MCP server (`/mcp`) and public enrollment, for the agents and the CI | `127.0.0.1:8000` |

Good to know:

- **Order of start-up.** `migrate` waits until PostgreSQL is ready; `controller` and `mcp` wait
  until `migrate` has succeeded. Only `migrate` changes the tables.
- **Keep `.env`.** It holds the password of the database and the secret of the sessions; never
  commit it. The password is inserted as is in the connection URL: keep hexadecimal characters,
  as generated above.
- **Open to the team.** The ports are only open on this machine (`127.0.0.1`). Enable the
  [built-in TLS](http.md#tls) or put a reverse proxy in front, then replace `127.0.0.1` in the
  `ports` of `controller` and `mcp` by the address of the server. TLS variables
  (`SECREVIEW_TLS_CERTFILE`, `SECREVIEW_TLS_KEYFILE`) go under `environment`, with the
  certificate files mounted read-only (see [Certificate Authority](http.md#certificate-authority)).
  The controller exposes no write route without a token: it can stay internal.
- **Vulnerability advisories.** The OSV database is **empty** at the first start: the dependency
  analysis answers that no database is loaded. To let the controller download it at start-up,
  then every 24 hours, uncomment `SECREVIEW_OSV_AUTO_UPDATE` (and `SECREVIEW_OSV_ECOSYSTEMS`) in
  the `controller` service, then run `docker compose up -d`. Follow the import with
  `docker compose logs -f controller`. Without Internet access, import an archive with
  `advisories import` (see [Dependencies](dependencies.md#manual-import)).
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
[Architecture and deployment](architecture.md)):

- the **MCP server** is the default entry point of the image (`security-review-mcp`, default
  command `serve`, in stdio; add `--transport streamable-http` for HTTP);
- the **controller** (REST API, web interface, administration) is started with
  `--entrypoint security-review-controller`, with the [built-in authentication and TLS](http.md)
  or behind a reverse proxy that handles them.

```bash
DB=postgresql+psycopg2://user:pass@db:5432/secreview

# 1. Schema (Alembic): must be run again after every image update
docker run --rm -e SECREVIEW_DATABASE_URL=$DB \
    --entrypoint security-review-controller security-review-mcp db upgrade

# 2. Controller: web interface and API, preferably on an internal network
docker run -d --name secreview-controller -p 127.0.0.1:8080:8000 \
    -e SECREVIEW_DATABASE_URL=$DB -e SECREVIEW_DB_AUTO_UPGRADE=false \
    --entrypoint security-review-controller \
    security-review-mcp serve --host 0.0.0.0 --port 8000

# 3. MCP server: exposed to the agents and the CI
docker run -d --name secreview-mcp -p 8443:8443 \
    -e SECREVIEW_DATABASE_URL=$DB \
    -v ./tls:/etc/secreview/tls:ro \
    -e SECREVIEW_TLS_CERTFILE=/etc/secreview/tls/cert.pem \
    -e SECREVIEW_TLS_KEYFILE=/etc/secreview/tls/key.pem \
    security-review-mcp serve --transport streamable-http --host 0.0.0.0 --port 8443

# 4. Password of the admin account, created at the first start of the controller
docker exec secreview-controller security-review-controller user reset-password admin
```

Mounted files must be readable by the user of the container (UID `10001`). The MCP server
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

The `migrate` service then applies any pending Alembic revisions. The export
contains reports, password hashes, and tokens; keep it outside the repository
(ensuring it is readable only by you, using `umask 077`) and delete it once the
restoration has been verified.

## Internal Rules and CLI

[Rules](../usage/rules.md#rules-command) are stored in the database; you can import a
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
