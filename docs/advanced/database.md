# Database

The Controller server and the MCP server share one database: reports and findings, rules, accounts,
token digests, settings and audit log. This page gathers what concerns it: choosing the engine,
schema migrations, retention, backup and upgrade. The variables are listed in
[Configuration](../reference/configuration.md#database-and-logs).

## SQLite or PostgreSQL

- In [local mode (stdio)](../getting-started/stdio.md), that is the all-in-one mode of a
  developer workstation, only an SQLite database is accepted. The local MCP server creates and
  migrates its SQLite database itself.

    An SQLite database is created by default in the user's data folder:
    `~/.local/share/security-review-mcp/security_reports.db`.

    To change the location of the SQLite database, start the local MCP server with the command
    `security-review-mcp local --database-url sqlite:////home/me/security_reports.db`.

- In shared mode, you can use a PostgreSQL database if you separate the MCP server and the
  Controller server. To do so, pass the environment variable to both processes:

```bash
SECREVIEW_DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/secreview
security-review-controller serve
```

!!! note "Shared database"
    With SQLite, both processes must run on the same machine and share the same file. As soon
    as they are in different pods or on different machines, use PostgreSQL.

## Schema migrations

The schema is managed by [Alembic](https://alembic.sqlalchemy.org/) migrations, embedded in the
package (no `alembic.ini` file to provide):

```bash
security-review-controller db upgrade   # creates or migrates the schema, then seeds the default rules
security-review-controller db status    # {"current": "0032", "head": "0032", "up_to_date": true}
```

- `db status` returns code `1` if the schema is not up to date: handy for a script or a probe.
- The **HTTP MCP server never migrates**: it refuses to start (code `2`, message
  `run security-review-controller db upgrade first`) while the database is not at the expected
  revision. Under Kubernetes, the pod restarts until the migration is done.
- The Controller server, the stdio MCP server and the CLI commands migrate at start-up: with Docker
  Compose and Kubernetes, the Controller server migrates when it starts, there is nothing to do.
- On PostgreSQL, a migration takes an advisory lock: instances that start together (several
  replicas, a `db upgrade` run by hand) wait for each other, and the next one finds the schema
  up to date.
- Version 10 (revision `0039`) moves the groups of web users to roles and projects of the users
  and OIDC mappings, keeping the rights of each account: the roles keep their permissions on the
  whole Controller server, their per-project permissions move to the projects of the users, of
  the mappings and of the role tokens, and the built-in `reader` role goes. It deletes the
  `triager` and `mcp-user` roles (the API tokens of these roles are revoked). It **cannot be downgraded**: back up the database
  before upgrading. Revision `0040` then adds `reports.write` wherever `reports.read` is held
  (accounts, their projects, OIDC mappings), so that the agents keep saving reports: remove it
  from the accounts that should only read.

### Dedicated migration job

By default, nothing has to be configured. `SECREVIEW_DB_AUTO_UPGRADE=false` is only for an
operator who keeps migrations out of the application, for instance when:

- the database account of the application has no right to change the schema (no DDL): a job
  runs `security-review-controller db upgrade` with a privileged account;
- a new image must not change the schema by itself: the migration is run after a backup, or
  during a maintenance window.

The Controller server, the stdio MCP server and the CLI commands then only check the schema: like the
HTTP MCP server, they refuse to start (code `2`) until `db upgrade` has been run.

## Retention of reports without findings

The Controller server deletes these reports once they are older than
`SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` days (default `90`): at the start, then every
day. The latest report of each project is always kept, so a project never disappears from the
list, and a report with findings is never deleted, whatever their status. `0` disables the
purge.

The same purge can be run on demand, for example from a scheduled job when the Controller server is
not running:

```bash
security-review-controller db prune              # retention of SECREVIEW_EMPTY_REPORT_RETENTION_DAYS
security-review-controller db prune --days 30    # another retention, for this run only
# {"retention_days": 30, "deleted": 4}
```

The events of the audit log have their own retention: see [Audit log](audit-log.md#retention).

## Backing up PostgreSQL

With [Docker Compose](deployment/docker.md#docker-compose-with-postgresql), the `secreview-pg`
volume holds the reports, the accounts and the token digests. Export it regularly (cron,
systemd timer) and keep the files away from the server, readable by you only:

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

The Controller server then applies any pending Alembic revisions at start. The export
contains reports, password hashes, and tokens; keep it outside the repository
(ensuring it is readable only by you, using `umask 077`) and delete it once the
restoration has been verified.

On Kubernetes, the `postgres.yaml` StatefulSet is a starting point: for production, prefer a
managed database or an operator, which handle replication, backups and upgrades (see
[Kubernetes](deployment/kubernetes.md)).
