# Dependency analysis

## Supported files

`requirements*.txt`, `pyproject.toml` (PEP 621/735, Poetry), `poetry.lock`, `Pipfile.lock`,
`uv.lock`, `package.json`, `package-lock.json` / `npm-shrinkwrap.json`, `yarn.lock` (v1 and
berry), `pom.xml`, `build.gradle(.kts)`.

In a `uv.lock`, the project itself and its workspace members (editable or virtual sources) are
not dependencies and are skipped; any other `git`, `url`, `path`, `directory` or `editable`
source raises `DEP-003`.

## Offline vulnerability database (OSV format)

The MCP server calls no external service: it looks up an OSV advisory base stored in the
database. Two ways to fill it:

- **manual import** (no network access required);
- **daily update by the controller**, if it is allowed to reach the Internet, directly or
  through a proxy.

### Manual import

On a connected machine, download the osv.dev exports
(`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`, same for `npm` and
`Maven`), transfer them, then import them (CLI-only operation, idempotent):

```bash
security-review-controller advisories import PyPI.zip      # .json, folder or .zip
security-review-controller advisories import npm.zip
security-review-controller advisories import Maven.zip --ecosystem Maven   # optional filter
security-review-controller advisories status
```

### Automatic update by the controller

With `SECREVIEW_OSV_AUTO_UPDATE=true`, `security-review-controller serve` downloads the
`all.zip` export of every ecosystem and imports it, then starts again every 24 hours:

```bash
SECREVIEW_OSV_AUTO_UPDATE=true
# Optional: outgoing HTTP proxy of the controller (credentials accepted, never logged)
SECREVIEW_PROXY=http://user:password@proxy.example.com:3128
```

- **Disabled by default**. The MCP server itself never connects outside.
- The due time depends on the age of the database (last import, manual or automatic): a restart
  or a second replica of the controller does not download again before the end of the interval
  (`SECREVIEW_OSV_UPDATE_INTERVAL_HOURS`, 24 by default). An empty or too old database is
  updated at start-up.
- **Proxy**: the download goes through the outgoing proxy of the controller,
  `SECREVIEW_PROXY` (`http://[user:password@]host:port`, `CONNECT` tunnel to the HTTPS site),
  except to the hosts of `SECREVIEW_NO_PROXY`. The same proxy serves the
  [SSO login](web-interface.md#openid-connect-sso-login). Without it, the standard
  `HTTPS_PROXY` and `NO_PROXY` variables apply. If the proxy inspects TLS, give its CA with
  `SECREVIEW_OSV_CAFILE` (it then replaces the system CAs).
- **Mirror**: `SECREVIEW_OSV_URL` replaces the source (Nexus, Artifactory, internal bucket…) as
  long as it serves `<URL>/<ecosystem>/all.zip` over HTTPS. Plain HTTP, credentials in the URL
  and redirects to anything other than HTTPS are refused.
- `SECREVIEW_OSV_ECOSYSTEMS` (`PyPI,npm,Maven` by default) limits the downloaded exports; every
  archive is bounded by `SECREVIEW_OSV_MAX_DOWNLOAD_MB` (1024 MiB), written to a temporary
  folder then deleted.
- A failed ecosystem (network, size, invalid archive) does not prevent the others; it is logged
  and a new attempt takes place one hour later.

#### Hosts without proxy

`SECREVIEW_NO_PROXY` (or the list of the **Settings** screen) gives, comma separated, the
destinations reached **without** the proxy:

| Entry | Example | Effect |
|---|---|---|
| Domain | `corp.example` or `.corp.example` | The domain and all its subdomains (`sso.corp.example`) |
| Subdomain wildcard | `*.corp.example` | Same as `.corp.example` |
| IP address | `10.0.0.5`, `[fd00::5]` | This address (a port, `10.0.0.5:8443`, is ignored) |
| CIDR range | `10.0.0.0/8`, `192.168.1.128/25`, `fd00::/8` | Any IPv4 or IPv6 address of the range |
| Everything | `*` | No connection goes through the proxy |

Like curl, an address or a CIDR range only applies to a URL whose host **is** an IP address
(`https://10.1.2.3/...`): a host name is never resolved to be compared with a range. To bypass
the proxy towards an internal server reached by its name, give its domain. The loopback
(`localhost`, `127.0.0.0/8`, `::1`) is always reached directly. An invalid range
(`10.0.0.0/33`, `example.com/path`) is refused.

```bash
SECREVIEW_NO_PROXY=.corp.example,10.0.0.0/8,172.16.0.0/12,fd00::/8
```

The proxy can also be chosen by an administrator in the [**Settings**](web-interface.md#screens)
screen of the web interface: proxy and hosts without proxy set there, or direct connection,
take precedence over `SECREVIEW_PROXY`, `SECREVIEW_NO_PROXY` and `HTTPS_PROXY`; they apply to
the next download. The same screen shows the state of the database, the history of the updates
(scheduled, CLI or web) and an **Update now** button (run in the background, one update at a
time), only available when `SECREVIEW_OSV_AUTO_UPDATE=true`.

To trigger an update on demand (or from a `CronJob` rather than from the controller), with the
same settings:

```bash
security-review-controller advisories update                  # ecosystems of SECREVIEW_OSV_ECOSYSTEMS
security-review-controller advisories update --ecosystem npm  # repeatable option
# exit code: 0 = all imported, 2 = at least one ecosystem failed or invalid setting
```

The controller downloads at most a few hundred MiB a day (the npm export is the largest): plan
the matching space in its temporary folder (`/tmp`).

## Pipeline scan

For large lockfiles, prefer the CLI to the MCP tool, limited to
`SECREVIEW_MAX_DEPENDENCY_CHARS`:

```bash
security-review-controller deps scan package-lock.json requirements.txt \
    --fail-on high --require-database --project my-project --save
# exit code: 0 = ok, 1 = blocked, 2 = error
```

## Reading the result

The `vulnerability_check` field says whether the check took place:

| Value | Meaning |
|---|---|
| `performed` | The versions were compared with the database |
| `skipped_no_advisory_database` | No database imported |
| `skipped_no_advisories_for_ecosystem` | No advisory for this ecosystem |

!!! danger "Empty list ≠ safe dependencies"
    In the last two cases, **an empty list does not mean that the dependencies are safe**.
    `--require-database` makes the pipeline fail in that case.

- A database older than 30 days is reported.
- A severity missing from the advisory is handled as `medium` (`severity_known: false`).
- Range versions (`>=2`) cannot be checked: analyze the lockfile.
- Each component is marked `dev` or not. In `pyproject.toml`, the extras named after
  development (`dev`, `test`, `docs`, `lint`...) and the `[dependency-groups]` are `dev`; the
  other extras (`postgres`...) are installed in production and stay runtime dependencies.
- Hygiene rules `DEP-001` to `DEP-009`: unpinned versions, URL / VCS, HTTP, extra index,
  `--trusted-host`, etc.
