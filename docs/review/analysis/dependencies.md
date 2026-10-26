# Dependency analysis

## Supported files

`requirements*.txt`, `pyproject.toml` (PEP 621/735, Poetry), `poetry.lock`, `Pipfile.lock`,
`uv.lock`, `package.json`, `package-lock.json` / `npm-shrinkwrap.json`, `yarn.lock` (v1 and
berry), `pom.xml`, `build.gradle(.kts)`, `go.mod`, `Cargo.lock`, `Cargo.toml`,
`packages.lock.json`, `*.csproj` / `*.fsproj` / `*.vbproj`, `Directory.Packages.props`,
`Directory.Build.props`, `packages.config`, `nuget.config`, CycloneDX SBOMs (`bom.json`,
`bom.xml`, `sbom.json`, `*.cdx.json`, `*.cdx.xml`...).

| Ecosystem | Best file to scan | Notes |
|---|---|---|
| Go | `go.mod` | Since Go 1.17, it lists every module of the build (`// indirect` included) at its selected version: it is handled like a lockfile. `replace` directives are applied (a fork raises `DEP-003`, a local path `DEP-007`). Pseudo-versions (`v0.0.0-<date>-<commit>`) are compared by date. The standard library (`go` and `toolchain` directives) is not checked: scan the binary with `govulncheck`. |
| Rust (crates.io) | `Cargo.lock` | Every crate of the build, transitive included; the workspace members are skipped. A `git` source raises `DEP-003`, another registry `DEP-005`. `Cargo.toml` only holds ranges (`"1.0"` is `^1.0`): it is checked for hygiene (`*`, `git`, `path`, `registry`, `[patch]`, `workspace = true`). |
| .NET (NuGet) | `packages.lock.json` | Enable it with `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`; the packages of every target framework are checked. In a `*.csproj`, `Version="1.2.3"` is the version restored (lowest applicable) and is checked; floating versions (`1.*`) raise `DEP-002`, versions managed in `Directory.Packages.props` or by an MSBuild property `DEP-009`. `nuget.config` is checked for HTTP sources (`DEP-004`) and for several sources without `packageSourceMapping` (`DEP-005`, dependency confusion). |

In a `uv.lock`, the project itself and its workspace members (editable or virtual sources) are
not dependencies and are skipped; any other `git`, `url`, `path`, `directory` or `editable`
source raises `DEP-003`.

### CycloneDX SBOM (transitive dependencies)

`pom.xml` and `build.gradle` only list the direct dependencies: their transitive dependencies,
often the vulnerable ones, are not checked (a note says so in the result). Generate a CycloneDX
SBOM of the resolved dependency tree in the pipeline and scan it:

```bash
# Maven: writes target/bom.json and target/bom.xml
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
security-review-ci scan-deps target/bom.json --project my-project --require-database
```

With Gradle, the `cyclonedxBom` task of the `org.cyclonedx.bom` plugin produces the same file;
`npm sbom --sbom-format cyclonedx` does it for npm.

- The SBOM is read in JSON (`bomFormat: "CycloneDX"`) or XML (CycloneDX namespace); nested
  components are included. An XML SBOM with a `DOCTYPE` or `ENTITY` is refused.
- Each component is identified by its package URL (`purl`): `pkg:maven/...` (Maven),
  `pkg:npm/...` (npm), `pkg:pypi/...` (PyPI), `pkg:golang/...` (Go), `pkg:cargo/...`
  (crates.io) and `pkg:nuget/...` (NuGet). An SBOM may mix these ecosystems. The other types
  (`pkg:gem`, `pkg:composer`...) and the components without a `purl` are counted in a note and
  not checked.
- The versions are resolved: the SBOM is handled like a lockfile. A component of scope
  `excluded` is marked `dev`; a Maven `-SNAPSHOT` version raises `DEP-002`.

## Offline vulnerability database (OSV format)

The MCP server calls no external service: it looks up an OSV advisory base stored in the
database. Two ways to fill it:

- **manual import** (no network access required);
- **daily update by the controller**, if it is allowed to reach the Internet, directly or
  through a proxy.

### Manual import

On a connected machine, download the osv.dev exports
(`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`, same for `npm`, `Maven`,
`Go`, `crates.io` and `NuGet`), transfer them, then import them (CLI-only operation, idempotent):

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
HTTPS_PROXY=http://user:password@proxy.example.com:3128
```

- **Disabled by default**. The MCP server itself never connects outside.
- The due time depends on the age of the database (last import, manual or automatic): a restart
  or a second replica of the controller does not download again before the end of the interval
  (`SECREVIEW_OSV_UPDATE_INTERVAL_HOURS`, 24 by default). An empty or too old database is
  updated at start-up.
- **Proxy**: the download goes through the outgoing proxy of the controller, given by the
  standard variables `HTTPS_PROXY` (else `HTTP_PROXY`; lowercase names accepted;
  `http://[user:password@]host:port`, `host:port` meaning `http://host:port`, `CONNECT` tunnel
  to the HTTPS site), except to the hosts of `NO_PROXY`. The same proxy serves the
  [OIDC login](../../advanced/oidc.md). Without these variables, the connection is direct. If the proxy
  inspects TLS, give its CA with `SECREVIEW_OSV_CAFILE` (it then replaces the system CAs).
- **Mirror**: `SECREVIEW_OSV_URL` replaces the source (Nexus, Artifactory, internal bucket…) as
  long as it serves `<URL>/<ecosystem>/all.zip` over HTTPS. Plain HTTP, credentials in the URL
  and redirects to anything other than HTTPS are refused.
- `SECREVIEW_OSV_ECOSYSTEMS` (`PyPI,npm,Maven,Go,crates.io,NuGet` by default) limits the downloaded exports; every
  archive is bounded by `SECREVIEW_OSV_MAX_DOWNLOAD_MB` (1024 MiB), written to a temporary
  folder then deleted.
- A failed ecosystem (network, size, invalid archive) does not prevent the others; it is logged
  and a new attempt takes place one hour later.

#### Hosts without proxy

`NO_PROXY` (or the list of the **General** screen) gives, comma separated, the
destinations reached **without** the proxy:

| Entry | Example | Effect |
|---|---|---|
| Domain | `corp.example` or `.corp.example` | The domain and all its subdomains (`sso.corp.example`) |
| Subdomain wildcard | `*.corp.example` | Same as `.corp.example` |
| IP address | `10.0.0.5`, `[fd00::5]` | This address (a port, `10.0.0.5:8443`, is ignored) |
| Everything | `*` | No connection goes through the proxy |

An address only applies to a URL whose host **is** that IP address (`https://10.0.0.5/...`): a
host name is never resolved. To bypass the proxy towards an internal server reached by its name,
give its domain. Address ranges (CIDR, `10.0.0.0/8`) are not supported: in `NO_PROXY`, such an
entry matches no host, and the **General** screen refuses it. The loopback (`localhost`,
`127.0.0.0/8`, `::1`) is always reached directly.

```bash
NO_PROXY=.corp.example,10.0.0.5
```

The proxy can also be chosen by an administrator in the **Outgoing proxy of the controller**
section of the [**General**](../../usage/index.md#screens) screen of the web interface, for the variables that are not set: `HTTPS_PROXY` (else
`HTTP_PROXY`) and `NO_PROXY`, when set, take precedence over the values of the screen. They
apply to the next download. The **OSV database** screen shows the state of the database, the history of the updates
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

## Scan in a pipeline (`security-review-ci scan-deps`)

In a pipeline, the [pipeline client](../../advanced/architecture/ci.md) sends
the dependency files to the controller, which checks them against its advisory database and,
with `--save`, stores a `dependency-scan` report of the project. The pipeline needs neither the
database nor the package, only a [`ci` token](../../advanced/architecture/ci.md#ci-token-and-visible-projects)
(or `admin`) of the project:

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_TOKEN=...   # ci token restricted to my-project
security-review-ci scan-deps package-lock.json requirements.txt \
    --fail-on high --require-database --project my-project --save
# exit code: 0 = ok, 1 = blocked, 2 = error
```

- `--require-database` refuses the scan (code `2`, nothing stored) when the vulnerability check
  cannot run for a file.
- With `--save`, the user of a personal `ci` token is the author of the report, else
  `--author` stores the username of the developer with it (see
  [author of a report](../prompts-tools.md#author-of-a-report)), `--repository`,
  `--branch` and `--commit` the context; the label of the token is stored as the device.
- Each file is limited to the `SECREVIEW_MAX_DEPENDENCY_CHARS` of the controller, the request
  to `SECREVIEW_MAX_SCAN_REQUEST_MB`. Symbolic links are not read.

## Scan from a workstation (commit hook)

Step-by-step setup, with the agent review: [Commit hooks](../../getting-started/commit-hooks.md).

A developer runs the same `security-review-ci scan-deps` on their workstation, with a
[personal `mcp` or `ci` token](../../usage/tokens.md#personal-mcp-and-ci-tokens) created in
**My account**: it reaches the projects the developer may read, and the files are sent to the
controller exactly as they are on disk. The workstation needs no Python: install the client with
uv (see [Installation](../../advanced/architecture/ci.md#installation)).

```bash
uv tool install security-review-ci
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_TOKEN=<personal mcp or ci token>
security-review-ci scan-deps uv.lock web/package-lock.json --project my-project --require-database
# exit code: 0 = ok, 1 = blocked, 2 = error (controller unreachable, token refused...)
```

Commit hook ([prek](https://prek.j178.dev) or [pre-commit](https://pre-commit.com)), run when a
manifest or a lockfile changes. With `language: python`, the hook installs `security-review-ci`
in its own environment: nothing else to install. prek is a single binary that also downloads
the Python of the hook (pre-commit needs a Python):

```yaml
repos:
  - repo: local
    hooks:
      - id: scan-deps
        name: dependency scan
        entry: security-review-ci scan-deps --skip-unconfigured --require-database --project my-project
        language: python
        additional_dependencies: ["security-review-ci==X.Y.Z"] # version of your controller
        files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
```

With the client already installed (`uv tool install`), `language: system` runs it from the
`PATH` instead.

`--skip-unconfigured` lets the commit through, with a warning, when `SECREVIEW_CONTROLLER_URL`
is not set (contributors without a controller). The two variables are read from the
environment only, never from the `.env` file.

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
- For an SBOM that mixes ecosystems, the check is `performed` as soon as one of them has
  advisories; a note names the ecosystems that could not be checked.
- Each component is marked `dev` or not. In `pyproject.toml`, the extras named after
  development (`dev`, `test`, `docs`, `lint`...) and the `[dependency-groups]` are `dev`; the
  other extras (`postgres`...) are installed in production and stay runtime dependencies.
- Hygiene rules `DEP-001` to `DEP-009`: unpinned versions, URL / VCS, HTTP, extra index,
  `--trusted-host`, etc.
