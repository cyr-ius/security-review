# OpenGrep engine

The Controller server runs OpenGrep as a second static-analysis engine during a
whole-codebase scan (`security-review-ci scan-code`). The built-in scanner remains enabled and
unchanged. Fragment scans (`scan_code`) do not start an external process.

## Docker image

The [`-opengrep` image](../../advanced/deployment/docker.md#published-images) (`latest-opengrep`,
`X.Y.Z-opengrep`) ships a pinned OpenGrep release in `/usr/local/bin/opengrep`, checked against its
SHA-256 digest at build time (`opengrep` target of the `Dockerfile`) and unpacked there, read-only,
so that a scan never extracts it: use it for the Controller server. The
[default rules](#default-rules) are installed and kept up to date at each start. The default image does not contain OpenGrep and sets `SECREVIEW_OPENGREP_ENABLED=false`. With an installation from
the PyPI package, install OpenGrep yourself and set `SECREVIEW_OPENGREP_BINARY` if it is not in
`/usr/local/bin`.

## Configuration

The engine is enabled by default (except in the default Docker image, without OpenGrep), but it only runs once at least one YAML rule is installed:
without any rule, `scan-code` runs the built-in scanner only. Set
`SECREVIEW_OPENGREP_ENABLED=false` to turn it off. Environment variables of the Controller server:

| Variable | Default | Description |
| --- | --- | --- |
| `SECREVIEW_OPENGREP_ENABLED` | `true` | Enable OpenGrep for whole-codebase scans |
| `SECREVIEW_OPENGREP_BINARY` | `/usr/local/bin/opengrep` | OpenGrep executable |
| `SECREVIEW_OPENGREP_RULES_DIR` | `/var/lib/secreview/rules/opengrep` | Directory containing OpenGrep YAML rule packs |
| `SECREVIEW_OPENGREP_TIMEOUT_SECONDS` | `600` | Maximum duration of one OpenGrep scan |
| `SECREVIEW_OPENGREP_MAX_CONCURRENT_SCANS` | `1` | OpenGrep scans running at the same time in one Controller server process; a scan beyond is refused with `503` and `Retry-After` |
| `SECREVIEW_OPENGREP_JOBS` | `2` | Cores used by one OpenGrep scan (`--jobs`) |
| `SECREVIEW_OPENGREP_MAX_MEMORY_MB` | `2048` | Memory in MiB of one OpenGrep scan (`--max-memory`, `0`: no limit) |

The [default rules](#default-rules) are installed at start-up by the `-opengrep` image, or by
`security-review-controller opengrep install`; add your own rule packs in the configured
directory, for example by mounting an administrator-managed directory at
`/var/lib/secreview/rules/opengrep` (keep it on a volume, so that the edits and deletions made
on the **OpenGrep rules** page survive a new container). Rules are never downloaded. The
directory must contain at least one `.yml` or `.yaml` file.

When enabled, the controller writes the source files already received from the CI client into a
private temporary directory, invokes OpenGrep without a shell, parses its JSON output, and removes
the workspace. Findings are normalized into the existing report format and are included in the
same report and SARIF export as built-in findings. OpenGrep rule IDs are prefixed with
`OPENGREP:` (`OPENGREP:secreview.python.taint-sql`). OpenGrep skips the paths of its default
ignore list (test directories such as `tests/`, `node_modules/`...).

## Default rules

Security Review ships 88 OpenGrep rules written for the project (Apache-2.0 license, like the
rest of the code): the community packs are not redistributed, because their licenses
(Semgrep Rules License, or LGPL with the Commons Clause for the `opengrep-rules` fork) forbid
their use in a product like this one. They complement the [built-in rules](../rules.md) with
what a line-by-line pattern cannot see:

- **taint analysis**: a value read from the request (Flask, Django, FastAPI, Spring, servlets,
  Express, NestJS, ASP.NET Core, `net/http`, Gin, Echo) is followed through variables and
  string building until it reaches a dangerous call (SQL, command, file path, outgoing URL,
  redirect, template, HTML, deserialization). A sanitizer on the way (`int()`,
  `secure_filename`, `path.basename`, `html.EscapeString`...) stops it;
- **structure**: an option that is missing (an XML factory without
  `disallow-doctype-decl`, an archive extracted without a filter, an HTTP server without timeouts,
  a Dockerfile without `USER`) or a combination of arguments (CORS with any origin *and*
  credentials).

| Language (directory) | Rules | Main checks |
| --- | --- | --- |
| Python (`python`) | 18 | Taint: SQL, command, `eval`, SSRF, path, redirect, template, HTML, deserialization; TLS, YAML, JWT, debug, CORS, archives, hashes, cookies |
| Java, Spring (`java`) | 18 | Taint: SQL/JPQL, command, path, SSRF, redirect, XSS, SpEL/OGNL, JNDI/LDAP; deserialization, XXE (DOM, SAX, StAX), CSRF, trust-all TLS, host name, ciphers, hashes, cookies, Jackson |
| JavaScript, TypeScript, Angular (`javascript`) | 15 | Taint: SQL, command, `eval`/`vm`, path, SSRF, redirect, XSS, RegExp, DOM XSS from the URL or the route; `bypassSecurityTrust*`, TLS, CORS, JWT, cookies, crypto |
| Go (`go`) | 11 | Taint: SQL, command, path, SSRF, redirect, XSS; `InsecureSkipVerify`, zip slip, server timeouts, crypto, `math/rand` for secrets |
| C#, ASP.NET Core (`csharp`) | 12 | Taint: SQL (ADO.NET, EF Core, Dapper), process, path, SSRF, redirect; deserializers, certificate validation, JWT, crypto, DTD, HTML encoding, CORS |
| Rust (`rust`) | 8 | SQL built with `format!`, shell, TLS, crypto, JWT, CORS, cookies, HTML |
| Dockerfile (`dockerfile`) | 2 | No `USER` before `CMD`/`ENTRYPOINT`, last `USER` is root |
| GitHub Actions (`github-actions`) | 4 | Script injection with `${{ }}`, `pull_request_target` checking out the pull request, action not pinned on a SHA, `write-all` |

Their ids follow `secreview.<language>.<check>` (`secreview.go.zip-slip`) and their metadata
give the CWE and the OWASP category, copied into the findings.

While the engine is enabled (`SECREVIEW_OPENGREP_ENABLED`) and the OpenGrep executable is present
(`-opengrep` image), the Controller server brings them up to date at each start, like the default TOML rules: a new rule is installed, a rule
left as installed is updated with the new version, and a rule edited or deleted on the
**OpenGrep rules** page is left alone. The digests of the installed versions are kept in
`.secreview-default-rules.json` in the rules directory; delete it to start over. The command
installs them on demand, on the Controller server:

```bash
security-review-controller opengrep list                          # bundled rules by language
security-review-controller opengrep install                       # every language
security-review-controller opengrep install --language python --language javascript
security-review-controller opengrep install --overwrite           # after an upgrade
```

`install` copies one file per rule into `SECREVIEW_OPENGREP_RULES_DIR` and prints the installed,
replaced and skipped ids (JSON). A rule that already exists is kept, so that an edit made on the
**OpenGrep rules** page survives; `--overwrite` replaces it with the version of the package
(after an upgrade, for instance). To drop a rule, delete it on that page. In a container, run
the command in the Controller server container
(`docker compose exec controller security-review-controller opengrep install`).

## Operational security

- Run the controller as the existing unprivileged `secreview` user.
- Keep rule packs administrator-controlled; treat rule updates as security-sensitive changes.
- Use container-level CPU, memory and process limits for the controller. The scan timeout, the
  number of concurrent scans and the cores and memory of a scan are enforced by the adapter (on
  timeout, OpenGrep and its workers are killed); they are not a substitute for container
  resource limits.
- If OpenGrep is busy with other scans or unavailable, `scan-code` gets a `503` answer: retry
  later.
- Do not mount application secrets or unrelated host paths into the scan workspace.
- The controller does not execute scanned source files. It does write the received source payload
  to a temporary directory for OpenGrep to read.
- If rules are installed but the OpenGrep binary is missing, or the scan fails, the code scan
  fails rather than silently reporting a successful built-in-only scan.

## Managing rules from the web interface

The Controller exposes an authenticated rule-management page at `/ui/opengrep-rules`.
Users with `rules.read` can inspect the YAML files in `SECREVIEW_OPENGREP_RULES_DIR`;
users with `rules.manage` can create, edit, validate and delete them. Each managed YAML file
contains exactly one rule, and its rule id must match the file identifier. Writes are validated
with `opengrep validate <file>` before an atomic replacement. The Controller does not download
rule packs or follow remote rule sources on behalf of the administrator.
