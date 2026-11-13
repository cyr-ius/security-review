# OpenGrep engine

The Controller server runs OpenGrep as a second static-analysis engine during a
whole-codebase scan (`security-review-ci scan-code`). The built-in scanner remains enabled and
unchanged. On the MCP server, fragment scans (`scan_code`) only use OpenGrep when they are
[delegated to the Controller server](#fragment-scans-scan_code).

The OpenGrep rules are stored in the database, like the internal rules: every replica of the
Controller server sees the same rules, and none is lost when a container restarts. OpenGrep only
reads files, so each process that runs it (the Controller server, a
[scan engine](../../advanced/architecture/scan-engine.md#rules)) copies the rules into its own
working directory, `SECREVIEW_OPENGREP_RULES_DIR`, and updates that copy before a scan when a
rule changed. The directory is a cache: it needs no persistent or shared volume.

## Fragment scans (`scan_code`)

By default, the `scan_code` tool scans the fragment it receives with the rules of the MCP server
only, and starts no external process. With the delegation turned on, it sends the
fragment to `POST /api/v1/scan/content` of the Controller server with the token of the agent: the
Controller server applies its rules, then its OpenGrep rules when the engine is enabled, and stores
nothing. The answer tells the engines that ran (`engines`: `rules`, `opengrep`). While the
delegation is off, the Controller server answers `404` on this route: an `mcp` token cannot
make it run OpenGrep for a feature that is not in use.

The Controller server decides, and stores its choice in the database where the MCP server reads
it at each call. `SECREVIEW_SCANCODE_DELEGATED`, set on the Controller server, gives `true` (to its
public URL), the root URL of the Controller server as seen by the MCP server (for example
`http://controller:8080` inside Compose: the fragments then stay on the internal network), or
`false`. Without the variable, an administrator can turn on the delegation in the web interface: on the
**General** page, under **Controller server address**, the **Delegate the scan_code tool to this
Controller server** switch sends the fragments to that public address (the MCP server must reach
it). It is off by default, needs a known address, applies at the next `scan_code` call, and is turned off when the address
changes (turn it on again for the new address: the tokens never follow a changed address). Each
change is recorded in the audit log (`mcp_scan_delegation.changed`). When the variable is set, the
switch is locked. `SECREVIEW_MCP_SCAN_CONTROLLER_URL`, the former variable of the MCP server, is
deprecated: still read with a warning, it takes precedence.

- The token of the agent is relayed as is: an `mcp` or `admin` token reaches this route only, not the
  rest of the REST API.
- Without a caller token (stdio, open server), or when the Controller server does not answer
  (unreachable, busy OpenGrep, `SECREVIEW_MCP_SCAN_TIMEOUT_SECONDS` exceeded), `scan_code` scans with
  the rules of the MCP server and gives the reason in `controller_error`.
- The call goes to the configured URL only, without proxy nor redirect, with a bounded answer; use an
  `https://` URL when the Controller server is not on the same private network.
- The fragments have their own OpenGrep slots (`SECREVIEW_OPENGREP_MAX_CONCURRENT_FRAGMENT_SCANS`):
  agents that call `scan_code` many times never make the codebase scans of the pipelines wait.
  The two pools add up: size the host for
  (`SECREVIEW_OPENGREP_MAX_CONCURRENT_SCANS` + `SECREVIEW_OPENGREP_MAX_CONCURRENT_FRAGMENT_SCANS`)
  scans at once, each with `SECREVIEW_OPENGREP_JOBS` cores and `SECREVIEW_OPENGREP_MAX_MEMORY_MB`
  MiB (keep a memory limit).

## Docker image

The [`-opengrep` image](../../advanced/deployment/docker.md#published-images) (`latest-opengrep`,
`X.Y.Z-opengrep`) ships a pinned OpenGrep release in `/usr/local/bin/opengrep`, checked against its
SHA-256 digest at build time (`opengrep` target of the `Dockerfile`) and unpacked there, read-only,
so that a scan never extracts it: use it for the Controller server. The
[default rules](#default-rules) are installed and kept up to date at each start. The `-opengrep` image sets `SECREVIEW_OPENGREP_ENABLED=true`; the default image does not contain OpenGrep. With an installation from
the PyPI package, install OpenGrep yourself, set `SECREVIEW_OPENGREP_ENABLED=true` and set `SECREVIEW_OPENGREP_BINARY` if it is not in
`/usr/local/bin`.

## Configuration

The engine is disabled by default and enabled in the `-opengrep` image; set
`SECREVIEW_OPENGREP_ENABLED=true` to turn it on elsewhere. Once enabled, it only runs once at least one YAML rule is installed:
without any rule, `scan-code` runs the built-in scanner only. Environment variables of the Controller server:

| Variable | Default | Description |
| --- | --- | --- |
| `SECREVIEW_OPENGREP_ENABLED` | `false` | Enable OpenGrep for whole-codebase scans |
| `SECREVIEW_OPENGREP_BINARY` | `/usr/local/bin/opengrep` | OpenGrep executable |
| `SECREVIEW_OPENGREP_RULES_DIR` | `/var/lib/secreview/rules/opengrep` | Working directory where the Controller server and the scan engines copy the OpenGrep rules of the database for OpenGrep (a cache: an `emptyDir` is enough, never shared between replicas); the rule files left there by a previous version are imported once into the database |
| `SECREVIEW_OPENGREP_TIMEOUT_SECONDS` | `600` | Maximum duration of one OpenGrep scan |
| `SECREVIEW_OPENGREP_MAX_CONCURRENT_SCANS` | `1` | OpenGrep scans running at the same time in one Controller server process; a scan beyond is refused with `503` and `Retry-After` |
| `SECREVIEW_OPENGREP_MAX_CONCURRENT_FRAGMENT_SCANS` | `1` | Fragments of [`scan_code`](#fragment-scans-scan_code) scanned with OpenGrep at the same time, in their own slots so that the agents never take those of the codebase scans (`503` beyond: the MCP server scans with its rules); `0`: fragments are scanned with the rules only |
| `SECREVIEW_OPENGREP_JOBS` | `2` | Cores used by one OpenGrep scan (`--jobs`) |
| `SECREVIEW_OPENGREP_MAX_MEMORY_MB` | `2048` | Memory in MiB of one OpenGrep scan (`--max-memory`, `0`: no limit) |
| `SECREVIEW_OPENGREP_TAINT_INTRAFILE` | `true` | Follow the data flow through the functions of a same file (`--taint-intrafile`, about 10 to 30 % longer); `false` for an older OpenGrep executable that lacks the option |

The [default rules](#default-rules) are installed in the database at start-up, or by
`security-review-controller opengrep install`; add your own rules on the
[**OpenGrep rules** page](#managing-rules-from-the-web-interface). Rules are never downloaded.
`SECREVIEW_OPENGREP_RULES_DIR` only holds the copy written for OpenGrep: a file put there by hand
is not read.

When enabled, the controller writes the source files already received from the CI client into a
private temporary directory, invokes OpenGrep without a shell, parses its JSON output, and removes
the workspace. Findings are normalized into the existing report format and are included in the
same report and SARIF export as built-in findings. OpenGrep rule IDs are prefixed with
`OPENGREP:` (`OPENGREP:secreview.python.taint-sql`). OpenGrep skips the paths of its default
ignore list (test directories such as `tests/`, `node_modules/`...).

## Default rules

Security Review ships 147 OpenGrep rules written for the project (Apache-2.0 license, like the
rest of the code): the community packs are not redistributed, because their licenses
(Semgrep Rules License, or LGPL with the Commons Clause for the `opengrep-rules` fork) forbid
their use in a product like this one. They complement the [built-in rules](../rules.md) with
what a line-by-line pattern cannot see:

- **taint analysis**: a value read from the request (Flask, Django, FastAPI, aiohttp, Tornado,
  Bottle, Pyramid, Azure Functions, Spring, servlets, Express, NestJS, ASP.NET Core, `net/http`,
  Gin, Echo), a socket, a websocket or an AWS Lambda event is followed through variables and
  string building until it reaches a dangerous call (SQL, command, file path, outgoing URL,
  redirect, template, HTML, deserialization). A sanitizer on the way (`int()`,
  `secure_filename`, `path.basename`, `html.EscapeString`...) stops it. Local data (command line
  arguments, standard input, environment variables) is not a source: a command line tool that
  acts on what its own user asks crosses no trust boundary. The value is followed within a
  file, across its functions (`SECREVIEW_OPENGREP_TAINT_INTRAFILE`), but not from one file to
  another ([detection benchmark](../../reference/detection-benchmark.md));
- **structure**: an option that is missing (an XML factory without
  `disallow-doctype-decl`, an archive extracted without a filter, an HTTP server without timeouts,
  a Dockerfile without `USER`) or a combination of arguments (CORS with any origin *and*
  credentials).

| Language (directory) | Rules | Main checks |
| --- | --- | --- |
| Python (`python`) | 30 | Taint: SQL, NoSQL, command, `eval`, SSRF, path, redirect, template, HTML (Flask, Django and FastAPI responses), XPath, LDAP, session (trust boundary), deserialization, mass assignment; TLS, YAML, JWT, debug, CORS, archives, hashes, cookies, XXE, `random` for secrets, TLS 1.0/1.1, `requests` without timeout, `csrf_exempt`, secrets compared with `==` |
| Java, Spring (`java`) | 31 | Taint: SQL/JPQL, command, `ScriptEngine`/Groovy, path, SSRF, redirect, XSS, XPath, session (trust boundary), SpEL/OGNL, Velocity/FreeMarker, JNDI/LDAP; deserialization, XXE (DOM, SAX, StAX), CSRF, trust-all TLS, host name, ciphers, hashes, cookies, Jackson, SnakeYAML, zip slip, `Random` for secrets, unverified JWT, TLS 1.0/1.1, `XMLDecoder`, XStream, CORS with any origin and credentials, secrets compared with `equals` |
| JavaScript, TypeScript, Angular (`javascript`) | 24 | Taint: SQL, NoSQL, command, deserialization, mass assignment, `eval`/`vm`, path, SSRF, redirect, XSS, RegExp, templates, prototype pollution, DOM XSS from the URL or the route; `message` data read without checking its origin, `bypassSecurityTrust*`, TLS, CORS, JWT, cookies, crypto, XXE (`noent`), `Math.random` for secrets, `postMessage` to any origin |
| Go (`go`) | 17 | Taint: SQL, command, path, SSRF, redirect, XSS, templates; `InsecureSkipVerify`, zip slip, server timeouts, crypto, `math/rand` for secrets, unverified JWT, cookies, TLS 1.0/1.1, HTTP client without timeout, secrets compared with `==` |
| C#, ASP.NET Core (`csharp`) | 20 | Taint: SQL (ADO.NET, EF Core, Dapper), process, path, SSRF, redirect, XSS, XPath; deserializers, certificate validation, JWT, crypto, DTD, HTML encoding, CORS, zip slip, `System.Random` for secrets, cookies, TLS 1.0/1.1, antiforgery disabled, secrets compared with `==` |
| Rust (`rust`) | 13 | Taint: SQL (sqlx, diesel, drivers), command, path, SSRF, redirect from axum and actix-web extractors; SQL built with `format!`, shell, TLS, crypto, JWT, CORS, cookies, HTML |
| Dockerfile (`dockerfile`) | 2 | No `USER` before `CMD`/`ENTRYPOINT`, last `USER` is root |
| GitHub Actions (`github-actions`) | 10 | Script injection with `${{ }}`, `pull_request_target` checking out the pull request, action not pinned on a SHA, `write-all`, `workflow_run` artifacts, self-hosted runner on pull requests, `secrets: inherit` to another repository, no `permissions`, `issue_comment` checking out a pull request, cache in `pull_request_target` |

Their ids follow `secreview.<language>.<check>` (`secreview.go.zip-slip`) and their metadata
give the CWE and the OWASP category, copied into the findings.

At each start, the Controller server copies the default rules into the database, like the
default TOML rules, whether OpenGrep runs on it or not (the scan engines get them from it): a new
rule is installed, a rule left as installed is updated with the new version, a rule edited or
deleted on the **OpenGrep rules** page is left alone, and a default rule no longer shipped is
removed unless it was edited. The command installs the bundled defaults on demand on the
Controller server:

```bash
security-review-controller opengrep list                          # bundled rules by language
security-review-controller opengrep install                       # every language
security-review-controller opengrep install --language python --language javascript
security-review-controller opengrep install --overwrite           # after an upgrade
```

`install` writes the rules into the database and prints the installed, replaced and skipped ids
(JSON). A rule that already exists is kept, so that an edit made on the
**OpenGrep rules** page survives; `--overwrite` replaces it with the version of the package
(after an upgrade, for instance). To drop a rule, delete it on that page. In a container, run
the command in the Controller server container
(`docker compose exec controller security-review-controller opengrep install`).

!!! note "Upgrading from a version that kept the rules in files"

    Before, the rules were files of `SECREVIEW_OPENGREP_RULES_DIR`. At its first start after the
    upgrade (`db upgrade` creates the table), the Controller server imports once the rule files
    of that directory (`<id>.yaml` or `<id>.yml`, one rule each) into the database, with the
    default rules recorded in its `.secreview-default-rules.json` manifest: an edited default rule
    stays edited, a deleted one is not installed again. Start a single replica first, with the
    directory mounted as before. The files are no longer read afterwards and may be deleted.

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

The Controller server exposes an authenticated rule-management page at `/ui/opengrep-rules`
(**OpenGrep rules**). Users with `rules.read` can inspect the YAML rules stored in the
database; users with `rules.manage` can create, edit, validate and delete them. Each rule holds
exactly one OpenGrep rule, whose YAML id must match the rule identifier. Writes are validated
with `opengrep validate` first, so creating or editing a rule needs the OpenGrep executable on
the Controller server (`-opengrep` image); the default rules do not.
The Controller server does not download rule packs or follow remote rule sources on behalf of
the administrator.

The rules are listed in a table: identifier, message, CWE, language, severity of the findings
(`ERROR` gives **High**, `WARNING` **Medium**, `INFO` **Low**) and date of the last change,
read from the YAML of each file (a field written otherwise shows `—`). The search field looks
in the identifier, the message and the CWE; the filters keep one or several languages and
severities, and every column but the message sorts the table. The pencil (the eye with
`rules.read` only) opens the YAML of the rule in a dialog, with **Validate**, **Save rule**
and **Delete rule**.

## Rules proposed by agents

During a review, when a confirmed issue follows a vulnerable pattern the scan missed and that
may recur, the agent can propose an OpenGrep rule with the MCP tool `propose_opengrep_rule`
([tools](../prompts-tools.md#tools)): the YAML rule, its reason and test code (`ruleid:` and
`ok:` cases). **The rule is not installed**: the MCP server only stores the proposal in the
database, and the review prompts tell the agent to propose a rule only after saving the report.

- The rule must hold exactly one rule whose `id` is the proposed identifier; the `secreview.`
  prefix is kept for the default rules. A rule that looks like it holds a secret, or with
  invisible characters, is refused. The reason is masked and bounded like the reason of a
  status proposal.
- The token must reach the project and hold `reports.write` on it (as for
  `save_security_report`). A new proposal with the identifier of a pending one of the same
  project replaces it (from another project, it is refused); at most
  `SECREVIEW_OPENGREP_MAX_PENDING_PROPOSALS` proposals wait at the same time.
- Duplicates are refused: a rule whose identifier is already installed, or that detects the
  same code as an installed rule, a default rule or another pending proposal. Two rules detect
  the same code when they differ only by their `id`, `message`, `metadata`, `severity` or
  `fix`, their comments, indentation, spacing or the quotes around a value. The refusal names
  the existing rule, or the proposal when it belongs to the same project; to correct a pending
  proposal, the agent proposes it again with its identifier.
- Pending proposals are listed at the top of the **OpenGrep rules** page for the users with
  `rules.manage`; their number is shown next to **OpenGrep rules** in the menu while some
  wait. **Review** opens one in the editor with its project, author, reason and test
  code: the approver may correct the YAML (not its identifier), validate it with OpenGrep, then
  **Approve and install** it or **Reject** it with an optional reason.
- Only a person logged in to the web interface decides: a bearer token, which an agent may
  hold, gets `403`. An approval validates the rule with `opengrep validate` and creates its file;
  it never replaces an installed rule (`409`). The proposal, the approval and the rejection are
  written to the [audit log](../../advanced/audit-log.md).

| Route | Permission | Role |
|---|---|---|
| `GET /api/v1/opengrep/proposals?status=pending` | `rules.manage` | Proposals of a status (`pending` by default, `approved`, `rejected`), newest first, with their `total` |
| `POST /api/v1/opengrep/proposals/{id}/approve` | `rules.manage`, web session | Body `{"content": null}` (or the corrected YAML): validates and installs the rule |
| `POST /api/v1/opengrep/proposals/{id}/reject` | `rules.manage`, web session | Body `{"reason": null}`: the rule is not installed |
