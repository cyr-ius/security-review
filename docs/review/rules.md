# Rules

A scan rule is a pattern searched in the code by `scan_code` and `security-review-ci scan-code`:
it gives leads that the agent confirms by reading the code. Every rule is stored in the
**database**: every instance of the server sharing the database applies the same rules. Your
security teams can add rules, edit the default rules and enable or disable any rule, **without
touching the code**.

Rules are managed with the `security-review-controller rules` command (import and export of
TOML packs, enabling, disabling, deletion) or from the **Rules** screen of the
[web interface](../usage/index.md), which also
[imports and exports the TOML packs](#import-and-export-in-the-web-interface). The same packs
carry the [checklists](checklists.md).

## Default rules

The server ships with a set of default rules and checklists, described in the
`default_rules.toml` file of the package (same format as a [pack](#pack-format)).

- **At first start** (creation of the database by the server or by a CLI command), this content
  is copied into the database.
- **At every start**, the default rules added by a new version of the server are added, and the
  ones it fixed are updated, **unless an administrator edited them**: an edited rule is never
  overwritten.
- A default rule can be **edited** (pattern, severity, advice...) or **disabled**, but not
  deleted. `rules list` then shows it with the `modified` origin (`modified: true` in JSON).
- If the database cannot be reached or was never initialized, the server applies the rules of
  the file directly: the scan never runs without rules.
- To go back to the default rules, use `rules import --replace` (see below).

## `rules` command

| Command | Role |
|---|---|
| `rules list [--language L] [--custom] [--format text\|json]` | Lists every rule with its origin (`builtin`, `modified`, `custom`) and its state (`enabled` / `disabled`) |
| `rules import PATH… [--replace]` | Imports TOML packs (files, or folders whose `*.toml` are read in alphabetical order) |
| `rules export [-o FILE]` | Exports as a re-importable TOML pack what differs from the defaults (custom or edited rules, disabled rules) |
| `rules disable ID…` / `rules enable ID…` | Disables or enables **default or custom** rules |
| `rules delete ID…` | Deletes custom rules or custom checklist items |

- The import is **all or nothing**: if an entry is invalid, nothing is imported and the command
  lists the errors (exit code `2`).
- Without `--replace`, the import adds or replaces the entries by identifier and adds the
  identifiers of `disabled_rules` to the rules already disabled. With `--replace`, the stored
  content is first **reset to the defaults** (custom rules and checklists deleted, edits
  undone, every rule enabled again): the database then matches the default rules plus the
  imported packs (handy to version the rules in a reviewed repository and deploy them from the
  CI).
- `enable`, `disable` and `delete` refuse an unknown identifier without changing anything. A
  default rule or checklist item cannot be deleted: disable or edit it.
- A **new** custom rule or checklist item cannot use the prefix of a default family (`PY`,
  `GEN`, `API`, `DEP`... see [Default rules by platform](#default-rules-by-platform)): these
  prefixes are reserved for the defaults of later versions, which are never copied over an
  existing entry. Use your own prefix, such as `ACME-001`. Reusing the identifier of a default
  entry stays allowed: it edits that entry. The import, the CLI and the web interface refuse
  such an identifier with the reason.
- The command does not follow symbolic links; a pack is limited to 256 KiB.

```bash
security-review-controller rules disable PY-008            # too noisy default rule
security-review-controller rules export -o rules.toml      # backup or review
security-review-controller rules import --replace rules.toml
```

```bash
security-review-controller rules import examples/rules/company.toml   # import a pack
security-review-controller rules list --custom                        # check
```

## Import and export in the web interface

The **Rules** and **Checklists** screens have **Export** and **Import** buttons (permission
`rules.manage`):

- **Export** downloads a TOML pack of what differs from the defaults, like `rules export`:
  `security-review-rules.toml` (custom or edited rules, disabled rules) from the **Rules**
  screen, `security-review-checklists.toml` (custom or edited checklist items) from the
  **Checklists** screen.
- **Import** reads a TOML pack chosen on your computer (256 KiB at most), on either screen: the
  rules, checklist items and `disabled_rules` it holds are imported, **all or nothing**, like
  `rules import` without `--replace` (entries added or replaced by identifier, the other entries
  kept). The message gives the number of imported entries, or the errors when nothing was
  imported. To reset the content to the defaults, use `rules import --replace` in the CLI.

| Method | Route | Role |
|---|---|---|
| `GET` | `/api/v1/packs/rules[?sections=rules\|checklist]` | `rules.manage`: TOML pack (both sections by default) |
| `POST` | `/api/v1/packs/rules` | `rules.manage`: body `{"name": "acme.toml", "content": "<TOML>"}`; `422` with the errors if the pack is invalid |

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" -o rules.toml \
  "https://secreview.example.com/api/v1/packs/rules?sections=rules"
```

## Pack format

A TOML pack is the exchange format of `rules import` and `rules export`:

```toml
disabled_rules = ["PY-008"]                  # disabled rules (default or custom)

[[rules]]
id = "ACME-001"                              # unique identifier, e.g. ACME-001 (50 characters max.)
title = "Direct JDBC connection"
severity = "medium"                          # critical | high | medium | low | info
cwe = "CWE-400"                              # optional
languages = ["java"]                         # or ["*"]
pattern = '''DriverManager\.getConnection\s*\('''
advice = "Use the managed DataSource."
ignore_case = true                           # optional (true by default)

[[checklist]]
domain = "company"                           # "company" and "*" are added to EVERY review prompt
id = "ACME-CL-01"
title = "Tenant isolation"
what_to_look_for = "Every query is filtered by the tenant of the token."
cwe = "CWE-639"
```

A full example is provided in `examples/rules/company.toml`.

## Behavior

- An `id` equal to a default rule **edits** it (it then shows as `modified` and is no longer
  updated by new versions of the server).
- A change (CLI, web interface) is picked up by every running server **within a few seconds**,
  without restart; the `reload_rules` tool and the **Reload** button of the **Rules** screen apply
  it immediately.
- A stored rule that no longer passes the validation is **ignored and reported** (`list_rules`
  tool, `load_errors` field); if the database cannot be reached, the default rules of the
  `default_rules.toml` file apply.
- Patterns with nested quantifiers (`(a+)+`), too long (500 characters) or matching the empty
  string are refused. Lines longer than 2000 characters are truncated before analysis.
- `security-review-ci scan-code` applies the rules of the database of the controller.

!!! warning "Trusted content"
    Internal rules are **trusted** content: only the operators who have access to the database
    (CLI) and the `admin` role of the web interface can change them. Version the packs in a
    reviewed repository and deploy them with `rules import --replace`.

## Default rules by platform

| Family | Main coverage |
|---|---|
| `GEN-*` (every language) | Hard-coded credentials, private keys, cloud keys, tokens with a known format (GitHub, GitLab, Slack, Google, Stripe, npm), credentials in a URL, hard-coded JWT, obsolete SSL/TLS, secrets written to logs, plain HTTP, clear-text LDAP, FTP, AMQP, Redis, MQTT or Telnet URLs, TLS disabled in a connection setting (`sslmode=disable`, `useSSL=false`, Kafka `PLAINTEXT`), unverified certificate outside HTTP (`TLS_REQCERT never`, `trustServerCertificate=true`) |
| `PY-*` (Python) | `eval`/`exec`, deserialization (pickle, `torch.load`, `joblib`...), YAML, shell commands, formatted SQL, disabled TLS, weak crypto or ECB mode, non-cryptographic randomness, XXE (lxml), SSTI, hard-coded `SECRET_KEY`, `ALLOWED_HOSTS = ['*']`, disabled CSRF, `mark_safe`, cookies without `Secure`/`HttpOnly`, SSRF, non-constant-time secret comparison, temporary files, disabled JWT signature verification |
| `JV-*` (Java) | Deserialization (including XStream, SnakeYAML), OS commands, concatenated SQL and LDAP, request-to-dynamic-SQL flows through local calls (`JV-019`), XXE, CSRF, CORS, weak crypto, "trust all" TLS, paths and redirects built from the request, SSRF from direct request URLs, JNDI lookup from request data, SpEL/EL, cookies, `Random`, `printStackTrace` |
| `NG-*` (Angular, JavaScript, TypeScript) | Sanitizer bypass, `innerHTML` and other HTML sinks, URL-to-DOM flows, unchecked `message` origins, prototype chain mutation, `eval`, `setTimeout` with a string, tokens in web storage, `postMessage('*')`, disabled XSRF, open redirects; on the Node.js side: shell commands, interpolated SQL, `$where`, file paths, open CORS, disabled TLS, `jwt.decode`, weak crypto |
| `TS-*` (TypeScript and JavaScript backend: Express, NestJS, Fastify, Prisma, TypeORM, Sequelize) | Unsafe raw SQL (`$queryRawUnsafe`, interpolated `where`, `literal`), request object used as a NoSQL filter, request body bound to a model, `vm`/`vm2`, `unserialize`, hard-coded JWT or cookie secret, session cookie without `httpOnly`/`secure`, SSRF, `RegExp` built from the request, reflected response, `ValidationPipe` without whitelist, huge body limit, `trust proxy` set to `true`, dotfiles served, non-constant-time secret comparison |
| `GO-*` (Go) | SQL built with `fmt.Sprintf`, `sh -c`, `InsecureSkipVerify`, MD5/SHA-1/DES/RC4, `math/rand`, `template.HTML` conversions, paths, SSRF and redirects from the request, server without timeouts, zip slip, `ParseUnverified` and `none` JWT, open CORS, cookies, `net/http/pprof`, obsolete TLS, world-writable modes, unbounded body read |
| `CS-*` (C#, ASP.NET Core, Razor, Blazor) | Concatenated or interpolated SQL (ADO.NET, `FromSqlRaw`, Dapper), `BinaryFormatter` and `TypeNameHandling`, `cmd`/`powershell`, certificate validation disabled, weak crypto, `Random`, XXE, `Html.Raw`/`MarkupString`, antiforgery disabled, open CORS, developer exception page, weakened JWT validation, cookies, paths, redirects and SSRF from the request, LDAP filters, obsolete TLS, XSLT scripts |
| `RS-*` (Rust) | SQL built with `format!`, `sh -c`, `danger_accept_invalid_certs`, `unsafe` blocks and memory-unsafe primitives (`transmute`, `from_raw_parts`), weak crypto, seeded or non-cryptographic RNG, paths from the request, permissive CORS, disabled JWT validation, cookies, HTML built with `format!` or `PreEscaped`, `bincode` without a limit, obsolete TLS |
| `CFG-*` (Docker, Compose, Kubernetes, servers) | Privileged or root container, Docker socket, host namespaces, dangerous capabilities, privilege escalation, sensitive mounts, exposed database ports, secrets in `ENV`/`ARG`, remote `ADD`, default passwords, services without authentication, `*` or `cluster-admin` RBAC, public buckets, `*` CORS, directory listing, weak SSH, `curl \| sh`, debug, WAF disabled, in detection-only mode or with broad exclusions (ModSecurity, Coraza, Ingress NGINX) |
| `GL-*` (GitLab CI) | Remote `include`, printed secrets, DinD without TLS, `allow_failure`, CI token on the command line, untrusted variables evaluated by a shell, `CI_DEBUG_TRACE`, public artifacts, `GIT_SSL_NO_VERIFY` |
| `JK-*` (Jenkinsfile) | Injection in `sh`, unpinned shared library, `agent any`, disabled sandbox, credential interpolated in a Groovy string, internal `Jenkins.instance` API |
| `CI-*` (common CI/CD) | Disabled TLS or signature verification, shell tracing, install without lockfile |
| `SP-*` (Spring) | Exposed or unprotected Actuator, H2 console, disabled TLS, SQL logs, `permitAll`, entities bound to the request body, returned error details, password in the configuration, `web.ignoring()`, disabled security headers |
| `FA-*` (FastAPI) | `*` CORS or `.*` regex, unverified JWT signature, `reload` mode |
| `AI-*` (every language, AI assistant instructions) | Text hidden from a person but read by an AI assistant: Unicode tags and supplementary variation selectors (`AI-001`), bidirectional controls of Trojan Source (`AI-002`), zero-width characters (`AI-003`); text addressed to the assistant (override of its instructions, chat-template tokens such as `<\|im_start\|>`, `AI-004`) or asking to dismiss a finding (`AI-005`) |

Languages accepted by `scan_code`: `python`, `java`, `typescript`, `javascript`, `angular`,
`go`, `csharp`, `rust`, `config`, `yaml`, `docker`, `gitlab-ci`, `jenkins`, `agent-instructions` (files that steer an
AI assistant: `AGENTS.md`, `CLAUDE.md`, `.cursorrules`...; only the rules of every language
apply) (aliases: `golang`, `c#`, `cs`, `dotnet`, `rs`, `jenkinsfile`, `groovy`, `gitlab`, `yml`...).

## Suppressing a false positive

Add a comment on the line concerned:

```python
subprocess.run(cmd, shell=True)  # secreview:ignore PY-004 fixed command, no user input
```

Without an identifier, every rule of the line is ignored.

Suppressions are **not hidden**: `scan_code` returns them in `suppressed`, and the prompts ask
the agent to report any unjustified suppression (a merge request author could otherwise hide a
vulnerability).
