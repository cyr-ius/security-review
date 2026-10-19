# Internal rules

Every scan rule and every checklist is stored in the **database**: every instance of the server
sharing the database applies the same rules. Your security teams can add scan rules and
checklist items, edit the default rules and enable or disable any rule, **without touching the
code**.

Rules are managed with the `security-review-controller rules` command (import and export of
TOML packs, enabling, disabling, deletion) or from the **Rules** screen of the
[web interface](../usage/web-interface.md). Checklist items are managed from the **Checklists** screen of
this interface, or with the TOML packs of the `rules` command. Both screens also
[import and export the TOML packs](#import-and-export-in-the-web-interface).

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

Python scans also include `PY-026`, a bounded Tree-sitter analysis for direct local flows from
`input()` or common request fields (`request.args`, `request.form`, and similar) into dynamically
constructed SQL passed to `execute`, `executemany`, or `text`. It is intentionally narrow and
does not replace a full SAST analysis. It follows arguments and returned values through direct
calls to local functions in the same file. Bound query parameters are not reported.

TypeScript, JavaScript, and Angular scans also include `NG-021`, which tracks simple local flows
from URL query/route data into `innerHTML` assignments or Angular `bypassSecurityTrust*` calls.
It recognizes `DomSanitizer.sanitize(SecurityContext.HTML, value)` as a sanitizer barrier and does
not report text-only DOM updates. This focused check is not a full browser taint analysis; it does
not infer sanitizer wrappers or indirect calls. It follows tainted arguments and returned values
through directly called local function declarations and arrow functions in the same file.

The same scans include `NG-022` for `message` event listeners that read `event.data` without
checking `event.origin`. The check is limited to inline callbacks passed to `addEventListener`;
origin validation delegated to another function is not inferred.

Java scans also include `JV-019`, a bounded Tree-sitter check that follows request data through
Servlet request getters and Spring `@RequestParam`, `@PathVariable`, `@RequestBody`, and
`@RequestHeader` parameters are treated as untrusted sources. The analysis tracks local
assignments, string concatenation, `String.format`, `concat`, `StringBuilder.append` and
`toString`, plus arguments and returned values across direct local method calls. SQL execution
methods on JDBC/JPA APIs are sinks. It does not report values bound separately with
`PreparedStatement` or JPA `setParameter`. The analysis does not resolve overloads, fields,
framework wrappers, or calls across files, and does not infer arbitrary validation or escaping
as a sanitizer.

Other focused additions include `PY-027` for explicitly disabled JWT signature verification,
`JV-018` for a direct request value passed to JNDI `lookup`, and `NG-023` for assignments that
mutate `__proto__` or `constructor.prototype`. These are line-level patterns and do not infer
indirect data flows; review the surrounding code before deciding whether a finding is exploitable.

```bash
security-review-controller rules import examples/rules/company.toml   # import a pack
security-review-controller rules list --custom                        # check
```

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
- The command does not follow symbolic links; a pack is limited to 256 KiB.

```bash
security-review-controller rules disable PY-008            # too noisy default rule
security-review-controller rules export -o rules.toml      # backup or review
security-review-controller rules import --replace rules.toml
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
domain = "company"                           # "company" is added to EVERY review prompt
id = "ACME-CL-01"
title = "Tenant isolation"
what_to_look_for = "Every query is filtered by the tenant of the token."
cwe = "CWE-639"
```

A full example is provided in `examples/rules/company.toml`.

## Behavior

- An `id` equal to a default rule **edits** it (it then shows as `modified` and is no longer
  updated by new versions of the server).
- A new `domain` can be used at once with `get_review_checklist`, and the review prompts name it
  for the agent to fetch.
- A change (CLI, web interface) is picked up by every running server **within a few seconds**,
  without restart; the `reload_rules` tool and the **Reload** button of the **Rules** screen apply
  it immediately. Changes made in the **Checklists** screen reload the registry immediately.
- A stored rule that no longer passes the validation is **ignored and reported** (`list_rules`
  tool, `load_errors` field); if the database cannot be reached, the default rules of the
  `default_rules.toml` file apply.
- Patterns with nested quantifiers (`(a+)+`), too long (500 characters) or matching the empty
  string are refused. Lines longer than 2000 characters are truncated before analysis.
- `security-review-ci code-scan` applies the rules of the database of the controller.

!!! warning "Trusted content"
    Internal rules are **trusted** content: only the operators who have access to the database
    (CLI) and the `admin` role of the web interface can change them. Version the packs in a
    reviewed repository and deploy them with `rules import --replace`.

## Default rules by platform

| Family | Main coverage |
|---|---|
| `GEN-*` (every language) | Hard-coded credentials, private keys, cloud keys, tokens with a known format (GitHub, GitLab, Slack, Google, Stripe, npm), credentials in a URL, hard-coded JWT, obsolete SSL/TLS, secrets written to logs, plain HTTP |
| `PY-*` (Python) | `eval`/`exec`, deserialization (pickle, `torch.load`, `joblib`...), YAML, shell commands, formatted SQL, disabled TLS, weak crypto or ECB mode, non-cryptographic randomness, XXE (lxml), SSTI, hard-coded `SECRET_KEY`, `ALLOWED_HOSTS = ['*']`, disabled CSRF, `mark_safe`, cookies without `Secure`/`HttpOnly`, SSRF, non-constant-time secret comparison, temporary files, disabled JWT signature verification |
| `JV-*` (Java) | Deserialization (including XStream, SnakeYAML), OS commands, concatenated SQL and LDAP, request-to-dynamic-SQL flows through local calls (`JV-019`), XXE, CSRF, CORS, weak crypto, "trust all" TLS, paths and redirects built from the request, SSRF from direct request URLs, JNDI lookup from request data, SpEL/EL, cookies, `Random`, `printStackTrace` |
| `NG-*` (Angular, JavaScript, TypeScript) | Sanitizer bypass, `innerHTML` and other HTML sinks, URL-to-DOM flows, unchecked `message` origins, prototype chain mutation, `eval`, `setTimeout` with a string, tokens in web storage, `postMessage('*')`, disabled XSRF, open redirects; on the Node.js side: shell commands, interpolated SQL, `$where`, file paths, open CORS, disabled TLS, `jwt.decode`, weak crypto |
| `CFG-*` (Docker, Compose, Kubernetes, servers) | Privileged or root container, Docker socket, host namespaces, dangerous capabilities, privilege escalation, sensitive mounts, exposed database ports, secrets in `ENV`/`ARG`, remote `ADD`, default passwords, services without authentication, `*` or `cluster-admin` RBAC, public buckets, `*` CORS, directory listing, weak SSH, `curl \| sh`, debug |
| `GL-*` (GitLab CI) | Remote `include`, printed secrets, DinD without TLS, `allow_failure`, CI token on the command line, untrusted variables evaluated by a shell, `CI_DEBUG_TRACE`, public artifacts, `GIT_SSL_NO_VERIFY` |
| `JK-*` (Jenkinsfile) | Injection in `sh`, unpinned shared library, `agent any`, disabled sandbox, credential interpolated in a Groovy string, internal `Jenkins.instance` API |
| `CI-*` (common CI/CD) | Disabled TLS or signature verification, shell tracing, install without lockfile |
| `SP-*` (Spring) | Exposed or unprotected Actuator, H2 console, disabled TLS, SQL logs, `permitAll`, entities bound to the request body, returned error details, password in the configuration, `web.ignoring()`, disabled security headers |
| `FA-*` (FastAPI) | `*` CORS or `.*` regex, unverified JWT signature, `reload` mode |

The default checklists cover the `python`, `java`, `angular`, `api`, `config`, `cicd` and
`dependencies` domains (for example: validation of OAuth/OIDC tokens, webhooks, sensitive
business flows, Kubernetes hardening, RBAC, proxy headers, lockfile integrity).
`get_review_checklist` and the **Checklists** screen of the web interface show them in full.

Languages accepted by `scan_code`: `python`, `java`, `typescript`, `javascript`, `angular`,
`config`, `yaml`, `docker`, `gitlab-ci`, `jenkins` (aliases: `jenkinsfile`, `groovy`, `gitlab`,
`yml`...).

### Checklists in review prompts

| Prompt | Embedded checklists |
|---|---|
| `security-review` | The checklists of `language` (`python`, `java`, `angular` for `typescript` and `javascript`, `config` and `cicd` for pipelines), then `api` |
| `codebase-review` | The checklists of `languages`, then `api`, `config` and `cicd` |
| `api-security-review` | `api` |
| `configuration-review` | `config`, plus `cicd` when the files look like a pipeline |
| `dependency-review` | `dependencies` |

The `company` checklist is added to every prompt. The other domains, internal ones included, are
named at the end of the checklists: the agent fetches with `get_review_checklist` those that
apply to the code it reviews. It then declares the outcome of each item it walked through in
`save_security_report` ([review coverage](../usage/prompts-tools.md#review-coverage)).

## Suppressing a false positive

Add a comment on the line concerned:

```python
subprocess.run(cmd, shell=True)  # secreview:ignore PY-004 fixed command, no user input
```

Without an identifier, every rule of the line is ignored.

Suppressions are **not hidden**: `scan_code` returns them in `suppressed`, and the prompts ask
the agent to report any unjustified suppression (a merge request author could otherwise hide a
vulnerability).
