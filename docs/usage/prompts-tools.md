# Prompts and tools

To understand when the rules, the checklists and the standards apply, and how to write the
`AGENTS.md` file of a project, see [How a review works](how-it-works.md).

## Prompts

| Prompt | Use | Arguments |
|---|---|---|
| `security-review` | General review of Python, Java, Go, C#, Rust, TypeScript/Node.js or Angular code (`language`: one or more languages, for example `python, angular`) | `language`, `code`, `context`, `focus`, `report_language` |
| `api-security-review` | REST API (OWASP API Top 10) | `framework`, `code`, `context`, `focus`, `report_language` |
| `configuration-review` | Dockerfile, CI/CD, Spring, YAML, properties | `config_type`, `content`, `context`, `focus`, `report_language` |
| `codebase-review` | Review of the **whole repository** (not only a diff) | `languages`, `scan_results`, `context`, `focus`, `report_language` |
| `dependency-review` | Manifests and lockfiles (supply chain) | `ecosystem`, `files`, `context`, `report_language` |
| `triage-report` | Re-qualify the findings of a stored report | `report_id`, `context`, `report_language` |
| `development-standards` | Gives the assistant the [development standards](../advanced/standards.md) of its stack **before it writes code** | `technologies`, `files`, `task`, `context` |

If `code` is empty, the prompt asks the agent to read the files of its workspace. Every review
prompt ends with the instruction to call `save_security_report` once; `development-standards`
saves nothing.

Each review prompt embeds the checklists of its domain (by language for `security-review` and
`codebase-review`, aliases such as `py` or `ts` accepted) and the `company` checklist, then names
the other available checklists, internal domains included, for the agent to fetch with
`get_review_checklist` when they apply ([details](../advanced/rules.md#checklists-in-review-prompts)).

### Report language

`report_language` sets the language of the agent's reply and of the written fields of the
stored report (summary, scope, titles, descriptions, recommendations), for example `French`,
`fr` or `pt-BR`. Without this argument, the prompt uses
[`SECREVIEW_REPORT_LANGUAGE`](../reference/configuration.md) when it is set, else the language
chosen by an administrator in the [**Report language**](web-interface.md#screens) screen of the
web interface; if none is set, the agent chooses (usually the language of the conversation).

An agent that reviews **without a prompt**, with the tools only (a common case: an MCP prompt is
a command started by the user, the agent cannot call it itself), gets the same configured
language (variable, else **Report language** screen) in the results of `get_review_checklist`
("Report language" section) and of `scan_code` (`report_language` field, `null` if the agent
chooses).

Code, excerpts, paths, rule ids, CWE / OWASP references and the fixed values expected by the
tools (severity, category, status) stay unchanged: the gate, the SARIF export and the trends
work whatever the language.

The value only accepts letters, spaces, `-`, `_` and parentheses (40 characters at most), so
that it cannot carry instructions; otherwise the prompt is refused.

## Tools

| Tool | Role |
|---|---|
| `list_checklists` / `get_review_checklist` | Checklists by domain: `python`, `java`, `angular`, `node`, `go`, `csharp`, `rust`, `api`, `config`, `cicd`, `dependencies` and internal domains |
| `scan_code` | Quick pattern scan plus focused Tree-sitter checks for request-to-SQL flows (Python, Java, Go, C#, Rust, Node.js), Angular DOM flows, and unchecked message origins (leads to check, **not** a full SAST). Masked excerpts, invisible characters shown as `<U+XXXX>` |
| `save_security_report` | **Stores the report and its findings in the database** |
| `get_security_report` | Reads a report back (Markdown by default, or JSON) |
| `list_security_reports` | List filtered by project / risk level / review type / author, with pagination |
| `propose_finding_status` | **Proposes** `fixed`, `accepted` or `false_positive` with a reason; never changes the status ([status of a finding](#status-of-a-finding)) |
| `get_project_security_posture` | Open findings by severity (useful as a CI safeguard) |
| `check_project_gate` | CI gate: `passed` is false while an **open** finding reaches the `fail_on` threshold |
| `export_sarif` | SARIF 2.1.0 export of a report or a project |
| `get_trend_report` | Trend of a project: new / fixed, backlog, risk score, MTTR |
| `scan_dependencies` | Analysis of a manifest, lockfile or CycloneDX SBOM: vulnerable versions + hygiene |
| `get_advisory_status` | Size and age of the vulnerability database |
| `request_enrollment` | Requests a project that does not exist yet, for an administrator to approve; no token is created and the current token gains no project: an administrator gives access to it ([enrollment](../advanced/http.md#enrollment-request-the-project)) |
| `list_development_standards` / `get_development_standards` | [Development standards](../advanced/standards.md): catalog, then the standards to apply for technologies or file names |
| `list_rules` / `reload_rules` | Active rules ([default and custom](../advanced/rules.md), stored in the database), loading errors, immediate reload |

On the HTTP transport, a restricted token can only use the report tools on its allowed
projects; `reload_rules` is refused to it (see
[tokens restricted to a project](../advanced/http.md#tokens-restricted-to-a-project)).
A token tied to several projects can use the report tools on each of them. A
[personal MCP token](web-interface.md#personal-mcp-and-ci-tokens) reaches the projects of its user: for
another project, an administrator gives the user access to it (`request_enrollment` requests
it first when it is new).

### Enrollment server

On the HTTP transport, a client that connects **without a token** reaches a restricted
server, with the same name, that only exposes (a token that is unknown, revoked or expired gets
a `401` instead, see [rejected token](../advanced/http.md#rejected-token-sign-in-again)):

| Item | Role |
|---|---|
| `request_enrollment` | Requests the project (`project`, optional `requested_by`), for an administrator to approve, and returns `web_url` and `next_steps`: the user signs in to the web interface and creates a personal MCP token; never a token |
| Prompts `security-review`, `api-security-review`, `configuration-review`, `codebase-review`, `dependency-review` | Optional `project` argument; explain to the agent how to get a token instead of running the review |

See [enrollment](../advanced/http.md#enrollment-request-the-project).

## Resources

- `report://{report_id}`: a stored report;
- `checklist://{domain}`: the checklist of a domain;
- `standards://catalog`: the catalog of the [development standards](../advanced/standards.md);
- `standard://{slug}`: a development standard.

## Stored report

`save_security_report` receives:

- `project` (normalized, see [project name](#project-name)), `summary`;
- a list of `findings`: `title`, `severity`, `description`, and optionally `cwe`, `owasp`,
  `file_path`, `line_start`, `line_end`, `evidence`, `recommendation`, `category`;
- `repository`, `branch`, `commit_sha`, `reviewer`, `scope`;
- `review_type`: the kind of review, given by each review prompt (see below);
- `author`: the username of the developer (see [author of a report](#author-of-a-report));
- `checklist_results` and `scan_rules`: the coverage of the review (see
  [review coverage](#review-coverage)).

Each field is bounded: `repository` (500 characters), `branch` (200), `commit_sha` (64),
`reviewer` (200), and each text (`summary`, `scope`, and the `description`, `evidence` and
`recommendation` of a finding) to `SECREVIEW_MAX_CONTENT_CHARS`; a longer value refuses the
report.

The **risk level** of the report is computed (highest severity of the findings). The
`risk_level` parameter can only raise it, never lower it.

### Project name

Reports, tokens, roles and gates are grouped by project name. The server **normalizes** every
project name it receives (MCP tools, REST API, pipeline client, CLI), so that the members of a
team who name the same repository differently reach the same project:

- the name is lowercased (after Unicode NFKC normalization);
- a git remote URL or a path keeps its last segment, without `.git`;
- every run of characters other than letters and digits (spaces, dots, underscores, dashes,
  punctuation) becomes a single `-`, removed at both ends.

| Given name | Stored project |
|---|---|
| `security-review-mcp`, `Security Review MCP`, `security_review_mcp` | `security-review-mcp` |
| `cyr-ius/security-review-mcp`, `https://github.com/cyr-ius/security-review-mcp.git` | `security-review-mcp` |
| `git@github.com:cyr-ius/Security_Review_MCP.git` | `security-review-mcp` |

A name with no letter or digit, or longer than 200 characters once normalized, is refused.
Since only the repository name is kept, two repositories with the same name in different
organizations or groups share one project: give one of them a distinct name.

### Review type

Each review prompt tells the model which `review_type` to pass, so the reports and their
findings can be told apart and filtered in the [web interface](web-interface.md) and in
`list_security_reports`:

| `review_type` | Set by |
|---|---|
| `security-review` | prompt `security-review` |
| `api-security-review` | prompt `api-security-review` |
| `configuration-review` | prompt `configuration-review` |
| `dependency-review` | prompt `dependency-review` |
| `codebase-review` | prompt `codebase-review` |
| `code-scan` | `security-review-ci scan-code --save` |
| `dependency-scan` | `security-review-ci scan-deps --save`, `security-review-mcp scan-deps --save` |
| `other` | any other review (manual, without a prompt) |

The field is optional: a report saved without it has no type. Any other value is refused.
The type is declared by the client: it labels and filters reports, it never grants a right
nor changes a gate.
Reports saved by the CLI scans before this field existed get their type when the database is
upgraded.

### Author of a report

A token is configured on a device, which several developers may share (a pipeline token, a
shared workstation): its label does not say who worked on the reviewed code. Each report therefore carries two fields:

| Field | Filled by | Value |
|---|---|---|
| `author` | the client | Username of the developer: the review prompts ask the agent for the output of `git config user.email` (else `git config user.name` or the login name), and to omit it rather than guess. With the CLI scans: `--author`. |
| `submitted_by` | the server | Label of the bearer token that saved the report (empty with stdio and the CLI). The client cannot change it. |

`author` is at most 200 characters: letters, digits, spaces and `. @ _ + - ' ,` only (no
Markdown nor HTML, as it is copied into the Markdown export); a blank value is not stored.
It is **declared, not authenticated**: use it to see who to talk to and to filter the reports
(`list_security_reports`, [web interface](web-interface.md)), never as a proof of identity;
`submitted_by` says which token actually sent the report. In the web interface and the REST
API, only a holder of `users.manage` or `tokens.manage` sees the `author`; the others see the
token label.

### Review coverage

The review prompts ask the agent to declare what it actually checked, so that a person can
tell a clean review from one that skipped the checklist:

| Field | Content |
|---|---|
| `checklist_results` | Each checklist item walked through, with its outcome: `ok` (verified, nothing found), `issue` (reported as a finding), `not_applicable`, `not_verifiable` (the reviewed code was not enough to judge it) |
| `scan_rules` | The rule id of every lead returned by `scan_code`, confirmed or dismissed |

The server checks them against the active rules and checklists when it stores the report:

- an unknown checklist item or rule is **not stored** and is named in the `warnings` of the
  answer; the report is never refused for it;
- the title and domain of each item are taken from the server, not from the agent;
- every item of a checklist domain the review used but did not report is stored as
  `not_covered`, and listed in `coverage.not_covered` of the answer;
- a finding `rule_id` that looks like a rule or checklist id (`PY-004`, `ACME-CL-01`) but
  matches neither gets a warning; advisory ids (`GHSA-...`, `CVE-...`) are not checked;
- a report without any checklist result gets a warning: its coverage is unknown.

At most 500 checklist results and 500 rules per report. The coverage is **declared by the
agent**: it shows what the agent says it did, not a proof; a rule of `scan_rules` cited by no
finding is a lead the agent dismissed. The CLI scans declare no coverage. The report page of the
[web interface](web-interface.md) and the Markdown export show it.

### Status of a finding

A finding is `open` when it is saved. **An agent never closes it**: the reviewed code is
untrusted input, and a prompt injection in a comment could otherwise lead the agent to dismiss
its own findings and unblock the [gate](gate.md). The server also makes hidden text visible in
what it hands back to the agent and reports injected instructions
([prompt injection](../reference/security.md#security-of-the-server-itself)).

- `propose_finding_status` stores a **proposal** (`fixed`, `accepted` or `false_positive`) with
  the agent's reason (10 to 1000 characters, secrets masked) and the label of its token. The
  status, the posture and the gate do not change. A new proposal replaces the previous one. It
  is written to the [audit log](../advanced/audit-metrics.md#audit-log), like the decision that follows.
- A person with the `triager` or `admin` role applies or rejects it in the
  [web interface](web-interface.md#triage-of-findings). `accepted` and `false_positive` need a
  reason, an approver (the logged-in user) and an expiry date; from that date the finding counts
  as open again.

This holds for every token role, `admin` included: the MCP server has no tool that changes a
status.

!!! info "Secret masking"
    Secrets found in `summary`, `description`, `evidence` and `recommendation` (passwords,
    tokens, `SECRET_KEY`, AWS keys, GitHub, GitLab, Slack, Google, Stripe and npm tokens, JWT,
    private keys, credentials in URLs) are masked before storage. Permission levels (`read`,
    `write`, `none`, as in the GitHub Actions `id-token: write`) are not secrets and are kept. It
    is a safety net: the agent must also avoid copying them.
