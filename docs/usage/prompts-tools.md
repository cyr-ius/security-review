# Prompts and tools

## Prompts

| Prompt | Use | Arguments |
|---|---|---|
| `security-review` | General Python / Java / Angular review | `language`, `code`, `context`, `focus`, `report_language` |
| `api-security-review` | REST API (OWASP API Top 10) | `framework`, `code`, `context`, `focus`, `report_language` |
| `configuration-review` | Dockerfile, CI/CD, Spring, YAML, properties | `config_type`, `content`, `context`, `focus`, `report_language` |
| `codebase-review` | Review of the **whole repository** (not only a diff) | `languages`, `scan_results`, `context`, `focus`, `report_language` |
| `dependency-review` | Manifests and lockfiles (supply chain) | `ecosystem`, `files`, `context`, `report_language` |
| `triage-report` | Re-qualify the findings of a stored report | `report_id`, `context`, `report_language` |
| `development-standards` | Gives the assistant the [development standards](standards.md) of its stack **before it writes code** | `technologies`, `files`, `task`, `context` |

If `code` is empty, the prompt asks the agent to read the files of its workspace. Every review
prompt ends with the instruction to call `save_security_report` once; `development-standards`
saves nothing.

### Report language

`report_language` sets the language of the agent's reply and of the written fields of the
stored report (summary, scope, titles, descriptions, recommendations), for example `French`,
`fr` or `pt-BR`. Without this argument, the prompt uses the language chosen by an administrator
in the [**Settings**](web-interface.md#screens) screen of the web interface, else
[`SECREVIEW_REPORT_LANGUAGE`](../reference/configuration.md); if none is set, the agent chooses
(usually the language of the conversation). The screen can also force "the agent chooses"
despite the variable.

An agent that reviews **without a prompt**, with the tools only (a common case: an MCP prompt is
a command started by the user, the agent cannot call it itself), gets the same configured
language (**Settings** screen, else variable) in the results of `get_review_checklist`
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
| `list_checklists` / `get_review_checklist` | Checklists by domain: `python`, `java`, `angular`, `api`, `config` |
| `scan_code` | Quick pattern scan (leads to check, **not** a SAST). Masked excerpts |
| `save_security_report` | **Stores the report and its findings in the database** |
| `get_security_report` | Reads a report back (Markdown by default, or JSON) |
| `list_security_reports` | List filtered by project / risk level, with pagination |
| `update_finding_status` | `open`, `fixed`, `accepted`, `false_positive` |
| `get_project_security_posture` | Open findings by severity (useful as a CI safeguard) |
| `check_project_gate` | CI gate: `passed` is false while an **open** finding reaches the `fail_on` threshold |
| `export_sarif` | SARIF 2.1.0 export of a report or a project |
| `get_trend_report` | Trend of a project: new / fixed, backlog, risk score, MTTR |
| `scan_dependencies` | Analysis of a manifest / lockfile: vulnerable versions + hygiene |
| `get_advisory_status` | Size and age of the vulnerability database |
| `request_enrollment` | Requests a token for a first project or the addition of a project to the presented token, after approval by an administrator ([enrollment](../getting-started/http.md#enrollment-a-project-requests-its-token)) |
| `list_development_standards` / `get_development_standards` | [Development standards](standards.md): catalog, then the standards to apply for technologies or file names |
| `list_rules` / `reload_rules` | Active rules ([default and custom](rules.md), stored in the database), loading errors, immediate reload |

On the HTTP transport, a restricted token can only use the report tools on its allowed
projects; `reload_rules` is refused to it (see
[tokens restricted to a project](../getting-started/http.md#tokens-restricted-to-a-project)).
A token tied to several projects can use the report tools on each of them;
`request_enrollment` requests the addition to the current token without creating nor revealing
a new secret.

### Enrollment server

On the HTTP transport, a client that connects **without a token** (or with a token whose
enrollment is not approved yet) reaches a restricted server, with the same name, that only
exposes:

| Item | Role |
|---|---|
| `request_enrollment` | Files the request for a project and returns the token (shown once) |
| `get_enrollment_status` | `pending` if the presented token awaits approval, `not_enrolled` without a token |
| Prompts `security-review`, `api-security-review`, `configuration-review`, `codebase-review`, `dependency-review` | Optional `project` argument; explain to the agent how to request access instead of running the review |

See [enrollment](../getting-started/http.md#enrollment-a-project-requests-its-token).

## Resources

- `report://{report_id}`: a stored report;
- `checklist://{domain}`: the checklist of a domain;
- `standards://catalog`: the catalog of the [development standards](standards.md);
- `standard://{slug}`: a development standard.

## Stored report

`save_security_report` receives:

- `project`, `summary`;
- a list of `findings`: `title`, `severity`, `description`, and optionally `cwe`, `owasp`,
  `file_path`, `line_start`, `line_end`, `evidence`, `recommendation`, `category`;
- `repository`, `branch`, `commit_sha`, `reviewer`, `scope`.

The **risk level** of the report is computed (highest severity of the findings). The
`risk_level` parameter can only raise it, never lower it.

!!! info "Secret masking"
    Secrets found in `summary`, `description`, `evidence` and `recommendation` (passwords,
    tokens, `SECRET_KEY`, AWS keys, GitHub, GitLab, Slack, Google, Stripe and npm tokens, JWT,
    private keys, credentials in URLs) are masked before storage. It is a safety net: the agent
    must also avoid copying them.
