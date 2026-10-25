# How a review works

This page explains how the agent reviews the security of the code. It explains when each check
runs. It specifies how to guide the agent with an `AGENTS.md` file.

## The three building blocks

The server provides three kinds of content. The AI agent uses them. A person makes the final
decisions.

| Block | What it is | Who uses it | When |
|---|---|---|---|
| **Rules** | Patterns that spot suspicious lines (automatic scan) | The `scan_code` tool and the pipeline scan | **During** the review and in CI |
| **Checklists** | Points to check by hand, one by one | The agent | **During** the review |
| **Standards** | The coding conventions of your organization, by technology | The agent | **Before** writing the code |

The three blocks are stored in the database. Administrators edit them in the web interface. A
change applies to every agent, without a restart.

### Rules: a lightweight SAST

- A rule is a regular expression. It has an id (`PY-004`), a severity and a CWE.
- A few rules go further. They follow the path of a value inside a file, with Tree-sitter
  (`PY-026`, `NG-021`, `JV-019`, and SQL flows in Go, C#, Rust and Node.js: `GO-019`, `CS-021`,
  `RS-015`, `TS-016`).
- A match is a **lead**, not a vulnerability. The agent must confirm it by reading the code.
- No result does not mean "safe code". It is not a full SAST.

Rule details: [Rules](rules.md).

### Checklists: the expert's eye

- A checklist covers a **domain**: `python`, `java`, `go`, `csharp`, `rust`, `angular`, `node`,
  `api`, `config`, `cicd`, `dependencies`.
- Each item says what to look for. Example: "every query is filtered by the tenant of the
  token".
- Checklists cover what a pattern cannot see: business logic, access rights, flows across
  files.
- The `*` checklist holds the points that apply to every language, and the `company` checklist
  the requirements of your organization. Both are added to **every** review.

Checklist details: [Checklists](checklists.md).

### Standards: write it right from the start

- A standard describes how to code in a technology: naming, tests, errors, security.
- The agent reads it before coding. The code follows your conventions from the first version.
- A standard does not replace the review. It reduces the number of findings.

Standard details: [Development standards](standards.md).

## Steps of a review

Every review prompt gives the agent the same method, in five steps:

1. **Understand the code.** The agent finds the inputs (requests, files, messages) and the
   sensitive points (SQL, commands, HTML).
2. **Run the scan.** The agent calls `scan_code`. It gets leads. It checks them one by one in
   the code.
3. **Walk through the checklists.** The agent checks each item. It notes the outcome: `ok`,
   `issue`, `not_applicable` or `not_verifiable`.
4. **Describe the vulnerabilities.** For each confirmed one, it gives the severity, the CWE,
   the file, the line and a fix.
5. **Save the report.** The agent calls `save_security_report` **once**. It also declares what
   it checked (the [coverage](prompts-tools.md#review-coverage)).

Then a person triages the findings in the [web interface](triage.md).
The agent can only **propose** a status. It never closes a finding.

## How the system picks the rules

The choice is **automatic**. It depends on the language of the scanned code.

- The agent passes the language to `scan_code`: `python`, `java`, `typescript`, `config`...
- The server keeps the rules of this language. It adds the rules valid everywhere (`GEN-*`,
  for example hard-coded secrets).
- Some languages inherit other rules. A `gitlab-ci` file also gets the `yaml` and `config`
  rules.
- A rule disabled by an administrator is never applied.
- A line marked `secreview:ignore` is not hidden. It comes back in `suppressed`, and the agent
  judges whether the exception is justified.

In CI, `security-review-ci scan-code` infers the language of each file from its name (`.py`,
`Dockerfile`, `Jenkinsfile`...). See [Whole codebase scan](../advanced/code-scan.md).

## How the system picks the checklists

The choice depends on the **prompt** you run, then on the agent's judgment.

| Prompt | Included checklists |
|---|---|
| `security-review` | Those of the language, then `api` |
| `api-security-review` | `api` |
| `configuration-review` | `config`, plus `cicd` if the files look like a pipeline |
| `dependency-review` | `dependencies` |
| `codebase-review` | Those of the languages, then `api`, `config` and `cicd` |

- The `*` and `company` checklists are added to every prompt.
- The prompt then names the **other** available checklists, your internal domains included.
- The agent fetches with `get_review_checklist` those that apply to the code. Example: a Python
  project with a `Dockerfile` gets `python`, then the agent asks for `config`.
- **Without a prompt**, nothing is included up front. The agent must call `list_checklists`
  then `get_review_checklist` itself. Your `AGENTS.md` must ask it to (see below).

When the report is saved, the server compares the declared coverage with the active
checklists. A forgotten item is marked `not_covered`. A person can thus see whether the review
skipped points.

## How the system picks the standards

- The agent gives its technologies (`python`, `angular`) or file names (`pyproject.toml`,
  `angular.json`).
- The server returns every active standard whose technology or file pattern matches.
- It also lists the technologies that no standard covers.

## The prompts

The prompts are available to the developer through the agent of their IDE.

| Prompt | What it does |
|---|---|
| `development-standards` | Gives the agent the development standards of its stack, before it writes code |
| `security-review` | General review of the code (Python, Java, Go, C#, Rust, TypeScript/Node.js, Angular) |
| `api-security-review`, `configuration-review` | Review of a REST API (OWASP API Top 10), or of a configuration (Dockerfile, CI/CD, YAML...) |
| `dependency-review` | Review of the manifests and lockfiles (supply chain) |
| `codebase-review` | Review of the whole repository, not only a diff |
| `triage-report` | Re-qualifies the findings of a stored report |

For an important review, prefer the prompt.

## The `AGENTS.md` file

!!! danger "Fill in the `AGENTS.md` file"
    It is the only way for the agent to run the security reviews **automatically**, without the
    developer having to start a prompt before each commit.

### Why you need it

- The agent does not start the prompts. Without instructions, it does not always think of the
  review.
- The agent reads `AGENTS.md` at the start of every session. The file tells it **when** to use
  the server, and **how**.
- It sets the **project name**. Every report lands in the same place. The gate, the trends and
  the posture work on this name.
- Without a set name, each agent makes one up. Reports get scattered and the gate does not see
  them all.

Some hosts read another file: `CLAUDE.md` for Claude Code, `.github/copilot-instructions.md`
for GitHub Copilot. Make them point to `AGENTS.md`. You keep a single source.

### Simple example

A `shop-api` project in Python (FastAPI), with a `Dockerfile`:

```markdown
# Instructions for AI agents

## Project
- Project name for the `security-review` MCP server: `shop-api`.
- Always use this name in `save_security_report`.

## Before writing code
- Call `get_development_standards` with the technologies of the change
  (e.g. `python`, `fastapi`) or the files you touch (`pyproject.toml`).
- Apply these standards. Report any deviation with its reason.

## Before saying a task is done
1. Call `scan_code` on each changed file. Check each lead in the code.
2. Call `get_review_checklist` for `python`, `api`, `*` and `company`.
   Add `config` if the `Dockerfile` changes.
3. If `pyproject.toml` or `uv.lock` changes, call `scan_dependencies`.
4. Call `save_security_report` once:
   project `shop-api`, `review_type` `security-review`, branch and commit,
   `checklist_results` and `scan_rules` filled in.
5. Fix the `critical` and `high` findings before finishing.
6. Never change a status. Use `propose_finding_status` with a reason.

If the `security-review` server does not answer, say so. Never claim the review was done.
```

And a minimal `CLAUDE.md` that points to this file:

```markdown
The project instructions are in `AGENTS.md`. Follow them in full.

@AGENTS.md
```

!!! warning "Development standards"
    The development standards are stored in the server: name them in `AGENTS.md` without copying
    them. See how to write the `AGENTS.md` file in the Advanced section:
    [How to mention them in `AGENTS.md`](../advanced/stored-standards.md#how-to-mention-them-in-agentsmd).

## Which check, at which moment

| Moment | Check | Started by |
|---|---|---|
| Before coding | Standards (`development-standards`, `get_development_standards`) | The developer or the agent |
| Review of a change | Rules (`scan_code`) + checklists of the language + `*` and `company` | The developer (prompt) or the agent (tools) |
| Review of an API or a configuration | Rules + `api` checklist, or `config` and `cicd` | The developer (prompt) |
| Review of the dependencies | OSV vulnerability database (`scan_dependencies`) + `dependencies` checklist | The developer (prompt) or the agent (tool) |
| Review of the whole repository | Results of `security-review-ci scan-code` + every useful checklist | The developer (prompt) |
| CI pipeline | Rules on the whole repository (`scan-code`), dependencies (`scan-deps`), [gate](gate.md) | The pipeline, without an agent |
| After the review | Triage, risk acceptance | A person, in the web interface |
