# Whole codebase analysis

The review prompts work on what the agent gives them, often the diff of a merge request, and
`scan_code` is limited to `SECREVIEW_MAX_CONTENT_CHARS` per call. To cover the **whole**
repository, there are two modes, independent and complementary:

| | [Automatic scan](#mode-1-automatic-scan-security-review-ci-scan-code) | [Agent review](#mode-2-agent-review-codebase-review-prompt) |
|---|---|---|
| Started by | the `security-review-ci scan-code` command (CI/CD pipeline or workstation) | the user, with the `codebase-review` prompt in their host (Claude, Copilot, Codex…) |
| Who analyzes | the Controller server, without AI | the AI agent, which reads the code |
| What is applied | the [rules](../rules.md) of the database, only | the rules (through the scan), the [checklists](../checklists.md) and the reasoning of the agent (flows between files, business logic) |
| Files | every eligible file of the repository | those the agent chooses to read (leads of the scan, sensitive areas) |
| Result | **leads** (pattern matches), `code-scan` report with `--save` | **confirmed findings**, `codebase-review` report |
| Cost | fast, deterministic, no token | slow, consumes many tokens |
| Typical use | at each commit or merge request, with a [gate](../gate.md) | first review of a repository, periodic audit |

The two combine: the JSON output of the automatic scan is the starting point of the agent
review (`scan_results` argument), which confirms or dismisses each lead.

## Mode 1: automatic scan (`security-review-ci scan-code`)

The [pipeline client](../../advanced/architecture/ci.md) `security-review-ci scan-code` reads
the files of the repository and sends their content to the Controller server, which scans them
with the [rules](../rules.md) of its database. No AI agent is involved: it is a pattern scan,
like `scan_code`, applied to the whole repository.

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_CI_TOKEN=...   # ci token restricted to the project (or admin token)

security-review-ci scan-code . --project portal                               # text summary, exit code 0/1/2
security-review-ci scan-code . --project portal --format json -o scan.json    # for the codebase-review prompt
security-review-ci scan-code . --project portal --format sarif -o code.sarif  # GitHub code scanning, Jenkins...
security-review-ci scan-code . --project portal --save --commit "$CI_COMMIT_SHA"
```

The pipeline needs neither the database nor the package: only Python and the
[`ci` token](../../advanced/architecture/ci.md#ci-token-and-visible-projects) of the project. On a workstation,
use a [personal `ci` token](../../usage/tokens.md#personal-mcp-and-ci-tokens).

### File selection

The client chooses the files; the Controller server never reads its own disk.

- Files come from `git ls-files` (tracked + untracked not ignored: `.gitignore` is honored).
  Outside a git repository, or with `--no-git`, the tree is walked, skipping `node_modules`,
  `.venv`, `dist`, `build`, `target`, `obj`, etc.
- The language is inferred from the name: `.py`, `.java`, `.go`, `.cs`/`.cshtml`/`.razor`, `.rs`, `.ts`,
  `.js`, `.html` (Angular templates), `.yml`/`.yaml`, `.properties`, `.toml`, `.env*`, `Dockerfile*`, `Jenkinsfile`,
  `.gitlab-ci.yml`, and the files that steer an AI assistant (`AGENTS.md`, `CLAUDE.md`,
  `GEMINI.md`, `copilot-instructions.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`,
  `*.mdc`, `*.instructions.md`, `*.prompt.md`, `*.md` under `.claude/`, `.cursor/`, `.windsurf/`
  or `.clinerules/`), scanned for hidden text and injected instructions (`AI-*` rules).
  Lockfiles, `*.min.js` and `*.d.ts` are skipped. Only these files are sent.
- Skipped files: `--exclude GLOB` (repeatable, e.g. `--exclude tests/`, only counted), and,
  reported, files beyond `--max-file-bytes` (1 MiB by default), binaries and symbolic links.

!!! note "The content leaves the build agent"
    The source code is sent to the Controller server (HTTPS, or plain HTTP to a loopback address or
    with `--allow-http`). Exclude what must not leave the agent with `--exclude`.

### Limits of the Controller server

| Variable | Default | Effect |
|---|---|---|
| `SECREVIEW_MAX_SCAN_REQUEST_MB` | `64` | Size of the request: beyond it, the Controller server answers `413` (exit code `2`) |
| `SECREVIEW_MAX_SCAN_FILES` | `10000` | Files per request: beyond it, `422` |
| `SECREVIEW_MAX_SCAN_FILE_CHARS` | `1048576` | A larger file is not scanned and is listed as skipped |

### Threshold and saving

- `--fail-on` (default `high`) sets the blocking threshold; the [rules](../rules.md) of the
  database and the `secreview:ignore` markers apply as for `scan_code`.
- `--save` stores the matches as a `code-scan` report (at most
  `SECREVIEW_MAX_FINDINGS_PER_REPORT` findings, the most severe first), with the list of files
  not analyzed in `scope` and the label of the token as the device that saved it; the user of a
  personal `ci` token is the author, else `--author` adds the username of the developer (see
  [author of a report](../prompts-tools.md#author-of-a-report)), `--repository`,
  `--branch` and `--commit` the context.
- With `--save --format sarif`, the SARIF log carries the ids of the stored findings.

!!! warning "Triage before blocking"
    Matches are **leads**. Triage them (`triage-report` prompt) before making a
    [gate](../gate.md) depend on this report, otherwise the false positives will block it.

## Mode 2: agent review (`codebase-review` prompt)

The `codebase-review` prompt of the MCP server has the AI agent of the user review the whole
repository, as an auditor would: it does not stop at the rules, it follows the data from one
file to another and walks through the checklists. It does not depend on mode 1, but builds on it
when it is available.

### Starting the review

In the host, start the `codebase-review` prompt, either:

- **with the results of the automatic scan** in `scan_results` (the JSON of
  `security-review-ci scan-code . --project portal --format json`, possibly filtered): the
  agent starts from these leads;
- **without `scan_results`**: the prompt asks an agent that can run commands to launch
  `security-review-ci scan-code` itself (with a personal `ci` token), or the user to run it and
  paste the output. The files thus reach the Controller server as they are, instead of being
  copied by the model into `scan_code` calls.

`languages` selects the checklists, `focus` and `context` steer the review (see
[prompts and tools](../prompts-tools.md#prompts)). The `dependency-review` prompt does the same
for the dependencies with `security-review-ci scan-deps`.

### What `codebase-review` does

The prompt reads no file itself: it gives the agent a **method**, and the agent reads the code
in its workspace.

1. **Inventory.** The agent lists the files of the repository, honoring `.gitignore`, without
   generated code, vendored dependencies nor build output. It spots the languages, the entry
   points (HTTP routes, CLI, message consumers, scheduled jobs) and the configuration and CI/CD
   files.
2. **Leads.** It starts from the scan results (`scan_results`, or `security-review-ci scan-code`
   run by itself), else, as a last resort, calls `scan_code` on each file it reads.
3. **Prioritization.** It reads first what an attacker can reach: entry points,
   authentication, input validation, database, files and processes, deserialization, outgoing
   requests, cryptography and secrets, then configuration and pipelines.
4. **Tracing.** It follows untrusted data from each entry point to the sensitive calls, across
   files: what a diff review misses.
5. **Checklists**, then **report** saved once (`review_type`: `codebase-review`), with the
   files read and **those not read** in `scope`.

**Does it take every file of the repository?** Not all at once. The *scan* covers every
eligible file ([file selection](#file-selection)); the *reading* by the agent targets the
files that matter (leads of the scan, entry points, sensitive areas). On a large repository,
the agent does not read everything in one session: the prompt asks it to say what remains
instead of pretending it was covered.

**Does it use the rules and the checklists?**

- **Rules**: yes, through the scan. `security-review-ci scan-code` applies every active rule of
  the database (built-in and internal); `scan_code` does the same file by file. Their matches
  are leads that the agent confirms or dismisses by reading the code.
- **Checklists**: yes, embedded in the prompt: those of the languages given in `languages`, then
  `api`, `config` and `cicd`, the `*` (every language) and `company` checklists; the other
  available checklists are named, for the agent to fetch with `get_review_checklist` when they
  apply ([details](../checklists.md#checklists-in-review-prompts)).

**Can it consume many tokens?** Yes, it is the most expensive prompt: the agent reads a large
part of the repository, and every file read counts in its context. To keep it under control:

- give `scan_results`, or let the agent run `security-review-ci scan-code`: the files reach the
  Controller server without going through the model, which then only reads the leads and the
  sensitive areas. Without it, the agent copies each file into a `scan_code` call, which
  costs the most;
- filter the scan (`--exclude tests/`, `--exclude docs/`, `--fail-on`): `scan_results` is
  limited to `SECREVIEW_MAX_CONTENT_CHARS` (200,000 characters by default);
- narrow the review with `focus` (for example `authentication, file upload`) or `context`, or
  review one part of the repository at a time;
- for a merge request, use `security-review` on the diff instead: `codebase-review` is meant
  for a first review or a periodic audit.
