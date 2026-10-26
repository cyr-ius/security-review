# Whole codebase scan

The review prompts work on what the agent gives them, often the diff of a merge request, and
`scan_code` is limited to `SECREVIEW_MAX_CONTENT_CHARS` per call. To cover the **whole**
repository, use the [pipeline client](../../advanced/architecture/ci.md)
`security-review-ci scan-code`: it reads the files of the repository and sends their content
to the controller, which scans them with the [rules](../rules.md) of its database.

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_TOKEN=...   # ci token restricted to the project (or admin token)

security-review-ci scan-code . --project portal                               # text summary, exit code 0/1/2
security-review-ci scan-code . --project portal --format json -o scan.json    # for the codebase-review prompt
security-review-ci scan-code . --project portal --format sarif -o code.sarif  # GitHub code scanning, Jenkins...
security-review-ci scan-code . --project portal --save --commit "$CI_COMMIT_SHA"
```

The pipeline needs neither the database nor the package: only Python and the
[`ci` token](../../advanced/architecture/ci.md#ci-token-and-visible-projects) of the project. On a workstation,
use a [personal `mcp` or `ci` token](../../usage/tokens.md#personal-mcp-and-ci-tokens).

## File selection

The client chooses the files; the controller never reads its own disk.

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
    The source code is sent to the controller (HTTPS, or plain HTTP to a loopback address or
    with `--allow-http`). Exclude what must not leave the agent with `--exclude`.

## Limits of the controller

| Variable | Default | Effect |
|---|---|---|
| `SECREVIEW_MAX_SCAN_REQUEST_MB` | `64` | Size of the request: beyond it, the controller answers `413` (exit code `2`) |
| `SECREVIEW_MAX_SCAN_FILES` | `10000` | Files per request: beyond it, `422` |
| `SECREVIEW_MAX_SCAN_FILE_CHARS` | `1048576` | A larger file is not scanned and is listed as skipped |

## Threshold and saving

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

## Agent-guided review

Then, the `codebase-review` prompt (`scan_results` argument = the JSON, possibly filtered)
guides the agent: inventory, prioritization of the entry points, tracing of the flows between
files, checklists, and a **coverage** section that says what was not read. Without `scan_results`, the
prompt asks an agent that can run commands to launch `security-review-ci scan-code` itself (with
a personal `mcp` or `ci` token): the files reach the controller as they are, instead of being copied by
the model into `scan_code` calls. The `dependency-review` prompt does the same with
`security-review-ci scan-deps`.
