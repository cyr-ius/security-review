# Whole codebase scan

The review prompts work on what the agent gives them, often the diff of a merge request, and
`scan_code` is limited to `SECREVIEW_MAX_CONTENT_CHARS` per call. To cover the **whole**
repository, use the CLI:

```bash
security-review-controller code scan .                               # text summary, exit code 0/1/2
security-review-controller code scan . --format json -o scan.json    # for the codebase-review prompt
security-review-controller code scan . --format sarif -o code.sarif  # GitHub code scanning, Jenkins...
security-review-controller code scan . --save --project portal --commit "$CI_COMMIT_SHA"
```

## File selection

- Files come from `git ls-files` (tracked + untracked not ignored: `.gitignore` is honored).
  Outside a git repository, or with `--no-git`, the tree is walked, skipping `node_modules`,
  `.venv`, `dist`, `build`, `target`, etc.
- The language is inferred from the name: `.py`, `.java`, `.ts`, `.js`, `.html` (Angular
  templates), `.yml`/`.yaml`, `.properties`, `.toml`, `.env*`, `Dockerfile*`, `Jenkinsfile`,
  `.gitlab-ci.yml`. Lockfiles, `*.min.js` and `*.d.ts` are skipped.
- Skipped and reported files: `--exclude GLOB` (repeatable, e.g. `--exclude tests/`), beyond
  `--max-file-bytes` (1 MiB by default), binaries, symbolic links.

## Threshold and saving

- `--fail-on` (default `high`) sets the blocking threshold; the [rules](rules.md) of the
  database (`SECREVIEW_DATABASE_URL`) and the `secreview:ignore` markers apply as for
  `scan_code`. If the database cannot be reached, the default rules (`default_rules.toml`)
  apply and a warning is written on stderr.
- `--save` stores the matches as findings (at most `SECREVIEW_MAX_FINDINGS_PER_REPORT`, the most
  severe first) and the list of files not analyzed in `scope`; `--author` adds the username of
  the developer (see [author of a report](prompts-tools.md#author-of-a-report)).

!!! warning "Triage before blocking"
    Matches are **leads**. Triage them (`triage-report` prompt) before making a
    [gate](../ci-cd/gate.md) depend on this report, otherwise the false positives will block it.

## Agent-guided review

Then, the `codebase-review` prompt (`scan_results` argument = the JSON, possibly filtered)
guides the agent: inventory, prioritization of the entry points, tracing of the flows between
files, checklists, and a **coverage** section that says what was not read.
