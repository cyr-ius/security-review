# Checks, reviews and releases

What runs before a change is merged, and how a version is published. CI runs every check again
(`lint.yml`, `tests.yml`, `docs.yml`, `docker.yml`).

## Linters and formatters

```bash
uv run ruff check --fix . && uv run ruff format .           # Python
npm --prefix web exec --no -- prettier --check <files>      # web/src/, YAML and JSON
prek install         # same checks before every commit, the dependency scan when
                     # SECREVIEW_CONTROLLER_URL is set, and the agent-review post-commit hook
```

The `prettier` hook formats the YAML and JSON files and the sources of `web/src/` with the
Prettier version locked by `web/package-lock.json` (the one of CI): run `npm ci` in `web/`
before the first commit. CI checks the same files (`lint.yml`, **web** job). `.prettierrc` sets
the width to 100 columns, like ruff; lock files are listed in `.prettierignore`.

### Checks by changed files

Run only the checks of the areas touched by the change (`git diff --stat`); CI runs them all
anyway.

| Changed files | Checks |
|---|---|
| Python (`src/**/*.py`, `tests/`, migrations), `default_rules.toml`, `pyproject.toml`, `uv.lock` | `uv run ruff check . && uv run ruff format --check .`, then `uv run pytest` |
| Angular (`web/`) | `npm --prefix web run build` and Prettier on the changed files; plus `uv run pytest tests/test_audit.py` when the catalog `web/src/app/core/i18n/messages/audit.ts` changes |
| Documentation (`docs/`, `mkdocs.yml`) | `uv run mkdocs build --strict` |
| Workflows, `docker-compose.yml`, YAML / JSON | Prettier on the changed files |

In CI, `lint.yml` runs ruff (**ruff** job) and, in the **web** job, Prettier and the Angular
build; `tests.yml` runs pytest on Python 3.14 and 3.15 with `uv sync --locked` (run `uv lock`
after a change of dependencies), and builds the `security-review-ci` client alone
(**ci-client** job).

## Tests

The method, the conventions and the fixtures are in [Tests](tests.md).

## Security review

The project reviews itself with its own MCP server. When the `security-review` server is
connected, each change is reviewed before it is declared done or a pull request is opened: the
`security-review` prompt (or `api-security-review`, `configuration-review`,
`dependency-review` depending on the files), helped by `scan_code` and
`get_review_checklist`, then one report saved with `save_security_report` (project
`security-review-mcp`). The `critical` and `high` findings are fixed, with a test; the others
are fixed or justified with `propose_finding_status`, which a person approves in the web
interface. The agent then adds a `Security-Review: <report id>` trailer to its commit message,
so that the `agent-review` hook does not review the commit again. The full procedure is in
`AGENTS.md`.

When `SECREVIEW_CONTROLLER_URL` and a personal `ci` token (`SECREVIEW_TOKEN`) are set, the
`scan-deps` hook also scans the dependencies when `uv.lock`, `pyproject.toml` or
`web/package*.json` change.

### Security review of each commit

The `agent-review` hook (`scripts/agent-review.sh`) asks your coding agent to review each of
your commits for security, in the background, with the `security-review` MCP server of your
`.mcp.json`. The review follows the security review procedure of `AGENTS.md` and saves
one report, which you read in the web interface. `prek install` installs it with the pre-commit
hooks (`default_install_hook_types`), and the devcontainer runs it at creation.

The hook uses the CLI of the agent you already have, signed in with your account:

| Agent | CLI | Installation |
|---|---|---|
| Claude Code | `claude` | `npm install -g @anthropic-ai/claude-code` |
| GitHub Copilot | `copilot` | `npm install -g @github/copilot` |
| Codex (ChatGPT account or OpenAI key) | `codex` | `npm install -g @openai/codex` |

It takes the first one installed, in this order, or the one named by `AGENT_REVIEW_CLI`
(`claude`, `copilot` or `codex`). The `security-review` server is read from `.mcp.json`
(`url` and `Authorization` header, the format of Claude Code and Copilot), whatever the agent.

```bash
prek install                          # pre-commit and post-commit hooks
export AGENT_REVIEW_CLI=copilot       # optional: choose the agent
SKIP=agent-review git commit ...      # skip it for one commit
```

- The commit is never blocked, even when findings remain open: the review runs after it, on
  every commit, and its log is in `.git/agent-review/<commit>.log`.
- The agent receives the commit in its prompt and only gets the `security-review` server,
  limited to its review tools (`scan_code`, `get_review_checklist`, `save_security_report`...):
  the other MCP servers of your configuration are not loaded. It edits no file and proposes no
  finding status.
- Claude Code runs with `--restricted` and `--permission-mode dontAsk`: no command, and `.env`,
  `.mcp.json` and the files outside the repository stay unreadable. Codex runs without its shell
  and image tools, in its read-only sandbox: it reads no file and reviews the commit of its
  prompt only. Copilot runs with the shell and write tools denied: it reads the files of the
  repository, `.env` and `.mcp.json` included. The reports mask secrets in any case.
- The hook does nothing for a commit that carries a `Security-Review: <report id>` trailer
  (already reviewed in the session of its agent), during a rebase or a cherry-pick, or when no agent CLI, no `.mcp.json` or no
  `security-review` server in it is found.
- Each review consumes model usage on the account of your agent.

## Branches

- **`dev`**: development branch, the default place to code.
- **`feat/<topic>`**: only for a large break (rework, API or schema change), created from `dev`
  and merged into `dev` by pull request.
- **`master`**: production branch, only fed by merges of `dev`.

## Releasing a version

A version is a tag pushed on `master`:

1. On `dev`, update `version` in `pyproject.toml` (e.g. `uv version 1.3.0`) and commit.
2. Merge `dev` into `master`.
3. On `master`, push the matching tag: `git tag v1.3.0 && git push origin v1.3.0`.
4. The push of the tag triggers `publish.yml`: lint and tests, check that the tag matches the
   version, publication on PyPI and of the Docker images (`docker.yml`), then creation of the
   GitHub release.

The tag publishes two PyPI distributions at the same version: `security-review` and
`security-review-ci`, the pipeline client alone (no dependency), whose project is written by
`scripts/build_ci_client.py` from `ci_client.py`, with the `requires-python` of the server. The
**ci-client** job of `tests.yml` builds it and runs the wheel alone, without the server.

The `.github/workflows/docker.yml` workflow builds the image (`linux/amd64`, `linux/arm64`,
with the PostgreSQL driver) and checks that both entry points start. On every pull request
(the protection of `master` requires these checks), it only builds; on a version tag, it pushes the
images to `ghcr.io/cyr-ius/security-review` and `docker.io/cyrius44/security-review`
(see [published images](../advanced/docker.md#published-images)). A manual run (**Actions →
Docker image → Run workflow**, `push` checked) publishes a branch image (`dev`). Every
tag is also published with the `-pg` suffix (`X.Y.Z-pg`, `latest-pg`, `dev-pg`): a deprecated
alias of the same image, kept for the former PostgreSQL variant until the next major version.

One-time setup: a Docker Hub access token (read and write) in the repository secret
`DOCKERHUB_TOKEN`; GHCR uses the token of the workflow. After the first publication, make the
GHCR package public (**Packages → security-review → Package settings**).

Every action of the workflows is pinned to a full commit SHA, with its version in a comment
(`uses: actions/checkout@<40-character SHA> # v7.0.1`): a tag can be moved, a commit cannot.
Dependabot (`.github/dependabot.yml`) updates the SHA and the comment together. Pin any new
action the same way.
