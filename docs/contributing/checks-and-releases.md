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

The `scan-deps` and `agent-review` hooks run the `security-review-ci` of the Controller server given by
`SECREVIEW_CONTROLLER_URL` ([client from the Controller server](../getting-started/commit-hooks.md)),
and are skipped while it is not set. With a personal `ci` token in `SECREVIEW_CI_TOKEN`,
`scan-deps` scans the dependencies when `uv.lock`, `pyproject.toml` or `web/package*.json`
change.

### Security review of each commit

The `agent-review` hook runs
[`security-review-ci agent-review`](../advanced/architecture/ci.md#agent-review-of-each-commit) after each of
your commits: your coding agent (Claude Code, GitHub Copilot or Codex) reviews it for security
in the background, with the `security-review` server of your `.mcp.json`, and saves one report,
which you read in the web interface. `prek install` installs it with the pre-commit hooks
(`default_install_hook_types`), and the devcontainer runs it at creation: you only install the
CLI of your agent, sign in and create your `.mcp.json`.

```bash
prek install                          # pre-commit and post-commit hooks
export AGENT_REVIEW_CLI=copilot       # optional: choose the agent
SKIP=agent-review git commit ...      # skip it for one commit
```

The commit is never blocked, even when findings remain open; the log is in
`.git/agent-review/<commit>.log`. A commit that carries a `Security-Review: <report id>`
trailer, already reviewed in the session of its agent, is not reviewed again.

## Branches

- **`dev`**: development branch, the default place to code.
- **`feat/<topic>`**: only for a large break (rework, API or schema change), created from `dev`
  and merged into `dev` by pull request.
- **`master`**: production branch, only fed by merges of `dev`.

## Releasing a version

A version is a `vX.Y.Z` tag on `master`, created by Release Please (`release-please.yml`)
from the Conventional Commits:

1. Merge `dev` into `master`.
2. Release Please opens (or updates) the release pull request: it computes the version, writes
   `CHANGELOG.md` and sets the version in `pyproject.toml` (the version the package reads from
   its installed metadata), `uv.lock`, `web/package.json` and `web/package-lock.json`
   (`release-please-config.json`).
3. Merging that pull request creates the tag and a draft GitHub release holding the changelog,
   then runs `publish.yml` on the tag: lint and tests, check that the tag matches the version,
   publication on PyPI and of the Docker images (`docker.yml`), then upload of the
   distributions to the release, which is published only then.
   A tag created with the workflow token triggers no workflow: `release-please.yml` starts
   `publish.yml` itself, with `workflow_dispatch` on the tag.

A tag pushed by hand (`git tag v1.3.0 && git push origin v1.3.0`) still triggers `publish.yml`.
If the publication did not start, run **Build & publish to PyPI and Docker registries** from
the **Actions** tab, on the tag, with the target `pypi`.

The tag publishes two PyPI distributions at the same version: `security-review` and
`security-review-ci`, the pipeline client alone (no dependency), whose project is written by
`scripts/build_ci_client.py` from `ci_client.py`, with the `requires-python` of the server. The
**ci-client** job of `tests.yml` builds it and runs the wheel alone, without the server.

The `.github/workflows/docker.yml` workflow builds the image (`linux/amd64`, `linux/arm64`,
with the PostgreSQL driver) and checks that both entry points start. On every pull request
(the protection of `master` requires these checks), it only builds; on a version tag, it pushes the
images to `ghcr.io/cyr-ius/security-review` and `docker.io/cyrius44/security-review`
(see [published images](../advanced/deployment/docker.md#published-images)). A manual run (**Actions →
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
