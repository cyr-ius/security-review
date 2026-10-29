# Pipeline client (CI/CD)

The pipeline client runs in the CI/CD jobs and on the workstations of the developers: it
sends the files of the repository to the [Controller server](controller.md), which scans them, and
reads the gate, the SARIF log and the trend of a project.

`security-review-ci` is a lightweight client of the Controller server: it calls the pipeline routes of
the REST API (`/api/v1/ci/gate`, `/api/v1/ci/sarif`, `/api/v1/ci/trend`, and
`/api/v1/ci/scan/code` and `/api/v1/ci/scan/deps` for the scans) and opens no database. It only
uses the Python standard library (Python 3.14), and is published alone on PyPI as
`security-review-ci`, at the version of the server, without its dependencies.

## Installation

| Machine | Command |
|---|---|
| Workstation without Python (Linux, macOS, Windows) | [uv](https://docs.astral.sh/uv/getting-started/installation/), then `uv tool install security-review-ci`: uv downloads a Python when none is installed |
| Build agent or workstation with Python ≥ 3.14 | `uv pip install security-review-ci` in the virtual environment of the job (`--system` without one) |
| Workstation or agent without PyPI, from the Controller server | `uvx --no-index --find-links https://secreview.example.com/api/ci-client/ security-review-ci@latest …`: the [client of the Controller server](#from-the-controller-server), at its version |
| Agent without access to PyPI | Copy the single file `security_review_mcp/ci_client.py` (or the `security_review_ci` wheel attached to the GitHub release) and run it with `python3 ci_client.py` |
| Docker | `docker run --rm -v "$PWD:/src:ro" -w /src -e SECREVIEW_CONTROLLER_URL -e SECREVIEW_CI_TOKEN --entrypoint security-review-ci ghcr.io/cyr-ius/security-review …` |

The `security-review` package also installs `security-review-ci`: do not install both
packages in the same environment. Install the version of your Controller server
(`uv tool install security-review-ci==X.Y.Z`); `uv tool upgrade security-review-ci` updates it.

### From the Controller server

Unless `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED=false`, the Controller server serves its own client on
`/api/ci-client/`: a links page for `uv --find-links` and the wheel
`security_review_ci-<version>-py3-none-any.whl`, built from its code, at its version. The
developers and the build agents then need neither PyPI nor a version to maintain:

```bash
uvx --no-index --find-links https://secreview.example.com/api/ci-client/ \
  security-review-ci@latest scan-deps uv.lock --project shop-api
```

- `--no-index` keeps uv away from PyPI, so no other package of the same name can be installed;
  `@latest` makes uv read the page again at each run and follow the version of the Controller server.
- uv checks the SHA-256 given by the page. Serve the Controller server over HTTPS: uv also accepts a
  plain HTTP URL, but then the page and the wheel can be replaced on the way, SHA-256 included,
  and the developers would run that code (see
  [Controller server in plain HTTP](../../getting-started/commit-hooks.md#controller-server-in-http-without-tls)).
- The two routes are public (uv sends no token) and read-only; like the API documentation, they
  tell the version of the Controller server: `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED=false` hides them.

## Commands

| Sub-command | Role |
|---|---|
| `gate` | [Gate](../../review/gate.md) of the project |
| `sarif` | SARIF 2.1.0 log of the project ([SARIF export](../reports/sarif.md)) |
| `trend` | Trend report of the project ([Trend report](#trend-report)) |
| `scan-code` | Sends the files of the repository to the Controller server, which scans them with its rules ([Whole codebase analysis](../../review/analysis/code-scan.md)) |
| `scan-deps` | Sends manifests and lockfiles to the Controller server, which checks them against its advisories ([Dependencies](../../review/analysis/dependencies.md#scan-in-a-pipeline-security-review-ci-scan-deps)) |
| `agent-review` | Has the coding agent of the developer review the last commit with the MCP server, in the background (post-commit hook, [Agent review of each commit](#agent-review-of-each-commit)) |
| `guard` | Checks the files that the coding agent is about to read for hidden text and text addressed to an assistant, offline (hook of the agent, [Read guard](../../review/analysis/read-guard.md)) |

All their options: [Command line](../../reference/cli.md#security-review-ci).

Common options (except `agent-review` and `guard`): `--url` (default `SECREVIEW_CONTROLLER_URL`), `--token-stdin` (reads the token
on stdin instead of `SECREVIEW_CI_TOKEN`), `--cafile` (CA of the Controller server certificate),
`--allow-http`, `--timeout` (seconds, default 60).

- The token is never accepted on the command line (process list, job log) and never written in
  an error message.
- Plain HTTP is refused except to `localhost` (or with `--allow-http`), and so are credentials
  in the URL; redirects are not followed, so the token is only sent to the given Controller server.
- The two variables are read from the environment only (the `.env` file is ignored).
- The answers are bounded (64 MiB) and the control characters of the text output are removed.

## Agent review of each commit

`agent-review` runs on the workstation of a developer, as a post-commit hook: the coding agent
of the developer reviews the last commit for security with the `security-review` MCP server,
in the background, and saves one report, which the developer reads in the web interface. The
command never contacts the Controller server and needs no `ci` token: the agent calls the MCP server
with the token of the MCP configuration.

The developer needs uv, the CLI of their agent, signed in with their account, and the MCP
configuration they already use with that agent:

| Agent | CLI | Installation |
|---|---|---|
| Claude Code | `claude` | `npm install -g @anthropic-ai/claude-code` |
| GitHub Copilot | `copilot` | `npm install -g @github/copilot` |
| Codex (ChatGPT account or OpenAI key) | `codex` | `npm install -g @openai/codex` |

The command takes the first one installed, in this order, or the one given by `--agent` or the
`AGENT_REVIEW_CLI` variable. The server is read from `.mcp.json` (`--mcp-config`) under the name
`security-review` (`--mcp-server`): `mcpServers` format of Claude Code and Copilot or `servers`
format of VS Code, HTTP server (`url`, `Authorization` header) or local server (`command`,
[local mode](../../getting-started/stdio.md)).

Step-by-step setup, with `scan-deps`: [Commit hooks](../../getting-started/commit-hooks.md).

A project declares the hook in its `.pre-commit-config.yaml` (prek or pre-commit), with the
client [of its Controller server](#from-the-controller-server) (or `uvx security-review-ci@X.Y.Z` from PyPI,
at the version of the Controller server):

```yaml
default_install_hook_types: [pre-commit, post-commit]
repos:
  - repo: local
    hooks:
      - id: agent-review
        name: agent security review
        entry: uvx --no-index --find-links https://secreview.example.com/api/ci-client/ security-review-ci@latest agent-review --project shop-api
        language: system
        stages: [post-commit]
        always_run: true
        pass_filenames: false
```

```bash
prek install                          # pre-commit and post-commit hooks
SKIP=agent-review git commit ...      # skip the review for one commit
```

- The commit is never blocked, even when findings remain open: the command exits with `0` when
  the review starts or is skipped (with a warning on stderr), `2` outside a git repository. The
  log of the agent is in `.git/agent-review/<commit>.log`. `--foreground` waits for the end of
  the review, which is always the case on Windows (no `fork`).
- The agent receives the commit (up to 100 KB) between random tags in its prompt, and only the
  `security-review` server, limited to its review tools (`scan_code`, `get_review_checklist`,
  `save_security_report`...): the other MCP servers of the developer are not loaded. Its MCP
  configuration goes to a private temporary file outside the repository, removed after the
  review; the token is never on a command line. The agent edits no file and proposes no finding
  status.
- Claude Code runs with `--restricted` and `--permission-mode dontAsk`: no command, and `.env`,
  `.mcp.json` and the files outside the repository stay unreadable. Codex runs without its shell
  and image tools, in its read-only sandbox: it reads no file and reviews the commit of its
  prompt only. Copilot runs with the shell and write tools denied: it reads the files of the
  repository, `.env` and `.mcp.json` included. The reports mask secrets in any case.
- The review is skipped for a commit that carries a `Security-Review: <report id>` trailer
  (added by an agent that already reviewed the change in its session), during a rebase or a
  cherry-pick, or when no agent CLI, no MCP configuration or no `security-review` server in it
  is found.
- Each review consumes model usage on the account of the agent.

## `ci` token and visible projects

A `ci` token only reaches the pipeline routes: neither `/mcp`, nor the rest of the REST API,
nor the web interface. It is **always restricted to projects**: it sees the gate, the SARIF
log and the trend of the selected projects only, and only stores scan reports for them; another
project answers `404`, like a project that does not exist. `--project` is
[normalized](../../review/prompts-tools.md#project-name) like the project of a review: give the repository
name.

- In the web interface, **Tokens** screen: **Usage** **CI/CD pipeline**, then tick the
  **Allowed projects**. The secret is shown once.
- From the CLI:

```bash
security-review-controller token create --label jenkins-portal --role ci \
  --project portal --project portal-api
```

On a workstation, a developer uses a
[personal `ci` token](../../usage/tokens.md#personal-mcp-and-ci-tokens) instead, created in
**My account**: it reaches the projects the developer may read.

Web sessions and `api` tokens (within the projects they read) and `admin` tokens may also call
the gate, SARIF and trend routes; `mcp` tokens may not, personal ones included. The scans, which store reports, need a `ci` or
`admin` token (`403` otherwise, web sessions included).

## Typical pipeline

A job of the pipeline chains four commands, with the `ci` token of the project in
`SECREVIEW_CI_TOKEN` and the URL of the Controller server in `SECREVIEW_CONTROLLER_URL`:

```bash
security-review-ci scan-code . --project portal --save --branch "$BRANCH" --commit "$COMMIT" || [ $? -eq 1 ]
security-review-ci scan-deps uv.lock package-lock.json --project portal --save --require-database \
    --branch "$BRANCH" --commit "$COMMIT" || [ $? -eq 1 ]
security-review-ci sarif --project portal -o security.sarif
security-review-ci gate --project portal --fail-on high
```

1. `scan-code` and `scan-deps` send the files to the Controller server, which scans them and, with
   `--save`, stores a `code-scan` and a `dependency-scan` report of the project
   ([Whole codebase analysis](../../review/analysis/code-scan.md), [Dependency analysis](../../review/analysis/dependencies.md#scan-in-a-pipeline-security-review-ci-scan-deps)).
2. `sarif` downloads the open findings of the project, for the code scanning of the platform
   ([SARIF export](../reports/sarif.md)).
3. `gate` decides: it fails (code `1`) while open findings reach `--fail-on`.

The exit code of a scan counts every match above its own `--fail-on`, triage decisions
ignored; only the gate takes into account the findings that a person accepted or marked as
false positives. `|| [ $? -eq 1 ]` lets a scan that found something (code `1`) go on to the gate,
but still stops the job on an error (code `2`: Controller server unreachable, token refused...).
Without it, the scans block by themselves, which is enough for a first test.

Install the client at the version of the Controller server (`X.Y.Z` below). The project name is
[normalized](../../review/prompts-tools.md#project-name): the name of the repository given by the
platform works as it is.

## Examples by platform

Each example stores the token as a secret of the platform, never in the file, and runs the
[typical pipeline](#typical-pipeline).

=== "GitHub Actions"

    ```yaml
    # .github/workflows/security-review.yml
    name: Security review
    on: [push, pull_request]
    permissions:
      contents: read
      security-events: write   # upload of the SARIF log
    jobs:
      security-review:
        runs-on: ubuntu-latest
        env:
          SECREVIEW_CONTROLLER_URL: https://secreview.example.com
          SECREVIEW_CI_TOKEN: ${{ secrets.SECREVIEW_CI_TOKEN }}
          PROJECT: ${{ github.event.repository.name }}
        steps:
          - uses: actions/checkout@v5
          - uses: actions/setup-python@v5
            with:
              python-version: "3.14"
          - run: pip install security-review-ci==X.Y.Z
          - run: |
              security-review-ci scan-code . --project "$PROJECT" --save \
                --branch "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" || [ $? -eq 1 ]
              security-review-ci scan-deps uv.lock --project "$PROJECT" --save --require-database \
                --branch "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" || [ $? -eq 1 ]
              security-review-ci sarif --project "$PROJECT" -o security.sarif
          - uses: github/codeql-action/upload-sarif@v4
            with:
              sarif_file: security.sarif
          - run: security-review-ci gate --project "$PROJECT" --fail-on high
    ```

    Pin each action on the SHA of a commit in production.

=== "GitLab CI"

    ```yaml
    # .gitlab-ci.yml
    security-review:
      stage: test
      image: python:3.14-slim
      variables:
        SECREVIEW_CONTROLLER_URL: https://secreview.example.com
        # SECREVIEW_CI_TOKEN: masked and protected CI/CD variable (ci token)
      script:
        - pip install security-review-ci==X.Y.Z
        - security-review-ci scan-code . --project "$CI_PROJECT_NAME" --save
            --branch "$CI_COMMIT_REF_NAME" --commit "$CI_COMMIT_SHA" || [ $? -eq 1 ]
        - security-review-ci scan-deps uv.lock --project "$CI_PROJECT_NAME" --save --require-database
            --branch "$CI_COMMIT_REF_NAME" --commit "$CI_COMMIT_SHA" || [ $? -eq 1 ]
        - security-review-ci sarif --project "$CI_PROJECT_NAME" -o security.sarif
        - security-review-ci gate --project "$CI_PROJECT_NAME" --fail-on high
      artifacts:
        when: always
        paths: [security.sarif]
    ```

    GitLab does not read SARIF natively: the log is kept as an artifact.

=== "Jenkins"

    ```groovy
    // Jenkinsfile: the ci token is a "Secret text" credential; security-review-ci is installed
    // on the agent (uv tool install security-review-ci==X.Y.Z)
    pipeline {
      agent any
      environment {
        SECREVIEW_CONTROLLER_URL = 'https://secreview.example.com'
        PROJECT = 'portal'
      }
      stages {
        stage('Security review') {
          steps {
            withCredentials([string(credentialsId: 'secreview-ci', variable: 'SECREVIEW_CI_TOKEN')]) {
              sh '''
                security-review-ci scan-code . --project "$PROJECT" --save \
                  --branch "$BRANCH_NAME" --commit "$GIT_COMMIT" || [ $? -eq 1 ]
                security-review-ci scan-deps uv.lock --project "$PROJECT" --save --require-database \
                  --branch "$BRANCH_NAME" --commit "$GIT_COMMIT" || [ $? -eq 1 ]
                security-review-ci sarif --project "$PROJECT" -o security.sarif
                security-review-ci gate --project "$PROJECT" --fail-on high
              '''
            }
          }
        }
      }
      post {
        always {
          // Warnings Next Generation plugin
          recordIssues tool: sarif(pattern: 'security.sarif')
        }
      }
    }
    ```

=== "Azure Pipelines"

    ```yaml
    # azure-pipelines.yml: SECREVIEW_CI_TOKEN is a secret variable of the pipeline
    trigger: [main]
    pool:
      vmImage: ubuntu-latest
    variables:
      SECREVIEW_CONTROLLER_URL: https://secreview.example.com
    steps:
      - task: UsePythonVersion@0
        inputs:
          versionSpec: "3.14"
      - script: pip install security-review-ci==X.Y.Z
      - script: |
          security-review-ci scan-code . --project "$(Build.Repository.Name)" --save \
            --branch "$(Build.SourceBranchName)" --commit "$(Build.SourceVersion)" || [ $? -eq 1 ]
          security-review-ci scan-deps uv.lock --project "$(Build.Repository.Name)" --save --require-database \
            --branch "$(Build.SourceBranchName)" --commit "$(Build.SourceVersion)" || [ $? -eq 1 ]
          security-review-ci sarif --project "$(Build.Repository.Name)" -o security.sarif
          security-review-ci gate --project "$(Build.Repository.Name)" --fail-on high
        env:
          SECREVIEW_CI_TOKEN: $(SECREVIEW_CI_TOKEN)   # a secret variable is never mapped implicitly
      - publish: security.sarif
        artifact: CodeAnalysisLogs
        condition: always()
    ```

    The **SARIF SAST Scans Tab** extension shows the `CodeAnalysisLogs` artifact in the build.

=== "Bitbucket Pipelines"

    ```yaml
    # bitbucket-pipelines.yml: SECREVIEW_CI_TOKEN is a secured repository variable
    image: python:3.14-slim
    pipelines:
      default:
        - step:
            name: Security review
            script:
              - export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
              - pip install security-review-ci==X.Y.Z
              - security-review-ci scan-code . --project "$BITBUCKET_REPO_SLUG" --save
                  --branch "$BITBUCKET_BRANCH" --commit "$BITBUCKET_COMMIT" || [ $? -eq 1 ]
              - security-review-ci scan-deps uv.lock --project "$BITBUCKET_REPO_SLUG" --save --require-database
                  --branch "$BITBUCKET_BRANCH" --commit "$BITBUCKET_COMMIT" || [ $? -eq 1 ]
              - security-review-ci sarif --project "$BITBUCKET_REPO_SLUG" -o security.sarif
              - security-review-ci gate --project "$BITBUCKET_REPO_SLUG" --fail-on high
            artifacts:
              - security.sarif
    ```

=== "CircleCI"

    ```yaml
    # .circleci/config.yml: SECREVIEW_CI_TOKEN is an environment variable of the project (or of a context)
    version: 2.1
    jobs:
      security-review:
        docker:
          - image: cimg/python:3.14
        environment:
          SECREVIEW_CONTROLLER_URL: https://secreview.example.com
        steps:
          - checkout
          - run: pip install security-review-ci==X.Y.Z
          - run: |
              security-review-ci scan-code . --project "$CIRCLE_PROJECT_REPONAME" --save \
                --branch "$CIRCLE_BRANCH" --commit "$CIRCLE_SHA1" || [ $? -eq 1 ]
              security-review-ci scan-deps uv.lock --project "$CIRCLE_PROJECT_REPONAME" --save --require-database \
                --branch "$CIRCLE_BRANCH" --commit "$CIRCLE_SHA1" || [ $? -eq 1 ]
              security-review-ci sarif --project "$CIRCLE_PROJECT_REPONAME" -o security.sarif
              security-review-ci gate --project "$CIRCLE_PROJECT_REPONAME" --fail-on high
          - store_artifacts:
              path: security.sarif
    workflows:
      security:
        jobs: [security-review]
    ```

Replace `uv.lock` with the manifests and lockfiles of the repository
([supported files](../../review/analysis/dependencies.md#supported-files)).

## Trend report

```bash
security-review-ci trend --project my-project --days 90 --granularity week --format markdown
```

Options: `--granularity day|week|month` (default `week`), `--format markdown|json`
(default `markdown`), `--days` (default 90).

For each period:

- new and fixed findings;
- open backlog;
- risk score (critical 10, high 5, medium 2, low 1) and direction (±10 % margin over the last
  two periods).

Overall: mean time to remediate (MTTR) by severity, oldest open finding, most frequent CWEs.

The same report is available on the MCP side with the `get_trend_report` tool.
