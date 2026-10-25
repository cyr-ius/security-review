# Pipeline client (CI/CD)

The pipeline client runs in the CI/CD jobs and on the workstations of the developers: it
sends the files of the repository to the [controller](controller.md), which scans them, and
reads the gate, the SARIF log and the trend of a project.

`security-review-ci` is a lightweight client of the controller: it calls the pipeline routes of
the REST API (`/api/v1/ci/gate`, `/api/v1/ci/sarif`, `/api/v1/ci/trend`, and
`/api/v1/ci/scan/code` and `/api/v1/ci/scan/deps` for the scans) and opens no database. It only
uses the Python standard library (Python 3.14), and is published alone on PyPI as
`security-review-ci`, at the version of the server, without its dependencies.

## Installation

| Machine | Command |
|---|---|
| Workstation without Python (Linux, macOS, Windows) | [uv](https://docs.astral.sh/uv/getting-started/installation/), then `uv tool install security-review-ci`: uv downloads a Python when none is installed |
| Build agent or workstation with Python ≥ 3.14 | `uv pip install security-review-ci` in the virtual environment of the job (`--system` without one) |
| Agent without access to PyPI | Copy the single file `security_review_mcp/ci_client.py` (or the `security_review_ci` wheel attached to the GitHub release) and run it with `python3 ci_client.py` |
| Docker | `docker run --rm -v "$PWD:/src:ro" -w /src -e SECREVIEW_CONTROLLER_URL -e SECREVIEW_TOKEN --entrypoint security-review-ci ghcr.io/cyr-ius/security-review …` |

The `security-review` package also installs `security-review-ci`: do not install both
packages in the same environment. Install the version of your controller
(`uv tool install security-review-ci==X.Y.Z`); `uv tool upgrade security-review-ci` updates it.

## Commands

| Sub-command | Role |
|---|---|
| `gate --project P [--fail-on S] [--report-id N]` | [Gate](../usage/gate.md) of the project |
| `sarif --project P [--include-resolved] [-o FILE]` | SARIF 2.1.0 log of the project ([SARIF export](sarif.md)) |
| `trend --project P [--days N] [--granularity day\|week\|month] [--format markdown\|json]` | Trend report of the project ([Trend report](#trend-report)) |
| `scan-code [PATH] --project P [--save] …` | Sends the files of the repository to the controller, which scans them with its rules ([Whole codebase scan](code-scan.md)) |
| `scan-deps FILE… --project P [--save] …` | Sends manifests and lockfiles to the controller, which checks them against its advisories ([Dependencies](dependencies.md#scan-in-a-pipeline-security-review-ci-scan-deps)) |

Common options: `--url` (default `SECREVIEW_CONTROLLER_URL`), `--token-stdin` (reads the token
on stdin instead of `SECREVIEW_TOKEN`), `--cafile` (CA of the controller certificate),
`--allow-http`, `--timeout` (seconds, default 60).

- The token is never accepted on the command line (process list, job log) and never written in
  an error message.
- Plain HTTP is refused except to `localhost` (or with `--allow-http`), and so are credentials
  in the URL; redirects are not followed, so the token is only sent to the given controller.
- The two variables are read from the environment only (the `.env` file is ignored).
- The answers are bounded (64 MiB) and the control characters of the text output are removed.

## `ci` token and visible projects

A `ci` token only reaches the pipeline routes: neither `/mcp`, nor the rest of the REST API,
nor the web interface. It is **always restricted to projects**: it sees the gate, the SARIF
log and the trend of the selected projects only, and only stores scan reports for them; another
project answers `404`, like a project that does not exist. `--project` is
[normalized](../usage/prompts-tools.md#project-name) like the project of a review: give the repository
name.

- In the web interface, **Tokens** screen: **Usage** **CI/CD pipeline**, then tick the
  **Allowed projects**. The secret is shown once.
- From the CLI:

```bash
security-review-controller token create --label jenkins-portal --role ci \
  --project portal --project portal-api
```

On a workstation, a developer uses a
[personal `mcp` or `ci` token](../usage/tokens.md#personal-mcp-and-ci-tokens) instead, created in
**My account**: it reaches the projects the developer may read.

Web sessions and `api` tokens (within the projects they read) and `admin` tokens may also call
the gate, SARIF and trend routes; `mcp` tokens may not, except a personal one, which acts as a `ci` token. The scans, which store reports, need a `ci` or
`admin` token (`403` otherwise, web sessions included).

## Typical pipeline

A job of the pipeline chains four commands, with the `ci` token of the project in
`SECREVIEW_TOKEN` and the URL of the controller in `SECREVIEW_CONTROLLER_URL`:

```bash
security-review-ci scan-code . --project portal --save --branch "$BRANCH" --commit "$COMMIT" || [ $? -eq 1 ]
security-review-ci scan-deps uv.lock package-lock.json --project portal --save --require-database \
    --branch "$BRANCH" --commit "$COMMIT" || [ $? -eq 1 ]
security-review-ci sarif --project portal -o security.sarif
security-review-ci gate --project portal --fail-on high
```

1. `scan-code` and `scan-deps` send the files to the controller, which scans them and, with
   `--save`, stores a `code-scan` and a `dependency-scan` report of the project
   ([Whole codebase scan](code-scan.md), [Dependency analysis](dependencies.md#scan-in-a-pipeline-security-review-ci-scan-deps)).
2. `sarif` downloads the open findings of the project, for the code scanning of the platform
   ([SARIF export](sarif.md)).
3. `gate` decides: it fails (code `1`) while open findings reach `--fail-on`.

The exit code of a scan counts every match above its own `--fail-on`, triage decisions
ignored; only the gate takes into account the findings that a person accepted or marked as
false positives. `|| [ $? -eq 1 ]` lets a scan that found something (code `1`) go on to the gate,
but still stops the job on an error (code `2`: controller unreachable, token refused...).
Without it, the scans block by themselves, which is enough for a first test.

Install the client at the version of the controller (`X.Y.Z` below). The project name is
[normalized](../usage/prompts-tools.md#project-name): the name of the repository given by the
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
          SECREVIEW_TOKEN: ${{ secrets.SECREVIEW_CI_TOKEN }}
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
        # SECREVIEW_TOKEN: masked and protected CI/CD variable (ci token)
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
            withCredentials([string(credentialsId: 'secreview-ci', variable: 'SECREVIEW_TOKEN')]) {
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
          SECREVIEW_TOKEN: $(SECREVIEW_CI_TOKEN)   # a secret variable is never mapped implicitly
      - publish: security.sarif
        artifact: CodeAnalysisLogs
        condition: always()
    ```

    The **SARIF SAST Scans Tab** extension shows the `CodeAnalysisLogs` artifact in the build.

=== "Bitbucket Pipelines"

    ```yaml
    # bitbucket-pipelines.yml: SECREVIEW_TOKEN is a secured repository variable
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
    # .circleci/config.yml: SECREVIEW_TOKEN is an environment variable of the project (or of a context)
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
([supported files](dependencies.md#supported-files)).

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
