# CI/CD gate

Without an agent or an MCP client, a Jenkins, GitLab or GitHub job can block a deployment while
critical findings remain open. The `security-review-ci gate` command does it through the
controller REST API, with a [`ci` token](#ci-token-and-visible-projects): it needs only Python 3
on the build agent (no database driver, no SQLModel, no database URL). The controller CLI
(`security-review-controller`) has no pipeline command.

```bash
security-review-ci gate --project portal --fail-on high
# exit code: 0 = passes, 1 = blocked, 2 = error (project/report not found, outside the token,
# controller unreachable, token refused)
# options: --report-id N to judge only one report
```

## Pipeline client (`security-review-ci`)

`security-review-ci` is a lightweight client of the controller: it calls the pipeline routes of
the REST API (`/api/v1/ci/gate`, `/api/v1/ci/sarif`, `/api/v1/ci/trend`, and
`/api/v1/ci/scan/code` and `/api/v1/ci/scan/deps` for the scans) and opens no database. It only uses the Python standard library: install the package
(`pip install security-review-mcp`), or copy the single file
`security_review_mcp/ci_client.py` to the agent and run it with `python3 ci_client.py`.

| Sub-command | Role |
|---|---|
| `gate --project P [--fail-on S] [--report-id N]` | Gate of the project (see above) |
| `sarif --project P [--include-resolved] [-o FILE]` | SARIF 2.1.0 log of the project ([SARIF export](../advanced/sarif.md)) |
| `trend --project P [--days N] [--granularity day\|week\|month] [--format markdown\|json]` | Trend report of the project ([Trend report](../advanced/trends.md)) |
| `code-scan [PATH] --project P [--save] …` | Sends the files of the repository to the controller, which scans them with its rules ([Whole codebase scan](../advanced/code-scan.md)) |
| `deps-scan FILE… --project P [--save] …` | Sends manifests and lockfiles to the controller, which checks them against its advisories ([Dependencies](../advanced/dependencies.md#scan-in-a-pipeline-security-review-ci-deps-scan)) |

Common options: `--url` (default `SECREVIEW_CONTROLLER_URL`), `--token-stdin` (reads the token
on stdin instead of `SECREVIEW_TOKEN`), `--cafile` (CA of the controller certificate),
`--allow-http`, `--timeout` (seconds, default 60).

- The token is never accepted on the command line (process list, job log) and never written in
  an error message.
- Plain HTTP is refused except to `localhost` (or with `--allow-http`), and so are credentials
  in the URL; redirects are not followed, so the token is only sent to the given controller.
- The two variables are read from the environment only (the `.env` file is ignored).
- The answers are bounded (64 MiB) and the control characters of the text output are removed.

### `ci` token and visible projects

A `ci` token only reaches the pipeline routes: neither `/mcp`, nor the rest of the REST API,
nor the web interface. It is **always restricted to projects**: it sees the gate, the SARIF
log and the trend of the selected projects only, and only stores scan reports for them; another
project answers `404`, like a project that does not exist.

- In the web interface, **Tokens** screen: **Usage** **CI/CD pipeline**, then tick the
  **Allowed projects**. The secret is shown once.
- From the CLI:

```bash
security-review-controller token create --label jenkins-portal --role ci \
  --project portal --project portal-api
```

`reader`, `triager` and `admin` tokens may also call the gate, SARIF and trend routes (within
their own projects); `mcp` tokens may not. The scans, which store reports, need a `ci` or
`admin` token (`403` otherwise, web sessions included).

### Examples

=== "Jenkins"

    ```groovy
    // Jenkinsfile: the ci token is a "Secret text" credential
    pipeline {
      agent any
      environment {
        SECREVIEW_CONTROLLER_URL = 'https://secreview.example.com'
      }
      stages {
        stage('Security gate') {
          steps {
            withCredentials([string(credentialsId: 'secreview-ci', variable: 'SECREVIEW_TOKEN')]) {
              sh 'security-review-ci sarif --project portal -o security.sarif'
              sh 'security-review-ci gate --project portal --fail-on high'
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

=== "GitLab CI"

    ```yaml
    # .gitlab-ci.yml
    security-gate:
      stage: test
      image: python:3.14-slim
      script:
        - pip install security-review-mcp
        - security-review-ci gate --project "$CI_PROJECT_PATH_SLUG" --fail-on high
      variables:
        SECREVIEW_CONTROLLER_URL: https://secreview.example.com
        # SECREVIEW_TOKEN: masked and protected CI/CD variable (ci token)
    ```

=== "GitHub Actions"

    ```yaml
    - name: Security gate
      run: security-review-ci gate --project "${{ github.event.repository.name }}" --fail-on high
      env:
        SECREVIEW_CONTROLLER_URL: https://secreview.example.com
        SECREVIEW_TOKEN: ${{ secrets.SECREVIEW_CI_TOKEN }}
    ```

A finding stops blocking when a person moves it to `fixed`, `accepted` or `false_positive` in
the [web interface](web-interface.md#triage-of-findings): the decision stays recorded in
the database with its reason and its approver. An agent can only propose a status
(`propose_finding_status`), which does not unblock the gate. An acceptance or a false positive
expires: from its expiry date, the finding blocks again.
