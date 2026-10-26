# CI/CD gate

Without an agent or an MCP client, a Jenkins, GitLab or GitHub job can block a deployment while
critical findings remain open. The `security-review-ci gate` command does it through the
controller REST API, with a [`ci` token](../advanced/architecture/ci.md#ci-token-and-visible-projects): it needs only Python 3.14
on the build agent (no database driver, no SQLModel, no database URL). The controller CLI
(`security-review-controller`) has no pipeline command.

```bash
security-review-ci gate --project portal --fail-on high
# exit code: 0 = passes, 1 = blocked, 2 = error (project/report not found, outside the token,
# controller unreachable, token refused)
# options: --report-id N to judge only one report
```

The client, its installation, the `ci` token and pipeline examples for GitHub Actions, GitLab CI,
Jenkins, Azure Pipelines, Bitbucket Pipelines and CircleCI: see
[Pipeline client (CI/CD)](../advanced/architecture/ci.md).

A finding stops blocking when a person moves it to `fixed`, `accepted` or `false_positive` in
the [web interface](../usage/triage.md): the decision stays recorded in
the database with its reason and its approver. An agent can only propose a status
(`propose_finding_status`), which does not unblock the gate. An acceptance or a false positive
expires: from its expiry date, the finding blocks again. A decision is carried to the same
issue raised by a later report ([finding reported again](../usage/triage.md#finding-reported-again)):
the gate of the next report does not block on an accepted risk. The exit code of
`scan-code` and `scan-deps`, on the other hand, counts every match above its threshold (see
[typical pipeline](../advanced/architecture/ci.md#typical-pipeline)).
