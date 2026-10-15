# CI/CD gate

Without an agent or an MCP client, a Jenkins, GitLab or GitHub job can block a deployment while
critical findings remain open:

```bash
security-review-controller gate --project portal --fail-on high
# exit code: 0 = passes, 1 = blocked, 2 = error (project/report not found)
# options: --report-id N to judge only one report
```

=== "GitLab CI"

    ```yaml
    # .gitlab-ci.yml
    security-gate:
      stage: test
      script:
        - security-review-controller gate --project "$CI_PROJECT_PATH_SLUG" --fail-on high
      variables:
        SECREVIEW_DATABASE_URL: $SECREVIEW_DATABASE_URL   # masked and protected variable
    ```

=== "GitHub Actions"

    ```yaml
    - name: Security gate
      run: security-review-controller gate --project "${{ github.event.repository.name }}" --fail-on high
      env:
        SECREVIEW_DATABASE_URL: ${{ secrets.SECREVIEW_DATABASE_URL }}
    ```

A finding stops blocking when it moves to `fixed`, `accepted` or `false_positive`
(`update_finding_status` tool): the decision stays recorded in the database.
