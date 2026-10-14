# Gate CI/CD

Sans agent ni client MCP, un job Jenkins, GitLab ou GitHub peut bloquer un déploiement tant que
des findings critiques restent ouverts :

```bash
security-review-controller gate --project portal --fail-on high
# code de sortie : 0 = passe, 1 = bloqué, 2 = erreur (projet/rapport introuvable)
# options : --report-id N pour ne juger qu'un rapport
```

=== "GitLab CI"

    ```yaml
    # .gitlab-ci.yml
    security-gate:
      stage: test
      script:
        - security-review-controller gate --project "$CI_PROJECT_PATH_SLUG" --fail-on high
      variables:
        SECREVIEW_DATABASE_URL: $SECREVIEW_DATABASE_URL   # variable masquée et protégée
    ```

=== "GitHub Actions"

    ```yaml
    - name: Security gate
      run: security-review-controller gate --project "${{ github.event.repository.name }}" --fail-on high
      env:
        SECREVIEW_DATABASE_URL: ${{ secrets.SECREVIEW_DATABASE_URL }}
    ```

Un finding sort du blocage quand il passe à `fixed`, `accepted` ou `false_positive`
(outil `update_finding_status`) : la décision reste tracée en base.
