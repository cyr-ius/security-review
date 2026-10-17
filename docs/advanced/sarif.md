# SARIF export

The [pipeline client](../usage/gate.md#pipeline-client-security-review-ci) downloads the SARIF
log of a project through the controller REST API, with a `ci` token and without database access:

```bash
security-review-ci sarif --project my-project -o results.sarif   # SECREVIEW_CONTROLLER_URL, SECREVIEW_TOKEN
```

The log of a single report is exported by the MCP tool `export_sarif` or the REST API
(`GET /api/v1/sarif?report_id=N`). The produced file is SARIF 2.1.0 (validated against the
official schema).

- Only **open** findings are exported; `--include-resolved` adds the others
  (`baselineState: absent` for the fixed ones, `suppressions` for the accepted / false
  positives). An expired acceptance or false positive is exported as open.
- For a project, a finding reported in several reports appears only once.
- The fingerprint (`partialFingerprints`) ignores the line number: it stays stable when the
  code moves.
- Without a file path, the finding only has a logical location.

## Integrations

| Platform | Ingestion |
|---|---|
| **GitHub** | `github/codeql-action/upload-sarif` (code scanning) |
| **GitLab** | Does **not** ingest SARIF natively (`sast` reports in the GitLab format); keep the file as an artifact or convert it |
| **Jenkins** | Warnings Next Generation plugin |

GitHub Actions example:

```yaml
- run: security-review-controller code scan . --format sarif -o code.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: code.sarif
```
