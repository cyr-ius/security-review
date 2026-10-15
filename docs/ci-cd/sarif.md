# SARIF export

```bash
security-review-controller sarif --project my-project -o results.sarif      # or --report-id N
```

The produced file is SARIF 2.1.0 (validated against the official schema).

- Only **open** findings are exported; `--include-resolved` adds the others
  (`baselineState: absent` for the fixed ones, `suppressions` for the accepted / false
  positives).
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
