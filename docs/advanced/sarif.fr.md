# Export SARIF

Le [client de pipeline](../usage/gate.md#client-de-pipeline-security-review-ci) télécharge le
journal SARIF d'un projet par l'API REST du contrôleur, avec un jeton `ci` et sans accès à la
base :

```bash
security-review-ci sarif --project mon-projet -o results.sarif   # SECREVIEW_CONTROLLER_URL, SECREVIEW_TOKEN
```

Le journal d'un seul rapport est exporté par l'outil MCP `export_sarif` ou par l'API REST
(`GET /api/v1/sarif?report_id=N`). Le fichier produit est du SARIF 2.1.0 (validé contre le
schéma officiel).

- Seuls les findings **ouverts** sont exportés ; `--include-resolved` ajoute les autres
  (`baselineState: absent` pour les corrigés, `suppressions` pour les acceptés / faux positifs).
  Une acceptation ou un faux positif expiré est exporté comme ouvert.
- Pour un projet, un finding signalé dans plusieurs rapports n'apparaît qu'une fois.
- L'empreinte (`partialFingerprints`) ignore le numéro de ligne : elle reste stable quand le
  code bouge.
- Sans chemin de fichier, le finding n'a qu'une localisation logique.

## Intégrations

| Plateforme | Ingestion |
|---|---|
| **GitHub** | `github/codeql-action/upload-sarif` (code scanning) |
| **GitLab** | N'ingère **pas** SARIF nativement (rapports `sast` au format GitLab) ; gardez le fichier comme artefact ou convertissez-le |
| **Jenkins** | Plugin Warnings Next Generation |

Exemple GitHub Actions :

```yaml
- run: security-review-ci scan-code . --project my-project --format sarif -o code.sarif
  env:
    SECREVIEW_CONTROLLER_URL: https://secreview.example.com
    SECREVIEW_TOKEN: ${{ secrets.SECREVIEW_CI_TOKEN }}
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: code.sarif
```
