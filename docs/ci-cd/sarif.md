# Export SARIF

```bash
security-review-mcp sarif --project mon-projet -o results.sarif      # ou --report-id N
```

Le fichier produit est du SARIF 2.1.0 (validé contre le schéma officiel).

- Seuls les findings **ouverts** sont exportés ; `--include-resolved` ajoute les autres
  (`baselineState: absent` pour les corrigés, `suppressions` pour les acceptés / faux positifs).
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
- run: security-review-mcp code scan . --format sarif -o code.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: code.sarif
```
