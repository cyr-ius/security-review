# Scan du code complet

Les prompts de revue travaillent sur ce que l'agent leur donne, souvent le diff d'une MR, et
`scan_code` est limité à `SECREVIEW_MAX_CONTENT_CHARS` par appel. Pour couvrir **tout** le
dépôt, utilisez la CLI :

```bash
security-review-mcp code scan .                               # résumé texte, code de sortie 0/1/2
security-review-mcp code scan . --format json -o scan.json    # pour le prompt codebase-review
security-review-mcp code scan . --format sarif -o code.sarif  # GitHub code scanning, Jenkins...
security-review-mcp code scan . --save --project portal --commit "$CI_COMMIT_SHA"
```

## Sélection des fichiers

- Les fichiers viennent de `git ls-files` (suivis + non suivis non ignorés : `.gitignore` est
  respecté). Hors dépôt git, ou avec `--no-git`, l'arborescence est parcourue en ignorant
  `node_modules`, `.venv`, `dist`, `build`, `target`, etc.
- Le langage est déduit du nom : `.py`, `.java`, `.ts`, `.js`, `.html` (templates Angular),
  `.yml`/`.yaml`, `.properties`, `.toml`, `.env*`, `Dockerfile*`, `Jenkinsfile`,
  `.gitlab-ci.yml`. Les lockfiles, `*.min.js` et `*.d.ts` sont ignorés.
- Fichiers ignorés et signalés : `--exclude GLOB` (répétable, ex. `--exclude tests/`), au-delà
  de `--max-file-bytes` (1 Mio par défaut), binaires, liens symboliques.

## Seuil et enregistrement

- `--fail-on` (défaut `high`) fixe le seuil de blocage ; les [règles internes](regles.md) de la
  base (`SECREVIEW_DATABASE_URL`) et les marqueurs `secreview:ignore` s'appliquent comme pour
  `scan_code`. Si la base est inaccessible, seules les règles intégrées s'appliquent et un
  avertissement est écrit sur stderr.
- `--save` enregistre les correspondances comme findings (au plus
  `SECREVIEW_MAX_FINDINGS_PER_REPORT`, les plus sévères d'abord) et la liste des fichiers non
  analysés dans `scope`.

!!! warning "Triez avant de bloquer"
    Les correspondances sont des **pistes**. Triez-les (prompt `triage-report`) avant de faire
    dépendre une [gate](../ci-cd/gate.md) de ce rapport, sinon les faux positifs la bloqueront.

## Revue guidée par l'agent

Ensuite, le prompt `codebase-review` (argument `scan_results` = le JSON, éventuellement filtré)
guide l'agent : inventaire, priorisation des points d'entrée, traçage des flux entre fichiers,
checklists, et une section **couverture** qui dit ce qui n'a pas été relu.
