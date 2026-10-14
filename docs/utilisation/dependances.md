# Analyse des dépendances

## Fichiers pris en charge

`requirements*.txt`, `pyproject.toml` (PEP 621/735, Poetry), `poetry.lock`, `Pipfile.lock`,
`package.json`, `package-lock.json` / `npm-shrinkwrap.json`, `yarn.lock` (v1 et berry),
`pom.xml`, `build.gradle(.kts)`.

## Base de vulnérabilités hors ligne (format OSV)

Le serveur n'appelle aucun service externe. Sur une machine connectée, téléchargez les exports
d'osv.dev (`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`, idem `npm` et
`Maven`), transférez-les, puis importez-les (opération réservée à la CLI, idempotente) :

```bash
security-review-controller advisories import PyPI.zip      # .json, dossier ou .zip
security-review-controller advisories import npm.zip
security-review-controller advisories import Maven.zip --ecosystem Maven   # filtre facultatif
security-review-controller advisories status
```

## Scan en pipeline

Pour les gros lockfiles, préférez la CLI à l'outil MCP, limité à
`SECREVIEW_MAX_DEPENDENCY_CHARS` :

```bash
security-review-controller deps scan package-lock.json requirements.txt \
    --fail-on high --require-database --project mon-projet --save
# code de sortie : 0 = ok, 1 = bloqué, 2 = erreur
```

## Lire le résultat

Le champ `vulnerability_check` dit si la vérification a eu lieu :

| Valeur | Signification |
|---|---|
| `performed` | Les versions ont été comparées à la base |
| `skipped_no_advisory_database` | Aucune base importée |
| `skipped_no_advisories_for_ecosystem` | Aucun avis pour cet écosystème |

!!! danger "Liste vide ≠ dépendances sûres"
    Dans les deux derniers cas, **une liste vide ne signifie pas que les dépendances sont
    sûres**. `--require-database` fait échouer le pipeline dans ce cas.

- Une base de plus de 30 jours est signalée.
- Une sévérité absente de l'avis est traitée comme `medium` (`severity_known: false`).
- Les versions en intervalle (`>=2`) ne sont pas vérifiables : analysez le lockfile.
- Règles d'hygiène `DEP-001` à `DEP-009` : versions non épinglées, URL / VCS, HTTP, index
  supplémentaire, `--trusted-host`, etc.
