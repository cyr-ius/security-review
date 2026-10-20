# Scan du code complet

Les prompts de revue travaillent sur ce que l'agent leur donne, souvent le diff d'une MR, et
`scan_code` est limité à `SECREVIEW_MAX_CONTENT_CHARS` par appel. Pour couvrir **tout** le
dépôt, utilisez le [client de pipeline](../usage/gate.md#client-de-pipeline-security-review-ci)
`security-review-ci scan-code` : il lit les fichiers du dépôt et envoie leur contenu au
contrôleur, qui les scanne avec les [règles](rules.md) de sa base.

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_TOKEN=...   # jeton ci limité au projet (ou jeton admin)

security-review-ci scan-code . --project portal                               # résumé texte, code de sortie 0/1/2
security-review-ci scan-code . --project portal --format json -o scan.json    # pour le prompt codebase-review
security-review-ci scan-code . --project portal --format sarif -o code.sarif  # GitHub code scanning, Jenkins...
security-review-ci scan-code . --project portal --save --commit "$CI_COMMIT_SHA"
```

Le pipeline n'a besoin ni de la base ni du paquet : seulement de Python et du
[jeton `ci`](../usage/gate.md#jeton-ci-et-projets-visibles) du projet.

## Sélection des fichiers

Le client choisit les fichiers ; le contrôleur ne lit jamais son propre disque.

- Les fichiers viennent de `git ls-files` (suivis + non suivis non ignorés : `.gitignore` est
  respecté). Hors dépôt git, ou avec `--no-git`, l'arborescence est parcourue en ignorant
  `node_modules`, `.venv`, `dist`, `build`, `target`, etc.
- Le langage est déduit du nom : `.py`, `.java`, `.ts`, `.js`, `.html` (templates Angular),
  `.yml`/`.yaml`, `.properties`, `.toml`, `.env*`, `Dockerfile*`, `Jenkinsfile`,
  `.gitlab-ci.yml`. Les lockfiles, `*.min.js` et `*.d.ts` sont ignorés. Seuls ces fichiers
  sont envoyés.
- Fichiers ignorés : `--exclude GLOB` (répétable, ex. `--exclude tests/`, seulement comptés),
  et, signalés, les fichiers au-delà de `--max-file-bytes` (1 Mio par défaut), les binaires et
  les liens symboliques.

!!! note "Le contenu quitte l'agent de build"
    Le code source est envoyé au contrôleur (HTTPS, ou HTTP simple vers une adresse de bouclage
    ou avec `--allow-http`). Excluez avec `--exclude` ce qui ne doit pas quitter l'agent.

## Limites du contrôleur

| Variable | Défaut | Effet |
|---|---|---|
| `SECREVIEW_MAX_SCAN_REQUEST_MB` | `64` | Taille de la requête : au-delà, le contrôleur répond `413` (code de sortie `2`) |
| `SECREVIEW_MAX_SCAN_FILES` | `10000` | Fichiers par requête : au-delà, `422` |
| `SECREVIEW_MAX_SCAN_FILE_CHARS` | `1048576` | Un fichier plus grand n'est pas scanné et figure parmi les fichiers ignorés |

## Seuil et enregistrement

- `--fail-on` (défaut `high`) fixe le seuil de blocage ; les [règles](rules.md) de la base et
  les marqueurs `secreview:ignore` s'appliquent comme pour `scan_code`.
- `--save` enregistre les correspondances comme un rapport `code-scan` (au plus
  `SECREVIEW_MAX_FINDINGS_PER_REPORT` findings, les plus sévères d'abord), avec la liste des
  fichiers non analysés dans `scope` et le libellé du jeton comme appareil qui l'a enregistré ;
  `--author` ajoute le nom d'utilisateur du développeur (voir
  [auteur d'un rapport](../usage/prompts-tools.md#auteur-dun-rapport)), `--repository`,
  `--branch` et `--commit` le contexte.
- Avec `--save --format sarif`, le journal SARIF porte les identifiants des findings
  enregistrés.

!!! warning "Triez avant de bloquer"
    Les correspondances sont des **pistes**. Triez-les (prompt `triage-report`) avant de faire
    dépendre une [gate](../usage/gate.md) de ce rapport, sinon les faux positifs la bloqueront.

## Revue guidée par l'agent

Ensuite, le prompt `codebase-review` (argument `scan_results` = le JSON, éventuellement filtré)
guide l'agent : inventaire, priorisation des points d'entrée, traçage des flux entre fichiers,
checklists, et une section **couverture** qui dit ce qui n'a pas été relu.
