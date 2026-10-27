# Scan du code complet

Les prompts de revue travaillent sur ce que l'agent leur donne, souvent le diff d'une MR, et
`scan_code` est limité à `SECREVIEW_MAX_CONTENT_CHARS` par appel. Pour couvrir **tout** le
dépôt, utilisez le [client de pipeline](../../advanced/architecture/ci.md)
`security-review-ci scan-code` : il lit les fichiers du dépôt et envoie leur contenu au
serveur Controller, qui les scanne avec les [règles](../rules.md) de sa base.

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_CI_TOKEN=...   # jeton ci limité au projet (ou jeton admin)

security-review-ci scan-code . --project portal                               # résumé texte, code de sortie 0/1/2
security-review-ci scan-code . --project portal --format json -o scan.json    # pour le prompt codebase-review
security-review-ci scan-code . --project portal --format sarif -o code.sarif  # GitHub code scanning, Jenkins...
security-review-ci scan-code . --project portal --save --commit "$CI_COMMIT_SHA"
```

Le pipeline n'a besoin ni de la base ni du paquet : seulement de Python et du
[jeton `ci`](../../advanced/architecture/ci.md#jeton-ci-et-projets-visibles) du projet. Sur un poste de travail,
utilisez un [jeton `ci` personnel](../../usage/tokens.md#jetons-mcp-et-ci-personnels).

## Sélection des fichiers

Le client choisit les fichiers ; le serveur Controller ne lit jamais son propre disque.

- Les fichiers viennent de `git ls-files` (suivis + non suivis non ignorés : `.gitignore` est
  respecté). Hors dépôt git, ou avec `--no-git`, l'arborescence est parcourue en ignorant
  `node_modules`, `.venv`, `dist`, `build`, `target`, `obj`, etc.
- Le langage est déduit du nom : `.py`, `.java`, `.go`, `.cs`/`.cshtml`/`.razor`, `.rs`, `.ts`, `.js`,
  `.html` (templates Angular),
  `.yml`/`.yaml`, `.properties`, `.toml`, `.env*`, `Dockerfile*`, `Jenkinsfile`,
  `.gitlab-ci.yml`, et les fichiers qui pilotent un assistant IA (`AGENTS.md`, `CLAUDE.md`,
  `GEMINI.md`, `copilot-instructions.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`,
  `*.mdc`, `*.instructions.md`, `*.prompt.md`, `*.md` sous `.claude/`, `.cursor/`, `.windsurf/`
  ou `.clinerules/`), analysés pour y trouver du texte caché et des instructions injectées
  (règles `AI-*`). Les lockfiles, `*.min.js` et `*.d.ts` sont ignorés. Seuls ces fichiers sont
  envoyés.
- Fichiers ignorés : `--exclude GLOB` (répétable, ex. `--exclude tests/`, seulement comptés),
  et, signalés, les fichiers au-delà de `--max-file-bytes` (1 Mio par défaut), les binaires et
  les liens symboliques.

!!! note "Le contenu quitte l'agent de build"
    Le code source est envoyé au serveur Controller (HTTPS, ou HTTP simple vers une adresse de bouclage
    ou avec `--allow-http`). Excluez avec `--exclude` ce qui ne doit pas quitter l'agent.

## Limites du serveur Controller

| Variable | Défaut | Effet |
|---|---|---|
| `SECREVIEW_MAX_SCAN_REQUEST_MB` | `64` | Taille de la requête : au-delà, le serveur Controller répond `413` (code de sortie `2`) |
| `SECREVIEW_MAX_SCAN_FILES` | `10000` | Fichiers par requête : au-delà, `422` |
| `SECREVIEW_MAX_SCAN_FILE_CHARS` | `1048576` | Un fichier plus grand n'est pas scanné et figure parmi les fichiers ignorés |

## Seuil et enregistrement

- `--fail-on` (défaut `high`) fixe le seuil de blocage ; les [règles](../rules.md) de la base et
  les marqueurs `secreview:ignore` s'appliquent comme pour `scan_code`.
- `--save` enregistre les correspondances comme un rapport `code-scan` (au plus
  `SECREVIEW_MAX_FINDINGS_PER_REPORT` findings, les plus sévères d'abord), avec la liste des
  fichiers non analysés dans `scope` et le libellé du jeton comme appareil qui l'a enregistré ;
  l'utilisateur d'un jeton `ci` personnel en est l'auteur, sinon `--author` ajoute le nom
  d'utilisateur du développeur (voir
  [auteur d'un rapport](../prompts-tools.md#auteur-dun-rapport)), `--repository`,
  `--branch` et `--commit` le contexte.
- Avec `--save --format sarif`, le journal SARIF porte les identifiants des findings
  enregistrés.

!!! warning "Triez avant de bloquer"
    Les correspondances sont des **pistes**. Triez-les (prompt `triage-report`) avant de faire
    dépendre une [gate](../gate.md) de ce rapport, sinon les faux positifs la bloqueront.

## Revue guidée par l'agent

Ensuite, le prompt `codebase-review` (argument `scan_results` = le JSON, éventuellement filtré)
guide l'agent : inventaire, priorisation des points d'entrée, traçage des flux entre fichiers,
checklists, et une section **couverture** qui dit ce qui n'a pas été relu. Sans `scan_results`,
le prompt demande à un agent qui peut lancer des commandes d'exécuter lui-même
`security-review-ci scan-code` (avec un jeton `ci` personnel) : les fichiers arrivent au
serveur Controller tels quels, au lieu d'être recopiés par le modèle dans des appels à `scan_code`. Le
prompt `dependency-review` fait de même avec `security-review-ci scan-deps`.
