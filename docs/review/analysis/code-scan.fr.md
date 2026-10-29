# Analyse du code complet

Les prompts de revue travaillent sur ce que l'agent leur donne, souvent le diff d'une MR, et
`scan_code` est limité à `SECREVIEW_MAX_CONTENT_CHARS` par appel. Pour couvrir **tout** le
dépôt, il existe deux modes, indépendants et complémentaires :

| | [Scan automatique](#mode-1-scan-automatique-security-review-ci-scan-code) | [Revue par l'agent](#mode-2-revue-par-lagent-prompt-codebase-review) |
|---|---|---|
| Lancé par | la commande `security-review-ci scan-code` (pipeline CI/CD ou poste de travail) | l'utilisateur, avec le prompt `codebase-review` dans son hôte (Claude, Copilot, Codex…) |
| Qui analyse | le serveur Controller, sans IA | l'agent IA, qui lit le code |
| Ce qui est appliqué | les [règles](../rules.md) de la base, seulement | les règles (par le scan), les [checklists](../checklists.md) et le raisonnement de l'agent (flux entre fichiers, logique métier) |
| Fichiers | tous les fichiers éligibles du dépôt | ceux que l'agent choisit de lire (pistes du scan, zones sensibles) |
| Résultat | des **pistes** (correspondances de motifs), rapport `code-scan` avec `--save` | des **findings confirmés**, rapport `codebase-review` |
| Coût | rapide, déterministe, aucun token | lent, consomme beaucoup de tokens |
| Usage type | à chaque commit ou MR, avec une [gate](../gate.md) | première revue d'un dépôt, audit périodique |

Les deux se combinent : la sortie JSON du scan automatique sert de point de départ à la revue
par l'agent (argument `scan_results`), qui confirme ou écarte chaque piste.

## Mode 1 : scan automatique (`security-review-ci scan-code`)

Le [client de pipeline](../../advanced/architecture/ci.md) `security-review-ci scan-code` lit
les fichiers du dépôt et envoie leur contenu au serveur Controller, qui les scanne avec les
[règles](../rules.md) de sa base. Aucun agent IA n'intervient : c'est un scan par motifs, comme
`scan_code`, appliqué à tout le dépôt.

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

### Sélection des fichiers

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

### Limites du serveur Controller

| Variable | Défaut | Effet |
|---|---|---|
| `SECREVIEW_MAX_SCAN_REQUEST_MB` | `64` | Taille de la requête : au-delà, le serveur Controller répond `413` (code de sortie `2`) |
| `SECREVIEW_MAX_SCAN_FILES` | `10000` | Fichiers par requête : au-delà, `422` |
| `SECREVIEW_MAX_SCAN_FILE_CHARS` | `1048576` | Un fichier plus grand n'est pas scanné et figure parmi les fichiers ignorés |

### Seuil et enregistrement

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

## Mode 2 : revue par l'agent (prompt `codebase-review`)

Le prompt `codebase-review` du serveur MCP fait relire tout le dépôt par l'agent IA de
l'utilisateur, comme le ferait un auditeur : il ne se limite pas aux règles, il suit les données
d'un fichier à l'autre et parcourt les checklists. Il ne dépend pas du mode 1, mais s'appuie sur
lui quand il est disponible.

### Lancer la revue

Dans l'hôte, lancez le prompt `codebase-review`, avec au choix :

- **les résultats du scan automatique** dans `scan_results` (le JSON de
  `security-review-ci scan-code . --project portal --format json`, éventuellement filtré) :
  l'agent part de ces pistes ;
- **sans `scan_results`** : le prompt demande à un agent qui peut lancer des commandes
  d'exécuter lui-même `security-review-ci scan-code` (avec un jeton `ci` personnel), ou à
  l'utilisateur de le lancer et de coller la sortie. Les fichiers arrivent ainsi au serveur
  Controller tels quels, au lieu d'être recopiés par le modèle dans des appels à `scan_code`.

`languages` choisit les checklists, `focus` et `context` orientent la revue (voir
[prompts et outils](../prompts-tools.md#prompts)). Le prompt `dependency-review` fait de même
pour les dépendances avec `security-review-ci scan-deps`.

### Ce que fait `codebase-review`

Le prompt ne lit lui-même aucun fichier : il donne une **méthode** à l'agent, et c'est l'agent
qui lit le code dans son espace de travail.

1. **Inventaire.** L'agent liste les fichiers du dépôt, en respectant `.gitignore`, sans le
   code généré, les dépendances embarquées ni les sorties de build. Il repère les langages, les
   points d'entrée (routes HTTP, CLI, consommateurs de messages, tâches planifiées) et les
   fichiers de configuration et de CI/CD.
2. **Pistes.** Il part des résultats du scan (`scan_results`, ou `security-review-ci scan-code`
   lancé par lui-même), sinon, en dernier recours, appelle `scan_code` sur chaque fichier lu.
3. **Priorisation.** Il lit d'abord ce qu'un attaquant peut atteindre : points d'entrée,
   authentification, validation des entrées, base de données, fichiers et processus,
   désérialisation, requêtes sortantes, cryptographie et secrets, puis configuration et
   pipelines.
4. **Traçage.** Il suit les données non fiables de chaque point d'entrée jusqu'aux appels
   sensibles, d'un fichier à l'autre : ce qu'une revue de diff ne voit pas.
5. **Checklists**, puis **rapport** enregistré une fois (`review_type` : `codebase-review`),
   avec dans `scope` les fichiers relus et **ceux qui ne l'ont pas été**.

**Prend-il tous les fichiers du dépôt ?** Pas tous d'un coup. Le *scan* couvre tous les fichiers
éligibles ([sélection des fichiers](#selection-des-fichiers)) ; la *lecture* par l'agent cible
les fichiers qui comptent (pistes du scan, points d'entrée, zones sensibles). Sur un gros dépôt,
l'agent ne lit pas tout en une session : le prompt lui demande de dire ce qui reste au lieu de
prétendre l'avoir couvert.

**Utilise-t-il les règles et les checklists ?**

- **Règles** : oui, par le scan. `security-review-ci scan-code` applique toutes les règles
  actives de la base (intégrées et internes) ; `scan_code` fait de même fichier par fichier.
  Leurs correspondances sont des pistes que l'agent confirme ou écarte en lisant le code.
- **Checklists** : oui, incluses dans le prompt : celles des langages donnés dans `languages`,
  puis `api`, `config` et `cicd`, les checklists `*` (tous langages) et `company` ; les autres
  checklists disponibles sont citées, pour que l'agent les récupère avec `get_review_checklist`
  quand elles s'appliquent ([détails](../checklists.md#checklists-des-prompts-de-revue)).

**La consommation de tokens peut-elle être importante ?** Oui, c'est le prompt le plus coûteux :
l'agent lit une grande partie du dépôt, et chaque fichier lu compte dans son contexte. Pour la
maîtriser :

- fournissez `scan_results`, ou laissez l'agent lancer `security-review-ci scan-code` : les
  fichiers arrivent au serveur Controller sans passer par le modèle, qui ne lit ensuite que les
  pistes et les zones sensibles. Sans cela, l'agent recopie chaque fichier dans un appel à
  `scan_code`, ce qui coûte le plus ;
- filtrez le scan (`--exclude tests/`, `--exclude docs/`, `--fail-on`) : `scan_results` est
  limité à `SECREVIEW_MAX_CONTENT_CHARS` (200 000 caractères par défaut) ;
- resserrez la revue avec `focus` (par exemple `authentification, upload de fichiers`) ou
  `context`, ou relisez une partie du dépôt à la fois ;
- pour une merge request, utilisez plutôt `security-review` sur le diff : `codebase-review` sert
  à une première revue ou à un audit périodique.
