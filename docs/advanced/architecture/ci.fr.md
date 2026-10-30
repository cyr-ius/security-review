# Client de pipeline (CI/CD)

Le client de pipeline tourne dans les jobs CI/CD et sur les postes des développeurs : il
envoie les fichiers du dépôt au [serveur Controller](controller.md), qui les scanne, et lit la gate,
le journal SARIF et la tendance d'un projet.

`security-review-ci` est un client léger du serveur Controller : il appelle les routes de pipeline de
l'API REST (`/api/v1/ci/gate`, `/api/v1/ci/sarif`, `/api/v1/ci/trend`, et
`/api/v1/ci/scan/code` et `/api/v1/ci/scan/deps` pour les scans) et n'ouvre aucune base. Il
n'utilise que la bibliothèque standard de Python (Python 3.14) et est publié seul
sur PyPI sous le nom `security-review-ci`, à la version du serveur, sans ses dépendances.

## Installation

| Machine | Commande |
|---|---|
| Poste sans Python (Linux, macOS, Windows) | [uv](https://docs.astral.sh/uv/getting-started/installation/), puis `uv tool install security-review-ci` : uv télécharge un Python quand aucun n'est installé |
| Agent de build ou poste avec Python ≥ 3.14 | `uv pip install security-review-ci` dans l'environnement virtuel du job (`--system` sans environnement) |
| Poste ou agent sans PyPI, depuis le serveur Controller | `uvx --no-index --find-links https://secreview.example.com/api/ci-client/ security-review-ci@latest …` : le [client du serveur Controller](#depuis-le-serveur-controller), à sa version |
| Agent sans accès à PyPI | Copiez le seul fichier `security_review_mcp/ci_client.py` (ou le wheel `security_review_ci` joint à la release GitHub) et lancez-le avec `python3 ci_client.py` |
| Docker | `docker run --rm -v "$PWD:/src:ro" -w /src -e SECREVIEW_CONTROLLER_URL -e SECREVIEW_CI_TOKEN --entrypoint security-review-ci ghcr.io/cyr-ius/security-review …` |

Le paquet `security-review` installe aussi `security-review-ci` : n'installez pas les deux
paquets dans le même environnement. Installez la version de votre serveur Controller
(`uv tool install security-review-ci==X.Y.Z`) ; `uv tool upgrade security-review-ci` le met à
jour.

### Depuis le serveur Controller

Sauf avec `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED=false`, le serveur Controller sert son propre client sur
`/api/ci-client/` : une page de liens pour `uv --find-links` et le wheel
`security_review_ci-<version>-py3-none-any.whl`, construit depuis son code, à sa version. Les
développeurs et les agents de build n'ont alors besoin ni de PyPI ni d'une version à tenir à
jour :

```bash
uvx --no-index --find-links https://secreview.example.com/api/ci-client/ \
  security-review-ci@latest scan-deps uv.lock --project shop-api
```

- `--no-index` tient uv à l'écart de PyPI : aucun autre paquet du même nom ne peut être
  installé ; `@latest` fait relire la page à chaque exécution et suivre la version du
  serveur Controller.
- uv vérifie le SHA-256 donné par la page. Servez le serveur Controller en HTTPS : uv accepte aussi une
  URL en HTTP, mais la page et le wheel peuvent alors être remplacés en chemin, SHA-256 compris,
  et les développeurs exécuteraient ce code (voir
  [serveur Controller en HTTP](../../getting-started/commit-hooks.md#serveur-controller-en-http-sans-tls)).
- Les deux routes sont publiques (uv n'envoie aucun jeton) et en lecture seule ; comme la
  documentation de l'API, elles indiquent la version du serveur Controller :
  `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED=false` les masque.

## Commandes

| Sous-commande | Rôle |
|---|---|
| `gate` | [Gate](../../review/gate.md) du projet |
| `sarif` | Journal SARIF 2.1.0 du projet ([Export SARIF](../reports/sarif.md)) |
| `trend` | Rapport de tendance du projet ([Rapport de tendance](#rapport-de-tendance)) |
| `scan-code` | Envoie les fichiers du dépôt au serveur Controller, qui les scanne avec ses règles ([Analyse du code complet](../../review/analysis/code-scan.md)) |
| `scan-deps` | Envoie manifestes et lockfiles au serveur Controller, qui les compare à ses avis ([Dépendances](../../review/analysis/dependencies.md#scan-dans-un-pipeline-security-review-ci-scan-deps)) |
| `agent-review` | Fait relire le dernier commit par l'agent de code du développeur avec le serveur MCP, en arrière-plan (hook post-commit, [Revue de chaque commit par un agent](#revue-de-chaque-commit-par-un-agent)) |
| `guard` | Vérifie, hors ligne, que les fichiers que l'agent de code va lire ne cachent pas de texte et ne s'adressent pas à un assistant (hook de l'agent, [Garde de lecture](../../review/analysis/read-guard.md)) |

Toutes leurs options : [Ligne de commande](../../reference/cli.md#security-review-ci).

Options communes (sauf `agent-review` et `guard`) : `--url` (par défaut `SECREVIEW_CONTROLLER_URL`), `--token-stdin` (lit le
jeton sur l'entrée standard au lieu de `SECREVIEW_CI_TOKEN`), `--cafile` (CA du certificat du
serveur Controller), `--allow-http`, `--timeout` (secondes, 60 par défaut).

- Le jeton n'est jamais accepté sur la ligne de commande (liste des processus, journal du job)
  et n'apparaît jamais dans un message d'erreur.
- Le HTTP en clair est refusé sauf vers `localhost` (ou avec `--allow-http`), de même que les
  identifiants dans l'URL ; les redirections ne sont pas suivies : le jeton n'est envoyé qu'au
  serveur Controller indiqué.
- Les deux variables ne sont lues que dans l'environnement (le fichier `.env` est ignoré).
- Les réponses sont bornées (64 Mio) et les caractères de contrôle de la sortie texte sont
  retirés.

## Revue de chaque commit par un agent

`agent-review` s'exécute sur le poste d'un développeur, en hook post-commit : l'agent de code du
développeur relit le dernier commit sous l'angle de la sécurité avec le serveur MCP
`security-review`, en arrière-plan, et enregistre un rapport, que le développeur lit dans
l'interface web. La commande ne contacte jamais le serveur Controller et ne demande aucun jeton `ci` :
l'agent appelle le serveur MCP avec le jeton de la configuration MCP.

Le développeur a besoin de uv, du CLI de son agent, connecté avec son compte, et de la
configuration MCP qu'il utilise déjà avec cet agent :

| Agent | CLI | Installation |
|---|---|---|
| Claude Code | `claude` | `npm install -g @anthropic-ai/claude-code` |
| GitHub Copilot | `copilot` | `npm install -g @github/copilot` |
| Codex (compte ChatGPT ou clé OpenAI) | `codex` | `npm install -g @openai/codex` |

La commande prend le premier installé, dans cet ordre, ou celui que désigne `--agent` ou la
variable `AGENT_REVIEW_CLI`. Le serveur est lu dans `.mcp.json` (`--mcp-config`) sous le nom
`security-review` (`--mcp-server`) : format `mcpServers` de Claude Code et Copilot ou format
`servers` de VS Code, serveur HTTP (`url`, en-tête `Authorization`) ou local (`command`,
[mode local](../../getting-started/stdio.md)).

Mise en place pas à pas, avec `scan-deps` : [Hooks de commit](../../getting-started/commit-hooks.md).

Un projet déclare le hook dans son `.pre-commit-config.yaml` (prek ou pre-commit), avec le client
[de son serveur Controller](#depuis-le-serveur-controller) (ou `uvx security-review-ci@X.Y.Z` depuis PyPI, à la
version du serveur Controller) :

```yaml
default_install_hook_types: [pre-commit, post-commit]
repos:
  - repo: local
    hooks:
      - id: agent-review
        name: agent security review
        entry: uvx --no-index --find-links https://secreview.example.com/api/ci-client/ security-review-ci@latest agent-review --project shop-api
        language: system
        stages: [post-commit]
        always_run: true
        pass_filenames: false
```

```bash
prek install                          # hooks pre-commit et post-commit
SKIP=agent-review git commit ...      # sauter la revue pour un commit
```

- Le commit n'est jamais bloqué, même s'il reste des findings ouverts : la commande sort avec
  `0` quand la revue démarre ou est sautée (avec un avertissement sur stderr), `2` hors d'un
  dépôt git. Le journal de l'agent est dans `.git/agent-review/<commit>.log`. `--foreground`
  attend la fin de la revue, ce qui est toujours le cas sous Windows (pas de `fork`).
- L'agent reçoit le commit (jusqu'à 100 Ko) entre des balises aléatoires dans son prompt, et
  seulement le serveur `security-review`, limité à ses outils de revue (`scan_code`,
  `get_review_checklist`, `save_security_report`...) : les autres serveurs MCP du développeur ne
  sont pas chargés. Sa configuration MCP va dans un fichier temporaire privé hors du dépôt,
  supprimé après la revue ; le jeton n'est jamais sur une ligne de commande. L'agent ne modifie
  aucun fichier et ne propose aucun statut de finding.
- Claude Code s'exécute avec `--restricted` et `--permission-mode dontAsk` : aucune commande, et
  `.env`, `.mcp.json` et les fichiers hors du dépôt restent illisibles. Codex s'exécute sans ses
  outils shell et image, dans son bac à sable en lecture seule : il ne lit aucun fichier et ne
  relit que le commit de son prompt. Copilot s'exécute avec les outils shell et d'écriture
  refusés : il lit les fichiers du dépôt, `.env` et `.mcp.json` compris. Les rapports masquent
  les secrets dans tous les cas.
- La revue est sautée pour un commit qui porte le trailer `Security-Review: <identifiant du
  rapport>` (ajouté par un agent qui a déjà relu le changement dans sa session), pendant un
  rebase ou un cherry-pick, ou si aucun CLI d'agent, aucune configuration MCP ou aucun serveur
  `security-review` dedans n'est trouvé.
- Chaque revue consomme de l'usage du modèle sur le compte de l'agent.

## Jeton `ci` et projets visibles

Un jeton `ci` n'atteint que les routes de pipeline : ni `/mcp`, ni le reste de l'API REST, ni
l'interface web. Il est **toujours restreint à des projets** : il ne voit le gate, le journal
SARIF et la tendance que des projets sélectionnés, et n'enregistre des rapports de scan que pour
eux ; un autre projet répond `404`, comme un projet inexistant. `--project` est
[normalisé](../../review/prompts-tools.md#nom-du-projet) comme le projet d'une revue : donnez le nom du dépôt.

- Dans l'interface web, page **Jetons** : **Usage** **Pipeline CI/CD**, puis cochez les
  **Projets autorisés**. Le secret n'est affiché qu'une fois.
- En CLI :

```bash
security-review-controller token create --label jenkins-portal --role ci \
  --project portal --project portal-api
```

Sur un poste de travail, un développeur utilise plutôt un
[jeton `ci` personnel](../../usage/tokens.md#jetons-mcp-et-ci-personnels), créé dans
**Mon compte** : il atteint les projets que le développeur peut lire, et n'enregistre de scan
que sur ceux de `reports.write`.

Les sessions web et les jetons `api` (dans les projets qu'ils lisent) et les jetons `admin`
peuvent aussi appeler les routes du gate, du SARIF et de la tendance ; les jetons `mcp`, non, personnels compris. Les scans, qui enregistrent
des rapports, demandent un jeton `ci` ou `admin` (`403` sinon, sessions web comprises).

## Pipeline type

Un job du pipeline enchaîne quatre commandes, avec le jeton `ci` du projet dans
`SECREVIEW_CI_TOKEN` et l'URL du serveur Controller dans `SECREVIEW_CONTROLLER_URL` :

```bash
security-review-ci scan-code . --project portal --save --branch "$BRANCH" --commit "$COMMIT" || [ $? -eq 1 ]
security-review-ci scan-deps uv.lock package-lock.json --project portal --save --require-database \
    --branch "$BRANCH" --commit "$COMMIT" || [ $? -eq 1 ]
security-review-ci sarif --project portal -o security.sarif
security-review-ci gate --project portal --fail-on high
```

1. `scan-code` et `scan-deps` envoient les fichiers au serveur Controller, qui les scanne et, avec
   `--save`, enregistre un rapport `code-scan` et un rapport `dependency-scan` du projet
   ([Scan de tout le dépôt](../../review/analysis/code-scan.md), [Analyse des dépendances](../../review/analysis/dependencies.md#scan-dans-un-pipeline-security-review-ci-scan-deps)).
2. `sarif` télécharge les findings ouverts du projet, pour le code scanning de la plateforme
   ([Export SARIF](../reports/sarif.md)).
3. `gate` décide : elle échoue (code `1`) tant que des findings ouverts atteignent `--fail-on`.

Le code de sortie d'un scan compte toutes les correspondances au-dessus de son propre
`--fail-on`, sans tenir compte des décisions de triage ; seule la gate tient compte des findings
qu'une personne a acceptés ou marqués comme faux positifs. `|| [ $? -eq 1 ]` laisse un scan qui
a trouvé quelque chose (code `1`) continuer jusqu'à la gate, mais arrête toujours le job sur une
erreur (code `2` : serveur Controller injoignable, jeton refusé...). Sans lui, les scans bloquent
d'eux-mêmes, ce qui suffit pour un premier essai.

Installez le client à la version du serveur Controller (`X.Y.Z` ci-dessous). Le nom du projet est
[normalisé](../../review/prompts-tools.md#nom-du-projet) : le nom du dépôt fourni par la plateforme
convient tel quel.

## Exemples par plateforme

Chaque exemple garde le jeton dans un secret de la plateforme, jamais dans le fichier, et
exécute le [pipeline type](#pipeline-type).

=== "GitHub Actions"

    ```yaml
    # .github/workflows/security-review.yml
    name: Security review
    on: [push, pull_request]
    permissions:
      contents: read
      security-events: write   # envoi du journal SARIF
    jobs:
      security-review:
        runs-on: ubuntu-latest
        env:
          SECREVIEW_CONTROLLER_URL: https://secreview.example.com
          SECREVIEW_CI_TOKEN: ${{ secrets.SECREVIEW_CI_TOKEN }}
          PROJECT: ${{ github.event.repository.name }}
        steps:
          - uses: actions/checkout@v5
          - uses: actions/setup-python@v5
            with:
              python-version: "3.14"
          - run: pip install security-review-ci==X.Y.Z
          - run: |
              security-review-ci scan-code . --project "$PROJECT" --save \
                --branch "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" || [ $? -eq 1 ]
              security-review-ci scan-deps uv.lock --project "$PROJECT" --save --require-database \
                --branch "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" || [ $? -eq 1 ]
              security-review-ci sarif --project "$PROJECT" -o security.sarif
          - uses: github/codeql-action/upload-sarif@v4
            with:
              sarif_file: security.sarif
          - run: security-review-ci gate --project "$PROJECT" --fail-on high
    ```

    En production, épinglez chaque action sur le SHA d'un commit.

=== "GitLab CI"

    ```yaml
    # .gitlab-ci.yml
    security-review:
      stage: test
      image: python:3.14-slim
      variables:
        SECREVIEW_CONTROLLER_URL: https://secreview.example.com
        # SECREVIEW_CI_TOKEN : variable CI/CD masquée et protégée (jeton ci)
      script:
        - pip install security-review-ci==X.Y.Z
        - security-review-ci scan-code . --project "$CI_PROJECT_NAME" --save
            --branch "$CI_COMMIT_REF_NAME" --commit "$CI_COMMIT_SHA" || [ $? -eq 1 ]
        - security-review-ci scan-deps uv.lock --project "$CI_PROJECT_NAME" --save --require-database
            --branch "$CI_COMMIT_REF_NAME" --commit "$CI_COMMIT_SHA" || [ $? -eq 1 ]
        - security-review-ci sarif --project "$CI_PROJECT_NAME" -o security.sarif
        - security-review-ci gate --project "$CI_PROJECT_NAME" --fail-on high
      artifacts:
        when: always
        paths: [security.sarif]
    ```

    GitLab ne lit pas le SARIF nativement : le journal est conservé comme artefact.

=== "Jenkins"

    ```groovy
    // Jenkinsfile : le jeton ci est un identifiant « Secret text » ; security-review-ci est
    // installé sur l'agent (uv tool install security-review-ci==X.Y.Z)
    pipeline {
      agent any
      environment {
        SECREVIEW_CONTROLLER_URL = 'https://secreview.example.com'
        PROJECT = 'portal'
      }
      stages {
        stage('Security review') {
          steps {
            withCredentials([string(credentialsId: 'secreview-ci', variable: 'SECREVIEW_CI_TOKEN')]) {
              sh '''
                security-review-ci scan-code . --project "$PROJECT" --save \
                  --branch "$BRANCH_NAME" --commit "$GIT_COMMIT" || [ $? -eq 1 ]
                security-review-ci scan-deps uv.lock --project "$PROJECT" --save --require-database \
                  --branch "$BRANCH_NAME" --commit "$GIT_COMMIT" || [ $? -eq 1 ]
                security-review-ci sarif --project "$PROJECT" -o security.sarif
                security-review-ci gate --project "$PROJECT" --fail-on high
              '''
            }
          }
        }
      }
      post {
        always {
          // Plugin Warnings Next Generation
          recordIssues tool: sarif(pattern: 'security.sarif')
        }
      }
    }
    ```

=== "Azure Pipelines"

    ```yaml
    # azure-pipelines.yml : SECREVIEW_CI_TOKEN est une variable secrète du pipeline
    trigger: [main]
    pool:
      vmImage: ubuntu-latest
    variables:
      SECREVIEW_CONTROLLER_URL: https://secreview.example.com
    steps:
      - task: UsePythonVersion@0
        inputs:
          versionSpec: "3.14"
      - script: pip install security-review-ci==X.Y.Z
      - script: |
          security-review-ci scan-code . --project "$(Build.Repository.Name)" --save \
            --branch "$(Build.SourceBranchName)" --commit "$(Build.SourceVersion)" || [ $? -eq 1 ]
          security-review-ci scan-deps uv.lock --project "$(Build.Repository.Name)" --save --require-database \
            --branch "$(Build.SourceBranchName)" --commit "$(Build.SourceVersion)" || [ $? -eq 1 ]
          security-review-ci sarif --project "$(Build.Repository.Name)" -o security.sarif
          security-review-ci gate --project "$(Build.Repository.Name)" --fail-on high
        env:
          SECREVIEW_CI_TOKEN: $(SECREVIEW_CI_TOKEN)   # une variable secrète n'est jamais transmise implicitement
      - publish: security.sarif
        artifact: CodeAnalysisLogs
        condition: always()
    ```

    L'extension **SARIF SAST Scans Tab** affiche l'artefact `CodeAnalysisLogs` dans le build.

=== "Bitbucket Pipelines"

    ```yaml
    # bitbucket-pipelines.yml : SECREVIEW_CI_TOKEN est une variable sécurisée du dépôt
    image: python:3.14-slim
    pipelines:
      default:
        - step:
            name: Security review
            script:
              - export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
              - pip install security-review-ci==X.Y.Z
              - security-review-ci scan-code . --project "$BITBUCKET_REPO_SLUG" --save
                  --branch "$BITBUCKET_BRANCH" --commit "$BITBUCKET_COMMIT" || [ $? -eq 1 ]
              - security-review-ci scan-deps uv.lock --project "$BITBUCKET_REPO_SLUG" --save --require-database
                  --branch "$BITBUCKET_BRANCH" --commit "$BITBUCKET_COMMIT" || [ $? -eq 1 ]
              - security-review-ci sarif --project "$BITBUCKET_REPO_SLUG" -o security.sarif
              - security-review-ci gate --project "$BITBUCKET_REPO_SLUG" --fail-on high
            artifacts:
              - security.sarif
    ```

=== "CircleCI"

    ```yaml
    # .circleci/config.yml : SECREVIEW_CI_TOKEN est une variable d'environnement du projet (ou d'un contexte)
    version: 2.1
    jobs:
      security-review:
        docker:
          - image: cimg/python:3.14
        environment:
          SECREVIEW_CONTROLLER_URL: https://secreview.example.com
        steps:
          - checkout
          - run: pip install security-review-ci==X.Y.Z
          - run: |
              security-review-ci scan-code . --project "$CIRCLE_PROJECT_REPONAME" --save \
                --branch "$CIRCLE_BRANCH" --commit "$CIRCLE_SHA1" || [ $? -eq 1 ]
              security-review-ci scan-deps uv.lock --project "$CIRCLE_PROJECT_REPONAME" --save --require-database \
                --branch "$CIRCLE_BRANCH" --commit "$CIRCLE_SHA1" || [ $? -eq 1 ]
              security-review-ci sarif --project "$CIRCLE_PROJECT_REPONAME" -o security.sarif
              security-review-ci gate --project "$CIRCLE_PROJECT_REPONAME" --fail-on high
          - store_artifacts:
              path: security.sarif
    workflows:
      security:
        jobs: [security-review]
    ```

Remplacez `uv.lock` par les manifestes et lockfiles du dépôt
([fichiers pris en charge](../../review/analysis/dependencies.md#fichiers-pris-en-charge)).

## Rapport de tendance

```bash
security-review-ci trend --project mon-projet --days 90 --granularity week --format markdown
```

Options : `--granularity day|week|month` (défaut `week`), `--format markdown|json`
(défaut `markdown`), `--days` (défaut 90).

Pour chaque période :

- findings nouveaux et corrigés ;
- backlog ouvert ;
- score de risque (critical 10, high 5, medium 2, low 1) et direction (marge de ±10 % sur les
  deux dernières périodes).

Sur l'ensemble : délai moyen de correction (MTTR) par sévérité, plus ancien finding ouvert, CWE
les plus fréquentes.

Le même rapport est disponible côté MCP avec l'outil `get_trend_report`.
