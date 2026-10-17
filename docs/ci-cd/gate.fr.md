# Gate CI/CD

Sans agent ni client MCP, un job Jenkins, GitLab ou GitHub peut bloquer un déploiement tant que
des findings critiques restent ouverts. Deux commandes le font :

| Commande | Contacte | Nécessite sur l'agent de build |
|---|---|---|
| `security-review-ci gate` (recommandée) | l'API REST du contrôleur, avec un [jeton `ci`](#jeton-ci-et-projets-visibles) | Python 3 seulement : ni pilote de base, ni SQLModel, ni URL de base |
| `security-review-controller gate` | la base directement | le paquet, le pilote de base et `SECREVIEW_DATABASE_URL` |

Les deux ont les mêmes codes de sortie et la même sortie JSON :

```bash
security-review-ci gate --project portal --fail-on high
# code de sortie : 0 = passe, 1 = bloqué, 2 = erreur (projet/rapport introuvable, hors du jeton,
# contrôleur injoignable, jeton refusé)
# options : --report-id N pour ne juger qu'un rapport
```

## Client de pipeline (`security-review-ci`)

`security-review-ci` est un client léger du contrôleur : il appelle les routes de pipeline, en
lecture seule, de l'API REST (`/api/v1/ci/gate`, `/api/v1/ci/sarif`, `/api/v1/ci/trend`) et
n'ouvre aucune base. Il n'utilise que la bibliothèque standard de Python : installez le paquet
(`pip install security-review-mcp`), ou copiez le seul fichier
`security_review_mcp/ci_client.py` sur l'agent et lancez-le avec `python3 ci_client.py`.

| Sous-commande | Rôle |
|---|---|
| `gate --project P [--fail-on S] [--report-id N]` | Gate du projet (voir ci-dessus) |
| `sarif --project P [--include-resolved] [-o FICHIER]` | Journal SARIF 2.1.0 du projet ([Export SARIF](sarif.md)) |
| `trend --project P [--days N] [--granularity day\|week\|month] [--format markdown\|json]` | Rapport de tendance du projet ([Rapport de tendance](trends.md)) |

Options communes : `--url` (par défaut `SECREVIEW_CONTROLLER_URL`), `--token-stdin` (lit le
jeton sur l'entrée standard au lieu de `SECREVIEW_TOKEN`), `--cafile` (CA du certificat du
contrôleur), `--allow-http`, `--timeout` (secondes, 60 par défaut).

- Le jeton n'est jamais accepté sur la ligne de commande (liste des processus, journal du job)
  et n'apparaît jamais dans un message d'erreur.
- Le HTTP en clair est refusé sauf vers `localhost` (ou avec `--allow-http`), de même que les
  identifiants dans l'URL ; les redirections ne sont pas suivies : le jeton n'est envoyé qu'au
  contrôleur indiqué.
- Les deux variables ne sont lues que dans l'environnement (le fichier `.env` est ignoré).
- Les réponses sont bornées (64 Mio) et les caractères de contrôle de la sortie texte sont
  retirés.

### Jeton `ci` et projets visibles

Un jeton `ci` n'atteint que les routes de pipeline : ni `/mcp`, ni le reste de l'API REST, ni
l'interface web. Il est **toujours restreint à des projets** : il ne voit le gate, le journal
SARIF et la tendance que des projets sélectionnés ; un autre projet répond `404`, comme un
projet inexistant.

- Dans l'interface web, écran **Jetons** : **Usage** **Pipeline CI/CD**, puis cochez les
  **Projets autorisés**. Le secret n'est affiché qu'une fois.
- En CLI :

```bash
security-review-controller token create --label jenkins-portal --role ci \
  --project portal --project portal-api
```

Les jetons `reader`, `triager` et `admin` peuvent aussi appeler les routes de pipeline (dans
leurs propres projets) ; les jetons `mcp`, non.

### Exemples

=== "Jenkins"

    ```groovy
    // Jenkinsfile : le jeton ci est un identifiant « Secret text »
    pipeline {
      agent any
      environment {
        SECREVIEW_CONTROLLER_URL = 'https://secreview.example.com'
      }
      stages {
        stage('Security gate') {
          steps {
            withCredentials([string(credentialsId: 'secreview-ci', variable: 'SECREVIEW_TOKEN')]) {
              sh 'security-review-ci sarif --project portal -o security.sarif'
              sh 'security-review-ci gate --project portal --fail-on high'
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

=== "GitLab CI"

    ```yaml
    # .gitlab-ci.yml
    security-gate:
      stage: test
      image: python:3.14-slim
      script:
        - pip install security-review-mcp
        - security-review-ci gate --project "$CI_PROJECT_PATH_SLUG" --fail-on high
      variables:
        SECREVIEW_CONTROLLER_URL: https://secreview.example.com
        # SECREVIEW_TOKEN : variable CI/CD masquée et protégée (jeton ci)
    ```

=== "GitHub Actions"

    ```yaml
    - name: Security gate
      run: security-review-ci gate --project "${{ github.event.repository.name }}" --fail-on high
      env:
        SECREVIEW_CONTROLLER_URL: https://secreview.example.com
        SECREVIEW_TOKEN: ${{ secrets.SECREVIEW_CI_TOKEN }}
    ```

## Accès direct à la base (`security-review-controller gate`)

Sur une machine qui atteint déjà la base (le contrôleur lui-même, un job d'administration), la
commande du contrôleur la lit directement :

```bash
security-review-controller gate --project portal --fail-on high
```

```yaml
# .gitlab-ci.yml
security-gate:
  stage: test
  script:
    - security-review-controller gate --project "$CI_PROJECT_PATH_SLUG" --fail-on high
  variables:
    SECREVIEW_DATABASE_URL: $SECREVIEW_DATABASE_URL   # variable masquée et protégée
```

Elle nécessite le pilote de base et donne au pipeline les identifiants de la base : préférez
`security-review-ci` et un jeton `ci`.

Un finding sort du blocage quand il passe à `fixed`, `accepted` ou `false_positive`
(outil `update_finding_status`) : la décision reste tracée en base.
