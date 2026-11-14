# Hooks de commit

Sur le poste de chaque développeur, un hook vérifie les dépendances avant chaque commit. Il est
exécuté par [prek](https://prek.j178.dev) (ou [pre-commit](https://pre-commit.com)). La revue
de sécurité du code elle-même est faite par l'agent de code, dans sa session, avec le
[serveur MCP](../getting-started/host.md).

Le hook est facultatif : pendant une revue, l'agent vérifie déjà les fichiers de dépendances
modifiés. Le hook ajoute une vérification automatique à chaque commit, sans agent, et bloque le
commit au-dessus du seuil.

| Hook | Quand | Ce qu'il fait | Bloque le commit |
|---|---|---|---|
| `scan-deps` | avant le commit, quand un manifeste ou un lockfile change | Envoie les fichiers de dépendances au serveur Controller, qui les compare à sa base d'avis ([analyse des dépendances](../review/analysis/dependencies.md)) | Oui, quand une dépendance vulnérable atteint le seuil (`--fail-on`, `high` par défaut) |

## 1. Préparer le poste (une fois)

Pour mettre en place le hook, installez le gestionnaire `uv`. `uv` et `uvx` sont l'équivalent
de `npm` et `npx` dans le monde Python. Ils n'ont besoin d'aucun prérequis : il n'est pas
nécessaire d'avoir Python sur le poste.

PyPI ou le serveur Controller peuvent distribuer le paquet `security-review-ci`.

| Quoi | Comment |
|---|---|
| uv/uvx | [Installation de uv](https://docs.astral.sh/uv/getting-started/installation/) |
| prek | `uv tool install prek` |
| Votre jeton `ci` personnel | **Mon compte** dans l'[interface web](../usage/tokens.md#jetons-mcp-et-ci-personnels) ; il atteint les projets que vous pouvez lire |

`scan-deps` envoie les fichiers de dépendances au serveur Controller : pour ce faire, inscrivez l'URL du
serveur et votre jeton dans l'environnement (le profil de votre shell, jamais le fichier `.env`).

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_CI_TOKEN=<jeton ci personnel>
```

## 2. Déclarer le hook dans le projet (une fois par dépôt)

Voici un exemple de fichier `.pre-commit-config.yaml`, commité à la racine de votre dépôt.
Remplacez `shop-api` par le nom du projet, et les fichiers de `scan-deps` par ceux de vos technologies.

=== "Client depuis le serveur Controller"

    Le client est téléchargé depuis le serveur Controller. Pour que l'adresse de votre serveur Controller
    n'apparaisse pas dans le fichier de pre-commit, voir l'onglet
    **Client depuis le serveur Controller (mode variable)**.

    ```yaml
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: uvx --no-index --find-links https://my-security-controller.com:8443/api/ci-client/ security-review-ci@latest scan-deps --require-database --project shop-api
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
    ```

=== "Client depuis PyPI"

    Le client de PyPI, à la version de votre serveur Controller (remplacez `X.Y.Z`).

    ```yaml
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: uvx security-review-ci@X.Y.Z scan-deps --skip-unconfigured --require-database --project shop-api
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
    ```

=== "Client depuis le serveur Controller (mode variable)"

    L'adresse du serveur Controller est lue dans la variable `SECREVIEW_CONTROLLER_URL` de chaque
    développeur : le fichier ne contient ainsi aucune référence à vos serveurs.

    ```yaml
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: bash -c '[ -n "$SECREVIEW_CONTROLLER_URL" ] || { echo "scan-deps skipped (SECREVIEW_CONTROLLER_URL is not set)" >&2; exit 0; }; exec uvx --no-index --find-links "${SECREVIEW_CONTROLLER_URL%/}/api/ci-client/" security-review-ci@latest scan-deps --require-database --project shop-api "$@"' --
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
    ```

## 3. Installer et vérifier

Chaque développeur lance, dans son clone :

```bash
prek install                    # installe les hooks pre-commit
prek run scan-deps --all-files  # scan des dépendances de tout le dépôt
```

Ensuite, à chaque commit, `scan-deps` affiche les dépendances vulnérables et arrête le commit
quand l'une atteint le seuil (code de sortie `1`) ; corrigez la version, ou faites accepter le finding au
[triage](../usage/triage.md).

## Serveur Controller en HTTP sans TLS

Servez de préférence le serveur Controller en HTTPS ([TLS](tls.md)), ou
derrière un reverse proxy. Si ce n'est pas possible, le HTTP fonctionne avec ces changements :

| Où | Changement |
|---|---|
| `scan-deps` | Ajoutez `--allow-http` sinon le client refuse d'envoyer le jeton en HTTP autre que `localhost` |

```yaml
          - id: scan-deps
            name: dependency scan
            entry: uvx --no-index --find-links http://my-security-controller.com:8080/api/ci-client/ security-review-ci@latest scan-deps --allow-http --require-database --project shop-api
```

!!! warning "Ce que le HTTP expose"
    Le jeton de chaque développeur circule en clair, et le client
    téléchargé depuis le serveur Controller peut être remplacé en chemin, SHA-256 compris : les postes
    exécuteraient ce code à chaque commit. Sur un tel réseau, préférez le client de PyPI
    (HTTPS) au client du serveur Controller.

## Sauter un hook ou dépanner

| Cas | Comportement |
|---|---|
| Sauter le hook une fois | `SKIP=scan-deps git commit …` |
| `SECREVIEW_CONTROLLER_URL` non défini | `scan-deps` laisse passer le commit avec un message (client du serveur Controller, ou `--skip-unconfigured` avec le client de PyPI) |
| Jeton refusé (`401`, `403`) ou projet inconnu (`404`) | Vérifiez le jeton dans **Mon compte** et qu'il atteint le projet (voir [jetons](../usage/tokens.md)) |

Les options de la commande sont dans [ligne de commande](../reference/cli.md#security-review-ci).
