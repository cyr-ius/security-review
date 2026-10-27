# Hooks de commit

La revue de sécurité sur le poste de chaque développeur est réalisée par deux hooks, à chaque commit.
Les hooks sont exécutés par [prek](https://prek.j178.dev) (ou [pre-commit](https://pre-commit.com)).

| Hook | Quand | Ce qu'il fait | Bloque le commit |
|---|---|---|---|
| `scan-deps` | avant le commit, quand un manifeste ou un lockfile change | Envoie les fichiers de dépendances au serveur Controller, qui les compare à sa base d'avis ([analyse des dépendances](../review/analysis/dependencies.md)) | Oui, quand une dépendance vulnérable atteint le seuil (`--fail-on`, `high` par défaut) |
| `agent-review` | après le commit | Fait relire le commit par l'agent de code du développeur (Claude Code, GitHub Copilot ou Codex) avec le serveur MCP, qui enregistre un rapport ([revue par un agent](../advanced/architecture/ci.md#revue-de-chaque-commit-par-un-agent)) | Jamais |

## 1. Préparer le poste (une fois)

Pour mettre en place les hooks, installez le gestionnaire `uv`. `uv` et `uvx` sont l'équivalent
de `npm` et `npx` dans le monde Python. Ils n'ont besoin d'aucun prérequis : il n'est pas
nécessaire d'avoir Python sur le poste.

PyPI ou le serveur Controller peuvent distribuer le paquet `security-review-ci`.

| Quoi | Comment |
|---|---|
| uv/uvx | [Installation de uv](https://docs.astral.sh/uv/getting-started/installation/) |
| prek | `uv tool install prek` |
| Vos jetons personnels | **Mon compte** dans l'[interface web](../usage/tokens.md#jetons-mcp-et-ci-personnels) : un jeton `ci` pour `scan-deps`, un jeton `mcp` (ou la [connexion OAuth](../advanced/mcp-oauth.md)) pour `agent-review` ; tous deux atteignent les projets que vous pouvez lire |
| Le CLI de votre agent (pour `agent-review`), connecté avec votre compte | `npm install -g @anthropic-ai/claude-code`, `npm install -g @github/copilot` ou `npm install -g @openai/codex` |

`scan-deps` envoie les fichiers de dépendances au serveur Controller : pour ce faire, inscrivez l'URL du
serveur et votre jeton dans l'environnement (le profil de votre shell, jamais le fichier `.env`).

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_CI_TOKEN=<jeton ci personnel>
```

`agent-review` s'appuie sur la déclaration de votre serveur MCP dans le fichier `.mcp.json` à la
racine du dépôt. Gardez-le hors de git : il contient votre jeton.

```json
{
  "mcpServers": {
    "security-review": {
      "type": "http",
      "url": "https://secreview.example.com:8443/mcp",
      "headers": { "Authorization": "Bearer <jeton mcp personnel>" }
    }
  }
}
```

```bash
echo ".mcp.json" >> .gitignore
```

## 2. Déclarer les hooks dans le projet (une fois par dépôt)

Voici un exemple de fichier `.pre-commit-config.yaml`, commité à la racine de votre dépôt.
Remplacez `shop-api` par le nom du projet, et les fichiers de `scan-deps` par ceux de vos technologies.

=== "Client depuis le serveur Controller"

    Le client est téléchargé depuis le serveur Controller. Pour que l'adresse de votre serveur Controller
    n'apparaisse pas dans le fichier de pre-commit, voir l'onglet
    **Client depuis le serveur Controller (mode variable)**.

    ```yaml
    default_install_hook_types: [pre-commit, post-commit]
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: uvx --no-index --find-links https://my-security-controller.com:8443/api/ci-client/ security-review-ci@latest scan-deps --require-database --project shop-api
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
          - id: agent-review
            name: agent security review
            entry: uvx --no-index --find-links https://my-security-controller.com:8443/api/ci-client/ security-review-ci@latest agent-review --project shop-api
            language: system
            stages: [post-commit]
            always_run: true
            pass_filenames: false
    ```

=== "Client depuis PyPI"

    Le client de PyPI, à la version de votre serveur Controller (remplacez `X.Y.Z`).

    ```yaml
    default_install_hook_types: [pre-commit, post-commit]
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: uvx security-review-ci@X.Y.Z scan-deps --skip-unconfigured --require-database --project shop-api
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
          - id: agent-review
            name: agent security review
            entry: uvx security-review-ci@X.Y.Z agent-review --project shop-api
            language: system
            stages: [post-commit]
            always_run: true
            pass_filenames: false
    ```

=== "Client depuis le serveur Controller (mode variable)"

    L'adresse du serveur Controller est lue dans la variable `SECREVIEW_CONTROLLER_URL` de chaque
    développeur : le fichier ne contient ainsi aucune référence à vos serveurs.

    ```yaml
    default_install_hook_types: [pre-commit, post-commit]
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: bash -c '[ -n "$SECREVIEW_CONTROLLER_URL" ] || { echo "scan-deps skipped (SECREVIEW_CONTROLLER_URL is not set)" >&2; exit 0; }; exec uvx --no-index --find-links "${SECREVIEW_CONTROLLER_URL%/}/api/ci-client/" security-review-ci@latest scan-deps --require-database --project shop-api "$@"' --
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
          - id: agent-review
            name: agent security review
            entry: bash -c '[ -n "$SECREVIEW_CONTROLLER_URL" ] || { echo "agent-review skipped (SECREVIEW_CONTROLLER_URL is not set)" >&2; exit 0; }; exec uvx --no-index --find-links "${SECREVIEW_CONTROLLER_URL%/}/api/ci-client/" security-review-ci@latest agent-review --project shop-api' --
            language: system
            stages: [post-commit]
            always_run: true
            pass_filenames: false
    ```

## 3. Installer et vérifier

Chaque développeur lance, dans son clone :

```bash
prek install                                   # installe les hooks pre-commit et post-commit
prek run scan-deps --all-files                 # scan des dépendances de tout le dépôt
prek run agent-review --hook-stage post-commit # revue du dernier commit, en arrière-plan
```

Ensuite, à chaque commit :

- `scan-deps` affiche les dépendances vulnérables et arrête le commit quand l'une atteint le
  seuil (code de sortie `1`) ; corrigez la version, ou faites accepter le finding au
  [triage](../usage/triage.md).
- `agent-review` affiche `security review of <commit> by <agent> started in the background` et
  rend la main tout de suite ; le rapport apparaît dans l'interface web après quelques minutes,
  et le journal de l'agent est dans `.git/agent-review/<commit>.log`.

## Serveur Controller en HTTP sans TLS

Servez de préférence le serveur Controller et le serveur MCP en HTTPS ([TLS](../advanced/tls.md)), ou
derrière un reverse proxy. Si ce n'est pas possible, le HTTP fonctionne avec ces changements :

| Où | Changement |
|---|---|
| `scan-deps` | Ajoutez `--allow-http` sinon le client refuse d'envoyer le jeton en HTTP autre que `localhost` |
| `.mcp.json` | Écrivez `http://` dans l'`url` du serveur MCP |

```yaml
          - id: scan-deps
            name: dependency scan
            entry: uvx --no-index --find-links http://my-security-controller.com:8080/api/ci-client/ security-review-ci@latest scan-deps --allow-http --require-database --project shop-api
          - id: agent-review
            name: agent security review
            entry: uvx --no-index --find-links http://my-security-controller.com:8080/api/ci-client/ security-review-ci@latest agent-review --project shop-api
            language: system
            stages: [post-commit]
            always_run: true
            pass_filenames: false
```

!!! warning "Ce que le HTTP expose"
    Le jeton de chaque développeur circule en clair (`scan-deps`, serveur MCP), et le client
    téléchargé depuis le serveur Controller peut être remplacé en chemin, SHA-256 compris : les postes
    exécuteraient ce code à chaque commit. Sur un tel réseau, préférez le client de PyPI
    (HTTPS) au client du serveur Controller.

## Sauter un hook ou dépanner

| Cas | Comportement |
|---|---|
| Sauter un hook une fois | `SKIP=agent-review git commit …` (ou `SKIP=scan-deps`) |
| `SECREVIEW_CONTROLLER_URL` non défini | Les deux hooks laissent passer le commit avec un message (client du serveur Controller) ; `scan-deps` aussi avec `--skip-unconfigured` (client de PyPI) |
| Aucun CLI d'agent, aucun `.mcp.json` ou aucun serveur `security-review` dedans | `agent-review` ne fait rien, avec un avertissement |
| Commit portant le trailer `Security-Review: <identifiant du rapport>` | `agent-review` ne fait rien : un agent l'a déjà relu dans sa session |
| Plusieurs agents installés | Le premier de `claude`, `copilot`, `codex`, ou celui de `AGENT_REVIEW_CLI` |
| Jeton refusé (`401`, `403`) ou projet inconnu (`404`) | Vérifiez le jeton dans **Mon compte** et qu'il atteint le projet (voir [jetons](../usage/tokens.md)) |

Les options des deux commandes sont dans [ligne de commande](../reference/cli.md#security-review-ci).
