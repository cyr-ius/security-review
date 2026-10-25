# Hooks de commit

Deux hooks amènent la revue de sécurité sur le poste de chaque développeur, à chaque commit :

| Hook | Quand | Ce qu'il fait | Bloque le commit |
|---|---|---|---|
| `scan-deps` | avant le commit, quand un manifeste ou un lockfile change | Envoie les fichiers de dépendances au contrôleur, qui les compare à sa base d'avis ([analyse des dépendances](../advanced/dependencies.md)) | Oui, quand une dépendance vulnérable atteint le seuil (`--fail-on`, `high` par défaut) |
| `agent-review` | après le commit | Fait relire le commit par l'agent de code du développeur (Claude Code, GitHub Copilot ou Codex) avec le serveur MCP, qui enregistre un rapport ([revue par un agent](../advanced/ci.md#revue-de-chaque-commit-par-un-agent)) | Jamais |

Les deux lancent `security-review-ci`, le client du contrôleur, qui n'a pas besoin de Python :
uv le télécharge, ainsi qu'un Python quand aucun n'est installé. Les hooks sont exécutés par
[prek](https://prek.j178.dev) (ou [pre-commit](https://pre-commit.com)).

## 1. Préparer le poste (une fois)

| Quoi | Comment |
|---|---|
| uv | [Installation de uv](https://docs.astral.sh/uv/getting-started/installation/) |
| prek | `uv tool install prek` |
| Un jeton `mcp` personnel | **Mon compte** dans l'[interface web](../usage/tokens.md#jetons-mcp-et-ci-personnels) : il atteint les projets que vous pouvez lire, pour les deux hooks |
| Le CLI de votre agent (pour `agent-review`), connecté avec votre compte | `npm install -g @anthropic-ai/claude-code`, `npm install -g @github/copilot` ou `npm install -g @openai/codex` |

`scan-deps` lit le contrôleur et le jeton dans l'environnement (le profil de votre shell, jamais
le fichier `.env`) :

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_TOKEN=<jeton mcp personnel>
```

`agent-review` donne à votre agent le serveur MCP `security-review` du fichier `.mcp.json` à la
racine du dépôt, le fichier que Claude Code et le CLI Copilot lisent déjà. Gardez-le hors de
git : il contient votre jeton.

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

`.pre-commit-config.yaml`, commité à la racine du dépôt. Remplacez `shop-api` par le nom du
projet dans le contrôleur, et les fichiers de `scan-deps` par ceux de vos technologies.
`default_install_hook_types` fait installer aussi le hook post-commit par `prek install`.

=== "Client du contrôleur"

    Le contrôleur sert son propre client : ni PyPI, ni version à tenir à jour (sauf avec
    `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED=false` sur le contrôleur, voir
    [depuis le contrôleur](../advanced/ci.md#depuis-le-controleur)). L'adresse vient du
    `SECREVIEW_CONTROLLER_URL` de chaque développeur : le fichier n'en contient aucune, et les
    deux hooks laissent passer le commit avec un message tant qu'elle n'est pas définie. prek ne
    remplace pas les variables d'`entry`, d'où `bash -c` (Git Bash sous Windows).

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

=== "Client de PyPI"

    Le client de PyPI, à la version de votre contrôleur (remplacez `X.Y.Z`).

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

prek passe les fichiers modifiés à `scan-deps` (`files` les sélectionne) ; `agent-review` ne
prend aucun fichier (`pass_filenames: false`) et lit le dernier commit.

## 3. Installer et vérifier

Chaque développeur lance, dans son clone :

```bash
prek install                                   # hooks pre-commit et post-commit
prek run scan-deps --all-files                 # scan des dépendances de tout le dépôt, tout de suite
prek run agent-review --hook-stage post-commit # revue du dernier commit, en arrière-plan
```

Ensuite, à chaque commit :

- `scan-deps` affiche les dépendances vulnérables et arrête le commit quand l'une atteint le
  seuil (code de sortie `1`) ; corrigez la version, ou faites accepter le finding au
  [triage](../usage/triage.md).
- `agent-review` affiche `security review of <commit> by <agent> started in the background` et
  rend la main tout de suite ; le rapport apparaît dans l'interface web après quelques minutes,
  et le journal de l'agent est dans `.git/agent-review/<commit>.log`.

## Contrôleur en HTTP

Servez le contrôleur et le serveur MCP en HTTPS ([TLS](../advanced/tls.md), ou un reverse
proxy). Sur un réseau fermé (labo, machine locale), le HTTP fonctionne avec ces changements :

| Où | Changement |
|---|---|
| `scan-deps` | Ajoutez `--allow-http` à son `entry` : le client refuse d'envoyer le jeton en HTTP à un autre hôte que `localhost` |
| Client du contrôleur | Rien : `SECREVIEW_CONTROLLER_URL=http://…` fonctionne, uv l'accepte |
| `.mcp.json` | Écrivez `http://` dans l'`url` du serveur MCP |
| `agent-review` | Rien : il ne contacte pas le contrôleur |

```yaml
          - id: scan-deps
            name: dependency scan
            entry: bash -c '[ -n "$SECREVIEW_CONTROLLER_URL" ] || { echo "scan-deps skipped (SECREVIEW_CONTROLLER_URL is not set)" >&2; exit 0; }; exec uvx --no-index --find-links "${SECREVIEW_CONTROLLER_URL%/}/api/ci-client/" security-review-ci@latest scan-deps --allow-http --require-database --project shop-api "$@"' --
```

!!! warning "Ce que le HTTP expose"
    Le jeton de chaque développeur circule en clair (`scan-deps`, serveur MCP), et le client
    téléchargé depuis le contrôleur peut être remplacé en chemin, SHA-256 compris : les postes
    exécuteraient ce code à chaque commit. Sur un tel réseau, préférez le client de PyPI
    (HTTPS) au client du contrôleur.

## Sauter un hook ou dépanner

| Cas | Comportement |
|---|---|
| Sauter un hook une fois | `SKIP=agent-review git commit …` (ou `SKIP=scan-deps`) |
| `SECREVIEW_CONTROLLER_URL` non défini | Les deux hooks laissent passer le commit avec un message (client du contrôleur) ; `scan-deps` aussi avec `--skip-unconfigured` (client de PyPI) |
| Aucun CLI d'agent, aucun `.mcp.json` ou aucun serveur `security-review` dedans | `agent-review` ne fait rien, avec un avertissement |
| Commit portant le trailer `Security-Review: <identifiant du rapport>` | `agent-review` ne fait rien : un agent l'a déjà relu dans sa session |
| Plusieurs agents installés | Le premier de `claude`, `copilot`, `codex`, ou celui de `AGENT_REVIEW_CLI` |
| Jeton refusé (`401`, `403`) ou projet inconnu (`404`) | Vérifiez le jeton dans **Mon compte** et qu'il atteint le projet (voir [jetons](../usage/tokens.md)) |

Les options des deux commandes sont dans [ligne de commande](../reference/cli.md#security-review-ci).
