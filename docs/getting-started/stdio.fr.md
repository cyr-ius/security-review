# Mode local (stdio)

En **mode local**, l'hôte (VS Code, Claude…) lance lui-même `security-review-mcp serve --transport stdio`
sur le poste du développeur et dialogue avec lui par stdin / stdout : pas de réseau, pas de jeton, pas de
contrôleur.

!!! warning "Réservé à des cas précis"
    Les rapports sont enregistrés dans une base SQLite **locale** que personne d'autre ne voit,
    il n'y a pas d'interface web pour les trier, et chaque poste garde ses propres règles. Pour
    une équipe, utilisez plutôt le [mode partagé (HTTP)](../getting-started/deploy.md). Le mode
    local sert à essayer les prompts seul, sur un poste hors ligne, ou pour un usage personnel.

## Installation

Le serveur est publié sur PyPI sous le nom de paquet `security-review` (Python 3.14). Il installe
la commande `security-review-mcp`, lancée par l'hôte, et `security-review-controller`, dont le mode
local n'a pas besoin. Installez-le dans un environnement virtuel dédié :

```bash
uv venv --python 3.14 /opt/security-review-mcp/venv
uv pip install --python /opt/security-review-mcp/venv security-review
```

!!! note "Anciennement `security-review-mcp`"
    Jusqu'à la version 2.0.0, le paquet était publié sur PyPI sous le nom `security-review-mcp`.
    Les deux paquets installent les mêmes commandes et le même module Python : désinstallez
    d'abord l'ancien (`uv pip uninstall --python /opt/security-review-mcp/venv security-review-mcp`),
    puis installez `security-review`. Les commandes, les paramètres et la base restent les mêmes.

Sans accès Internet, ou depuis les sources : voir [Installation : autres cas](../advanced/installation.md).

## Lancement

```bash
security-review-mcp serve --transport stdio   # lancé par l'hôte, pas à la main
```

Une base SQLite est créé en locale (`~/.local/share/security-review-mcp/security_reports.db`.
Vous pouvez changer son emplacement via  [`SECREVIEW_DATABASE_URL`](../reference/configuration.md#base-de-donnees)).
C'est le seul fichier écrit par le serveur : supprimez-le pour effacer toute trace.

!!! note "`--transport stdio` est obligatoire"
    Sans `--transport`, `serve` lance le serveur HTTP du mode partagé
    ([`SECREVIEW_TRANSPORT`](../reference/configuration.md#serveur-mcp), `streamable-http` par
    défaut). Jusqu'à la version 3.0.0, `serve` tournait en stdio par défaut : ajoutez
    `--transport stdio` aux configurations d'hôte existantes.

## Configuration de l'hôte

En transport **stdio**, l'hôte (VS Code, Claude…) lance lui-même le processus du serveur.
Indiquez le chemin de l'exécutable, la commande `serve --transport stdio`.

VS Code, GitHub Copilot et Claude lisent le même fichier `.mcp.json` à la racine du dépôt :

```json
{
  "mcpServers": {
    "security-review": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from","security-review==4.0.0","security-review-mcp","serve","--transport","stdio"]
    }
  }
}
```

Pour lancer le serveur depuis un conteneur, voir [Docker](../advanced/docker.md).
