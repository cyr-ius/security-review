# Mode local (stdio)

En **mode local**, l'hôte (VS Code, Claude…) lance lui-même `security-review-mcp serve` sur le poste
du développeur et dialogue avec lui par stdin / stdout : pas de réseau, pas de jeton, pas de
contrôleur.

!!! warning "Réservé à des cas précis"
    Les rapports sont enregistrés dans une base SQLite **locale** que personne d'autre ne voit,
    il n'y a pas d'interface web pour les trier, et chaque poste garde ses propres règles. Pour
    une équipe, déployez plutôt le [serveur partagé](../getting-started/deploy.md). Le mode
    local sert à essayer les prompts seul, sur un poste hors ligne, ou pour un usage personnel.

## Lancement

```bash
security-review-mcp serve   # lancé par l'hôte, pas à la main
```

La base SQLite locale (`./security_reports.db` par défaut, voir
[`SECREVIEW_DATABASE_URL`](../reference/configuration.md#base-de-donnees)) est créée ou migrée
automatiquement au démarrage. Le contrôleur n'est pas nécessaire.

## Configuration de l'hôte

En transport **stdio**, l'hôte (VS Code, Claude…) lance lui-même le processus du serveur.
Indiquez le chemin de l'exécutable, la commande `serve` et, si besoin, les variables `SECREVIEW_*`
(voir [Configuration](../reference/configuration.md)).

VS Code, GitHub Copilot et Claude lisent le même fichier `.mcp.json` à la racine du dépôt :

```json
{
  "mcpServers": {
    "security-review": {
      "type": "stdio",
      "command": "/opt/security-review-mcp/venv/bin/security-review-mcp",
      "args": ["serve"],
      "env": { "SECREVIEW_DATABASE_URL": "sqlite:////var/lib/secreview/security_reports.db" }
    }
  }
}
```

Pour lancer le serveur depuis un conteneur, voir [Docker](docker.md#poste-developpeur-stdio).
