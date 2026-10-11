# Configuration de l'hôte

En transport **stdio**, l'hôte (VS Code, Claude…) lance lui-même le processus du serveur.
Indiquez le chemin de l'exécutable et, si besoin, les variables `SECREVIEW_*`
(voir [Configuration](../reference/configuration.md)).

=== "VS Code / GitHub Copilot"

    `.vscode/mcp.json` :

    ```json
    {
      "servers": {
        "security-review": {
          "type": "stdio",
          "command": "/opt/security-review-mcp/venv/bin/security-review-mcp",
          "env": { "SECREVIEW_DATABASE_URL": "sqlite:////data/security_reports.db" }
        }
      }
    }
    ```

=== "Claude"

    `.mcp.json` :

    ```json
    {
      "mcpServers": {
        "security-review": {
          "command": "/opt/security-review-mcp/venv/bin/security-review-mcp",
          "env": { "SECREVIEW_DATABASE_URL": "sqlite:////data/security_reports.db" }
        }
      }
    }
    ```

Pour lancer le serveur depuis un conteneur, voir [Docker](docker.md#poste-developpeur-stdio).
Pour un serveur partagé en HTTP, voir [Serveur HTTP, authentification et TLS](http.md).
