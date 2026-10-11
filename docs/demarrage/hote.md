# Configuration de l'hôte

## Transport stdio

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

## Transport HTTP

Pour un serveur partagé, lancé avec `--transport streamable-http`, l'hôte se connecte à
l'endpoint `/mcp` au lieu de lancer un processus. Si l'authentification est activée, il envoie
le jeton dans l'en-tête `Authorization: Bearer <jeton>` (génération des jetons, TLS et
démarrage du serveur : voir [Serveur HTTP, authentification et TLS](http.md)).

=== "VS Code / GitHub Copilot"

    `.vscode/mcp.json`, avec un jeton demandé à l'utilisateur au premier lancement :

    ```json
    {
      "servers": {
        "security-review": {
          "type": "http",
          "url": "https://secreview.example.internal:8443/mcp",
          "headers": { "Authorization": "Bearer ${input:secreview-token}" }
        }
      },
      "inputs": [
        { "id": "secreview-token", "type": "promptString", "description": "Jeton", "password": true }
      ]
    }
    ```

=== "Claude"

    `.mcp.json`, avec le jeton lu dans la variable d'environnement `SECURITY_REVIEW_TOKEN` du
    poste (côté client, distincte des paramètres `SECREVIEW_*` du serveur) :

    ```json
    {
      "mcpServers": {
        "security-review": {
          "type": "http",
          "url": "https://secreview.example.internal:8443/mcp",
          "headers": { "Authorization": "Bearer ${SECURITY_REVIEW_TOKEN}" }
        }
      }
    }
    ```

Sans authentification (serveur local sur `127.0.0.1`, ou authentification assurée par un
reverse proxy), omettez `headers` et `inputs`, par exemple
`"url": "http://127.0.0.1:8000/mcp"`.

!!! tip
    N'écrivez jamais le jeton en clair dans un fichier de configuration versionné : utilisez une
    saisie (`${input:...}`) ou une variable d'environnement.
