# Configuration de l'hôte

Chaque développeur déclare le serveur MCP partagé dans son hôte (VS Code, IntelliJ, Claude Code…). Le serveur
doit déjà tourner : voir [Mise en service du serveur](deploy.md).

## Transport HTTP

L'hôte se connecte au serveur par son URL, terminée par `/mcp`. Choisissez votre hôte, puis
le mode de connexion que l'administrateur a mis en place :

=== "VS Code / GitHub Copilot"

    === "Connexion OAuth"

        `.mcp.json` à la racine du dépôt :

        ```json
        {
          "mcpServers": {
            "security-review": {
              "type": "http",
              "url": "https://secreview.example.internal/mcp"
            }
          }
        }
        ```

        À la première connexion, l'hôte ouvre le navigateur : connectez-vous et approuvez la
        demande. Aucun jeton à créer ni à copier
        ([connexion OAuth des clients MCP](../advanced/mcp-oauth.md)).

    === "Jeton personnel"

        `.vscode/mcp.json`, avec le jeton demandé au premier lancement :

        ```json
        {
          "servers": {
            "security-review": {
              "type": "http",
              "url": "https://secreview.example.internal/mcp",
              "headers": { "Authorization": "Bearer ${input:secreview-token}" }
            }
          },
          "inputs": [
            { "id": "secreview-token", "type": "promptString", "description": "Jeton", "password": true }
          ]
        }
        ```

        Gardez `.vscode/mcp.json` pour un jeton : dans `.mcp.json`, VS Code ne substitue pas
        encore les variables, et le jeton devrait y être écrit en clair.

    === "Sans authentification"

        Pour un serveur local sur `127.0.0.1`, ou derrière un reverse proxy qui gère
        l'authentification. `.mcp.json` à la racine du dépôt :

        ```json
        {
          "mcpServers": {
            "security-review": {
              "type": "http",
              "url": "http://127.0.0.1:8000/mcp"
            }
          }
        }
        ```

=== "Claude Code"

    === "Connexion OAuth"

        `.mcp.json` à la racine du dépôt :

        ```json
        {
          "mcpServers": {
            "security-review": {
              "type": "http",
              "url": "https://secreview.example.internal/mcp"
            }
          }
        }
        ```

        À la première connexion, l'hôte ouvre le navigateur : connectez-vous et approuvez la
        demande. Aucun jeton à créer ni à copier
        ([connexion OAuth des clients MCP](../advanced/mcp-oauth.md)).

    === "Jeton personnel"

        `.mcp.json`, avec le jeton lu dans la variable d'environnement `SECURITY_REVIEW_TOKEN`
        du poste. Tant qu'elle n'existe pas, l'en-tête reste vide, ce qui permet
        l'[enrôlement](#obtenir-un-jeton) :

        ```json
        {
          "mcpServers": {
            "security-review": {
              "type": "http",
              "url": "https://secreview.example.internal/mcp",
              "headers": { "Authorization": "Bearer ${SECURITY_REVIEW_TOKEN:-}" }
            }
          }
        }
        ```

    === "Sans authentification"

        Pour un serveur local sur `127.0.0.1`, ou derrière un reverse proxy qui gère
        l'authentification. `.mcp.json` à la racine du dépôt :

        ```json
        {
          "mcpServers": {
            "security-review": {
              "type": "http",
              "url": "http://127.0.0.1:8000/mcp"
            }
          }
        }
        ```

=== "IntelliJ / JetBrains"

    Plugin **GitHub Copilot** : dans le chat Copilot, en mode **Agent**, cliquez sur l'icône des
    outils (**Configure your MCP server**) puis sur **Add MCP Tools**. L'IDE ouvre son fichier
    `mcp.json`, propre à votre profil utilisateur.

    === "Jeton personnel"

        ```json
        {
          "servers": {
            "security-review": {
              "url": "https://secreview.example.internal/mcp",
              "requestInit": {
                "headers": { "Authorization": "Bearer <token>" }
              }
            }
          }
        }
        ```

        Le jeton est écrit dans le fichier : ne le copiez jamais dans le dépôt. Omettez
        `requestInit` tant que vous n'avez pas de jeton (voir [l'enrôlement](#obtenir-un-jeton)).

    === "Sans authentification"

        Pour un serveur local sur `127.0.0.1`, ou derrière un reverse proxy qui gère
        l'authentification.

        ```json
        {
          "servers": {
            "security-review": {
              "url": "http://127.0.0.1:8000/mcp"
            }
          }
        }
        ```

        **JetBrains AI Assistant** : **Settings** > **Tools** > **AI Assistant** > **Model Context
        Protocol (MCP)** > **Add**, puis collez la même configuration. AI Assistant ne documente pas d'en-têtes
        personnalisés : avec un jeton, utilisez le plugin GitHub Copilot.

    Connexion OAuth : non documentée pour IntelliJ, utilisez un jeton personnel.

!!! tip
    N'écrivez jamais le jeton en clair dans un fichier de configuration versionné : utilisez une
    saisie (`${input:...}`) ou une variable d'environnement.

## Obtenir un jeton

Avec la connexion OAuth, aucun jeton n'est nécessaire. Sinon :

1. **Créez un jeton MCP** : dans l'interface web, ouvrez **Mon compte** > **Jetons personnels**
   et créez un jeton d'usage **MCP**. Il n'est affiché **qu'une seule fois** : copiez-le.
2. **Enregistrez-le dans l'hôte**, puis redémarrez le serveur `security-review` dans l'hôte :

    === "VS Code / GitHub Copilot"

        Redémarrez le serveur `security-review` (commande **MCP: List Servers**) : VS Code
        demande le jeton, collez-le. S'il ne le demande pas, exécutez d'abord **MCP: Reset Cached
        Inputs**.

    === "Claude Code"

        Définissez la variable avant de lancer Claude Code, par exemple dans le profil du shell :

        ```bash
        export SECURITY_REVIEW_TOKEN='Zq3…'
        ```

    === "IntelliJ / JetBrains"

        Ajoutez le bloc `requestInit` avec le jeton dans le fichier `mcp.json` de GitHub
        Copilot, puis redémarrez le serveur `security-review` depuis les outils MCP du chat
        Copilot.

3. **Lancez une revue.** La première fois, l'agent demande l'accès au projet. Si un
   administrateur doit le valider, l'agent vous le dit : relancez la revue une fois l'accès
   donné.

Un jeton refusé (révoqué ou expiré) se remplace de la même façon : créez-en un nouveau et
enregistrez-le dans l'hôte.

**Pour aller plus loin :** [jetons personnels](../usage/tokens.md#jetons-mcp-et-ci-personnels),
[premier lancement sans jeton](../advanced/architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet).

## Autres cas

- **Certificat du serveur signé par une CA interne** (`unable to verify the first certificate`) :
  voir [Autorité de certification](../advanced/tls.md#autorite-de-certification).
- **Mode local (stdio)**, sans serveur (l'hôte lance lui-même le processus) : voir
  [Mode local (stdio)](stdio.md).

**Étape suivante :** lancez votre première revue avec les [prompts et outils](../reference/prompts-tools.md).
