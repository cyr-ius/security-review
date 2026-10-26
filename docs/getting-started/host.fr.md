# Configuration de l'hôte

Chaque développeur déclare le serveur MCP partagé dans son hôte (VS Code, IntelliJ, Claude…). Le serveur
doit déjà tourner : voir [Mise en service du serveur](deploy.md).

## Transport HTTP

En mode partagé, avec le serveur lancé par `serve --transport streamable-http`, l'hôte se connecte à
l'endpoint `/mcp` au lieu de lancer un processus. Il envoie le jeton dans l'en-tête
`Authorization: Bearer <jeton>` (voir [Jetons Bearer](../advanced/bearer-tokens.md) et
[TLS](../advanced/tls.md)).

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

    VS Code privilégie désormais le fichier `.mcp.json` à la racine du dépôt et signale
    `.vscode/mcp.json` comme déprécié, mais le lit toujours. Gardez-le pour un serveur avec
    jeton : dans `.mcp.json`, VS Code ne substitue pas encore les variables (ni `${input:...}`,
    ni les variables d'environnement), et le jeton devrait être écrit en clair.

=== "Claude"

    `.mcp.json`, avec le jeton lu dans la variable d'environnement `SECURITY_REVIEW_TOKEN` du
    poste (côté client, distincte des paramètres `SECREVIEW_*` du serveur). `:-` donne une
    valeur vide tant que la variable n'existe pas, ce qui permet l'[enrôlement](#obtenir-un-jeton) :

    ```json
    {
      "mcpServers": {
        "security-review": {
          "type": "http",
          "url": "https://secreview.example.internal:8443/mcp",
          "headers": { "Authorization": "Bearer ${SECURITY_REVIEW_TOKEN:-}" }
        }
      }
    }
    ```

=== "IntelliJ / JetBrains"

    Plugin **GitHub Copilot** : dans le chat Copilot, en mode **Agent**, cliquez sur l'icône des
    outils (**Configure your MCP server**) puis sur **Add MCP Tools**. L'IDE ouvre son fichier
    `mcp.json`, propre à votre profil utilisateur et extérieur au dépôt :

    ```json
    {
      "servers": {
        "security-review": {
          "url": "https://secreview.example.internal:8443/mcp",
          "requestInit": {
            "headers": { "Authorization": "Bearer <token>" }
          }
        }
      }
    }
    ```

    Ce fichier ne substitue pas les variables : le jeton y est écrit, ne le copiez donc jamais
    dans le dépôt. Omettez `requestInit` tant que vous n'avez pas de jeton (voir
    [l'enrôlement](#obtenir-un-jeton)).

    **JetBrains AI Assistant** : **Settings** > **Tools** > **AI Assistant** > **Model Context
    Protocol (MCP)** > **Add**, puis collez la configuration d'un serveur sans authentification
    (exemple ci-dessous). AI Assistant ne documente pas d'en-têtes
    personnalisés : avec un jeton, utilisez le plugin GitHub Copilot.

Sans authentification (serveur local sur `127.0.0.1`, ou authentification assurée par un
reverse proxy), VS Code, GitHub Copilot et Claude partagent le même fichier `.mcp.json` à la
racine du dépôt, sans `headers` :

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

!!! tip
    N'écrivez jamais le jeton en clair dans un fichier de configuration versionné : utilisez une
    saisie (`${input:...}`) ou une variable d'environnement.

## Obtenir un jeton

En mode partagé, quand le serveur exige un jeton, vous utilisez un **jeton MCP personnel**, créé dans
l'interface web. Inutile d'en réclamer un à un administrateur avant de commencer : configurez
l'hôte comme ci-dessus, **sans jeton**, et lancez votre première revue. L'agent vous indique où
créer votre jeton, puis demande le projet à la revue suivante (voir
[l'enrôlement](../advanced/architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)).

1. **Configurez l'hôte sans jeton.** Avec les exemples de la section
   [Transport HTTP](#transport-http), laissez la saisie du jeton vide (VS Code), ne définissez
   pas `SECURITY_REVIEW_TOKEN` (Claude) ou omettez `requestInit` (IntelliJ). Un en-tête absent ou un `Bearer` vide mène au serveur
   d'enrôlement, qui porte le même nom `security-review`.
2. **Lancez une revue**, par exemple le prompt `security-review`. Au lieu de relire le code,
   l'agent vous invite à vous connecter à l'interface web (son adresse est donnée quand
   l'administrateur l'a définie : `SECREVIEW_CONTROLLER_URL` ou écran **Général**) et à créer un jeton MCP personnel. Le serveur
   n'enregistre rien à cette étape.

3. **Créez votre jeton MCP personnel** : connectez-vous à l'interface web, ouvrez
   **Mon compte** > **Jetons personnels** et créez un jeton d'usage **MCP** (voir
   [jetons MCP personnels](../usage/tokens.md#jetons-mcp-et-ci-personnels) ; vos groupes doivent
   avoir le rôle `mcp-user`). Il n'est affiché **qu'une seule fois**.
4. **Enregistrez le jeton dans l'hôte**, puis redémarrez le serveur MCP dans l'hôte :

    === "VS Code / GitHub Copilot"

        Si la saisie a déjà été mémorisée vide, exécutez la commande **MCP: Reset Cached Inputs**
        puis redémarrez le serveur `security-review` (commande **MCP: List Servers**) : VS Code
        redemande le jeton, collez-le. Il est conservé dans le stockage sécurisé de VS Code.

    === "Claude"

        Définissez la variable avant de lancer Claude, par exemple dans le profil du shell :

        ```bash
        export SECURITY_REVIEW_TOKEN='Zq3…'
        ```

    === "IntelliJ / JetBrains"

        Ajoutez le bloc `requestInit` avec le jeton dans le fichier `mcp.json` de GitHub
        Copilot, puis redémarrez le serveur `security-review` depuis les outils MCP du chat
        Copilot.

5. **Relancez la revue.** L'agent appelle d'abord `request_project` avec le nom du projet (le
   nom du dépôt en général). Si vous pouvez créer des projets, un nouveau projet est créé avec
   vous pour membre et la revue continue. Sinon l'agent s'arrête et vous indique que le projet
   est demandé : un administrateur le valide dans l'écran **Projets**, ce qui vous en donne
   l'accès. Pour un projet qui existe déjà, la demande est une demande d'accès, validée de la
   même façon. L'accès s'applique aussitôt : relancez la revue, sans rien
   reconfigurer.

Quand le serveur refuse le jeton (inconnu, révoqué ou expiré), l'hôte reçoit `401` avec un
message qui vous invite à vous reconnecter à l'interface web pour créer un nouveau jeton MCP
personnel : remplacez-le dans l'hôte comme à l'étape 4 (voir
[jeton refusé](../advanced/architecture/mcp-server.md#jeton-refuse-se-reconnecter)).

!!! note
    Si l'administrateur a désactivé l'enrôlement (`SECREVIEW_ENROLLMENT=false`), un hôte sans
    jeton reçoit `401`, et `request_project` ne crée ni ne demande aucun projet : créez
    directement votre jeton MCP personnel dans l'interface web, et demandez à un administrateur
    l'accès au projet.

## Autres cas

- **Certificat du serveur signé par une CA interne** (`unable to verify the first certificate`) :
  voir [Serveur HTTPS avec une CA interne](../advanced/tls.md#serveur-https-avec-une-ca-interne).
- **Mode local (stdio)**, sans serveur (l'hôte lance lui-même le processus) : voir
  [Mode local (stdio)](stdio.md).

**Étape suivante :** lancez votre première revue avec les [prompts et outils](../review/prompts-tools.md).
