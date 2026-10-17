# Configuration de l'hôte

Chaque développeur déclare le serveur MCP partagé dans son hôte (VS Code, Claude…). Le serveur
doit déjà tourner : voir [Mise en service du serveur](deploy.md).

## Transport HTTP

Pour un serveur partagé, lancé avec `--transport streamable-http`, l'hôte se connecte à
l'endpoint `/mcp` au lieu de lancer un processus. Si l'authentification est activée, il envoie
le jeton dans l'en-tête `Authorization: Bearer <jeton>` (génération des jetons, TLS et
démarrage du serveur : voir [Serveur HTTP, authentification et TLS](../advanced/http.md)).

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
    valeur vide tant que la variable n'existe pas, ce qui permet l'[enrôlement](#obtenir-un-jeton-enrolement) :

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

## Obtenir un jeton (enrôlement)

Sur un serveur partagé qui exige un jeton, vous n'avez pas besoin d'en réclamer un à
l'administrateur avant de commencer : configurez l'hôte comme ci-dessus, **sans jeton**, et
lancez votre première revue. Le jeton est demandé au passage, puis validé par un administrateur
(voir [l'enrôlement](../advanced/http.md#enrolement-un-projet-demande-son-jeton)).

1. **Configurez l'hôte sans jeton.** Avec les exemples de la section
   [Transport HTTP](#transport-http), laissez la saisie du jeton vide (VS Code) ou ne définissez
   pas `SECURITY_REVIEW_TOKEN` (Claude). Un en-tête absent ou un `Bearer` vide mène au serveur
   d'enrôlement, qui porte le même nom `security-review`.
2. **Lancez une revue**, par exemple le prompt `security-review`. Au lieu de relire le code,
   l'agent appelle l'outil `request_enrollment` avec le nom du projet (le nom du dépôt en
   général) et votre nom d'utilisateur comme label (le jeton est personnel), et vous affiche le jeton, **une seule fois** :

    ```json
    {
      "label": "alice-3fa9c1",
      "project": "shop-api",
      "status": "pending",
      "token": "UJB7…"
    }
    ```

    Sans agent, demandez-le en ligne de commande :

    ```bash
    security-review-mcp enroll --url https://secreview.example.internal:8443 \
        --project shop-api --requested-by "alice (équipe shop)"
    ```

3. **Enregistrez le jeton dans l'hôte**, puis redémarrez le serveur MCP dans l'hôte :

    === "VS Code / GitHub Copilot"

        Si la saisie a déjà été mémorisée vide, exécutez la commande **MCP: Reset Cached Inputs**
        puis redémarrez le serveur `security-review` (commande **MCP: List Servers**) : VS Code
        redemande le jeton, collez-le. Il est conservé dans le stockage sécurisé de VS Code.

    === "Claude"

        Définissez la variable avant de lancer Claude, par exemple dans le profil du shell :

        ```bash
        export SECURITY_REVIEW_TOKEN='UJB7…'
        ```

4. **Attendez l'approbation.** Prévenez l'administrateur en lui donnant le label du jeton. Tant
   que la demande est en attente, l'hôte reste sur le serveur d'enrôlement : l'outil
   `get_enrollment_status` répond `pending`. Dès que l'administrateur l'approuve (écran
   **Jetons** de l'interface web, ou `security-review-controller token approve <label>`), le même
   jeton donne accès aux outils de revue. Il suffit de relancer la revue, sans rien
   reconfigurer.

Le jeton obtenu est de rôle `mcp` et [restreint au projet](../advanced/http.md#jetons-restreints-a-un-projet)
demandé : il n'enregistre et ne lit que les rapports de ce projet. Pour un autre projet,
l'agent peut demander un nouveau jeton avec `request_enrollment` ; `save_security_report` le
lui propose quand il refuse le projet.

!!! note
    Si l'administrateur a désactivé l'enrôlement (`SECREVIEW_ENROLLMENT=false`), un hôte sans
    jeton reçoit `401` : demandez-lui un jeton créé avec `security-review-controller token create`.

## Autres cas

- **Certificat du serveur signé par une CA interne** (`unable to verify the first certificate`) :
  voir [Serveur HTTPS avec une CA interne](../advanced/http.md#serveur-https-avec-une-ca-interne).
- **Mode local, sans serveur partagé** (l'hôte lance lui-même le processus) : voir
  [Mode local (stdio)](../advanced/stdio.md).

**Étape suivante :** lancez votre première revue avec les [prompts et outils](../usage/prompts-tools.md).
