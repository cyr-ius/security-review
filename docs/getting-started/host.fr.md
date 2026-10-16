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
reverse proxy), omettez `headers` et `inputs`, par exemple
`"url": "http://127.0.0.1:8000/mcp"`.

!!! tip
    N'écrivez jamais le jeton en clair dans un fichier de configuration versionné : utilisez une
    saisie (`${input:...}`) ou une variable d'environnement.

## Serveur HTTPS avec une CA interne

Quand le certificat du serveur est signé par une
[CA interne](http.md#autorite-de-certification), l'hôte refuse la connexion
(`unable to verify the first certificate`, `unable to get local issuer certificate`). Ni VS Code ni Claude
n'ont d'option TLS par serveur dans leur configuration MCP : on ajoute le certificat aux
autorités de confiance du **processus** de l'hôte. Claude Code et VS Code reposent sur Node.js,
qui lit pour cela la variable d'environnement `NODE_EXTRA_CA_CERTS` (fichier PEM) **au
démarrage** du processus.

1. Obtenez le certificat de la CA interne (PEM) auprès de ses administrateurs, enregistrez-le
   sous `~/.config/secreview/ca.pem`, et vérifiez que le nom ou l'adresse de l'`url` MCP figure
   dans le certificat du serveur :

    ```bash
    openssl s_client -connect 192.168.1.1:8000 -CAfile ~/.config/secreview/ca.pem </dev/null \
        2>/dev/null | openssl x509 -noout -ext subjectAltName
    ```

2. Déclarez-le à l'hôte, puis **redémarrez-le** :

=== "Claude Code"

    Dans le profil du shell (`~/.bashrc`, `~/.zshrc`), avant de lancer `claude` :

    ```bash
    export NODE_EXTRA_CA_CERTS="$HOME/.config/secreview/ca.pem"
    ```

    La [documentation de Claude Code](https://code.claude.com/docs/en/network-config) indique
    aussi la clé `env` de `settings.json`
    (`"env": { "NODE_EXTRA_CA_CERTS": "/home/moi/.config/secreview/ca.pem" }`). La variable
    s'applique à toutes les connexions de Claude Code, pas seulement au serveur MCP.

=== "VS Code / GitHub Copilot"

    Lancez VS Code depuis un shell où la variable est définie (`code .`), ou définissez-la au
    niveau du système :

    ```bash
    export NODE_EXTRA_CA_CERTS="$HOME/.config/secreview/ca.pem"
    code .
    ```

    Autre solution : ajoutez le certificat au magasin de certificats du système (Windows :
    *Autorités de certification racines de confiance* ; macOS : Trousseau, *Toujours approuver* ;
    Linux : `/usr/local/share/ca-certificates/` puis `sudo update-ca-certificates`). VS Code
    charge les certificats du système (paramètre `http.systemCertificates`, actif par défaut).

    Dans un **dev container**, la connexion part du conteneur : montez le fichier et définissez
    la variable dans `devcontainer.json` (`"remoteEnv": { "NODE_EXTRA_CA_CERTS": "..." }`), puis
    reconstruisez ou rechargez la fenêtre.

!!! warning
    N'utilisez pas `NODE_TLS_REJECT_UNAUTHORIZED=0` : il désactive la vérification de **toutes**
    les connexions du processus (API, extensions, mises à jour), pas seulement celle du serveur
    MCP, et laisse passer une interception.

Les connecteurs distants ajoutés depuis l'interface web de Claude (claude.ai, Claude Desktop)
sont contactés depuis l'infrastructure d'Anthropic, pas depuis le poste : ils exigent un
serveur joignable depuis Internet avec un certificat reconnu publiquement, ce qui exclut une CA
interne.

Pour l'enrôlement en CLI, `security-review-mcp enroll` accepte directement `--cafile` (voir
ci-dessous).

## Obtenir un jeton (enrôlement)

Sur un serveur partagé qui exige un jeton, vous n'avez pas besoin d'en réclamer un à
l'administrateur avant de commencer : configurez l'hôte comme ci-dessus, **sans jeton**, et
lancez votre première revue. Le jeton est demandé au passage, puis validé par un administrateur
(voir [l'enrôlement](http.md#enrolement-un-projet-demande-son-jeton)).

1. **Configurez l'hôte sans jeton.** Avec les exemples de la section
   [Transport HTTP](#transport-http), laissez la saisie du jeton vide (VS Code) ou ne définissez
   pas `SECURITY_REVIEW_TOKEN` (Claude). Un en-tête absent ou un `Bearer` vide mène au serveur
   d'enrôlement, qui porte le même nom `security-review`.
2. **Lancez une revue**, par exemple le prompt `security-review`. Au lieu de relire le code,
   l'agent appelle l'outil `request_enrollment` avec le nom du projet (le nom du dépôt en
   général) et vous affiche le jeton, **une seule fois** :

    ```json
    {
      "label": "shop-api-enroll-3fa9c1",
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

Le jeton obtenu est de rôle `mcp` et [restreint au projet](http.md#jetons-restreints-a-un-projet)
demandé : il n'enregistre et ne lit que les rapports de ce projet. Pour un autre projet,
l'agent peut demander un nouveau jeton avec `request_enrollment` ; `save_security_report` le
lui propose quand il refuse le projet.

!!! note
    Si l'administrateur a désactivé l'enrôlement (`SECREVIEW_ENROLLMENT=false`), un hôte sans
    jeton reçoit `401` : demandez-lui un jeton créé avec `security-review-controller token create`.
