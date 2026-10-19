# Serveur HTTP, authentification et TLS

Un serveur partagé (équipe, CI/CD) se compose de **deux processus** qui partagent la même base
de données (voir [Architecture et déploiement](architecture.md)) :

- le **serveur MCP** (`security-review-mcp serve --transport streamable-http`) : endpoint `/mcp`,
  enrôlement public (`/api/v1/enroll`) et sonde `/healthz` ; c'est lui qu'on expose aux agents et
  à la CI ;
- le **contrôleur** (`security-review-controller serve`) : API REST `/api/v1`, interface web
  `/ui/` et sonde `/healthz` ; il peut rester sur un réseau interne.

L'authentification MCP et le TLS sont **facultatifs** et indépendants ; l'API du contrôleur
exige toujours un jeton. En stdio, l'hôte lance lui-même le processus et le contrôleur n'est pas
nécessaire.

```bash
security-review-controller db upgrade                        # crée ou migre le schéma
security-review-controller serve --host 127.0.0.1 --port 8080
# interface web : http://127.0.0.1:8080/ui/
security-review-mcp serve --transport streamable-http --host 127.0.0.1 --port 8000
# endpoint MCP : http://127.0.0.1:8000/mcp
```

Avec SQLite, les deux processus doivent tourner sur la même machine (même fichier) ; utilisez
PostgreSQL dès qu'ils sont sur des machines ou des pods différents.

## Jetons Bearer

Les jetons sont stockés dans la base de données (table `apitoken`) : seule leur empreinte
SHA-256 est conservée, le secret n'est affiché qu'une fois, à la création. Gérez-les avec la
commande `token` (voir la [CLI](../reference/cli.md)) :

```bash
security-review-controller token create --label ci                      # rôle mcp par défaut
security-review-controller token create --label jenkins --role ci --project shop-api
security-review-controller token create --label ops-script --role admin
# {"id": "6f1c…", "label": "ci", "role": "mcp", "project": null, "created_at": "…", "token": "UJB7…"}
security-review-controller token list [--project shop-api]             # jamais le secret ni l'empreinte
security-review-controller token revoke ci                              # par label ou par id
```

Les développeurs peuvent aussi créer un jeton MCP personnel dans l'interface web, après avoir
enrôlé leur projet : voir [l'enrôlement](#enrolement-demander-le-projet).

- Donnez `token` au client ; le `label`, unique, apparaît dans les journaux.
- `--role` vaut `mcp` par défaut (serveur MCP) ; `admin` atteint le serveur MCP et toute l'API
  REST du contrôleur, jamais l'interface web ; `ci` (toujours avec `--project`) n'atteint que les routes de pipeline utilisées par
  [`security-review-ci`](../usage/gate.md#client-de-pipeline-security-review-ci) : voir les
  [rôles](../usage/web-interface.md#roles) ; `metrics` (jamais avec `--project`) n'atteint que
  les [métriques Prometheus](audit-metrics.md#metriques-prometheus) du contrôleur. Les jetons
  sont destinés aux machines : il n'existe pas de jeton `reader` ou `triager`, une personne lit
  et trie avec un [compte utilisateur](../usage/web-interface.md#comptes-utilisateurs) et ses
  [groupes](access-control.md). Les jetons `api` de l'API REST et de son Swagger, qui portent
  les droits d'un utilisateur ou d'un rôle, se créent dans l'interface web
  ([jetons API](../usage/web-interface.md#jetons-api)).
- `--expires-in-days` fixe la validité du jeton : voir
  [expiration et renouvellement](#expiration-et-renouvellement-des-jetons).
- `--project` limite le jeton à un ou plusieurs projets (répétez l'option), pour les outils MCP
  et les routes de pipeline (rôles `mcp` et `ci` ; refusé pour `admin` et `metrics`). Voir
  [jetons restreints à un projet](#jetons-restreints-a-un-projet). Les administrateurs peuvent
  aussi créer et révoquer des jetons `mcp` et `ci` restreints depuis l'écran **Jetons**.
- Le serveur consulte la base à chaque requête : une création ou une révocation s'applique
  immédiatement, y compris aux autres instances qui partagent la même base PostgreSQL.

L'endpoint MCP et l'API du contrôleur exigent `Authorization: Bearer <jeton>`. Restent publics : `/healthz` sur les deux processus,
`/api/v1/enroll` sur le serveur MCP, et sur le contrôleur les fichiers statiques de `/ui/`,
l'icône `/api/favicon.svg`, la disponibilité de l'API `/api/health` et, avec `SECREVIEW_SWAGGER_ENABLED=true` (désactivé par défaut), la
documentation Swagger (`/api/docs`, schéma `/api/openapi.json`, fichiers `/api/swagger/`). Tant qu'aucun jeton n'existe,
l'API du contrôleur répond `503` et le serveur MCP **reste fermé** : un client sans jeton
n'atteint que l'[enrôlement](#enrolement-demander-le-projet), toute autre requête reçoit
`401`, quelle que soit la valeur Bearer (un avertissement est journalisé au démarrage). `/mcp`
n'est ouvert dans ce cas que si le serveur écoute sur localhost (`127.0.0.1`, `::1`) ou avec
`SECREVIEW_ALLOW_UNAUTHENTICATED=true`, à réserver aux tests sur un réseau isolé : dès qu'un jeton
existe, il est exigé dans tous les cas. `token revoke` avertit sur stderr quand il supprime le
dernier jeton.

Chaque création, renouvellement et révocation de jeton, et chaque enrôlement, est écrit dans
le [journal d'audit](audit-metrics.md#journal-daudit),
avec son auteur.

### Expiration et renouvellement des jetons

Un jeton peut expirer : après sa date d'expiration il n'authentifie plus rien (`401`,
`error="invalid_token"`, description `The bearer token has expired`, suivie sur `/mcp` de la
façon d'[en obtenir un nouveau](#jeton-refuse-se-reconnecter)), mais il reste listé pour
qu'un administrateur le renouvelle ou le révoque. `SECREVIEW_TOKEN_MAX_DAYS` (`0` par défaut)
fixe la validité maximale d'un jeton créé ou renouvelé, et sa validité par défaut ; à `0`, les
jetons n'expirent pas, sauf validité demandée.

```bash
security-review-controller token create --label shop-ci --project shop-api --expires-in-days 90
security-review-controller token rotate shop-ci --grace-hours 24     # nouveau secret, affiché une fois
# {"id": "6f1c…", "label": "shop-ci", …, "expires_at": "…", "rotated_at": "…", "grace_until": "…", "token": "pX4q…"}
```

Un renouvellement remplace le secret d'un jeton : il garde son id, son label, son rôle et ses
projets, et reçoit une nouvelle validité (`--expires-in-days`, défaut comme à la création).
Pendant `--grace-hours` (`0` par défaut, `168` au plus), l'ancien secret reste valable, le temps
de mettre à jour les clients (`grace_until` dans `token list`) ; ensuite, seul le nouveau
authentifie. L'ancien secret d'un jeton expiré ne revient jamais. Après une fuite, renouvelez sans délai de
grâce (ou révoquez) : le secret divulgué cesse alors immédiatement de fonctionner. Un jeton personnel ne peut pas
être renouvelé : son utilisateur en crée un nouveau. Dans l'interface web, l'écran **Jetons**
renouvelle les jetons de projet (bouton **Renouveler**, délai de grâce choisi au-dessus de la
liste).

Les jetons expirés comptent toujours comme jetons configurés : un serveur dont tous les jetons
ont expiré reste fermé, il ne devient jamais ouvert.

### Jetons restreints à un projet

Sur un serveur partagé par plusieurs équipes, donnez à chaque pipeline un jeton limité à son
projet :

```bash
security-review-controller token create --label shop-ci --project shop-api            # rôle mcp
security-review-controller token create --label shop-gate --role ci --project shop-api
```

Un jeton sans `--project` accède à tous les projets. Dans l'interface web, l'écran
[**Jetons**](../usage/web-interface.md#ecrans) crée un jeton pour certains projets ou pour
**Tous les projets**, et change les projets d'un jeton existant (sauf `admin` et `metrics` ; un
jeton `ci` garde toujours au moins un projet). Un jeton restreint :

- n'enregistre de rapport (`save_security_report`) que pour son projet ;
- ne lit, ne liste, n'exporte et ne propose de statut (`propose_finding_status`) que pour les
  rapports et findings de son projet ; `list_security_reports` sans filtre ne renvoie que
  ceux-ci ;
- reçoit pour tout autre projet, rapport ou finding la même erreur « not found » que pour un
  objet inexistant, afin de ne pas révéler les autres projets ;
- ne peut pas appeler `reload_rules`.

La restriction s'applique aussi à la ressource `report://` et au prompt `triage-report`. En
stdio, il n'y a pas de jeton, donc pas de restriction.

### Mot de passe administrateur initial

À son premier démarrage, le **contrôleur** crée le
[compte](../usage/web-interface.md#comptes-utilisateurs) `admin` de l'interface web
(`SECREVIEW_ADMIN_USERNAME`), avec un mot de passe aléatoire que personne ne connaît :
définissez-le avec la CLI, qui l'affiche une fois (l'ancien est aussitôt invalidé), voir le [premier administrateur](../usage/web-interface.md#premier-administrateur).
Ce compte n'ouvre que l'interface web et l'API REST, jamais `/mcp` : pour un agent, créez un
jeton (`token create`).

```bash
security-review-controller user reset-password admin
```

### Enrôlement : demander le projet

L'enrôlement **ne crée jamais de jeton** : il demande le projet, qu'un administrateur valide, et
le développeur crée un jeton MCP personnel dans l'interface web. Il est activé par défaut
(`SECREVIEW_ENROLLMENT=true`), même avant la création du premier jeton (sauf sur un
[serveur ouvert](#jetons-bearer), qui n'a pas besoin de jeton).

1. **Demande.** Le client donne le nom de son projet (en général le nom du dépôt). Un nouveau
   projet est **en attente** : ce n'est pas encore un projet et il ne donne aucun accès. Un
   projet qui existe déjà, ou déjà en attente, reste inchangé, et la réponse est la même dans
   tous les cas, pour ne pas révéler quels projets existent. Trois façons de s'enrôler :
    - **Depuis l'agent, à la première revue.** Un client MCP qui se connecte **sans** en-tête
      `Authorization` n'est pas rejeté : il atteint un serveur MCP restreint (même nom
      `security-review`) qui n'expose que l'outil `request_enrollment`, et des prompts nommés
      comme les revues (`security-review`, `codebase-review`…) qui expliquent la marche à
      suivre. L'agent appelle `request_enrollment` avec le nom du projet.
    - **En ligne de commande**, depuis le poste du développeur ou la CI :

        ```bash
        security-review-mcp enroll --url https://secreview.example.internal:8443 \
            --project shop-api --requested-by "alice (équipe shop)"
        # {"project": "shop-api", "web_url": "https://secreview.example.internal/ui", "next_steps": "…"}
        ```

    - **Par l'API du serveur MCP** : `POST /api/v1/enroll` (sans jeton) avec
      `{"project": "shop-api"}`, qui répond `202`. Le contrôleur ne sert pas cet endpoint : il
      n'expose aucune route d'écriture non authentifiée.
2. **Validation.** Un utilisateur qui porte `projects.create` (entre autres le rôle `admin`)
   valide ou refuse la demande dans la section **Projets en attente** de l'écran **Projets**,
   ou en CLI :

    ```bash
    security-review-controller project list          # demandeur, adresse, expiration
    security-review-controller project approve 3     # id de la liste
    security-review-controller project reject 4
    ```

    La validation crée le projet, avec son groupe `project:<projet>` **sans aucun membre** :
    personne n'obtient d'accès, pas même le validateur. Une demande que personne n'a validée
    sous `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` (7 jours par défaut) est supprimée.
3. **Jeton personnel.** La réponse de l'enrôlement donne l'URL de l'interface web (`web_url`,
   issue de [`SECREVIEW_WEB_URL`](../reference/configuration.md)) et la marche à suivre :
   l'utilisateur se connecte, crée un **jeton MCP personnel** dans **Mon compte** (voir
   [jetons MCP personnels](../usage/web-interface.md#jetons-mcp-personnels)) et le place dans la
   [configuration de l'hôte](../getting-started/host.md#obtenir-un-jeton). Le jeton atteint les
   projets que l'utilisateur peut lire, relus à chaque requête.
4. **Accès.** Un administrateur donne à l'utilisateur l'accès au projet en l'ajoutant au groupe
   `project:<projet>` (écran **Groupes**, voir [contrôle d'accès](access-control.md)) ; le
   jeton personnel atteint le projet dès la requête suivante, sans reconfiguration.

Un agent qui a déjà un jeton peut aussi appeler `request_enrollment` (par exemple quand
`save_security_report` refuse un projet que son jeton n'atteint pas) : le projet est demandé de
la même façon, et le jeton ne gagne aucun projet. Un utilisateur portant `projects.create` qui
[crée le projet](access-control.md#creation-dun-projet) lui-même solde sa demande en attente.

### Jeton refusé : se reconnecter

Un client dont le jeton est **inconnu, révoqué ou expiré** reçoit `401` sur `/mcp`
(`error="invalid_token"`) : la description invite l'utilisateur à se connecter à l'interface web
(avec son URL quand `SECREVIEW_WEB_URL` est défini) et à créer un nouveau jeton MCP personnel,
puis à le remplacer dans la [configuration de l'hôte](../getting-started/host.md#obtenir-un-jeton).
Un tel client n'atteint jamais les outils de revue ni le serveur d'enrôlement. Le refus est
journalisé en avertissement par le serveur MCP (`Rejected unauthenticated request` /
`Rejected expired token`). `security-review-mcp scan-deps` donne le même conseil.

Garde-fous : quiconque atteint le serveur peut s'enrôler, donc au plus 20 projets sont en
attente à la fois, une adresse cliente s'enrôle au plus 5 fois par heure (`429` au-delà ;
derrière un reverse proxy, définissez
[`SECREVIEW_FORWARDED_ALLOW_IPS`](../reference/configuration.md)), et un projet en attente
expire après `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS`. Chaque demande, validation, refus et
expiration est écrit dans le [journal d'audit](audit-metrics.md#journal-daudit)
(`enrollment.requested`, `enrollment.approved`, `enrollment.rejected`, avec le demandeur et
l'adresse cliente). Pour désactiver l'enrôlement :
`SECREVIEW_ENROLLMENT=false` (les clients sans jeton reçoivent alors `401`, avec le même conseil).

`--url` est l'URL du **serveur MCP** (avec ou sans `/mcp`) : c'est lui qui reçoit les demandes.

!!! tip
    Les commandes `token` s'exécutent côté contrôleur (ou dans son conteneur), avec la même
    `SECREVIEW_DATABASE_URL` que lui. Les jetons ne passent jamais en argument de ligne de
    commande.

## TLS

Uvicorn sert directement en HTTPS quand un certificat est fourni, pour le serveur MCP comme pour
le contrôleur (mêmes options, mêmes variables) :

```bash
security-review-mcp serve --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
security-review-controller serve --host 0.0.0.0 --port 9443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# ou SECREVIEW_TLS_CERTFILE / SECREVIEW_TLS_KEYFILE (+ SECREVIEW_TLS_KEYFILE_PASSWORD)
```

`SECREVIEW_TLS_CLIENT_CA` active en plus le **TLS mutuel** : seuls les clients présentant un
certificat signé par cette CA peuvent se connecter.

### Autorité de certification

Le serveur ne génère jamais de certificat : fournissez-en un signé par une autorité de
certification reconnue par les clients, une CA publique (par exemple Let's Encrypt, ou
cert-manager dans Kubernetes) ou la **CA interne** de votre organisation. Son `subjectAltName`
doit contenir les noms et adresses utilisés par les clients (par exemple
`DNS:secreview.lan,IP:192.168.1.1`) ; sinon les clients refusent la connexion même s'ils font
confiance à la CA. Le fichier de clé (`key.pem`) ne quitte jamais le serveur : gardez-le lisible
par le seul compte du serveur (`chmod 600`).

Avec une CA interne, les clients doivent faire confiance à son certificat : voir
[Configuration de l'hôte](http.md#serveur-https-avec-une-ca-interne).

## Serveur HTTPS avec une CA interne

Quand le certificat du serveur est signé par une
[CA interne](#autorite-de-certification), l'hôte refuse la connexion
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

## Configuration du client

VS Code, avec un jeton demandé à l'utilisateur (`.vscode/mcp.json`, voir
[Configuration de l'hôte](../getting-started/host.md#transport-http)) :

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

Pour Claude et pour obtenir un jeton depuis l'hôte, voir
[Configuration de l'hôte](../getting-started/host.md#obtenir-un-jeton).

## Derrière un reverse proxy

Un reverse proxy (TLS, OIDC, limitation de débit) reste une option valable : dans ce cas,
laissez ces variables vides.

!!! warning
    Si le serveur écoute ailleurs que sur localhost sans authentification ou sans TLS, un
    avertissement est journalisé. Tout jeton de rôle `mcp` ou `admin` donne accès à **tous** les
    outils.
