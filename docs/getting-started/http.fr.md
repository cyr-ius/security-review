# Serveur HTTP, authentification et TLS

Un serveur partagé (équipe, CI/CD) se compose de **deux processus** qui partagent la même base
de données (voir [Architecture et déploiement](kubernetes.md)) :

- le **serveur MCP** (`security-review-mcp --transport streamable-http`) : endpoint `/mcp`,
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
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
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
security-review-controller token create --label triage-bot --role triager
security-review-controller token create --label shop-ci --role reader --project shop-api
# {"id": "6f1c…", "label": "ci", "role": "mcp", "project": null, "created_at": "…", "token": "UJB7…"}
security-review-controller token list [--project shop-api]             # jamais le secret ni l'empreinte
security-review-controller token revoke ci                              # par label ou par id
```

Les projets peuvent aussi demander eux-mêmes leur jeton : voir
[l'enrôlement](#enrolement-un-projet-demande-son-jeton).

- Donnez `token` au client ; le `label`, unique, apparaît dans les journaux.
- `--role` vaut `mcp` par défaut (serveur MCP) ; `reader` (lecture seule) et `triager` (lecture
  et triage) donnent accès à l'API REST du contrôleur, jamais à l'interface web : voir les
  [rôles](../usage/web-interface.md#roles).
- `--project` limite le jeton à un ou plusieurs projets (répétez l'option), pour les outils MCP
  comme pour l'API REST
  (rôles `mcp`, `reader` et `triager` ; refusé pour `admin`). Voir
  [jetons restreints à un projet](#jetons-restreints-a-un-projet). Les administrateurs peuvent
  aussi créer et révoquer des jetons `reader` restreints depuis l'écran **Jetons**.
- Le serveur consulte la base à chaque requête : une création ou une révocation s'applique
  immédiatement, y compris aux autres instances qui partagent la même base PostgreSQL.

Dès qu'un jeton existe en base, l'endpoint MCP et l'API du contrôleur exigent
`Authorization: Bearer <jeton>`. Restent publics : `/healthz` sur les deux processus,
`/api/v1/enroll` sur le serveur MCP, et sur le contrôleur les fichiers statiques de `/ui/` et la
documentation Swagger (`/api/docs`, schéma `/api/openapi.json`, icône `/api/favicon.svg`). Tant qu'aucun jeton n'existe,
`/mcp` est ouvert (un avertissement est journalisé si l'écoute n'est pas sur localhost) et l'API
du contrôleur répond `503`. `token revoke` avertit sur stderr quand il
supprime le dernier jeton.

### Jetons restreints à un projet

Sur un serveur partagé par plusieurs équipes, donnez à chaque pipeline un jeton limité à son
projet :

```bash
security-review-controller token create --label shop-ci --project shop-api            # rôle mcp
security-review-controller token create --label shop-triage --role triager --project shop-api
```

Un jeton sans `--project` accède à tous les projets. Un jeton restreint :

- n'enregistre de rapport (`save_security_report`) que pour son projet ;
- ne lit, ne liste, n'exporte et ne trie (`update_finding_status`, `PATCH` de l'API web) que les
  rapports et findings de son projet ; `list_security_reports` sans filtre ne renvoie que
  ceux-ci ;
- reçoit pour tout autre projet, rapport ou finding la même erreur « not found » que pour un
  objet inexistant, afin de ne pas révéler les autres projets ;
- ne peut pas appeler `reload_rules`.

La restriction s'applique aussi à la ressource `report://` et au prompt `triage-report`. En
stdio, il n'y a pas de jeton, donc pas de restriction.

### Mot de passe administrateur initial

Avec `SECREVIEW_AUTH_BOOTSTRAP_ADMIN=true` (c'est le cas dans l'image Docker), le **contrôleur**
crée au premier démarrage le [compte](../usage/web-interface.md#comptes-utilisateurs)
`admin` de l'interface web, avec un mot de passe aléatoire affiché une seule fois dans ses logs.
Ce compte n'ouvre que l'interface web et l'API REST, jamais `/mcp` : pour un agent, créez un
jeton (`token create`). S'il est perdu, remplacez le mot de passe (l'ancien est aussitôt
invalidé) :

```bash
security-review-controller user reset-password admin
```

### Enrôlement : un projet demande son jeton

Plutôt que de créer chaque jeton à l'avance, laissez les projets **demander** le leur, puis
validez la demande. C'est actif par défaut (`SECREVIEW_ENROLLMENT=true`) dès qu'un jeton existe.

1. **Demande.** Le client obtient tout de suite un jeton de rôle `mcp`, restreint au projet
   demandé, mais **en attente** : il ne donne encore accès à rien. Un jeton est personnel (il
   pourra ensuite atteindre d'autres projets) : son label est donc le **nom d'utilisateur du
   développeur**, le nom de connexion avec `enroll`, le nom transmis par l'agent ; sans label,
   le nom du projet suivi de `-enroll`. Un suffixe aléatoire est ajouté. Trois façons de
   demander :
    - **Depuis l'agent, à la première revue.** Un client MCP qui se connecte **sans** en-tête
      `Authorization` n'est pas rejeté : il atteint un serveur MCP restreint (même nom
      `security-review`) qui n'expose que les outils `request_enrollment` et
      `get_enrollment_status`, et des prompts du même nom que les revues (`security-review`,
      `codebase-review`…) qui expliquent la marche à suivre. L'agent appelle
      `request_enrollment` avec le nom du projet et le nom d'utilisateur du développeur,
      et remet le jeton à l'utilisateur.
    - **En ligne de commande**, depuis le poste du développeur ou la CI :

        ```bash
        security-review-mcp enroll --url https://secreview.example.internal:8443 \
            --project shop-api --requested-by "alice (équipe shop)"
        # {"id": "…", "label": "alice-3fa9c1", "status": "pending", "token": "UJB7…", …}
        ```

    - **Par l'API du serveur MCP** : `POST /api/v1/enroll` (sans jeton) avec
      `{"project": "shop-api"}`. Le contrôleur ne sert pas cet endpoint : il n'expose aucune
      route d'écriture sans authentification.
2. **Configuration.** L'utilisateur place aussitôt le jeton dans la
   [configuration de l'hôte](host.md#obtenir-un-jeton-enrolement). Tant qu'il est en attente, le client
   reste sur le serveur d'enrôlement (`get_enrollment_status` répond `pending`) et l'API web
   répond `403 enrollment_pending`.
3. **Validation.** Un administrateur approuve ou refuse la demande dans l'écran **Jetons** de
   l'[interface web](../usage/web-interface.md), ou en CLI :

    ```bash
    security-review-controller token list --pending           # demandeur, adresse, date
    security-review-controller token approve alice-3fa9c1
    security-review-controller token reject alice-3fa9c1
    ```

    Une fois approuvé, le jeton fonctionne dès la requête suivante, sans reconfiguration.
    L'approbation peut aussi donner au développeur la **lecture du projet dans le portail**,
    sur son compte utilisateur (colonne **Lecture dans le portail** de l'interface, ou
    `token approve ID --portal-user alice` en CLI) ; avec la
    [connexion SSO](../usage/web-interface.md#connexion-sso-openid-connect), un nom
    inconnu devient un compte SSO. Voir la
    [lecture du projet à l'enrôlement](../usage/web-interface.md#lecture-du-projet-a-lenrolement).

### Enrôlement complémentaire

Un hôte qui possède déjà un jeton actif restreint à un ou plusieurs projets peut demander un
projet supplémentaire avec **le même jeton**. Celui-ci continue de fonctionner pour ses projets
actuels pendant l'attente ; aucun nouveau secret n'est créé. Après approbation, le projet est
ajouté à ses droits.

- **Depuis un agent MCP** : connecté avec le jeton existant, appelez `request_enrollment` pour le
  nouveau projet. `save_security_report` suggère cet appel si le projet demandé n'est pas
  autorisé.
- **En ligne de commande** : transmettez le jeton sur stdin, jamais comme argument :

    ```bash
    printf '%s\n' "$SECURITY_REVIEW_TOKEN" | security-review-mcp enroll \
        --url https://secreview.example.internal:8443 --project billing \
        --requested-by "alice (équipe billing)" --token-stdin
    ```

  La réponse confirme la demande en attente sans afficher de nouveau jeton. Un administrateur
  l'approuve ou la refuse dans l'interface web ou avec `security-review-controller token approve ID` /
  `security-review-controller token reject ID`. La commande `token list --pending` affiche le projet
  demandé et le jeton concerné.

Un jeton sans restriction atteint déjà tous les projets : il ne peut pas faire d'enrôlement
complémentaire. Créez un jeton restreint si vous devez limiter ses accès.

Garde-fous : au plus 20 demandes en attente à la fois, 3 par adresse cliente (derrière un
reverse proxy, définissez [`SECREVIEW_FORWARDED_ALLOW_IPS`](../reference/configuration.md)), une
demande non traitée expire au bout de
7 jours, un jeton avec un secret invalide reste refusé (`401`) et les demandes en attente
n'activent jamais l'authentification d'un serveur ouvert. Vérifiez le demandeur avant
d'approuver : n'importe quel client qui atteint le serveur peut déposer une demande. Pour
désactiver l'enrôlement : `SECREVIEW_ENROLLMENT=false` (les clients sans jeton reçoivent alors
`401`).

`--url` est l'URL du **serveur MCP** (avec ou sans `/mcp`) : c'est lui qui reçoit les demandes.

!!! tip
    Les commandes `token` s'exécutent côté contrôleur (ou dans son conteneur), avec la même
    `SECREVIEW_DATABASE_URL` que lui. Les jetons ne passent jamais en argument de ligne de
    commande.

## TLS

Uvicorn sert directement en HTTPS quand un certificat est fourni, pour le serveur MCP comme pour
le contrôleur (mêmes options, mêmes variables) :

```bash
security-review-mcp --transport streamable-http --host 0.0.0.0 --port 8443 \
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
[Configuration de l'hôte](host.md#serveur-https-avec-une-ca-interne).

## Configuration du client

VS Code, avec un jeton demandé à l'utilisateur :

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

Pour Claude et pour obtenir un jeton par enrôlement depuis l'hôte, voir
[Configuration de l'hôte](host.md#obtenir-un-jeton-enrolement).

## Derrière un reverse proxy

Un reverse proxy (TLS, SSO, limitation de débit) reste une option valable : dans ce cas,
laissez ces variables vides.

!!! warning
    Si le serveur écoute ailleurs que sur localhost sans authentification ou sans TLS, un
    avertissement est journalisé. Tout jeton de rôle `mcp` ou `admin` donne accès à **tous** les
    outils.
