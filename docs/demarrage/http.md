# Serveur HTTP, authentification et TLS

Le transport `streamable-http` sert un serveur partagé (équipe, CI/CD). L'authentification MCP
et le TLS sont **facultatifs** et indépendants ; l'API de la Web UI exige toujours un jeton.
En stdio, l'hôte lance lui-même le processus.

```bash
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
# endpoint : http://127.0.0.1:8000/mcp
# interface web : http://127.0.0.1:8000/ui/
```

## Jetons Bearer

Les jetons sont stockés dans la base de données (table `apitoken`) : seule leur empreinte
SHA-256 est conservée, le secret n'est affiché qu'une fois, à la création. Gérez-les avec la
commande `token` (voir la [CLI](../reference/cli.md)) :

```bash
security-review-mcp token create --label ci                      # rôle mcp par défaut
security-review-mcp token create --label alice --role triager
security-review-mcp token create --label shop-ci --role reader --project shop-api
# {"id": "6f1c…", "label": "ci", "role": "mcp", "project": null, "created_at": "…", "token": "UJB7…"}
security-review-mcp token list [--project shop-api]             # jamais le secret ni l'empreinte
security-review-mcp token revoke ci                              # par label ou par id
```

Les projets peuvent aussi demander eux-mêmes leur jeton : voir
[l'enrôlement](#enrolement-un-projet-demande-son-jeton).

- Donnez `token` au client ; le `label`, unique, apparaît dans les journaux.
- `--role` vaut `mcp` par défaut : voir les [rôles](../utilisation/interface-web.md#roles) pour
  donner accès à l'interface web.
- `--project` limite le jeton à un ou plusieurs projets (répétez l'option), pour les outils MCP
  comme pour l'interface web
  (rôles `mcp`, `reader` et `triager` ; refusé pour `admin`). Voir
  [jetons restreints à un projet](#jetons-restreints-a-un-projet). Les administrateurs peuvent
  aussi créer et révoquer des jetons `reader` restreints depuis l'écran **Jetons**.
- Le serveur consulte la base à chaque requête : une création ou une révocation s'applique
  immédiatement, y compris aux autres instances qui partagent la même base PostgreSQL.

Dès qu'un jeton existe en base, les endpoints MCP et les routes applicatives protégées exigent
`Authorization: Bearer <jeton>` ; les fichiers statiques de `/ui/` et la documentation Swagger
(`/api/docs`, schéma `/api/openapi.json`) restent accessibles sans jeton. Tant qu'aucun jeton
n'existe, `/mcp` est ouvert (un avertissement est journalisé si l'écoute n'est pas sur
localhost) et l'API de la Web UI répond `503`. `token revoke` avertit sur stderr quand il
supprime le dernier jeton.

### Jetons restreints à un projet

Sur un serveur partagé par plusieurs équipes, donnez à chaque pipeline un jeton limité à son
projet :

```bash
security-review-mcp token create --label shop-ci --project shop-api            # rôle mcp
security-review-mcp token create --label shop-triage --role triager --project shop-api
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

Avec `SECREVIEW_AUTH_BOOTSTRAP_ADMIN=true` (c'est le cas dans l'image Docker), un jeton aléatoire
de rôle `admin` (label `bootstrap-admin`) est créé au premier démarrage HTTP et affiché une seule
fois dans les logs. Il donne accès à la Web UI et à `/mcp`. S'il est perdu, remplacez-le
(l'ancien est aussitôt invalidé) :

```bash
security-review-mcp token reset-admin
```

### Enrôlement : un projet demande son jeton

Plutôt que de créer chaque jeton à l'avance, laissez les projets **demander** le leur, puis
validez la demande. C'est actif par défaut (`SECREVIEW_ENROLLMENT=true`) dès qu'un jeton existe.

1. **Demande.** Le client obtient tout de suite un jeton de rôle `mcp`, restreint au projet
   demandé, mais **en attente** : il ne donne encore accès à rien. Son label (le nom du projet
   par défaut) reçoit un suffixe aléatoire. Trois façons de demander :
    - **Depuis l'agent, à la première revue.** Un client MCP qui se connecte **sans** en-tête
      `Authorization` n'est pas rejeté : il atteint un serveur MCP restreint (même nom
      `security-review`) qui n'expose que les outils `request_enrollment` et
      `get_enrollment_status`, et des prompts du même nom que les revues (`security-review`,
      `codebase-review`…) qui expliquent la marche à suivre. L'agent appelle
      `request_enrollment` avec le nom du projet et remet le jeton à l'utilisateur.
    - **En ligne de commande**, depuis le poste du développeur ou la CI :

        ```bash
        security-review-mcp enroll --url https://secreview.example.internal:8443 \
            --project shop-api --requested-by "alice (équipe shop)"
        # {"id": "…", "label": "shop-api-enroll-3fa9c1", "status": "pending", "token": "UJB7…", …}
        ```

    - **Par l'API** : `POST /api/v1/enroll` (sans jeton) avec `{"project": "shop-api"}`.
2. **Configuration.** L'utilisateur place aussitôt le jeton dans la
   [configuration de l'hôte](hote.md#obtenir-un-jeton-enrolement). Tant qu'il est en attente, le client
   reste sur le serveur d'enrôlement (`get_enrollment_status` répond `pending`) et l'API web
   répond `403 enrollment_pending`.
3. **Validation.** Un administrateur approuve ou refuse la demande dans l'écran **Jetons** de
   l'[interface web](../utilisation/interface-web.md), ou en CLI :

    ```bash
    security-review-mcp token list --pending           # demandeur, adresse, date
    security-review-mcp token approve shop-api-enroll-3fa9c1
    security-review-mcp token reject shop-api-enroll-3fa9c1
    ```

    Une fois approuvé, le jeton fonctionne dès la requête suivante, sans reconfiguration.

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
  l'approuve ou la refuse dans l'interface web ou avec `security-review-mcp token approve ID` /
  `security-review-mcp token reject ID`. La commande `token list --pending` affiche le projet
  demandé et le jeton concerné.

Un jeton sans restriction atteint déjà tous les projets : il ne peut pas faire d'enrôlement
complémentaire. Créez un jeton restreint si vous devez limiter ses accès.

Garde-fous : au plus 20 demandes en attente à la fois, une demande non traitée expire au bout de
7 jours, un jeton avec un secret invalide reste refusé (`401`) et les demandes en attente
n'activent jamais l'authentification d'un serveur ouvert. Vérifiez le demandeur avant
d'approuver : n'importe quel client qui atteint le serveur peut déposer une demande. Pour
désactiver l'enrôlement : `SECREVIEW_ENROLLMENT=false` (les clients sans jeton reçoivent alors
`401`).

!!! tip
    Les commandes `token` s'exécutent sur le serveur (ou dans son conteneur), avec la même
    `SECREVIEW_DATABASE_URL` que lui. Les jetons ne passent jamais en argument de ligne de
    commande.

## TLS

Uvicorn sert directement en HTTPS quand un certificat est fourni :

```bash
security-review-mcp --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# ou SECREVIEW_TLS_CERTFILE / SECREVIEW_TLS_KEYFILE (+ SECREVIEW_TLS_KEYFILE_PASSWORD)
```

`SECREVIEW_TLS_CLIENT_CA` active en plus le **TLS mutuel** : seuls les clients présentant un
certificat signé par cette CA peuvent se connecter.

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
[Configuration de l'hôte](hote.md#obtenir-un-jeton-enrolement).

## Derrière un reverse proxy

Un reverse proxy (TLS, SSO, limitation de débit) reste une option valable : dans ce cas,
laissez ces variables vides.

!!! warning
    Si le serveur écoute ailleurs que sur localhost sans authentification ou sans TLS, un
    avertissement est journalisé. Tout jeton de rôle `mcp` ou `admin` donne accès à **tous** les
    outils.
