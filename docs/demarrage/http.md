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

- Donnez `token` au client ; le `label`, unique, apparaît dans les journaux.
- `--role` vaut `mcp` par défaut : voir les [rôles](../utilisation/interface-web.md#roles) pour
  donner accès à l'interface web.
- `--project` limite le jeton à un seul projet, pour les outils MCP comme pour l'interface web
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

## Derrière un reverse proxy

Un reverse proxy (TLS, SSO, limitation de débit) reste une option valable : dans ce cas,
laissez ces variables vides.

!!! warning
    Si le serveur écoute ailleurs que sur localhost sans authentification ou sans TLS, un
    avertissement est journalisé. Tout jeton de rôle `mcp` ou `admin` donne accès à **tous** les
    outils.
