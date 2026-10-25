# Jetons Bearer

Les jetons du [serveur MCP](mcp-server.md) et du [contrôleur](controller.md) se gèrent avec la
CLI du contrôleur. Ce que chaque jeton peut atteindre est dans [Jetons](../usage/tokens.md) ;
les routes servies par chaque processus sont dans [Ce qu'il sert](mcp-server.md#ce-quil-sert)
(serveur MCP) et [Ce qu'il sert](controller.md#ce-quil-sert) (contrôleur).

Les jetons sont stockés dans la base de données (table `apitoken`) : seule leur empreinte
SHA-256 est conservée, le secret n'est affiché qu'une fois, à la création. Gérez-les avec la
commande `token` (voir la [CLI](../reference/cli.md#security-review-controller)) :

```bash
security-review-controller token create --label ci                      # rôle mcp par défaut
security-review-controller token create --label jenkins --role ci --project shop-api
security-review-controller token create --label ops-script --role admin
# {"id": "6f1c…", "label": "ci", "role": "mcp", "project": null, "created_at": "…", "token": "UJB7…"}
security-review-controller token list [--project shop-api]             # jamais le secret ni l'empreinte
security-review-controller token revoke ci                              # par label ou par id
```

- Donnez `token` au client ; le `label`, unique, apparaît dans les journaux.
- `--role` vaut `mcp` par défaut ; `admin`, `ci` et `metrics` sont les autres rôles de la CLI
  (voir [Rôles d'un jeton](../usage/tokens.md#roles-dun-jeton)). Les jetons `api` se créent dans
  l'interface web ([jetons API](../usage/tokens.md#jetons-api)).
- `--project` limite le jeton à un ou plusieurs projets (répétez l'option), pour les outils MCP
  et les routes de pipeline (rôles `mcp` et `ci`, toujours pour `ci` ; refusé pour `admin` et
  `metrics`) : voir [jetons restreints à un projet](#jetons-restreints-a-un-projet).
- `--expires-in-days` fixe la validité du jeton : voir
  [expiration et renouvellement](#expiration-et-renouvellement-des-jetons).
- Le serveur consulte la base à chaque requête : une création ou une révocation s'applique
  immédiatement, y compris aux autres instances qui partagent la même base PostgreSQL.

Les développeurs créent leurs propres jetons personnels dans l'interface web
([jetons personnels](../usage/tokens.md#jetons-personnels)). Chaque création, renouvellement et
révocation de jeton est écrit dans le [journal d'audit](audit-metrics.md), avec
son auteur.

## Avant le premier jeton

Tant qu'aucun jeton n'existe, l'API du contrôleur répond `503` et le serveur MCP **reste
fermé** : un client sans jeton n'atteint que le [serveur d'enrôlement](mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet) (sans outil),
toute autre requête reçoit `401`, quelle que soit la valeur Bearer (un avertissement est
journalisé au démarrage). `/mcp` n'est ouvert dans ce cas que si le serveur écoute sur localhost
(`127.0.0.1`, `::1`) ou avec `SECREVIEW_ALLOW_UNAUTHENTICATED=true`, à réserver aux tests sur un
réseau isolé : dès qu'un jeton existe, il est exigé dans tous les cas. `token revoke` avertit sur
stderr quand il supprime le dernier jeton.

## Expiration et renouvellement des jetons

Un jeton peut expirer : après sa date d'expiration il n'authentifie plus rien (`401`,
`error="invalid_token"`, description `The bearer token has expired`, suivie sur `/mcp` de la
façon d'[en obtenir un nouveau](mcp-server.md#jeton-refuse-se-reconnecter)), mais il reste listé pour
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

## Jetons restreints à un projet

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

!!! tip
    Les commandes `token` s'exécutent côté contrôleur (ou dans son conteneur), avec la même
    `SECREVIEW_DATABASE_URL` que lui. Les jetons ne passent jamais en argument de ligne de
    commande.
