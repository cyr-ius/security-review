# Jetons Bearer

Les jetons du [serveur MCP](architecture/mcp-server.md) et du [serveur Controller](architecture/controller.md) se gèrent avec la
CLI du serveur Controller. Ce que chaque jeton peut atteindre est dans [Jetons](../usage/tokens.md) ;
les routes servies par chaque processus sont dans [Ce qu'il sert](architecture/mcp-server.md#ce-quil-sert)
(serveur MCP) et [Ce qu'il sert](architecture/controller.md#ce-quil-sert) (serveur Controller).

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
révocation de jeton est écrit dans le [journal d'audit](audit-log.md), avec
son auteur.

## Avant le premier jeton

Tant qu'aucun jeton n'existe, l'API du serveur Controller répond `503` et le serveur MCP **reste
fermé** : un client sans jeton n'atteint que le [serveur d'enrôlement](architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet) (sans outil),
toute autre requête reçoit `401`, quelle que soit la valeur Bearer (un avertissement est
journalisé au démarrage). `/mcp` n'est ouvert dans ce cas que si le serveur écoute sur localhost
(`127.0.0.1`, `::1`) ou avec `SECREVIEW_ALLOW_UNAUTHENTICATED=true`, à réserver aux tests sur un
réseau isolé : dès qu'un jeton existe, il est exigé dans tous les cas. Avec la
[connexion OAuth](mcp-oauth.md) active, `/mcp` n'est jamais ouvert : un client sans jeton reçoit
le `401` qui lance la connexion. `token revoke` avertit sur
stderr quand il supprime le dernier jeton.

## Expiration et renouvellement des jetons

Un jeton peut expirer : après sa date d'expiration il n'authentifie plus rien (`401`,
`error="invalid_token"`, description `The bearer token has expired`, suivie sur `/mcp` de la
façon d'[en obtenir un nouveau](architecture/mcp-server.md#jeton-refuse-se-reconnecter)), mais il reste listé pour
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
être renouvelé : son utilisateur en crée un nouveau. Dans l'interface web, la page **Jetons**
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

Un jeton sans `--project` accède à tous les projets. Dans l'interface web, la page
[**Jetons**](../usage/index.md#pages) crée un jeton pour certains projets ou pour
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
    Les commandes `token` s'exécutent côté serveur Controller (ou dans son conteneur), avec la même
    `SECREVIEW_DATABASE_URL` que lui. Les jetons ne passent jamais en argument de ligne de
    commande.

## Appeler l'API REST avec un jeton

Un jeton `admin` appelle toute l'API REST, par exemple depuis un script d'administration, mais
**n'ouvre pas l'interface** (la page de connexion ne propose que les comptes) :

```bash
security-review-controller token create --label ops-script --role admin
# {"id": "…", "label": "ops-script", "role": "admin", "project": null, "created_at": "…", "token": "UJB7…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/projects
```

Ses changements de statut se limitent à `open` et `fixed`, comme ceux d'un jeton `api` avec
`findings.triage` : `accepted` et `false_positive` exigent une session
([triage par l'API REST](reports/triage-api.md)).

L'API REST liste les findings d'un projet sur l'ensemble de ses rapports, ouverts par défaut,
du plus grave au moins grave (filtres `status`, `severity` et `review_type`, chacun répétable :
l'une des valeurs suffit ; `limit` plafonné par `SECREVIEW_MAX_LIST_LIMIT`, `total` donne le nombre de findings correspondants pour paginer).
Sans `project`, elle liste les findings de tous les projets que lit l'appelant
(`"project": null`) :

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/findings?project=shop-api&status=open&severity=critical&severity=high&limit=50"
# {"project": "shop-api", "total": 12, "findings": [{"id": 42, "severity": "critical", "report_id": 7, "project": "shop-api", "branch": "main", "commit_sha": "abc123", "review_type": "codebase-review", "report_created_at": "…", …}, …]}
```

`GET /api/v1/reports` liste les rapports (filtres `project`, `risk_level`, `review_type` et
`author` ; les trois premiers sont répétables, 50 projets au plus), chacun avec son `author` et son `submitted_by`. L'`author` n'est renvoyé, filtré,
recherché et trié que pour un appelant qui détient `users.manage` ou `tokens.manage` : pour les
autres, il vaut `null` (dans le rapport et son export Markdown aussi) et le filtre `author` est
ignoré :

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/reports?project=shop-api&author=alice@example.com"
```

Chaque changement de statut est journalisé avec le label du jeton ou du compte :

```
INFO security_review_mcp.web: Finding 42 set to fixed by ops-script
```

et écrit dans le [journal d'audit](audit-log.md) (`GET /api/v1/audit`, permission
`audit.read`), avec l'acteur `token:ops-script` ou `user:<nom>`.

Un jeton `api` lit le contrôle d'accès à chaque requête : un jeton personnel porte les droits de
son utilisateur, un jeton de rôle les permissions de son **Rôle** sur ses projets (tous les
projets, ou une liste quand le rôle ne détient que des permissions par projet).

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "swagger", "expires_in_days": 30}'
# {"id": "…", "label": "alice:swagger", "role": "api", "personal": true, "access_role_id": null, …, "token": "Zq3…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/me
# {"client": "alice:swagger", "role": "api", "permissions": {"reports.read": ["shop-api"]}, …}
```

## Jetons créés depuis l'interface

Un jeton ne donne jamais plus que ce que détient son créateur : créer un jeton, changer ses
projets, renouveler son secret ou le révoquer demande `reports.read` sur tous les projets du
jeton, avant et après un changement de ses projets, et, pour un jeton `api` de rôle, chaque
permission de son rôle sur ces projets. La page **Jetons** ne liste que les jetons des projets
que l'utilisateur lit. Sa **Validité** va de 30 jours à 1 an, ou le défaut du serveur
(`SECREVIEW_TOKEN_MAX_DAYS`).

## Jetons personnels

Tout jeton personnel ([jetons personnels](../usage/tokens.md#jetons-personnels)) suit les mêmes
règles :

- un au plus par usage par défaut (`SECREVIEW_PERSONAL_TOKENS_PER_USER`) ;
- label `<utilisateur>:<label>`, avec un `:` qu'aucun autre label de jeton ne peut contenir, et
  validité bornée par `SECREVIEW_TOKEN_MAX_DAYS` ;
- personne ne peut le renouveler ni changer ses projets ; un administrateur peut le révoquer
  depuis la page **Jetons**.

Tout compte peut créer un jeton `mcp` ou `ci` personnel, sauf avec
`SECREVIEW_PERSONAL_TOKENS_ENABLED=false` (`422`) : les jetons déjà créés sont alors refusés
(`401`) par le serveur MCP et le serveur Controller, mais conservés, et fonctionnent de nouveau
une fois la variable à `true`. Il atteint les projets de `reports.read` des groupes du compte : tous les
projets quand l'un de ses groupes lit tous les projets, aucun quand il n'en a pas. Quand le
serveur le refuse (inconnu, révoqué ou expiré), l'agent reçoit un `401` qui invite
l'utilisateur à se reconnecter pour en créer un nouveau.

Chaque jeton personnel a un seul usage : un jeton `mcp` personnel n'atteint que `/mcp`, un jeton
`ci` personnel (proposé dans **Mon compte**, pour `security-review-ci` par `SECREVIEW_CI_TOKEN`)
que les routes de pipeline. Un rapport enregistré par un jeton `ci` personnel est soumis par le
jeton (`alice:laptop`),
et son utilisateur en est l'auteur (voir
[scan depuis un poste de travail](../review/analysis/dependencies.md#scan-depuis-un-poste-de-travail-hook-de-commit)).

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "mcp"}'
# {"id": "…", "label": "alice:laptop", "role": "mcp", "personal": true, …, "token": "Zq3…"}
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "ci"}'
# {"id": "…", "label": "alice:laptop", "role": "ci", "personal": true, …, "token": "Zq3…"}
```
