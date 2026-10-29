# Contrôle d'accès par l'API REST

Les pages [rôles et permissions](../usage/access-control.md) et
[projets](../usage/projects.md) décrivent le modèle dans l'interface web. Cette page donne les
limites, les règles détaillées et les appels de l'API REST (permission `users.manage` pour les
rôles, les rôles et projets des utilisateurs, les membres des projets et les correspondances
OIDC).

## Limites

| Élément | Limite |
|---|---|
| Rôles créés par les administrateurs | 100 au plus |
| Rôles d'un utilisateur | 100 au plus |
| Projets d'un utilisateur | 200 au plus ; au-delà (avec les correspondances OIDC), le compte n'a aucun accès |
| Membres définis d'un coup sur un projet | 500 au plus |
| Correspondances OIDC | 500 au plus, une par valeur du claim (200 caractères au plus), chacune de 100 rôles et 50 projets au plus |

Un rôle ne porte que des droits sur tout le serveur Controller : un rôle avec `reports.read` ou
`findings.triage` est refusé (`422`). Ces droits par projet se donnent avec chaque projet d'un
utilisateur (`projects[].permissions`, au moins un) et avec tous les projets
(`all_projects_permissions`). Seul un projet connu peut être donné (`404` sinon).

`users.manage` couvre aussi les réglages OIDC, puisqu'ils décident qui reçoit quel rôle. Le rôle
`admin`, avec la lecture et le triage de tous les projets, est aussi donné par une correspondance
créée à la première connexion d'un utilisateur qui porte une valeur de
`SECREVIEW_OIDC_ADMIN_GROUPS` ([OIDC](oidc.md)) ; une correspondance qui nomme déjà cette valeur
est laissée telle qu'un administrateur l'a modifiée. Les valeurs du claim des rôles qu'aucune
correspondance ne nomme sont ignorées.

## Rôles et utilisateurs

```bash
# Un rôle, puis une utilisatrice qui l'a, lit « billing » et lit et trie « crm »
curl -X POST https://secreview.example.com/api/v1/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Auditor", "description": "", "permissions": ["audit.read"]}'
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "alice", "role_ids": [2], "projects": [{"project": "billing"}, {"project": "crm", "permissions": ["reports.read", "findings.triage"]}]}'
# La lecture de tous les projets pour le compte 7 (ses rôles et ses projets sont gardés)
curl -X PUT https://secreview.example.com/api/v1/users/7 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"all_projects_permissions": ["reports.read"]}'
```

| Route | Effet |
|---|---|
| `GET /api/v1/permissions` | Permissions qu'un rôle peut porter, et si elles s'appliquent par projet |
| `GET`, `POST /api/v1/roles` ; `PUT`, `DELETE /api/v1/roles/{id}` | Rôles, avec le nombre d'utilisateurs et de correspondances OIDC qui donnent chacun |
| `POST /api/v1/users` | Crée un utilisateur avec ses rôles (`role_ids`), ses droits par projet sur tous les projets (`all_projects_permissions`) et ses projets (`projects`, chacun avec ses `permissions`, la lecture par défaut) |
| `PUT /api/v1/users/{id}` | Remplace les rôles, les droits par projet sur tous les projets ou les projets d'un utilisateur ; un champ absent reste inchangé, ceux de ses correspondances OIDC sont gardés |
| `GET /api/v1/access/projects?search=&limit=` | Projets connus dont le nom contient `search` (tous les projets, y compris ceux que l'appelant ne lit pas), 200 au plus |
| `GET`, `PUT /api/v1/access/projects/{project}/members` | Utilisateurs qui ont un projet, chacun avec ses `permissions` sur ce projet (ceux qui ont tous les projets et ceux des correspondances OIDC ne sont pas listés) |
| `GET`, `PUT /api/v1/oidc/mappings` | Correspondances OIDC, remplacées d'un bloc ([OIDC](oidc.md#correspondances-oidc)) |

Un champ inconnu (comme l'ancien `group_ids`) est refusé (`422`). Les rôles intégrés `reader` et
`admin` ne peuvent être ni modifiés ni supprimés ; supprimer un autre rôle le retire des
utilisateurs et des correspondances OIDC qui le donnent (un rôle utilisé par un jeton ne peut pas
être supprimé).

```bash
curl -X PUT https://secreview.example.com/api/v1/access/projects/billing/members \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"members": [{"user_id": 7}, {"user_id": 9, "permissions": ["reports.read", "findings.triage"]}]}'
```

Chaque changement est écrit dans le [journal d'audit](audit-log.md) (`role.*`,
`user.roles_changed`, `user.projects_changed`, `oidc.mappings_changed`). En CLI,
`security-review-controller user set-access` change les rôles et projets d'un compte, et
`security-review-controller role list` / `role mappings` liste les rôles et les correspondances
OIDC (voir [CLI](../reference/cli.md#security-review-controller)).

## Permissions de l'appelant

`GET /api/v1/me` renvoie les permissions de l'appelant, chacune avec ses projets (`null` : tous
les projets), et `role` vaut toujours `user` pour une session web (le rôle du jeton sinon). Un
utilisateur qui ne gère que les jetons et les normes ne lit aucun projet. Une session web ne passe
jamais pour un jeton `admin`, même avec toutes les permissions : les routes réservées aux jetons
(`/metrics`, les scans de pipeline) la refusent.

```json
{"client": "alice", "role": "user", "projects": null,
 "permissions": {"reports.read": null, "findings.triage": ["crm"]}, …}
```

Un compte sans aucune permission ne peut pas se connecter, et ses sessions ouvertes s'arrêtent.
Retirer le dernier détenteur de `users.manage` (supprimer son compte, ses rôles, la permission de
son rôle ou la correspondance OIDC qui la lui donne) est refusé avec `409` ou `422`. Une connexion
OIDC ne la retire jamais : les valeurs du claim qui la donnaient sont gardées, avec un
avertissement dans les journaux et un événement `user.roles_changed`.

## Projets

### Projets connus

Un projet est connu dès qu'il a une ligne en base : créé par son premier rapport, un jeton qui
l'atteint, une validation ou une création dans l'interface web. Une demande en attente ne rend pas
un projet connu.

### Lecture d'un projet demandé

La validation d'un projet demandé par un agent
([enrôlement](architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)) l'ajoute
aux projets de l'utilisateur demandeur avec sa seule lecture (en créant le projet s'il est nouveau ;
pour un projet existant, la demande est une demande d'accès, que seul un utilisateur doté de
`users.manage` valide), et créer un projet l'ajoute de la même façon à son créateur. Voir aussi
[lecture du projet](../usage/sso.md#lecture-du-projet).

### Création d'un projet

`POST /api/v1/projects` crée un projet, depuis une session de l'interface web uniquement. Le seul
jeton qui crée un projet est le jeton MCP personnel d'un utilisateur doté de `projects.create`,
par l'outil `request_project` de son agent. Le serveur Controller ajoute le projet au compte avec sa
lecture.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/projects -d '{"project": "mobile-app"}'
# {"project": "mobile-app", "reports_total": 0, "last_report_at": null, …}
```

Un projet connu est refusé (`409`). Un projet encore en attente n'est pas encore connu : le créer
règle la demande de son créateur (les demandes des autres utilisateurs deviennent des demandes
d'accès). Chaque création est écrite dans le journal d'audit (`project.created`).

### Adhésion automatique à un projet

Un utilisateur doté de `projects.autojoin` rejoint un projet existant par l'outil
`request_project` de son agent : le serveur Controller ajoute le projet au compte avec sa
lecture,
règle sa demande en attente pour ce projet et écrit `project.joined` dans le journal d'audit. Un
utilisateur qui lit déjà 200 projets est refusé. `PUT /api/v1/projects/{project}/autojoin` bloque
(`true`) ou autorise de nouveau (`false`) cette adhésion automatique, avec `projects.create`,
depuis une session de l'interface web uniquement, pour un projet que l'appelant lit (un autre
donne `404`). Un projet bloqué affiche `"autojoin_blocked": true` dans `GET /api/v1/projects` ;
les utilisateurs qui l'ont déjà rejoint gardent leur accès. Chaque changement est écrit dans le
journal d'audit (`project.autojoin_changed`).

```bash
curl -X PUT -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/projects/mobile-app/autojoin -d '{"blocked": true}'
# {"project": "mobile-app", "autojoin_blocked": true}
```

### Suppression d'un projet

`DELETE /api/v1/projects/{project}` supprime un projet, depuis une session de l'interface web
uniquement : un jeton ne supprime jamais un projet. La suppression se fait en une transaction :

- ses rapports, avec leurs findings et les commentaires de ces findings ;
- le projet dans les projets des utilisateurs ;
- le projet dans les correspondances OIDC : une correspondance qui n'a plus de projet est
  supprimée (jamais laissée atteindre tous les projets) ;
- le projet dans les jetons : un jeton qui n'atteint plus aucun autre projet est révoqué (jamais
  laissé atteindre tous les projets), les autres gardent leurs autres projets.

```bash
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/projects/mobile-app
# {"project": "mobile-app", "reports": 3, "findings": 12, "members_removed": 2, "mappings_changed": [], …}
```

Le journal d'audit garde les événements du projet et enregistre `project.deleted`, avec les
nombres dans ses détails ; les correspondances OIDC et les jetons changés ou supprimés ont leurs
propres événements (`oidc.mappings_changed`, `token.revoked`, `token.projects_changed`). Un projet
inconnu donne `404`.
