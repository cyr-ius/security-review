# Contrôle d'accès par l'API REST

Les pages [rôles, groupes et permissions](../usage/access-control.md) et
[projets](../usage/projects.md) décrivent le modèle dans l'interface web. Cette page donne les
limites, les règles détaillées et les appels de l'API REST (permission `users.manage` pour les
rôles, groupes et utilisateurs).

## Limites

| Élément | Limite |
|---|---|
| Rôles créés par les administrateurs | 100 au plus |
| Nom d'un groupe | 200 caractères au plus |
| Projets d'un rôle dans un groupe | 50 au plus, seulement pour un rôle fait de permissions par projet (`reports.read`, `findings.triage`) ; un rôle qui contient une permission sur tout le contrôleur s'applique toujours à tous les projets |
| Projets d'une permission pour un utilisateur | 200 au plus, union de ses groupes : au-delà, le compte n'a aucun accès |

`users.manage` couvre aussi la configuration OIDC, puisqu'elle décide qui rejoint quel groupe. Le
rôle `admin` est aussi donné aux groupes nommés par `SECREVIEW_OIDC_ADMIN_GROUPS`
([OIDC](oidc.md)). Un nouveau groupe n'est ouvert au OIDC que sur demande
(`"sso": true`) ; les valeurs du claim des groupes qui ne nomment aucun groupe sont ignorées.

## Rôles, groupes et utilisateurs

```bash
# Un rôle et un groupe qui le donne sur le projet « billing », ouvert au OIDC
curl -X POST https://secreview.example.com/api/v1/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Auditor", "description": "Reads the log", "permissions": ["audit.read", "reports.read"]}'
curl -X POST https://secreview.example.com/api/v1/groups \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "payments-team", "description": "", "sso": true}'
curl -X PUT https://secreview.example.com/api/v1/groups/4/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"roles": [{"role_id": 2, "projects": ["billing"]}]}'
curl -X PUT https://secreview.example.com/api/v1/groups/4/members \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"user_ids": [7, 9]}'
# Les groupes locaux du compte 7 (ses groupes OIDC sont gardés)
curl -X PUT https://secreview.example.com/api/v1/users/7 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"group_ids": [4]}'
```

| Route | Effet |
|---|---|
| `GET /api/v1/permissions` | Permissions qu'un rôle peut contenir, et si elles peuvent être limitées à des projets |
| `GET`, `POST /api/v1/roles` ; `PUT`, `DELETE /api/v1/roles/{id}` | Rôles |
| `GET`, `POST /api/v1/groups` ; `PUT`, `DELETE /api/v1/groups/{id}` | Groupes (`GET` renvoie aussi la configuration OIDC qui les utilise) |
| `PUT /api/v1/groups/{id}/roles` | Remplace les rôles d'un groupe |
| `PUT /api/v1/groups/{id}/members` | Remplace les membres locaux d'un groupe (les membres OIDC sont gardés) |
| `POST /api/v1/users` | Crée un utilisateur, membre des groupes `group_ids` |
| `PUT /api/v1/users/{id}` | Remplace les groupes locaux (`group_ids`) d'un utilisateur ; un champ absent reste inchangé |

Un champ `roles` dans le corps de ces deux routes est refusé (`422`) : un compte n'a pas de rôle
propre. Les rôles intégrés `reader` et `admin` ne peuvent être ni modifiés ni supprimés ;
supprimer un autre rôle le retire de ses groupes.

Chaque modification est écrite au [journal d'audit](audit-log.md) (`role.*`,
`group.*`, `user.groups_changed`). En CLI, `security-review-controller user set-groups` change les
groupes d'un compte, et `security-review-controller group list` / `group roles` liste les groupes
et les rôles (voir [CLI](../reference/cli.md#security-review-controller)).

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
Retirer le dernier détenteur de `users.manage` (supprimer son compte, son groupe, le rôle de son
groupe ou la permission de son rôle) est refusé avec `409` ou `422` ; une connexion OIDC qui le
retire de son groupe OIDC n'est pas bloquée.

## Projets

### Groupes de projet

Le **groupe de projet** d'un projet est un groupe non ouvert au OIDC dont le seul rôle est
`reader` sur ce seul projet. La validation d'un projet demandé par un agent
([enrôlement](mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)) y ajoute
l'utilisateur demandeur (en le créant pour un nouveau projet ; pour un projet existant, la
demande est une demande d'accès, que seul un utilisateur portant `users.manage` valide), et la
création d'un projet le crée avec son créateur. Un groupe existant de ce type est réutilisé (même
créé par un administrateur, quel que soit son nom) ; sinon le groupe `project:<projet>` est créé
(avec un numéro, par exemple `project:shop (2)`, quand un autre groupe porte déjà ce nom). Voir
aussi [lecture du projet](../usage/sso.md#lecture-du-projet).

### Création d'un projet

`POST /api/v1/projects` crée un projet, depuis une session de l'interface web uniquement. Le seul
jeton qui crée un projet est le jeton MCP personnel d'un utilisateur portant `projects.create`,
par l'outil `request_project` de son agent. Le contrôleur ajoute le compte au groupe de projet
comme membre local.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/projects -d '{"project": "mobile-app"}'
# {"project": "mobile-app", "reports_total": 0, "last_report_at": null, …}
```

Un nom qui a déjà un rapport, qu'un rôle d'un groupe cite (projet validé compris), ou qu'un jeton
atteint est refusé (`409`). Un projet encore en attente n'est pas encore connu : le créer solde la
demande de son créateur (celles des autres utilisateurs deviennent des demandes d'accès). Chaque
création est inscrite au journal d'audit (`project.created`).

### Suppression d'un projet

`DELETE /api/v1/projects/{project}` supprime un projet, depuis une session de l'interface web
uniquement : un jeton ne supprime jamais de projet. La suppression se fait en une seule
transaction :

- ses rapports, avec leurs findings et les commentaires de ces findings ;
- le projet dans les rôles des groupes : un rôle qui n'a plus de projet est retiré (jamais laissé
  sur tous les projets), et un groupe de projet qui n'a plus de rôle est supprimé avec ses
  membres ; tout autre groupe est conservé ;
- le projet dans les jetons : un jeton qui n'atteint aucun autre projet est révoqué (jamais laissé
  sur tous les projets), les autres gardent leurs autres projets.

```bash
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/projects/mobile-app
# {"project": "mobile-app", "reports": 3, "findings": 12, "groups_deleted": ["project:mobile-app"], …}
```

Le journal d'audit conserve les événements du projet et inscrit `project.deleted`, avec les
comptes dans son détail ; chaque groupe et jeton modifié ou supprimé a son propre événement
(`group.deleted`, `group.roles_changed`, `token.revoked`, `token.projects_changed`). Un projet
inconnu donne `404`.
