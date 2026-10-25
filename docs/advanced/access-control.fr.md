# Rôles, groupes et permissions

Ce qu'un [compte utilisateur](../usage/user-accounts.md) peut faire dans
l'interface web et l'API REST vient uniquement de **rôles**, un rôle étant un ensemble de
**permissions**, donnés à ses **groupes**, chacun sur tous les projets ou sur une liste de
projets. Un compte n'a jamais de rôle ni de projet propre : pour donner un accès à une personne,
ajoutez-la à un groupe. Les administrateurs les gèrent dans les écrans **Groupes**,
**Rôles** et **Utilisateurs** (permission `users.manage`), ou par l'API `/api/v1/groups`,
`/api/v1/roles` et `/api/v1/users`.

Les jetons sont destinés aux machines : ils gardent un rôle fixe, sauf les jetons `api`, qui
suivent ce modèle (voir [Jetons](../usage/tokens.md)).

## Permissions

| Permission | Autorise | Par projet |
|---|---|---|
| `reports.read` | Projets, rapports, findings, posture, tendance, SARIF | ✅ |
| `findings.triage` | Changer le statut d'un finding, rejeter la proposition d'un agent | ✅ |
| `rules.manage` | Règles de scan et checklists | |
| `standards.manage` | Normes de développement | |
| `tokens.manage` | Jetons de projet | |
| `settings.manage` | Langue des rapports, proxy sortant, base d'avis | |
| `users.manage` | Utilisateurs, groupes, rôles et configuration OIDC (elle décide qui rejoint quel groupe) | |
| `audit.read` | Journal d'audit | |
| `projects.create` | Créer un nouveau projet, que son créateur lit ensuite (voir [Création d'un projet](#creation-dun-projet)), et valider ou refuser les projets demandés par un [enrôlement](mcp-server.md#enrolement-demander-le-projet) | |
| `projects.delete` | Supprimer un projet avec ses rapports, ses findings et ses références (voir [Suppression d'un projet](#suppression-dun-projet)) | |
| `mcp_tokens.create` | Créer un [jeton MCP ou CI personnel](../usage/tokens.md#jetons-mcp-et-ci-personnels) dans **Mon compte** | |

`users.manage` permet à son détenteur de se donner toutes les autres permissions : ne la donnez
qu'aux administrateurs. Accepter un risque ou marquer un faux positif demande en plus une session
de l'interface web, jamais un jeton (voir [triage des findings](../usage/triage.md)).

## Rôles

Un rôle est un nom, une description et au moins une permission. Deux rôles **intégrés** existent
dès le départ et ne peuvent être ni modifiés ni supprimés, car le contrôleur s'appuie sur eux :

| Rôle intégré | Permissions | Utilisé par |
|---|---|---|
| `reader` | `reports.read` | les [groupes de projet](#groupes-de-projet) des projets validés ou créés |
| `admin` | toutes les permissions (y compris celles qu'ajoute une version ultérieure) | le groupe `administrators` du premier administrateur, `SECREVIEW_OIDC_ADMIN_GROUPS` |

Deux rôles ordinaires sont aussi créés avec la base : les administrateurs les modifient ou les
suppriment comme n'importe quel autre.

| Rôle ordinaire | Permissions | Donne |
|---|---|---|
| `triager` | `reports.read`, `findings.triage` | le triage des findings |
| `mcp-user` | `mcp_tokens.create` | la création d'un [jeton MCP ou CI personnel](../usage/tokens.md#jetons-mcp-et-ci-personnels) ; donnez-le avec un rôle de lecture, car le jeton atteint les projets que son utilisateur peut lire |

Les administrateurs créent d'autres rôles (100 au plus), par exemple un rôle *Auditeur* avec
`audit.read` et `reports.read`. La modification d'un rôle s'applique aussitôt aux sessions
ouvertes des membres de ses groupes ; supprimer un rôle le retire de ses groupes.

## Groupes

Un groupe a un nom (200 caractères au plus), une description, des rôles et des membres. Chaque
rôle d'un groupe s'applique **à tous les projets**, ou seulement **à une liste de projets**
(50 au plus) quand le rôle n'est fait que de permissions par projet (`reports.read`,
`findings.triage`). Un rôle qui contient une permission sur tout le contrôleur s'applique
toujours à tous les projets.

Les membres ont deux origines :

- **locale** : ajoutés par un administrateur (écran **Groupes** ou **Utilisateurs**, CLI) ;
- **OIDC** : quand le groupe est **ouvert au OIDC**, les utilisateurs OIDC dont le claim des groupes
  contient **exactement le nom du groupe** le rejoignent à chaque connexion (voir
  [OIDC](sso.md#groupes-du-fournisseur-didentite)). Les valeurs du claim qui ne nomment aucun groupe
  sont ignorées.

Un nouveau groupe n'est ouvert au OIDC que sur demande (`"sso": true` par l'API).
Renommer un groupe, ou le fermer au OIDC, retire aussitôt ses membres OIDC.

## Groupes de projet

Le **groupe de projet** d'un projet est un groupe non ouvert au OIDC dont le seul rôle est
`reader` sur ce seul projet. La validation d'un [enrôlement](mcp-server.md#enrolement-demander-le-projet) le
crée **sans aucun membre** (pour que le projet existe, sans donner d'accès), et la
[création d'un projet](#creation-dun-projet) le crée avec son créateur. Un groupe existant de ce
type est réutilisé (même créé par un administrateur, quel que soit son nom) ; sinon le groupe
`project:<projet>` est créé (avec un numéro, par exemple `project:shop (2)`, quand un autre groupe
porte déjà ce nom). Un administrateur donne à un développeur la lecture du projet en ajoutant son
compte à ce groupe (voir [lecture du projet](sso.md#lecture-du-projet)) : tous les développeurs
d'un projet partagent ainsi un groupe, géré comme les autres.

## Création d'un projet

Un utilisateur dont les groupes portent `projects.create` crée un projet avec le bouton
**Nouveau projet** (à gauche d'**Actualiser**) de l'écran **Projets**, dans une fenêtre modale (`POST /api/v1/projects`, depuis une session de l'interface web
uniquement : un jeton ne crée jamais de projet). Le contrôleur crée le
[groupe de projet](#groupes-de-projet) du projet et y ajoute le compte comme membre local : le
compte lit aussitôt le projet, de même que son
[jeton MCP personnel](../usage/tokens.md#jetons-mcp-et-ci-personnels), qui peut alors y
enregistrer les rapports de son agent. Le projet apparaît sur l'écran **Projets**,
**Aucun rapport**, jusqu'à son premier rapport.

Le nom est [normalisé](../usage/prompts-tools.md#nom-du-projet) (`Mobile App` crée
`mobile-app`). Seul un **nouveau** projet peut être créé : un nom qui a déjà un rapport, qu'un rôle d'un groupe
cite (projet validé compris), ou qu'un jeton atteint est refusé (409) ; un projet encore en
attente n'est pas encore connu : le créer solde sa demande, pour que cette
permission n'ouvre jamais les rapports d'un projet existant. Le créateur n'obtient que `reader` ;
un administrateur donne le triage ou d'autres membres par les groupes, comme d'habitude. Chaque
création est inscrite au journal d'audit (`project.created`).

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/projects -d '{"project": "mobile-app"}'
# {"project": "mobile-app", "reports_total": 0, "last_report_at": null, …}
```

## Suppression d'un projet

Un utilisateur dont les groupes portent `projects.delete` (seul `admin` par défaut) supprime un
projet avec le bouton corbeille de sa ligne sur l'écran **Projets**, après confirmation
(`DELETE /api/v1/projects/{project}`, depuis une session de l'interface web uniquement : un
jeton ne supprime jamais de projet). La suppression est irréversible et retire, en une seule
transaction, tout ce qui se rapporte au projet :

- ses rapports, avec leurs findings et les commentaires de ces findings ;
- le projet dans les rôles des groupes : un rôle qui n'a plus de projet est retiré (jamais laissé
  sur tous les projets), et un [groupe de projet](#groupes-de-projet) qui n'a plus de rôle est
  supprimé avec ses membres ; tout autre groupe est conservé ;
- le projet dans les jetons : un jeton qui n'atteint aucun autre
  projet est révoqué (jamais laissé sur tous les projets), les autres gardent leurs autres projets.

Le journal d'audit conserve les événements du projet et inscrit `project.deleted`, avec les
comptes dans son détail ; chaque groupe et jeton modifié ou supprimé a son propre événement
(`group.deleted`, `group.roles_changed`, `token.revoked`, `token.projects_changed`). Un projet
inconnu donne 404.

```bash
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/projects/mobile-app
# {"project": "mobile-app", "reports": 3, "findings": 12, "groups_deleted": ["project:mobile-app"], …}
```

## Ce qu'un utilisateur peut faire

Les permissions d'un utilisateur sont l'union des permissions des rôles de **tous ses groupes**.
Chaque permission garde ses propres projets : elle couvre tous les projets si l'un de ses rôles
les couvre, sinon l'union de leurs projets (200 au plus par permission : au-delà, le compte n'a
aucun accès). Un utilisateur `reader` sur tous les projets par un groupe et `triager` sur `crm`
par un autre lit tous les projets et ne trie que `crm`.

Un changement de groupe (rôles, membres) ou de rôle s'applique aussitôt aux sessions ouvertes. Un
compte sans aucune permission ne peut pas se connecter, et ses sessions ouvertes s'arrêtent.

Un utilisateur n'a pas de rôle à lui : `GET /api/v1/me` renvoie ses permissions, chacune avec
ses projets (`null` : tous les projets), et `role` vaut toujours `user` pour une session web (le
rôle du jeton sinon). L'écran **Utilisateurs** et **Mon compte** affichent ces permissions telles
quelles : un utilisateur qui ne gère que les jetons et les normes ne lit aucun projet. Une session
web ne passe jamais pour un jeton `admin`, même avec toutes les permissions : les routes réservées
aux jetons (`/metrics`, les scans de pipeline) la refusent.

```json
{"client": "alice", "role": "user", "projects": null,
 "permissions": {"reports.read": null, "findings.triage": ["crm"]}, …}
```

## Le dernier administrateur

Au moins un compte garde `users.manage` : supprimer ce compte, son groupe, le rôle de son groupe
ou la permission de son rôle est refusé (`409` ou `422`). Une connexion OIDC qui retire le dernier
détenteur de son groupe OIDC n'est pas bloquée : le fournisseur d'identité reste l'autorité.
Gardez de préférence un administrateur local.

## API

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
propre.

Chaque modification est écrite au [journal d'audit](audit-metrics.md) (`role.*`,
`group.*`, `user.groups_changed`). En CLI, `security-review-controller user set-groups` change les
groupes d'un compte, et `security-review-controller group list` / `group roles` liste les groupes et les rôles (voir
[CLI](../reference/cli.md#security-review-controller)).
