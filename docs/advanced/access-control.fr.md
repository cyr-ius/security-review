# Rôles, groupes et permissions

Ce qu'un [compte utilisateur](../usage/web-interface.md#comptes-utilisateurs) peut faire dans
l'interface web et l'API REST vient uniquement de **rôles**, un rôle étant un ensemble de
**permissions**, donnés à ses **groupes**, chacun sur tous les projets ou sur une liste de
projets. Un compte n'a jamais de rôle ni de projet propre : pour donner un accès à une personne,
ajoutez-la à un groupe. Les administrateurs les gèrent dans les écrans **Groupes**,
**Rôles** et **Utilisateurs** (permission `users.manage`), ou par l'API `/api/v1/groups`,
`/api/v1/roles` et `/api/v1/users`.

Les jetons Bearer sont destinés aux machines et gardent leur rôle fixe (`mcp`, `admin`, `ci`,
`metrics`, voir [Rôles](../usage/web-interface.md#roles)), sauf les jetons `api` de l'API REST et
de son Swagger, qui suivent ce modèle (voir [jetons API](../usage/web-interface.md#jetons-api)) :
un jeton personnel porte les droits actuels de son utilisateur, un jeton de rôle les permissions
d'un rôle sur ses projets. Une personne obtient la lecture ou le triage par les groupes de son
compte.

## Permissions

| Permission | Autorise | Par projet |
|---|---|---|
| `reports.read` | Projets, rapports, findings, posture, tendance, SARIF | ✅ |
| `findings.triage` | Changer le statut d'un finding, rejeter la proposition d'un agent | ✅ |
| `rules.manage` | Règles de scan et checklists | |
| `standards.manage` | Normes de développement | |
| `tokens.manage` | Jetons de projet et demandes d'enrôlement | |
| `settings.manage` | Langue des rapports, proxy sortant, base d'avis | |
| `users.manage` | Utilisateurs, groupes, rôles et configuration OIDC (elle décide qui rejoint quel groupe) | |
| `audit.read` | Journal d'audit | |

`users.manage` permet à son détenteur de se donner toutes les autres permissions : ne la donnez
qu'aux administrateurs. Accepter un risque ou marquer un faux positif demande en plus une session
de l'interface web, jamais un jeton (voir [triage des findings](../usage/web-interface.md#triage-des-findings)).

## Rôles

Un rôle est un nom, une description et au moins une permission. Deux rôles **intégrés** existent
dès le départ et ne peuvent être ni modifiés ni supprimés, car le contrôleur s'appuie sur eux :

| Rôle intégré | Permissions | Utilisé par |
|---|---|---|
| `reader` | `reports.read` | les [groupes de projet](#groupes-de-projet) créés à l'approbation d'un enrôlement |
| `admin` | toutes les permissions (y compris celles qu'ajoute une version ultérieure) | le groupe `administrators` du premier administrateur, `SECREVIEW_OIDC_ADMIN_GROUPS` |

Le rôle `triager` (`reports.read`, `findings.triage`) est lui aussi créé avec la base, mais c'est
un rôle ordinaire : les administrateurs le modifient ou le suppriment comme n'importe quel autre.

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

- **locale** : ajoutés par un administrateur (écran **Groupes** ou **Utilisateurs**, CLI,
  approbation d'un enrôlement) ;
- **OIDC** : quand le groupe est **ouvert au OIDC**, les utilisateurs OIDC dont le claim des groupes
  contient **exactement le nom du groupe** le rejoignent à chaque connexion (voir
  [OIDC](sso.md#groupes-du-fournisseur-didentite)). Les valeurs du claim qui ne nomment aucun groupe
  sont ignorées.

Renommer un groupe, ou le fermer au OIDC, retire aussitôt ses membres OIDC.

## Groupes de projet

L'approbation d'un enrôlement avec lecture dans le portail (voir
[OIDC](sso.md#lecture-du-projet-a-lenrolement)) ajoute le compte, comme membre local, au **groupe
de projet** du projet : un groupe non ouvert au OIDC dont le seul rôle est `reader` sur ce seul
projet. Un groupe existant de ce type est réutilisé (même créé par un administrateur, quel que
soit son nom) ; sinon le groupe `project:<projet>` est créé (avec un numéro, par exemple
`project:shop (2)`, quand un autre groupe porte déjà ce nom). Tous les développeurs enrôlés sur un
projet partagent ainsi un groupe, qu'un administrateur gère comme les autres.

## Ce qu'un utilisateur peut faire

Les permissions d'un utilisateur sont l'union des permissions des rôles de **tous ses groupes**.
Chaque permission garde ses propres projets : elle couvre tous les projets si l'un de ses rôles
les couvre, sinon l'union de leurs projets (200 au plus par permission : au-delà, le compte n'a
aucun accès). Un utilisateur `reader` sur tous les projets par un groupe et `triager` sur `crm`
par un autre lit tous les projets et ne trie que `crm`.

Un changement de groupe (rôles, membres) ou de rôle s'applique aussitôt aux sessions ouvertes. Un
compte sans aucune permission ne peut pas se connecter, et ses sessions ouvertes s'arrêtent.

`GET /api/v1/me` renvoie les permissions de l'appelant ; `role` les résume pour l'affichage :
`admin` avec toutes les permissions sur tous les projets, `triager` avec `findings.triage`,
`reader` sinon.

```json
{"client": "alice", "role": "triager", "projects": null,
 "permissions": {"reports.read": null, "findings.triage": ["crm"]}, …}
```

## Le dernier administrateur

Au moins un compte garde `users.manage` : supprimer ce compte, son groupe, le rôle de son groupe
ou la permission de son rôle est refusé (`409` ou `422`). Une connexion OIDC qui retire le dernier
détenteur de son groupe OIDC n'est pas bloquée : le fournisseur d'identité reste l'autorité.
Gardez de préférence un administrateur local.

## Jetons créés depuis l'interface

Un jeton ne donne jamais plus que ce que détient son créateur : créer un jeton, changer ses
projets, renouveler son secret, le révoquer, ou approuver ou rejeter une demande d'enrôlement
demande `reports.read` sur tous les projets du jeton, avant et après un changement de ses
projets, et, pour un jeton `api` de rôle, chaque permission de son rôle sur ces projets ; l'écran **Jetons** ne liste que les jetons et demandes des projets que l'utilisateur
lit. Donner à un utilisateur
la lecture d'un projet à l'approbation d'un enrôlement demande aussi `users.manage`.

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

Chaque modification est écrite au [journal d'audit](audit-metrics.md#journal-daudit) (`role.*`,
`group.*`, `user.groups_changed`). En CLI, `security-review-controller user set-groups` change les
groupes d'un compte, et `security-review-controller group list` / `group roles` liste les groupes et les rôles (voir
[CLI](../reference/cli.md)).

## Mise à jour depuis les rôles fixes

La migration de schéma `0013` déplace les anciens accès dans des groupes :

- chaque association de rôle OIDC devient un groupe ouvert au OIDC du nom de son groupe, avec le
  rôle de l'association sur les mêmes projets ;
- chaque compte qui avait un rôle propre rejoint `administrators`, `triagers` ou `readers`
  (groupes non ouverts au OIDC) s'il voyait tous les projets, sinon un groupe personnel
  `user:<nom>`.

La migration de schéma `0014` transforme ensuite chaque groupe personnel `user:<nom>` dont le seul
membre est ce compte (ajouté par un administrateur) en rôles directs du compte, sur les mêmes
projets, et supprime le groupe. Un groupe personnel qui a d'autres membres, ou ouvert au OIDC, est
gardé.

La migration de schéma `0018` supprime ces rôles directs : chacun devient l'appartenance locale à
un groupe non ouvert au OIDC qui a le même rôle sur les mêmes projets, de sorte que personne ne
perd ni ne gagne d'accès (dernier administrateur compris). Un rôle sur une liste de projets donne
un groupe par projet, `project:<projet>` pour `reader` (le [groupe de projet](#groupes-de-projet)),
sinon `project:<projet>:<rôle>` ; un rôle sur tous les projets donne le groupe `role:<rôle>`. Un
groupe existant non ouvert au OIDC dont le seul rôle est le même (comme `administrators` pour
`admin`) est réutilisé.

Le rôle donné à un compte OIDC par ses groupes à sa dernière connexion est recalculé à sa
prochaine connexion. Les variables `SECREVIEW_OIDC_TRIAGER_GROUPS`, `SECREVIEW_OIDC_READER_GROUPS`
et `SECREVIEW_OIDC_DEFAULT_ROLE` disparaissent : créez les groupes de mêmes noms avec le rôle
`triager` ou `reader`, et utilisez `SECREVIEW_OIDC_DEFAULT_GROUP` à la place du rôle par défaut.

## Mise à jour depuis les jetons reader et triager

La migration de schéma `0021` réserve les jetons aux machines :

- les jetons `reader` et `triager` sont révoqués ; chaque révocation est écrite dans le
  [journal d'audit](audit-metrics.md) (`token.revoked`, acteur `migration`). Donnez aux personnes
  qui les utilisaient un [compte utilisateur](../usage/web-interface.md#comptes-utilisateurs) dans
  un groupe qui a le rôle `reader` ou `triager` sur les mêmes projets ; un script
  d'administration utilise un jeton `admin` ;
- le rôle `triager` n'est plus intégré : il garde ses permissions et ses groupes, et peut
  désormais être modifié ou supprimé.
