# Rôles, groupes et permissions

Ce qu'un [compte utilisateur](../usage/web-interface.md#comptes-utilisateurs) peut faire dans
l'interface web et l'API REST vient de **rôles**, un rôle étant un ensemble de **permissions** :
les rôles de ses **groupes** et les rôles donnés **directement au compte**, chacun sur tous les
projets ou sur une liste de projets. Les administrateurs les gèrent dans les écrans **Groupes**,
**Rôles** et **Utilisateurs** (permission `users.manage`), ou par l'API `/api/v1/groups`,
`/api/v1/roles` et `/api/v1/users`.

Les jetons Bearer ne sont pas concernés : ils gardent leur rôle fixe (`mcp`, `reader`, `triager`,
`admin`, `ci`, `metrics`, voir [Rôles](../usage/web-interface.md#roles)).

## Permissions

| Permission | Autorise | Par projet |
|---|---|---|
| `reports.read` | Projets, rapports, findings, posture, tendance, SARIF | ✅ |
| `findings.triage` | Changer le statut d'un finding, rejeter la proposition d'un agent | ✅ |
| `rules.manage` | Règles de scan et checklists | |
| `standards.manage` | Normes de développement | |
| `tokens.manage` | Jetons de projet et demandes d'enrôlement | |
| `settings.manage` | Langue des rapports, proxy sortant, base d'avis | |
| `users.manage` | Utilisateurs, groupes, rôles et configuration SSO (elle décide qui rejoint quel groupe) | |
| `audit.read` | Journal d'audit | |

`users.manage` permet à son détenteur de se donner toutes les autres permissions : ne la donnez
qu'aux administrateurs. Accepter un risque ou marquer un faux positif demande en plus une session
de l'interface web, jamais un jeton (voir [triage des findings](../usage/web-interface.md#triage-des-findings)).

## Rôles

Un rôle est un nom, une description et au moins une permission. Trois rôles **système** existent
dès le départ et ne peuvent être ni modifiés ni supprimés :

| Rôle système | Permissions |
|---|---|
| `reader` | `reports.read` |
| `triager` | `reports.read`, `findings.triage` |
| `admin` | toutes les permissions |

Les administrateurs créent d'autres rôles (100 au plus), par exemple un rôle *Auditeur* avec
`audit.read` et `reports.read`. La modification d'un rôle s'applique aussitôt aux sessions
ouvertes des membres de ses groupes et des comptes qui l'ont directement ; supprimer un rôle le
retire de ses groupes et de ces comptes.

## Groupes

Un groupe a un nom (200 caractères au plus), une description, des rôles et des membres. Chaque
rôle d'un groupe s'applique **à tous les projets**, ou seulement **à une liste de projets**
(50 au plus) quand le rôle n'est fait que de permissions par projet (`reports.read`,
`findings.triage`). Un rôle qui contient une permission sur tout le contrôleur s'applique
toujours à tous les projets.

Les membres ont deux origines :

- **locale** : ajoutés par un administrateur (écran **Groupes** ou **Utilisateurs**, CLI,
  approbation d'un enrôlement) ;
- **SSO** : quand le groupe est **ouvert au SSO**, les utilisateurs SSO dont le claim des groupes
  contient **exactement le nom du groupe** le rejoignent à chaque connexion (voir
  [SSO](sso.md#groupes-du-fournisseur-didentite)). Les valeurs du claim qui ne nomment aucun groupe
  sont ignorées.

Renommer un groupe, ou le fermer au SSO, retire aussitôt ses membres SSO.

## Rôles et projets directs d'un compte

En plus de ses groupes, un compte peut recevoir des rôles propres, dans la partie **Rôles et
projets directs** de son formulaire de l'écran **Utilisateurs** : par exemple `triager` sur `shop`
et `billing` pour une personne, sans créer de groupe pour elle. Les règles sont celles des rôles
d'un groupe : un rôle fait de permissions par projet s'applique à tous les projets ou à une liste
de projets (50 au plus), un rôle qui contient une permission sur tout le contrôleur s'applique
toujours à tous les projets, et un compte a 20 rôles directs au plus.

Les rôles directs sont gardés quand le compte change de groupes, y compris les groupes SSO
recalculés à chaque connexion. L'approbation d'un enrôlement avec lecture dans le portail ajoute
le projet au rôle direct `reader` du compte (voir
[SSO](sso.md#lecture-du-projet-a-lenrolement)).

## Ce qu'un utilisateur peut faire

Les permissions d'un utilisateur sont l'union des permissions des rôles de **tous ses groupes**
et de ses **rôles directs**.
Chaque permission garde ses propres projets : elle couvre tous les projets si l'un de ses rôles
les couvre, sinon l'union de leurs projets (200 au plus par permission : au-delà, le compte n'a
aucun accès). Un utilisateur `reader` sur tous les projets par un groupe et `triager` sur `crm`
par un rôle direct lit tous les projets et ne trie que `crm`.

Un changement de groupe (rôles, membres), de rôle ou des rôles directs d'un compte s'applique
aussitôt aux sessions ouvertes. Un
compte sans aucune permission ne peut pas se connecter, et ses sessions ouvertes s'arrêtent.

`GET /api/v1/me` renvoie les permissions de l'appelant ; `role` les résume pour l'affichage :
`admin` avec toutes les permissions sur tous les projets, `triager` avec `findings.triage`,
`reader` sinon.

```json
{"client": "alice", "role": "triager", "projects": null,
 "permissions": {"reports.read": null, "findings.triage": ["crm"]}, …}
```

## Le dernier administrateur

Au moins un compte garde `users.manage` : supprimer ce compte, son groupe, le rôle de son groupe,
son rôle direct ou la permission de son rôle est refusé (`409` ou `422`). Une connexion SSO qui retire le dernier
détenteur de son groupe SSO n'est pas bloquée : le fournisseur d'identité reste l'autorité.
Gardez de préférence un administrateur local.

## Jetons créés depuis l'interface

Un jeton ne donne jamais plus que ce que détient son créateur : créer un jeton, changer ses
projets, renouveler son secret, le révoquer, ou approuver ou rejeter une demande d'enrôlement
demande `reports.read` sur tous les projets du jeton, avant et après un changement de ses projets
(et `findings.triage` pour un jeton `triager`) ; l'écran **Jetons** ne liste que les jetons et demandes des projets que l'utilisateur
lit. Donner à un utilisateur
la lecture d'un projet à l'approbation d'un enrôlement demande aussi `users.manage`.

## API

```bash
# Un rôle et un groupe qui le donne sur le projet « billing », ouvert au SSO
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
# Le compte 7 trie aussi « crm » par un rôle direct (ses groupes ne changent pas)
curl -X PUT https://secreview.example.com/api/v1/users/7 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"roles": [{"role_id": 3, "projects": ["crm"]}]}'
```

| Route | Effet |
|---|---|
| `GET /api/v1/permissions` | Permissions qu'un rôle peut contenir, et si elles peuvent être limitées à des projets |
| `GET`, `POST /api/v1/roles` ; `PUT`, `DELETE /api/v1/roles/{id}` | Rôles |
| `GET`, `POST /api/v1/groups` ; `PUT`, `DELETE /api/v1/groups/{id}` | Groupes (`GET` renvoie aussi la configuration SSO qui les utilise) |
| `PUT /api/v1/groups/{id}/roles` | Remplace les rôles d'un groupe |
| `PUT /api/v1/groups/{id}/members` | Remplace les membres locaux d'un groupe (les membres SSO sont gardés) |
| `POST /api/v1/users` | Crée un utilisateur, avec `group_ids` et `roles` (rôles directs) |
| `PUT /api/v1/users/{id}` | Remplace les groupes locaux (`group_ids`) et les rôles directs (`roles`, chacun `{"role_id": 3, "projects": ["crm"]}`, `projects` vide : tous les projets) d'un utilisateur ; un champ absent reste inchangé |

Chaque modification est écrite au [journal d'audit](audit-metrics.md#journal-daudit) (`role.*`,
`group.*`, `user.groups_changed`, `user.roles_changed`). En CLI, `security-review-controller user
set-groups` change les groupes d'un compte, `user set-roles` ses rôles directs
(`--role triager:crm,billing`, `--role reader` pour tous les projets), et
`security-review-controller group list` / `group roles` liste les groupes et les rôles (voir
[CLI](../reference/cli.md)).

## Mise à jour depuis les rôles fixes

La migration de schéma `0013` déplace les anciens accès dans des groupes :

- chaque association de rôle OIDC devient un groupe ouvert au SSO du nom de son groupe, avec le
  rôle de l'association sur les mêmes projets ;
- chaque compte qui avait un rôle propre rejoint `administrators`, `triagers` ou `readers`
  (groupes non ouverts au SSO) s'il voyait tous les projets, sinon un groupe personnel
  `user:<nom>`.

La migration de schéma `0014` transforme ensuite chaque groupe personnel `user:<nom>` dont le seul
membre est ce compte (ajouté par un administrateur) en rôles directs du compte, sur les mêmes
projets, et supprime le groupe. Un groupe personnel qui a d'autres membres, ou ouvert au SSO, est
gardé.

Le rôle donné à un compte SSO par ses groupes à sa dernière connexion est recalculé à sa
prochaine connexion. Les variables `SECREVIEW_OIDC_TRIAGER_GROUPS`, `SECREVIEW_OIDC_READER_GROUPS`
et `SECREVIEW_OIDC_DEFAULT_ROLE` disparaissent : créez les groupes de mêmes noms avec le rôle
`triager` ou `reader`, et utilisez `SECREVIEW_OIDC_DEFAULT_GROUP` à la place du rôle par défaut.
