# Rôles et permissions

Ce qu'un [compte utilisateur](user-accounts.md) peut faire vient uniquement de ses **rôles** et
de ses **projets**. Un rôle est un ensemble de **permissions** : celles marquées *par projet*
s'appliquent aux projets du compte (ou à tous les projets), les autres à tout le serveur
Controller. Un compte OIDC porte aussi les rôles et projets des
[correspondances OIDC](sso.md#correspondances-oidc) des groupes de son fournisseur d'identité. Les
administrateurs gèrent tout cela dans les pages **Utilisateurs**, **Rôles** et **Connexions**, et
sur la page de chaque projet ([membres](projects.md#membres)).

L'API REST, les limites et les règles détaillées sont dans
[Contrôle d'accès par l'API REST](../advanced/access-control-api.md). Les jetons des machines
gardent un rôle fixe ([jetons](tokens.md)).

## Permissions

| Permission | Autorise | Par projet |
|---|---|---|
| `reports.read` | Lire les projets, rapports et findings | ✅ |
| `findings.triage` | [Trier](triage.md) les findings | ✅ |
| `rules.manage` | Modifier les règles de scan et les checklists | |
| `standards.manage` | Modifier les normes de développement | |
| `tokens.manage` | Gérer les jetons de projet | |
| `settings.manage` | Modifier les réglages généraux, le proxy sortant et la base OSV | |
| `users.manage` | Gérer les utilisateurs et leurs rôles, les rôles, les correspondances OIDC et la connexion OIDC | |
| `audit.read` | Lire le journal d'audit | |
| `projects.create` | [Créer un projet](projects.md#creation-dun-projet), valider les projets demandés par les agents et [bloquer l'adhésion automatique](projects.md#blocage-de-ladhesion-automatique) d'un projet qu'il lit | |
| `projects.delete` | [Supprimer un projet](projects.md#suppression-dun-projet) | |
| `projects.autojoin` | [Rejoindre un projet existant](projects.md#rejoindre-un-projet) aussitôt, en lecteur, quand l'agent le demande, sauf si [son adhésion automatique est bloquée](projects.md#blocage-de-ladhesion-automatique) | |

Une permission marquée **par projet** s'applique aux projets du compte ; les autres s'appliquent
à tout le serveur Controller. Aucune permission n'est nécessaire pour les
[jetons personnels MCP et CI](tokens.md#jetons-mcp-et-ci-personnels) : tout compte peut les créer,
sauf si `SECREVIEW_PERSONAL_TOKENS_ENABLED=false`.

## Rôles

| Rôle | Permissions | Remarque |
|---|---|---|
| `reader` | `reports.read` | Intégré, non modifiable : coché par défaut pour un nouveau compte |
| `admin` | Toutes les permissions, y compris celles des versions suivantes | Intégré, non modifiable : le rôle du premier administrateur, avec tous les projets |

Les administrateurs créent d'autres rôles, par exemple un rôle *Triager* avec `reports.read` et
`findings.triage`, ou un rôle *Auditeur* avec `audit.read` et `reports.read`.

## Rôles et projets d'un compte

Dans **Utilisateurs**, le formulaire d'un compte donne :

- ses **Rôles** : `reader` est coché par défaut ;
- ses **Projets** : **Tous les projets**, ou une liste de projets. Plusieurs projets s'ajoutent
  d'un coup : recherchez-les, cochez-les et ajoutez-les. Un projet en **Lecture seule** n'est que
  lu, quels que soient les rôles.

Les permissions par projet de tous ses rôles s'appliquent à tous ses projets. Par exemple, un
compte avec les rôles `reader` et *Triager* et les projets `shop` et `crm` lit et trie les deux.
Pour lire `shop` et ne trier que `crm`, mettez `shop` en lecture seule. Un compte avec des rôles
mais sans projet (et sans **Tous les projets**) ne lit aucun projet, et un compte sans aucun rôle
ne voit rien et ne peut pas se connecter.

Un projet qu'un compte crée, rejoint ou obtient par la validation d'une demande de son agent est
ajouté **en lecture seule** : le compte le lit, jamais plus.

Les permissions sur tout le serveur Controller (`audit.read`, `users.manage`...) s'appliquent
quels que soient les projets. **Mon compte** et la page **Utilisateurs** affichent les permissions
de chaque compte. Un changement des rôles ou des projets d'un compte, d'un rôle ou d'une
correspondance OIDC s'applique aussitôt aux sessions ouvertes.

## Le dernier administrateur

Au moins un compte garde `users.manage` : le supprimer, lui retirer cette permission ou supprimer
la correspondance OIDC qui la lui donne est refusé. Une connexion OIDC ne la lui retire pas non
plus : quand le fournisseur d'identité ne nomme plus le groupe qui en faisait le dernier
administrateur, le compte la garde (l'événement est journalisé et audité). Gardez de préférence un
administrateur local.

## Points d'attention

- **`users.manage` ouvre tout** : son titulaire peut se donner toutes les autres permissions.
  Réservez-la aux administrateurs.
- **Accepter un risque ou marquer un faux positif** exige une personne connectée, jamais un
  jeton, même avec `findings.triage`.
- **Tous les projets** atteint tous les projets, y compris les sensibles : préférez une liste de
  projets pour les développeurs.
- **Supprimer un rôle** le retire des comptes et des correspondances OIDC qui le donnent.
