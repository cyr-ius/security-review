# Rôles, groupes et permissions

Ce qu'un [compte utilisateur](user-accounts.md) peut faire vient uniquement de ses **groupes**.
Un groupe donne des **rôles**, chacun sur tous les projets ou sur certains
[projets](projects.md) ; un rôle est un ensemble de **permissions**. Un compte n'a jamais de rôle
propre : pour donner un accès à une personne, ajoutez-la à un groupe. Les administrateurs gèrent
tout cela dans les pages **Groupes**, **Rôles** et **Utilisateurs**.

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
| `settings.manage` | Changer les paramètres généraux, le proxy sortant et la base OSV | |
| `users.manage` | Gérer les utilisateurs, groupes, rôles et la connexion OIDC | |
| `audit.read` | Lire le journal d'audit | |
| `projects.create` | [Créer un projet](projects.md#creation-dun-projet) et valider les projets demandés par les agents | |
| `projects.delete` | [Supprimer un projet](projects.md#suppression-dun-projet) | |
| `mcp_tokens.create` | Créer un [jeton MCP personnel](tokens.md#jetons-mcp-et-ci-personnels) | |

Une permission marquée **par projet** peut être limitée à certains projets ; les autres
s'appliquent à tout le serveur Controller.

## Rôles

| Rôle | Permissions | Remarque |
|---|---|---|
| `reader` | `reports.read` | Intégré, non modifiable : utilisé par les [groupes de projet](projects.md#groupe-de-projet) |
| `admin` | Toutes les permissions, y compris celles des versions ultérieures | Intégré, non modifiable : le rôle du groupe `administrators` |
| `triager` | `reports.read`, `findings.triage` | Créé avec la base, modifiable |
| `mcp-user` | `mcp_tokens.create` | Créé avec la base, modifiable ; donnez-le avec un rôle de lecture, car le jeton atteint les projets que lit son utilisateur |

Les administrateurs créent d'autres rôles, par exemple un rôle *Auditeur* avec `audit.read` et
`reports.read`.

## Groupes

Un groupe a un nom, des rôles et des membres. Chaque rôle d'un groupe s'applique **à tous les
projets**, ou **à certains projets** quand il ne contient que des permissions par projet.

Les membres ont deux origines :

- **locale** : ajoutés par un administrateur, dans **Groupes** ou **Utilisateurs** ;
- **OIDC** : quand le groupe est **Ouvert au OIDC**, les utilisateurs OIDC dont le fournisseur
  d'identité nomme exactement ce groupe le rejoignent à chaque connexion (voir
  [groupes du fournisseur d'identité](sso.md#groupes-du-fournisseur-didentite)).

## Ce qu'un utilisateur peut faire

Les permissions d'un utilisateur s'additionnent sur **tous ses groupes**, chacune avec ses
propres projets. Par exemple, un utilisateur `reader` sur tous les projets par un groupe et
`triager` sur `crm` par un autre lit tous les projets et ne trie que `crm`. **Mon compte** et
la page **Utilisateurs** affichent ces permissions.

Un changement de groupe ou de rôle s'applique aussitôt aux sessions ouvertes. Un compte sans
aucune permission ne peut pas se connecter.

## Le dernier administrateur

Au moins un compte garde `users.manage` : le supprimer, ou lui retirer cette permission, est
refusé. Une connexion OIDC fait exception : le fournisseur d'identité peut retirer le dernier
administrateur de son groupe. Gardez de préférence un administrateur local.

## Points d'attention

- **`users.manage` ouvre tout** : son détenteur peut se donner toutes les autres permissions. Ne
  la donnez qu'aux administrateurs.
- **Accepter un risque ou marquer un faux positif** demande une personne connectée, jamais un
  jeton, même avec `findings.triage`.
- **Renommer un groupe, ou le fermer au OIDC**, retire aussitôt ses membres OIDC.
- **Supprimer un rôle** le retire de ses groupes : leurs membres perdent ses permissions.
