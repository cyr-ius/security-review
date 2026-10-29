# Rôles et permissions

Ce qu'un [compte utilisateur](user-accounts.md) peut faire vient uniquement de ses **rôles**. Un
rôle est un ensemble de **permissions** ; un administrateur le donne à un compte **sur tous les
projets** ou **sur un projet**. Un compte OIDC porte aussi les rôles des
[correspondances OIDC](sso.md#correspondances-oidc) des groupes de son fournisseur d'identité. Les
administrateurs gèrent tout cela dans les pages **Utilisateurs**, **Rôles** et **Connexions**, et sur la page de chaque projet ([membres](projects.md#membres)).

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

Une permission marquée **par projet** s'applique aux projets du rôle ; les autres s'appliquent à
tout le serveur Controller. Aucune permission n'est nécessaire pour les
[jetons personnels MCP et CI](tokens.md#jetons-mcp-et-ci-personnels) : tout compte peut les créer,
sauf si `SECREVIEW_PERSONAL_TOKENS_ENABLED=false`.

## Rôles

| Rôle | Permissions | Remarque |
|---|---|---|
| `reader` | `reports.read` | Intégré, non modifiable : donné sur un projet à son créateur et aux utilisateurs qui le rejoignent |
| `admin` | Toutes les permissions, y compris celles des versions suivantes | Intégré, non modifiable : le rôle du premier administrateur |

Les administrateurs créent d'autres rôles, par exemple un rôle *Triager* avec `reports.read` et
`findings.triage`, ou un rôle *Auditeur* avec `audit.read` et `reports.read`.

## Tous les projets ou un projet

Un rôle est donné à un compte de deux façons, dans **Utilisateurs** :

- **sur tous les projets** (**Rôles sur tous les projets**) : toutes ses permissions s'appliquent partout, y
  compris aux projets créés plus tard et aux projets sensibles ;
- **sur un projet** : seules ses permissions **par projet** s'appliquent, sur ce projet. Un rôle
  `admin` donné sur un projet y donne la lecture et le triage, rien de plus. L'interface signale
  les permissions d'un rôle qui ne s'appliquent pas sur un projet : pour en donner une
  (`audit.read` par exemple), donnez un rôle qui la porte sur tous les projets.

Plusieurs projets s'ajoutent d'un coup : recherchez-les, cochez-les, choisissez le rôle
(`reader` par défaut) et ajoutez-les. Un compte peut porter plusieurs rôles sur un même projet.

## Ce qu'un utilisateur peut faire

Les permissions d'un utilisateur s'additionnent sur **tous ses rôles**, chacun avec ses projets.
Par exemple, un utilisateur `reader` sur tous les projets et *Triager* sur `crm` lit tous les
projets et ne trie que `crm`. Un compte sans aucun rôle ne voit rien et ne peut pas se connecter.
**Mon compte** et la page **Utilisateurs** affichent ces permissions.

Un changement des rôles d'un utilisateur, d'un rôle ou d'une correspondance OIDC s'applique
aussitôt aux sessions ouvertes.

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
- **Un rôle sur tous les projets** atteint tous les projets, y compris les sensibles : préférez
  des rôles sur des projets pour les développeurs.
- **Supprimer un rôle** le retire des comptes et des correspondances OIDC qui le donnent.
