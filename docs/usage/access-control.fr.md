# Rôles et permissions

Ce qu'un [compte utilisateur](user-accounts.md) peut faire vient uniquement de ses **rôles** et de
ses **projets**. Un rôle porte des droits sur tout le serveur Controller (règles, jetons,
utilisateurs, audit...). Chaque projet d'un compte porte ses propres **droits par projet**
(lecture, écriture, triage), de même que **Tous les projets**. Un compte OIDC porte aussi les rôles et
projets des [correspondances OIDC](sso.md#correspondances-oidc) des groupes de son fournisseur
d'identité. Les administrateurs gèrent tout cela dans les pages **Utilisateurs**, **Rôles** et
**Connexions**, et sur la page de chaque projet ([membres](projects.md#membres)).

L'API REST, les limites et les règles détaillées sont dans
[Contrôle d'accès par l'API REST](../advanced/access-control-api.md). Les jetons des machines
gardent un rôle fixe ([jetons](tokens.md)).

## Permissions

| Permission | Autorise | Par projet |
|---|---|---|
| `reports.read` | Lire les projets, rapports et findings | ✅ |
| `reports.write` | Enregistrer des rapports et proposer le statut d'un finding avec un [jeton MCP ou CI personnel](tokens.md#jetons-mcp-et-ci-personnels) ou un client MCP connecté par OAuth (comprend `reports.read`) | ✅ |
| `findings.triage` | [Trier](triage.md) les findings | ✅ |
| `rules.read` | Lire les règles de scan et les checklists, et les exporter | |
| `rules.manage` | Modifier les règles de scan et les checklists (comprend `rules.read`) | |
| `standards.read` | Lire les normes de développement, et les exporter | |
| `standards.manage` | Modifier les normes de développement (comprend `standards.read`) | |
| `tokens.manage` | Gérer les jetons de projet | |
| `settings.manage` | Modifier les réglages généraux, le proxy sortant et la base OSV | |
| `users.manage` | Gérer les utilisateurs et leurs rôles, les rôles, les correspondances OIDC et la connexion OIDC | |
| `audit.read` | Lire le journal d'audit | |
| `projects.create` | [Créer un projet](projects.md#creation-dun-projet) et valider les projets demandés par les agents | |
| `projects.delete` | [Supprimer un projet](projects.md#suppression-dun-projet) | |
| `projects.autojoin` | [Rejoindre un projet existant](projects.md#rejoindre-un-projet) aussitôt, avec `reports.read` et `reports.write`, quand l'agent le demande, sauf si [son adhésion automatique est bloquée](projects.md#blocage-de-ladhesion-automatique) | |

Une permission marquée **par projet** se donne avec un projet (ou avec tous les projets), jamais
par un rôle ; les autres se donnent par les rôles et s'appliquent à tout le serveur Controller. Aucune permission n'est nécessaire pour les
[jetons personnels MCP et CI](tokens.md#jetons-mcp-et-ci-personnels) : tout compte peut les créer,
sauf si `SECREVIEW_PERSONAL_TOKENS_ENABLED=false`. Ils lisent les projets de `reports.read` et
n'enregistrent de rapport ni ne proposent de statut que sur ceux de `reports.write` : un compte
qui ne fait que lire un projet ne peut pas y écrire par son agent.

## Rôles

| Rôle | Permissions | Remarque |
|---|---|---|
| `admin` | Toutes les permissions sur tout le serveur Controller, y compris celles des versions suivantes | Intégré, non modifiable : le rôle du premier administrateur, qui lit, écrit et trie aussi tous les projets |

Les administrateurs créent d'autres rôles, par exemple un rôle *Auditeur* avec `audit.read`. Un
rôle ne porte jamais `reports.read`, `reports.write` ni `findings.triage`.

## Rôles et projets d'un compte

Dans **Utilisateurs**, le formulaire d'un compte donne :

- ses **Rôles** : des droits sur tout le serveur Controller ;
- ses droits par projet sur **Tous les projets** (aucun par défaut) ;
- ses **Projets**, chacun avec ses propres droits par projet, choisis dans une liste à choix
  multiple. Plusieurs projets s'ajoutent d'un coup : recherchez-les, cochez-les et ajoutez-les
  (avec leur lecture), puis choisissez les droits de chacun.

Par exemple, un compte avec le rôle *Auditeur*, **Lire les rapports** sur `shop` et **Lire les
rapports** et **Trier les findings** sur `crm` lit le journal d'audit, lit les deux projets et ne
trie que `crm`. Un compte sans aucun droit ne voit rien et ne peut pas se connecter.

Un projet qu'un compte crée, rejoint ou obtient par la validation d'une demande de son agent est
ajouté avec `reports.read` et `reports.write`, jamais plus, pour que son agent le relise. Un
compte qui lit un projet sans `reports.write` le demande par son agent comme un nouvel accès :
`projects.autojoin` ne l'ajoute jamais.

**Mon compte** et la page **Utilisateurs** affichent les droits de chaque compte. Un changement
des rôles ou des projets d'un compte, d'un rôle ou d'une correspondance OIDC s'applique aussitôt
aux sessions ouvertes.

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
- **Un rôle vaut pour tout le serveur Controller** : pour qu'une personne lise ou trie, donnez-lui
  des projets, pas un rôle.
- **Supprimer un rôle** le retire des comptes et des correspondances OIDC qui le donnent.
