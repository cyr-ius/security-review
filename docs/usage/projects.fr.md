# Projets

Un **projet** regroupe tout ce qui concerne une application, en général un dépôt : ses rapports,
ses findings, sa tendance et sa gate, et qui peut le lire ou le trier. Chaque revue est
enregistrée dans un projet.

L'API REST et les règles détaillées sont dans
[Contrôle d'accès par l'API REST](../advanced/access-control-api.md#projets).

## Nom d'un projet

Le nom est **normalisé** : minuscules, dernier segment d'une URL de dépôt, et un seul `-` entre
les mots. `Mobile App`, `mobile_app` et `git@github.com:acme/mobile-app.git` donnent tous le
projet `mobile-app`, pour que les membres d'une équipe atteignent le même projet quelle que soit
leur saisie (voir [nom du projet](../review/prompts-tools.md#nom-du-projet)).

## Comment un projet apparaît

| Moyen | Qui | Résultat |
|---|---|---|
| Bouton **Nouveau projet** de la page **Projets** | Une personne qui a `projects.create` | Créé aussitôt ([création d'un projet](#creation-dun-projet)) |
| L'agent d'un développeur le demande avant une revue | Un développeur avec un [jeton MCP personnel](tokens.md#jetons-mcp-et-ci-personnels) | Créé aussitôt, avec son groupe de projet, si le développeur peut créer des projets (même si son jeton atteint déjà tous les projets) ; sinon listé dans **Projets en attente**, à valider ([enrôlement](../advanced/architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)) |
| Premier rapport enregistré pour lui | Un jeton qui l'atteint (pipeline, jeton pour **Tous les projets**) | Le projet apparaît avec son premier rapport |

Un projet créé sans rapport affiche **Aucun rapport** jusqu'à sa première revue.

## Groupe de projet

Chaque projet a son **groupe de projet**, `project:<projet>`, qui donne la lecture de ce seul
projet (rôle `reader`). Son créateur, ou le développeur dont la demande a été validée, en est le
premier membre.

Pour qu'un collègue lise le projet (et que son agent le relise), ajoutez son compte à ce groupe
dans **Groupes** ou **Utilisateurs**, ou validez la **Demande d'accès** déposée par son agent dans
**Projets**. Pour qu'il trie, donnez-lui un groupe avec le rôle `triager` sur le projet
([groupes](access-control.md#groupes)).

## Création d'un projet

Si vous avez la permission `projects.create`, le bouton **Nouveau projet** apparaît sur la page
**Projets**. Créer un projet vous rend membre de son groupe de projet : vous le lisez aussitôt, et
votre agent peut y enregistrer ses revues.

## Suppression d'un projet

Avec la permission `projects.delete`, un bouton corbeille apparaît sur chaque ligne de la page
**Projets**. La suppression est **irréversible** et retire tout ce qui se rapporte au projet :

- ses rapports, findings et commentaires ;
- le projet dans les rôles des groupes ; son groupe de projet est supprimé ;
- le projet dans les jetons : un jeton qui n'atteignait que ce projet est **révoqué**, et un
  pipeline qui l'utilisait s'arrête.

Le journal d'audit conserve les événements du projet. Une confirmation est demandée au moment
de l'action.

## Rejoindre un projet

L'agent d'un développeur peut demander à rejoindre un projet existant. Sa demande apparaît,
en attente de validation, dans **Projets en attente** sur la page **Projets**.

Une personne dotée des permissions `projects.create` et `users.manage` peut valider cette
demande ; une personne dotée de `users.manage` peut aussi ajouter l'utilisateur au groupe de
projet.

Avec la permission `projects.autojoin`, le développeur **rejoint aussitôt le projet**, sans
demande : la requête de son agent l'ajoute au groupe de projet, pour qu'il lise le projet (jamais
plus : pas de tri) et que la revue continue. Cette permission ne crée pas de nouveau projet : il
faut pour cela `projects.create`.

## Blocage de l'adhésion automatique

Avec la permission `projects.create`, un bouton cadenas apparaît sur chaque ligne de la page
**Projets**, pour les projets que vous lisez. Il **bloque l'adhésion automatique** au projet : les
titulaires de `projects.autojoin` déposent alors une demande qui attend une validation, comme les
autres. Le projet affiche le badge **Adhésion automatique bloquée** ; le bouton cadenas ouvert
autorise de nouveau l'adhésion automatique. Les utilisateurs qui ont déjà rejoint le projet
gardent leur accès : retirez-les de son groupe de projet si nécessaire.

## Points d'attention

- **Une demande en attente expire** après 7 jours par défaut : l'agent doit la refaire.
- **Valider une demande d'accès** à un projet existant demande aussi `users.manage` : créer des
  projets ne donne jamais accès aux autres.
- **Supprimer un projet révoque ses jetons dédiés** : prévenez les équipes qui les utilisent.
- **`projects.autojoin` ouvre tous les projets** dont l'adhésion automatique n'est pas bloquée,
  et indique à son titulaire quels projets existent : bloquez l'adhésion automatique des projets
  sensibles.
- **Un nom est normalisé** : `My.App` et `my-app` sont le même projet.
