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
| Bouton **Nouveau projet** de l'écran **Projets** | Une personne qui a `projects.create` | Créé aussitôt ([création d'un projet](#creation-dun-projet)) |
| L'agent d'un développeur le demande avant une revue | Un développeur avec un [jeton MCP personnel](tokens.md#jetons-mcp-et-ci-personnels) | Créé aussitôt si le développeur peut créer des projets ; sinon listé dans **Projets en attente**, à valider ([enrôlement](../advanced/architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)) |
| Premier rapport enregistré pour lui | Un jeton qui l'atteint (pipeline, jeton pour **Tous les projets**) | Le projet apparaît avec son premier rapport |

Un projet créé sans rapport affiche **Aucun rapport** jusqu'à sa première revue.

## Groupes de projet

Chaque projet a son **groupe de projet**, `project:<projet>`, qui donne la lecture de ce seul
projet (rôle `reader`). Son créateur, ou le développeur dont la demande a été validée, en est le
premier membre.

Pour qu'un collègue lise le projet (et que son agent le relise), ajoutez son compte à ce groupe
dans **Groupes** ou **Utilisateurs**, ou validez la **Demande d'accès** déposée par son agent dans
**Projets**. Pour qu'il trie, donnez-lui un groupe avec le rôle `triager` sur le projet
([groupes](access-control.md#groupes)).

## Création d'un projet

Avec la permission `projects.create`, **Nouveau projet** sur l'écran **Projets** crée le projet
et vous rend membre de son groupe de projet : vous le lisez aussitôt, et votre agent peut y
enregistrer ses revues. Seul un **nouveau** nom est accepté : cette permission n'ouvre jamais un
projet qui existe déjà. Vous n'obtenez que la lecture ; un administrateur donne le triage par les
groupes.

## Suppression d'un projet

Avec la permission `projects.delete` (seul `admin` par défaut), le bouton corbeille d'une ligne de
l'écran **Projets** supprime le projet après confirmation. La suppression est **irréversible** et
retire tout ce qui se rapporte au projet :

- ses rapports, findings et commentaires ;
- le projet dans les rôles des groupes ; son groupe de projet est supprimé ;
- le projet dans les jetons : un jeton qui n'atteignait que ce projet est **révoqué**, et un
  pipeline qui l'utilisait s'arrête.

Le journal d'audit conserve les événements du projet.

## Points d'attention

- **Une demande en attente expire** après 7 jours par défaut : l'agent doit la refaire.
- **Valider une demande d'accès** à un projet existant demande aussi `users.manage` : créer des
  projets ne donne jamais accès aux autres.
- **Supprimer un projet révoque ses jetons dédiés** : prévenez les équipes qui les utilisent.
- **Un nom est normalisé** : `My.App` et `my-app` sont le même projet.
