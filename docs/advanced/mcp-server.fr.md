# Serveur MCP

Le **serveur MCP** (`security-review-mcp`) est le processus des agents IA : il leur fournit les
prompts de revue, les checklists, le scan par motifs et les normes de développement, et
enregistre leurs rapports. Il n'appelle jamais le [contrôleur](controller.md) : les deux
partagent la base (voir [Architecture](architecture.md)).

## Ce qu'il sert

| Route | Utilisée par | Identifiant |
|---|---|---|
| `/mcp` | les agents : [prompts, outils et ressources](../usage/prompts-tools.md) | jeton `mcp` (personnel ou non) ou jeton `admin` |
| `/mcp` sans jeton | un agent pas encore connecté : [serveur d'enrôlement](../usage/prompts-tools.md#serveur-denrolement), qui explique comment obtenir un jeton | aucun |
| `/healthz` | sondes (`HEALTHCHECK` Docker, Kubernetes) | aucun |

Il ne sert aucune page web, aucune autre route de l'API REST, et aucune route qui écrit sans
jeton.

## Deux transports

| Transport | Commande | Usage |
|---|---|---|
| HTTP streamable | `security-review-mcp serve` (défaut de l'image, port `8000`) | [mode partagé](../getting-started/deploy.md) : tous les agents de l'équipe, avec un jeton |
| stdio | `security-review-mcp local` | [mode local](../getting-started/stdio.md) : lancé par l'hôte sur un poste, base SQLite locale, sans jeton |

## Démarrage

En HTTP, `security-review-mcp serve` :

1. **vérifie** le schéma de la base et refuse de démarrer (code `2`) tant que le contrôleur ne
   l'a pas migré : il ne migre jamais (voir [Migrations du schéma](controller.md#migrations-du-schema)) ;
2. vérifie les réglages TLS, charge les règles de la base ;
3. sert `/mcp`. Tant qu'aucun jeton n'existe, il reste **fermé** : un client n'atteint que
   le serveur d'enrôlement, sauf si le serveur écoute sur localhost ou avec
   `SECREVIEW_ALLOW_UNAUTHENTICATED=true` (voir [Jetons Bearer](bearer-tokens.md)).

En stdio, `security-review-mcp local` migre lui-même sa base locale.

## Ce que reçoit un agent

| Client | Réponse |
|---|---|
| Sans jeton | le [serveur d'enrôlement](../usage/prompts-tools.md#serveur-denrolement) : aucun outil, des prompts qui expliquent comment obtenir un jeton ; `401` avec `SECREVIEW_ENROLLMENT=false` |
| Jeton inconnu, révoqué ou expiré | `401` qui indique à l'utilisateur où créer un nouveau jeton ([jeton refusé](#jeton-refuse-se-reconnecter)) |
| Jeton `mcp` ou `admin` valide | tous les prompts, outils et ressources, sur les projets du jeton ([jetons restreints à un projet](bearer-tokens.md#jetons-restreints-a-un-projet)) |

Les jetons et les règles sont lus en base : un jeton créé ou révoqué sur le contrôleur
s'applique à la requête suivante, une règle modifiée en 5 secondes.

## Ce qu'il ne fait jamais

- Il ne fait **aucune connexion sortante** (la base OSV est importée par le contrôleur), et ne
  charge aucun module du contrôleur.
- Ses outils **ne lisent jamais le disque** à partir d'un chemin donné par le client : ils
  travaillent sur le contenu transmis.
- Toute entrée est bornée (`SECREVIEW_MAX_CONTENT_CHARS`, `SECREVIEW_MAX_FINDINGS_PER_REPORT`,
  `SECREVIEW_MAX_MCP_REQUEST_MB`, 64 Kio pour un client sans jeton), et les secrets sont masqués
  avant stockage.
- Il **ne change jamais le statut d'un finding** : `propose_finding_status` enregistre seulement
  une proposition, qu'une personne valide dans l'interface web.
- En stdio, stdout est réservé au protocole MCP : les journaux vont sur stderr.

Voir [Sécurité et limites](../reference/security.md).

## Exposition et réplicas

Exposez le serveur MCP avec TLS ([intégré ou reverse proxy](tls.md)) aux postes des
développeurs. Derrière un reverse proxy ou un Ingress, réglez `SECREVIEW_FORWARDED_ALLOW_IPS`,
sinon tous les clients partagent l'adresse du proxy dans le journal d'audit des demandes de
projet.

Les sessions MCP (HTTP streamable) vivent dans la mémoire du processus qui les a ouvertes : avant
de lancer plusieurs réplicas, envoyez toutes les requêtes d'une session au même réplica
(affinité sur l'en-tête `Mcp-Session-Id`, voir [Kubernetes](kubernetes.md#plusieurs-replicas)).

Les variables du serveur MCP : [Configuration](../reference/configuration.md#serveur-mcp). Ses
commandes (`serve`, `local`) : [Ligne de commande](../reference/cli.md#security-review-mcp).

## Enrôlement : jeton personnel et demande de projet

Le serveur MCP **ne crée jamais de jeton** et n'écrit rien pour un client sans jeton.
L'enrôlement est activé par défaut (`SECREVIEW_ENROLLMENT=true`), même avant la création du
premier jeton (sauf sur un [serveur ouvert](bearer-tokens.md), qui n'a pas besoin de jeton).

1. **Jeton personnel.** Un client MCP qui se connecte **sans** en-tête `Authorization` n'est
   pas rejeté : il atteint un serveur MCP restreint (même nom `security-review`) **sans aucun
   outil**, dont les prompts sont nommés comme les revues (`security-review`,
   `codebase-review`…). Ils invitent l'utilisateur à se connecter à l'interface web (son URL
   vient de [`SECREVIEW_WEB_URL`](../reference/configuration.md#serveur-mcp)), à créer un
   **jeton MCP personnel** dans **Mon compte** (voir
   [jetons MCP personnels](../usage/tokens.md#jetons-mcp-et-ci-personnels)) et à le placer dans
   la [configuration de l'hôte](../getting-started/host.md#obtenir-un-jeton). Le jeton atteint
   les projets que l'utilisateur peut lire, relus à chaque requête.
2. **Projet de la revue.** Chaque prompt de revue commence par l'outil `request_project`, avec
   le nom du projet (en général le nom du dépôt) :
    - le jeton atteint déjà le projet : `accessible`, la revue continue ;
    - le projet est nouveau et l'utilisateur porte `projects.create` : il est **créé**
      immédiatement, avec l'utilisateur pour membre (groupe `project:<projet>`), et la revue
      continue ;
    - sinon la réponse est `requested`, et l'agent s'arrête avant la revue, pour qu'aucune revue
      ne soit perdue. Un nouveau projet est **en attente** : ce n'est pas encore un projet et il
      ne donne aucun accès. Un projet qui existe déjà, ou déjà en attente, reste inchangé, et la
      réponse est la même, pour ne pas révéler quels projets existent.
3. **Validation.** Un utilisateur qui porte `projects.create` (entre autres le rôle `admin`)
   valide ou refuse la demande dans la section **Projets en attente** de l'écran **Projets**,
   ou en CLI :

    ```bash
    security-review-controller project list          # demandeur, adresse, expiration
    security-review-controller project approve 3     # id de la liste
    security-review-controller project reject 4
    ```

    La validation crée le projet, avec son groupe `project:<projet>`, et y ajoute le
    **demandeur** : son jeton personnel atteint le projet dès la requête suivante, sans
    reconfiguration. Une demande que personne n'a validée sous
    `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` (7 jours par défaut) est supprimée. Pour un projet
    qui existe déjà, un administrateur ajoute l'utilisateur à son groupe (écran **Groupes**,
    voir [contrôle d'accès](access-control.md#groupes-de-projet)).

`save_security_report` refuse un projet que le jeton n'atteint pas et renvoie vers
`request_project`. Quand un utilisateur portant `projects.create`
[crée le projet](access-control.md#creation-dun-projet) depuis l'écran **Projets**, sa demande
en attente est soldée.

Garde-fous : au plus 20 projets sont en attente à la fois, un utilisateur (ou un jeton sans
utilisateur) demande au plus 5 projets par heure, et un projet en attente expire après
`SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS`. Chaque demande, validation, refus et expiration est
écrit dans le [journal d'audit](audit-metrics.md) (`enrollment.requested`,
`enrollment.approved`, `enrollment.rejected`, avec le jeton, l'utilisateur demandeur et
l'adresse cliente). Pour désactiver l'enrôlement : `SECREVIEW_ENROLLMENT=false` (les clients
sans jeton reçoivent alors `401`, avec le même conseil, et `request_project` refuse les projets
que le jeton n'atteint pas).

## Jeton refusé : se reconnecter

Un client dont le jeton est **inconnu, révoqué ou expiré** reçoit `401` sur `/mcp`
(`error="invalid_token"`) : la description invite l'utilisateur à se connecter à l'interface web
(avec son URL quand `SECREVIEW_WEB_URL` est défini) et à créer un nouveau jeton MCP personnel,
puis à le remplacer dans la [configuration de l'hôte](../getting-started/host.md#obtenir-un-jeton).
Un tel client n'atteint jamais les outils de revue ni le serveur d'enrôlement. Le refus est
journalisé en avertissement par le serveur MCP (`Rejected unauthenticated request` /
`Rejected expired token`).
