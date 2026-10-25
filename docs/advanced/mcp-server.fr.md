# Serveur MCP

Le **serveur MCP** (`security-review-mcp`) est le processus des agents IA : il leur fournit les
prompts de revue, les checklists, le scan par motifs et les normes de développement, et
enregistre leurs rapports. Il n'appelle jamais le [contrôleur](controller.md) : les deux
partagent la base (voir [Architecture](architecture.md)).

## Ce qu'il sert

| Route | Utilisée par | Identifiant |
|---|---|---|
| `/mcp` | les agents : [prompts, outils et ressources](../usage/prompts-tools.md) | jeton `mcp` (personnel ou non) ou jeton `admin` |
| `/mcp` sans jeton | un agent pas encore connecté : [serveur d'enrôlement](../usage/prompts-tools.md#serveur-denrolement) | aucun |
| `POST /api/v1/enroll` | `security-review-mcp enroll` et les scripts : [enrôlement](#enrolement-demander-le-projet) | aucun |
| `/healthz` | sondes (`HEALTHCHECK` Docker, Kubernetes) | aucun |

Il ne sert aucune page web ni aucune autre route de l'API REST.

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
   l'enrôlement, sauf si le serveur écoute sur localhost ou avec
   `SECREVIEW_ALLOW_UNAUTHENTICATED=true` (voir [Jetons Bearer](bearer-tokens.md)).

En stdio, `security-review-mcp local` migre lui-même sa base locale.

## Ce que reçoit un agent

| Client | Réponse |
|---|---|
| Sans jeton | le [serveur d'enrôlement](../usage/prompts-tools.md#serveur-denrolement) : `request_enrollment` et des prompts qui expliquent comment obtenir un jeton ; `401` avec `SECREVIEW_ENROLLMENT=false` |
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
sinon tous les clients partagent l'adresse du proxy pour les limites d'enrôlement.

Les sessions MCP (HTTP streamable) vivent dans la mémoire du processus qui les a ouvertes : avant
de lancer plusieurs réplicas, envoyez toutes les requêtes d'une session au même réplica
(affinité sur l'en-tête `Mcp-Session-Id`, voir [Kubernetes](kubernetes.md#plusieurs-replicas)).

Les variables du serveur MCP : [Configuration](../reference/configuration.md#serveur-mcp). Ses
commandes (`serve`, `local`, `enroll`) : [Ligne de commande](../reference/cli.md#security-review-mcp).

## Enrôlement : demander le projet

L'enrôlement **ne crée jamais de jeton** : il demande le projet, qu'un administrateur valide, et
le développeur crée un jeton MCP personnel dans l'interface web. Il est activé par défaut
(`SECREVIEW_ENROLLMENT=true`), même avant la création du premier jeton (sauf sur un
[serveur ouvert](bearer-tokens.md), qui n'a pas besoin de jeton).

1. **Demande.** Le client donne le nom de son projet (en général le nom du dépôt). Un nouveau
   projet est **en attente** : ce n'est pas encore un projet et il ne donne aucun accès. Un
   projet qui existe déjà, ou déjà en attente, reste inchangé, et la réponse est la même dans
   tous les cas, pour ne pas révéler quels projets existent. Trois façons de s'enrôler :
    - **Depuis l'agent, à la première revue.** Un client MCP qui se connecte **sans** en-tête
      `Authorization` n'est pas rejeté : il atteint un serveur MCP restreint (même nom
      `security-review`) qui n'expose que l'outil `request_enrollment`, et des prompts nommés
      comme les revues (`security-review`, `codebase-review`…) qui expliquent la marche à
      suivre. L'agent appelle `request_enrollment` avec le nom du projet.
    - **En ligne de commande**, depuis le poste du développeur ou la CI :

        ```bash
        security-review-mcp enroll --url https://secreview.example.internal:8443 \
            --project shop-api --requested-by "alice (équipe shop)"
        # {"project": "shop-api", "web_url": "https://secreview.example.internal/ui", "next_steps": "…"}
        ```

    - **Par l'API du serveur MCP** : `POST /api/v1/enroll` (sans jeton) avec
      `{"project": "shop-api"}`, qui répond `202`. Le contrôleur ne sert pas cet endpoint : il
      n'expose aucune route d'écriture non authentifiée.
2. **Validation.** Un utilisateur qui porte `projects.create` (entre autres le rôle `admin`)
   valide ou refuse la demande dans la section **Projets en attente** de l'écran **Projets**,
   ou en CLI :

    ```bash
    security-review-controller project list          # demandeur, adresse, expiration
    security-review-controller project approve 3     # id de la liste
    security-review-controller project reject 4
    ```

    La validation crée le projet, avec son groupe `project:<projet>` **sans aucun membre** :
    personne n'obtient d'accès, pas même le validateur. Une demande que personne n'a validée
    sous `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` (7 jours par défaut) est supprimée.
3. **Jeton personnel.** La réponse de l'enrôlement donne l'URL de l'interface web (`web_url`,
   issue de [`SECREVIEW_WEB_URL`](../reference/configuration.md#serveur-mcp)) et la marche à suivre :
   l'utilisateur se connecte, crée un **jeton MCP personnel** dans **Mon compte** (voir
   [jetons MCP personnels](../usage/tokens.md#jetons-mcp-et-ci-personnels)) et le place dans la
   [configuration de l'hôte](../getting-started/host.md#obtenir-un-jeton). Le jeton atteint les
   projets que l'utilisateur peut lire, relus à chaque requête.
4. **Accès.** Un administrateur donne à l'utilisateur l'accès au projet en l'ajoutant au groupe
   `project:<projet>` (écran **Groupes**, voir [contrôle d'accès](access-control.md#groupes-de-projet)) ; le
   jeton personnel atteint le projet dès la requête suivante, sans reconfiguration.

Un agent qui a déjà un jeton peut aussi appeler `request_enrollment` (par exemple quand
`save_security_report` refuse un projet que son jeton n'atteint pas) : le projet est demandé de
la même façon, et le jeton ne gagne aucun projet. Un utilisateur portant `projects.create` qui
[crée le projet](access-control.md#creation-dun-projet) lui-même solde sa demande en attente.

## Jeton refusé : se reconnecter

Un client dont le jeton est **inconnu, révoqué ou expiré** reçoit `401` sur `/mcp`
(`error="invalid_token"`) : la description invite l'utilisateur à se connecter à l'interface web
(avec son URL quand `SECREVIEW_WEB_URL` est défini) et à créer un nouveau jeton MCP personnel,
puis à le remplacer dans la [configuration de l'hôte](../getting-started/host.md#obtenir-un-jeton).
Un tel client n'atteint jamais les outils de revue ni le serveur d'enrôlement. Le refus est
journalisé en avertissement par le serveur MCP (`Rejected unauthenticated request` /
`Rejected expired token`).

Garde-fous : quiconque atteint le serveur peut s'enrôler, donc au plus 20 projets sont en
attente à la fois, une adresse cliente s'enrôle au plus 5 fois par heure (`429` au-delà ;
derrière un reverse proxy, définissez
[`SECREVIEW_FORWARDED_ALLOW_IPS`](../reference/configuration.md#ecoute-tls-et-reverse-proxy)), et un projet en attente
expire après `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS`. Chaque demande, validation, refus et
expiration est écrit dans le [journal d'audit](audit-metrics.md)
(`enrollment.requested`, `enrollment.approved`, `enrollment.rejected`, avec le demandeur et
l'adresse cliente). Pour désactiver l'enrôlement :
`SECREVIEW_ENROLLMENT=false` (les clients sans jeton reçoivent alors `401`, avec le même conseil).

`--url` est l'URL du **serveur MCP** (avec ou sans `/mcp`) : c'est lui qui reçoit les demandes.
