# Contrôleur

Le **contrôleur** (`security-review-controller`) est le processus des personnes et des
pipelines : il sert l'interface web, l'API REST et les routes de pipeline, gère le schéma de la
base et exécute les tâches de fond. Il n'appelle jamais le serveur MCP : les deux partagent la
base (voir [Architecture](architecture.md)).

## Ce qu'il sert

| Route | Utilisée par | Identifiant |
|---|---|---|
| `/ui/` | les personnes (navigateur) : [interface web](../usage/web-interface.md) | aucun pour les fichiers statiques ; les données viennent de l'API |
| `/api/v1/auth/` | la page de connexion : mot de passe et connexion [OIDC](sso.md) | aucun |
| `/api/v1/` | l'interface web, les scripts, Swagger | session web, jeton `admin` ou `api` |
| `/api/v1/ci/` | [`security-review-ci`](ci.md) : gate, SARIF, tendance, scans du code et des dépendances | jeton `ci` ou jeton `mcp` personnel |
| `/metrics` | Prometheus ([métriques](../reference/metrics.md)) | jeton `metrics` ou `admin` |
| `/api/docs` | Swagger, seulement avec `SECREVIEW_SWAGGER_ENABLED=true` | aucun (les appels demandent un [jeton API](../usage/tokens.md#jetons-api)) |
| `/api/ci-client/` | uv : [téléchargement de `security-review-ci`](ci.md#depuis-le-controleur), seulement avec `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED=true` | aucun |
| `/api/health`, `/api/favicon.svg` | disponibilité de l'API, icône | aucun |
| `/healthz` | sondes (`HEALTHCHECK` Docker, Kubernetes) | aucun |

Les rôles des jetons sont décrits dans [Rôles](../usage/tokens.md), leur gestion
dans [Jetons Bearer](bearer-tokens.md).

## Démarrage

`security-review-controller serve` (port `8000` dans l'image, `--host` et `--port` sinon) :

1. migre le schéma, ou le vérifie seulement avec `SECREVIEW_DB_AUTO_UPGRADE=false` (voir
   [Migrations du schéma](#migrations-du-schema)) ;
2. vérifie les réglages (TLS, OIDC, OSV, syslog, connecteurs) : une valeur invalide l'arrête
   avec le code `2` ;
3. crée le [premier administrateur](#premier-administrateur) tant qu'aucun compte n'existe ;
4. démarre les tâches de fond, puis sert les routes.

## Migrations du schéma

Le schéma est géré par des migrations [Alembic](https://alembic.sqlalchemy.org/), embarquées
dans le paquet (aucun fichier `alembic.ini` à fournir) :

```bash
security-review-controller db upgrade   # crée ou migre le schéma, puis amorce les règles par défaut
security-review-controller db status    # {"current": "0032", "head": "0032", "up_to_date": true}
```

- `db status` renvoie le code `1` si le schéma n'est pas à jour : pratique pour un script ou
  une sonde.
- Le **serveur MCP HTTP ne migre jamais** : il refuse de démarrer (code `2`, message
  `run security-review-controller db upgrade first`) tant que la base n'est pas à la révision
  attendue. Sous Kubernetes, le pod redémarre jusqu'à ce que la migration soit faite.
- Le contrôleur, le serveur MCP stdio et les commandes CLI migrent au démarrage, sauf avec
  `SECREVIEW_DB_AUTO_UPGRADE=false`. Ils vérifient alors seulement le schéma. Avec Docker
  Compose, le contrôleur migre à son démarrage ; sous Kubernetes, c'est son init container.
- Sur PostgreSQL, une migration prend un verrou consultatif (advisory lock) : des instances qui
  démarrent ensemble (plusieurs réplicas, un `db upgrade` lancé à la main) s'attendent, et la
  suivante trouve le schéma à jour. Ne désactivez la migration automatique que pour la confier à
  une tâche dédiée.

## Tâches de fond

| Tâche | Activée par | Détails |
|---|---|---|
| Mise à jour quotidienne des avis OSV | `SECREVIEW_OSV_AUTO_UPDATE=true` (désactivée par défaut) | [Mise à jour automatique par le contrôleur](dependencies.md#mise-a-jour-automatique-par-le-controleur) |
| Purge des rapports sans finding et du journal d'audit | `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` (90), `SECREVIEW_AUDIT_RETENTION_DAYS` (365), `SECREVIEW_AUDIT_MAX_EVENTS` | [Conservation](../reference/configuration.md#conservation-des-rapports-sans-findings), [conservation de l'audit](audit-metrics.md#conservation) |
| Envoi du journal d'audit vers syslog | un serveur syslog défini dans l'environnement ou dans l'interface | [Envoi vers syslog](audit-metrics.md#envoi-vers-syslog) |
| Envoi automatique des findings par les connecteurs | un connecteur activé, un seuil de sévérité sur le projet ; `SECREVIEW_CONNECTORS_ENABLED=false` verrouille tout | [Connecteurs](../connectors/index.md) |

Le serveur MCP n'en exécute aucune.

## Connexions sortantes

Le contrôleur est le seul processus qui peut se connecter à l'extérieur, et chaque connexion est
**désactivée par défaut** : le téléchargement OSV, le fournisseur [OIDC](sso.md), la recherche
d'une nouvelle version sur la page **À propos** (`SECREVIEW_UPDATE_CHECK_ENABLED`), le serveur
syslog et les connecteurs. Elles passent en HTTPS (syslog : UDP, TCP ou TLS), par le proxy
sortant (`HTTPS_PROXY`, `NO_PROXY`, ou l'écran **Paramètres**). Voir
[Sécurité et limites](../reference/security.md).

## Exposition

Exposez le contrôleur avec TLS ([intégré ou reverse proxy](tls.md)) aux personnes
(interface web, jetons personnels) et aux runners des pipelines. Derrière un reverse proxy ou un
Ingress :

- réglez `SECREVIEW_FORWARDED_ALLOW_IPS` sur l'adresse du proxy, sinon tous les clients
  partagent son adresse pour la limitation des connexions et la limite de débit ;
- réglez `SECREVIEW_WEB_URL` (lu par le serveur MCP) sur l'URL publique de l'interface, pour
  qu'un agent sans jeton valide sache où en créer un.

## Plusieurs réplicas

Le contrôleur peut tourner en plusieurs réplicas sur la même base PostgreSQL : les migrations
s'attendent (verrou consultatif), les sessions sont partagées grâce à `SECREVIEW_SECRET_KEY`, les
compteurs de connexion et de limite de débit sont tenus en base, un seul réplica à la fois
télécharge les avis OSV, et un lot syslog n'est envoyé qu'une fois. Donnez le même
`SECREVIEW_SECRET_KEY` à tous les réplicas.

## Commandes d'administration

Les autres commandes de `security-review-controller` s'exécutent là où tourne le contrôleur
(même `SECREVIEW_DATABASE_URL`), par exemple `docker compose exec controller …` ou
`kubectl exec deploy/secreview-controller -c controller -- …` :

| Commande | Rôle |
|---|---|
| `db` | migrer le schéma, afficher sa révision, purger des rapports |
| `token` | créer, lister, renouveler et révoquer les jetons ([Jetons Bearer](bearer-tokens.md)) |
| `user`, `group` | comptes de l'interface web et leurs groupes ([Comptes utilisateurs](../usage/user-accounts.md)) |
| `project` | valider ou refuser les projets demandés par un [enrôlement](mcp-server.md#enrolement-demander-le-projet) |
| `rules` | importer et exporter les [règles](../usage/rules.md) internes et les checklists |
| `advisories` | importer ou télécharger la [base OSV](dependencies.md#base-de-vulnerabilites-hors-ligne-format-osv) |
| `audit` | lire ou purger le [journal d'audit](audit-metrics.md) |

Toutes leurs options : [Ligne de commande](../reference/cli.md#security-review-controller). Les
variables du contrôleur : [Configuration](../reference/configuration.md#controleur).

## Premier administrateur

À son premier démarrage, tant qu'aucun compte n'existe, le contrôleur crée le compte local
**`admin`** (`SECREVIEW_ADMIN_USERNAME`), membre du groupe `administrators` (rôle `admin`),
avec un mot de passe aléatoire que personne ne connaît et qui n'est jamais écrit dans les
journaux. Le seul moyen d'obtenir un mot de passe est la CLI, qui en définit un nouveau et
l'affiche une fois :

```bash
security-review-controller user reset-password admin
# {"id": 1, "username": "admin", …, "must_change_password": true, "password": "q3V…"}
```

```
WARNING security_review_mcp.controller: Initial Web UI administrator 'admin' created: set its password with `security-review-controller user reset-password admin`
```

Traitez ce mot de passe comme un secret et connectez-vous avec `admin`. L'interface **exige alors
un nouveau mot de passe** avant toute autre chose : elle ouvre **Mon compte**, et l'API refuse
toutes les autres routes (`403`) tant que le mot de passe n'est pas changé. S'il est perdu,
voir [mot de passe perdu](#mot-de-passe-perdu).

Il en va de même de tout mot de passe défini par quelqu'un d'autre : un compte local créé ou
réinitialisé par un administrateur (écran ou CLI) change son mot de passe à sa première connexion.
L'écran **Utilisateurs** affiche **mot de passe à changer** jusque-là.

### Mot de passe perdu

Le mot de passe est stocké sous forme d'empreinte scrypt : il est impossible de le relire.
Remplacez-le avec la CLI du contrôleur, sur la même base :

```bash
security-review-controller user reset-password admin
```

La commande affiche le compte en JSON, avec un mot de passe généré dans le champ `password`
(`| jq -r .password` pour ne garder que lui). L'ancien mot de passe est aussitôt invalidé, les
sessions ouvertes du compte prennent fin et le nouveau mot de passe doit être changé à la
prochaine connexion. Pour le choisir, donnez-le sur la première ligne de l'entrée standard (il
n'apparaît alors ni dans l'historique du shell ni dans la liste des processus, et le JSON n'a pas
de champ `password`) :

```bash
printf '%s\n' "$NEW_PASSWORD" | security-review-controller user reset-password admin --password-stdin
```

Lancez-la là où tourne le contrôleur :

```bash
# Docker Compose
docker compose exec controller security-review-controller user reset-password admin
# Kubernetes
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller user reset-password admin
```

Un compte OIDC n'a pas de mot de passe (code de sortie `2`). S'il ne reste aucun administrateur,
créez-en un avec `security-review-controller user create NAME --group administrators` (mot de
passe généré, affiché de la même façon) : le compte `admin` n'est créé au démarrage que tant
qu'aucun compte n'existe.

## Connexion et sessions

Quand le contrôleur n'accepte plus la session pendant la navigation (session expirée, mot de passe
changé dans un autre onglet, compte supprimé), une fenêtre **Session expirée** s'ouvre :
**Se reconnecter** ouvre la page de connexion puis revient à la même page.

La page de connexion propose l'identifiant et le mot de passe d'un compte local et, avec la
[connexion OIDC](sso.md), le bouton du fournisseur d'identité ; elle
n'accepte pas de jeton. `POST /api/v1/auth/login` vérifie le mot de passe d'un compte local et
renvoie un **jeton de session** signé, valable `SECREVIEW_SESSION_HOURS` heures (8 par défaut),
que l'onglet utilise comme un jeton Bearer :

```bash
curl -s -X POST https://secreview.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username": "alice", "password": "…"}'
# {"session": "eyJ…", "expires_in": 28800, "username": "alice"}
```

Chaque session désigne un compte (local ou OIDC) ; à chaque requête, le contrôleur le relit en
base :

- un changement de ses **groupes**, de leurs rôles ou d'un rôle s'applique immédiatement aux
  sessions ouvertes ;
- une **suppression** ou un **nouveau mot de passe** (changé par l'utilisateur ou réinitialisé
  par un administrateur) ferme toutes les sessions du compte ; `PUT /api/v1/me/password` remet une
  nouvelle session à l'onglet qui a changé le mot de passe.

Les sessions sont signées avec `SECREVIEW_SECRET_KEY` (32 caractères au moins), partagé par
toutes les répliques du contrôleur. Sans lui, un secret aléatoire est tiré à chaque démarrage
(un avertissement est journalisé) : les sessions se terminent au redémarrage du contrôleur et ne
sont pas partagées entre répliques. Définissez-le en production (en Kubernetes, depuis un
`Secret` : voir [Kubernetes](kubernetes.md#secrets)).

Les échecs de connexion sont limités : après **5 échecs en 15 minutes** pour un identifiant
depuis une même adresse, ou **20 échecs** depuis une adresse tous identifiants confondus, la
connexion est refusée (`429`, en-tête `Retry-After`), même avec le bon mot de passe. Les
compteurs sont tenus en base : tous les workers et réplicas du contrôleur les partagent. Chaque
adresse est aussi limitée sur toute l'API REST (par défaut 600 requêtes par minute, 30 sur les
routes de connexion, voir [`SECREVIEW_RATE_LIMIT_*`](../reference/configuration.md#limitation-des-requetes)). Derrière un reverse proxy, l'adresse vue est celle du
proxy, et la limite s'appliquerait alors à tous les clients du proxy : déclarez le proxy dans
[`SECREVIEW_FORWARDED_ALLOW_IPS`](../reference/configuration.md#ecoute-tls-et-reverse-proxy) pour que l'adresse du client
soit lue dans `X-Forwarded-For`. Chaque connexion et chaque échec
sont journalisés, sans le mot de passe :

```
INFO security_review_mcp.web: Web login of alice (role triager) from 10.0.0.12
WARNING security_review_mcp.web: Failed web login of alice from 10.0.0.12
```

## Sécurité de l'interface web

- Les fichiers statiques de `/ui/` sont publics (ils ne contiennent aucune donnée) ; l'API
  `/api/v1/` exige une session ou un jeton `admin` ou `api` (les routes de pipeline `/api/v1/ci/`
  prennent les jetons `ci`, voir [Ce qu'il sert](#ce-quil-sert)). Seules les routes de
  connexion (`/api/v1/auth/…`) sont publiques, ainsi que le téléchargement du client de
  pipeline (`/api/ci-client/`) une fois activé.
- Les mots de passe des comptes ne sont jamais stockés : seule une empreinte **scrypt** salée
  (N=2¹⁴, r=8, p=5) est enregistrée et aucune réponse de l'API ne la renvoie. La vérification
  prend le même temps que l'identifiant existe ou non, et la réponse d'échec est identique. La documentation Swagger (`/api/docs`)
  et son schéma (`/api/openapi.json`) sont **désactivés par défaut**
  (`SECREVIEW_SWAGGER_ENABLED=true` les sert) ; une fois activés, ils sont publics et ne donnent
  accès à aucune donnée. Leurs fichiers sont fournis avec la build de l'interface web : rien
  n'est chargé depuis Internet, et Swagger n'envoie jamais le schéma au validateur en ligne.
  Dans Swagger, le cadenas d'une route indique qu'elle exige un jeton : il reste **ouvert**
  tant que vous n'avez pas saisi de jeton avec **Authorize**, et ne veut pas dire que la route
  est accessible sans jeton. Saisissez-y un [jeton API](../usage/tokens.md#jetons-api).
- Le contrôleur n'expose aucune route d'écriture sans jeton.
  L'[enrôlement](mcp-server.md#enrolement-demander-le-projet) est servi par le **serveur
  MCP** (`POST /api/v1/enroll`, public) : il demande un projet, jamais un jeton ; le
  contrôleur liste et traite les demandes (`GET /api/v1/projects/pending`,
  `POST /api/v1/projects/pending/{id}/approve`, `DELETE /api/v1/projects/pending/{id}`,
  permission `projects.create`).
- Le jeton est envoyé dans l'en-tête `Authorization` : pas de cookie, donc pas de CSRF.
  Seule la [connexion OIDC](sso.md) pose un cookie, `HttpOnly`,
  `SameSite=Lax`, `Secure` en HTTPS, limité à l'URL de retour et valable 10 minutes : il lie le
  retour du fournisseur au navigateur qui a lancé la connexion (protection contre le *login
  CSRF*). Le jeton de session est remis dans le fragment d'URL (`#session=...`), jamais envoyé à
  un serveur, et l'interface l'efface aussitôt de la barre d'adresse et de l'historique.
- Il est conservé dans le `sessionStorage` de l'onglet et disparaît à sa fermeture.
- Les pages sont servies avec une CSP stricte (`script-src 'self'`, aucune ressource externe),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` et `Referrer-Policy: no-referrer`.
- Servez l'interface en HTTPS ([TLS intégré ou reverse proxy](tls.md)) dès
  qu'elle n'écoute plus sur localhost : le jeton circule à chaque requête.

Le paquet publié et l'image Docker contiennent l'application déjà compilée. Si vous installez
depuis les sources sans la compiler, le contrôleur ne sert que l'API REST et un avertissement est
journalisé. Voir [Contribuer](../contributing/web-ui.md) pour la compiler.
