# Serveur Controller

Le **serveur Controller** (`security-review-controller`) est le processus des personnes et des
pipelines : il sert l'interface web, l'API REST et les routes de pipeline, gère le schéma de la
base et exécute les tâches de fond. Il n'appelle jamais le serveur MCP : les deux partagent la
base (voir [Architecture](index.md)).

## Ce qu'il sert

| Route | Utilisée par | Identifiant |
|---|---|---|
| `/ui/` | les personnes (navigateur) : [interface web](../../usage/index.md) | aucun pour les fichiers statiques ; les données viennent de l'API |
| `/api/v1/auth/` | la page de connexion : mot de passe et connexion [OIDC](../oidc.md) | aucun |
| `/api/v1/` | l'interface web, les scripts, Swagger | session web, jeton `admin` ou `api` |
| `/api/v1/ci/` | [`security-review-ci`](ci.md) : gate, SARIF, tendance, scans du code et des dépendances | jeton `ci` (personnel ou non) |
| `/metrics` | Prometheus ([métriques](../../reference/metrics.md)) | jeton `metrics` ou `admin` |
| `/api/docs` | Swagger : documentation OpenAPI de l'API REST, sans données, seulement avec `SECREVIEW_SWAGGER_ENABLED=true` | aucun (les appels demandent un [jeton API](../../usage/tokens.md#jetons-api)) |
| `/api/ci-client/` | uv : [téléchargement de `security-review-ci`](ci.md#depuis-le-serveur-controller), sauf avec `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED=false` | aucun |
| `/api/health` | l'interface web, qui vérifie la disponibilité de l'API au chargement (ne révèle ni la version ni les réglages) | aucun |
| `/api/favicon.svg` | icône de l'interface web et de Swagger | aucun |
| `/.well-known/oauth-authorization-server`, `/authorize`, `/token`, `/register`, `/revoke` | les hôtes MCP : [connexion OAuth](../mcp-oauth.md), seulement avec `SECREVIEW_MCP_OAUTH_ENABLED=true` | aucun (PKCE ; l'autorisation passe par une session web) |
| `/healthz` | sondes (`HEALTHCHECK` Docker, Kubernetes) | aucun |

Les rôles des jetons sont décrits dans [Rôles](../../usage/tokens.md), leur gestion
dans [Jetons Bearer](../bearer-tokens.md).

## Démarrage

`security-review-controller serve` (port `8000` dans l'image, `--host` et `--port` sinon) :

1. migre le schéma (voir [Migrations du schéma](#migrations-du-schema)) ;
2. vérifie les réglages (TLS, OIDC, OSV, syslog, connecteurs) : une valeur invalide l'arrête
   avec le code `2` ;
3. crée le [premier administrateur](#premier-administrateur) tant qu'aucun compte n'existe ;
4. démarre les tâches de fond, puis sert les routes.

## Migrations du schéma

Le serveur Controller migre le schéma à son démarrage ; le serveur MCP HTTP ne le fait jamais. Commandes,
verrou entre réplicas et tâche de migration dédiée : voir
[Base de données](../database.md#migrations-du-schema).

## Tâches de fond

| Tâche | Activée par | Détails |
|---|---|---|
| Mise à jour quotidienne des avis OSV | `SECREVIEW_OSV_AUTO_UPDATE=true` (désactivée par défaut) | [Mise à jour automatique par le serveur Controller](../../review/analysis/dependencies.md#mise-a-jour-automatique-par-le-serveur-controller) |
| Purge des rapports sans finding et du journal d'audit | `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` (90), `SECREVIEW_AUDIT_RETENTION_DAYS` (365), `SECREVIEW_AUDIT_MAX_EVENTS` | [Conservation](../database.md#conservation-des-rapports-sans-findings), [conservation de l'audit](../audit-log.md#conservation) |
| Envoi du journal d'audit vers syslog | un serveur syslog défini dans l'environnement ou dans l'interface | [Envoi vers syslog](../audit-log.md#envoi-vers-syslog) |
| Envoi automatique des findings par les connecteurs | un connecteur activé, un seuil de sévérité sur le projet ; `SECREVIEW_CONNECTORS_ENABLED=false` verrouille tout | [Connecteurs](../../usage/connectors/index.md) |

Le serveur MCP n'en exécute aucune.

## Connexions sortantes

Le serveur Controller est le seul processus qui peut se connecter à l'extérieur, et chaque connexion est
**désactivée par défaut** : le téléchargement OSV, le fournisseur [OIDC](../oidc.md), la recherche
d'une nouvelle version sur la page **À propos** (`SECREVIEW_UPDATE_CHECK_ENABLED`), le serveur
syslog et les connecteurs. Elles passent en HTTPS (syslog : UDP, TCP ou TLS), par le proxy
sortant (`HTTPS_PROXY`, `NO_PROXY`, ou la page **Paramètres**). Voir
[Sécurité et limites](../../reference/security.md).

## Exposition

Exposez le serveur Controller avec TLS ([intégré ou reverse proxy](../tls.md)) aux personnes
(interface web, jetons personnels) et aux runners des pipelines. Derrière un reverse proxy ou un
Ingress :

- réglez `SECREVIEW_FORWARDED_ALLOW_IPS` sur l'adresse du proxy, sinon tous les clients
  partagent son adresse pour la limitation des connexions et la limite de débit ;
- réglez `SECREVIEW_PUBLIC_URL` sur l'URL publique racine du serveur Controller, sans `/ui` (ou
  renseignez la page
  **Général**) : le serveur Controller la recopie en base au démarrage et le serveur
  MCP l'y lit, pour qu'un agent sans jeton valide sache où en créer un. Tant qu'elle est
  inconnue, un bandeau en haut de l'interface web le signale aux administrateurs (permission
  `settings.manage`) et renvoie au champ.

## Plusieurs réplicas

Le serveur Controller peut tourner en plusieurs réplicas sur la même base PostgreSQL : les migrations
s'attendent (verrou consultatif), les sessions sont partagées grâce à `SECREVIEW_SECRET_KEY`, les
compteurs de connexion et de limite de débit sont tenus en base, un seul réplica à la fois
télécharge les avis OSV, et un lot syslog n'est envoyé qu'une fois. Donnez le même
`SECREVIEW_SECRET_KEY` à tous les réplicas.

## Commandes d'administration

Les autres commandes de `security-review-controller` s'exécutent là où tourne le serveur Controller
(même `SECREVIEW_DATABASE_URL`), par exemple `docker compose exec controller …` ou
`kubectl exec deploy/secreview-controller -c controller -- …` :

| Commande | Rôle |
|---|---|
| `db` | migrer le schéma, afficher sa révision, purger des rapports |
| `token` | créer, lister, renouveler et révoquer les jetons ([Jetons Bearer](../bearer-tokens.md)) |
| `user`, `group` | comptes de l'interface web et leurs groupes ([Gérer les comptes](#gerer-les-comptes)) |
| `project` | valider ou refuser les projets demandés par les agents MCP des utilisateurs ([enrôlement](mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)) |
| `rules` | importer et exporter les [règles](../../review/rules.md) internes et les checklists |
| `advisories` | importer ou télécharger la [base OSV](../../review/analysis/dependencies.md#base-de-vulnerabilites-hors-ligne-format-osv) |
| `audit` | lire ou purger le [journal d'audit](../audit-log.md) |

Toutes leurs options : [Ligne de commande](../../reference/cli.md#security-review-controller). Les
variables du serveur Controller : [Configuration](../../reference/configuration.md#serveur-controller).

## Gérer les comptes

Les [comptes utilisateurs](../../usage/user-accounts.md) se gèrent dans la page **Utilisateurs**,
par l'API REST `/api/v1/users` (permission `users.manage`) ou par la
[CLI](../../reference/cli.md#security-review-controller). Un identifiant contient des lettres, des
chiffres et `. _ @ -`, 64 caractères au plus ; le type d'un compte est son `auth_source`
(`local` ou `oidc`).

```bash
security-review-controller user create alice --group shop-triagers
# {"id": 2, "username": "alice", "auth_source": "local", "groups": [{"group_id": 3, "name": "shop-triagers", "source": "local"}], "permissions": {…}, …, "password": "q3V…"}
printf '%s\n' "$PASSWORD" | security-review-controller user create bob --password-stdin
security-review-controller user create carol@example.com --sso   # groupes OIDC uniquement
security-review-controller user list
security-review-controller user set-groups alice --group readers --group auditors
security-review-controller user set-groups alice --group administrators   # créé s'il manque
security-review-controller user reset-password alice   # compte local : nouveau mot de passe, sessions fermées
security-review-controller user delete alice
security-review-controller group list    # groupes, leurs rôles et leurs membres
```

Par l'API, un compte OIDC se crée avec `"auth_source": "oidc"`, sans `password` ; `group_ids`
liste ses groupes :

```bash
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "carol@example.com", "auth_source": "oidc", "group_ids": [4]}'
```

Un compte OIDC est aussi créé à sa première connexion avec
`SECREVIEW_OIDC_AUTO_CREATE_USERS=true` ([comptes OIDC](../oidc.md#comptes-oidc)).

Pour un compte local, sans `--password-stdin` (ou sans mot de passe dans l'interface), un mot de
passe aléatoire de 24 caractères est généré et affiché **une seule fois**. Un mot de passe choisi
respecte la **politique de mot de passe** : 12 à 256 caractères, avec au moins une minuscule, une
majuscule, un chiffre et un caractère qui n'est ni une lettre ni un chiffre. La politique
s'applique aux nouveaux mots de passe : un mot de passe défini avant reste valable jusqu'à son
changement. Un compte OIDC n'a jamais de mot de passe : la connexion par identifiant et mot de
passe, la réinitialisation et **Mon compte** le refusent.

!!! warning "Authentification requise pour la Web UI"
    L'API de l'interface refuse les requêtes avec le statut `503` tant qu'aucun utilisateur ni
    jeton n'existe ; la mire de connexion reste affichée et indique que l'authentification doit
    être configurée. `security-review-controller serve` crée le
    [premier administrateur](#premier-administrateur) à son premier démarrage : cela n'arrive
    donc qu'avant ; un compte peut aussi être créé avec `security-review-controller user create`.
    Cette restriction concerne la Web UI ; l'authentification MCP reste indépendante (un compte
    utilisateur n'ouvre jamais `/mcp`). Avec la [connexion OIDC](../oidc.md), l'API demande une
    connexion (`401`) même sans utilisateur ni jeton en base.

Les variables de l'interface sont dans la
[Configuration](../../reference/configuration.md#interface-web-et-sessions).

## Premier administrateur

À son premier démarrage, tant qu'aucun compte n'existe, le serveur Controller crée le compte local
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
réinitialisé par un administrateur (page ou CLI) change son mot de passe à sa première connexion.
La page **Utilisateurs** affiche **mot de passe à changer** jusque-là.

### Mot de passe perdu

Le mot de passe est stocké sous forme d'empreinte scrypt : il est impossible de le relire.
Remplacez-le avec la CLI du serveur Controller, sur la même base :

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

Lancez-la là où tourne le serveur Controller :

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

Quand le serveur Controller n'accepte plus la session pendant la navigation (session expirée, mot de passe
changé dans un autre onglet, compte supprimé), une fenêtre **Session expirée** s'ouvre :
**Se reconnecter** ouvre la page de connexion puis revient à la même page.

La page de connexion propose l'identifiant et le mot de passe d'un compte local et, avec la
[connexion OIDC](../oidc.md), le bouton du fournisseur d'identité ; elle
n'accepte pas de jeton. `POST /api/v1/auth/login` vérifie le mot de passe d'un compte local et
renvoie un **jeton de session** signé, valable `SECREVIEW_SESSION_HOURS` heures (8 par défaut),
que l'onglet utilise comme un jeton Bearer :

```bash
curl -s -X POST https://secreview.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username": "alice", "password": "…"}'
# {"session": "eyJ…", "expires_in": 28800, "username": "alice"}
```

Chaque session désigne un compte (local ou OIDC) ; à chaque requête, le serveur Controller le relit en
base :

- un changement de ses **groupes**, de leurs rôles ou d'un rôle s'applique immédiatement aux
  sessions ouvertes ;
- une **suppression** ou un **nouveau mot de passe** (changé par l'utilisateur ou réinitialisé
  par un administrateur) ferme toutes les sessions du compte ; `PUT /api/v1/me/password` remet une
  nouvelle session à l'onglet qui a changé le mot de passe ;
- une **déconnexion** (`POST /api/v1/me/logout`) ferme aussi toutes les sessions du compte, dans
  tous les onglets et navigateurs : un jeton de session volé cesse de fonctionner quand son
  utilisateur se déconnecte.

Les sessions sont signées avec `SECREVIEW_SECRET_KEY` (32 caractères au moins), partagé par
toutes les répliques du serveur Controller. Sans lui, un secret aléatoire est tiré à chaque démarrage
(un avertissement est journalisé) : les sessions se terminent au redémarrage du serveur Controller et ne
sont pas partagées entre répliques. Définissez-le en production (en Kubernetes, depuis un
`Secret` : voir [Kubernetes](../deployment/kubernetes.md#secrets)).

Les échecs de connexion sont limités : après **5 échecs en 15 minutes** pour un identifiant
depuis une même adresse, ou **20 échecs** depuis une adresse tous identifiants confondus, la
connexion est refusée (`429`, en-tête `Retry-After`), même avec le bon mot de passe. Les
compteurs sont tenus en base : tous les workers et réplicas du serveur Controller les partagent. Chaque
adresse est aussi limitée sur toute l'API REST (par défaut 600 requêtes par minute, 30 sur les
routes de connexion, voir [`SECREVIEW_RATE_LIMIT_*`](../../reference/configuration.md#limitation-des-requetes)). Derrière un reverse proxy, l'adresse vue est celle du
proxy, et la limite s'appliquerait alors à tous les clients du proxy : déclarez le proxy dans
[`SECREVIEW_FORWARDED_ALLOW_IPS`](../../reference/configuration.md#ecoute-tls-et-reverse-proxy) pour que l'adresse du client
soit lue dans `X-Forwarded-For`. Chaque connexion et chaque échec
sont journalisés, sans le mot de passe :

```
INFO security_review_mcp.web: Web login of alice (role triager) from 10.0.0.12
WARNING security_review_mcp.web: Failed web login of alice from 10.0.0.12
```

## Réglages enregistrés en base

Les pages **Général** (langue des rapports, adresse du serveur Controller, proxy sortant) et **Connexions** (OIDC) de l'[interface web](../../usage/index.md)
enregistrent des réglages en base, partagés par le serveur MCP et le serveur Controller (permission
`settings.manage` ; les anciennes adresses `/ui/settings`, `/ui/settings/language` et
`/ui/settings/proxy` ouvrent **Général**). **Une variable d'environnement définie (environnement ou fichier `.env`, non vide)
est toujours prioritaire** : son champ est alors verrouillé et affiche la variable, et une valeur
enregistrée avant que la variable soit définie est signalée comme ignorée, avec un bouton
**Supprimer**. Un changement s'applique sans redémarrage : le serveur MCP lit l'adresse du
serveur Controller en moins d'une minute (le changement est enregistré dans le journal d'audit,
`controller_url.changed`), et le proxy s'applique au prochain téléchargement OSV et à la
prochaine connexion OIDC. **Utiliser l'adresse actuelle** remplit l'adresse de ce serveur Controller.

| Route | Effet |
|---|---|
| `GET /api/v1/settings` | Pour chaque réglage : la valeur enregistrée `value`, la variable `env`, `env_set` (la variable est définie et prioritaire) et la valeur effective |
| `PUT /api/v1/settings/controller-url` | `value` (`null` la supprime) |
| `PUT /api/v1/settings/proxy` | `url` et `no_proxy` : `null` supprime la valeur enregistrée, `"url": ""` force la connexion directe, un champ absent est inchangé. Les mots de passe ne sont jamais réaffichés (`***`) : renvoyer `***` conserve celui enregistré |

Une valeur dont la variable est définie est refusée avec `422`. Les réglages OIDC ont leurs
propres routes ([configuration OIDC](../oidc.md#configurer-le-oidc-dans-linterface)). Le thème choisi
par un utilisateur connecté est conservé dans son compte (`GET` et `PUT /api/v1/me/preferences`),
pour tous les navigateurs qu'il utilise.

## Sécurité de l'interface web

- Les fichiers statiques de `/ui/` sont publics (ils ne contiennent aucune donnée) ; l'API
  `/api/v1/` exige une session ou un jeton `admin` ou `api` (les routes de pipeline `/api/v1/ci/`
  prennent les jetons `ci`, voir [Ce qu'il sert](#ce-quil-sert)). Seules les routes de
  connexion (`/api/v1/auth/…`) sont publiques, ainsi que le téléchargement du client de
  pipeline (`/api/ci-client/`) sauf s'il est désactivé.
- Les mots de passe des comptes ne sont jamais stockés : seule une empreinte **scrypt** salée
  (N=2¹⁴, r=8, p=5) est enregistrée et aucune réponse de l'API ne la renvoie. La vérification
  prend le même temps que l'identifiant existe ou non, et la réponse d'échec est identique. La documentation Swagger (`/api/docs`)
  et son schéma (`/api/openapi.json`) sont **désactivés par défaut**
  (`SECREVIEW_SWAGGER_ENABLED=true` les sert) ; une fois activés, ils sont publics et ne donnent
  accès à aucune donnée. Leurs fichiers sont fournis avec la build de l'interface web : rien
  n'est chargé depuis Internet, et Swagger n'envoie jamais le schéma au validateur en ligne.
  Dans Swagger, le cadenas d'une route indique qu'elle exige un jeton : il reste **ouvert**
  tant que vous n'avez pas saisi de jeton avec **Authorize**, et ne veut pas dire que la route
  est accessible sans jeton. Saisissez-y un [jeton API](../../usage/tokens.md#jetons-api).
- Le serveur Controller n'expose aucune route d'écriture sans jeton. Un projet est demandé par un
  agent muni d'un jeton, avec l'outil `request_project` du **serveur MCP**
  ([enrôlement](mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)) ; le serveur Controller
  liste et traite les demandes (`GET /api/v1/projects/pending`,
  `POST /api/v1/projects/pending/{id}/approve`, `DELETE /api/v1/projects/pending/{id}`,
  permission `projects.create`).
- Le jeton est envoyé dans l'en-tête `Authorization` : pas de cookie, donc pas de CSRF.
  Seule la [connexion OIDC](../oidc.md) pose un cookie, `HttpOnly`,
  `SameSite=Lax`, `Secure` en HTTPS, limité à l'URL de retour et valable 10 minutes : il lie le
  retour du fournisseur au navigateur qui a lancé la connexion (protection contre le *login
  CSRF*). Le jeton de session est remis dans le fragment d'URL (`#session=...`), jamais envoyé à
  un serveur, et l'interface l'efface aussitôt de la barre d'adresse et de l'historique.
- Il est conservé dans le `sessionStorage` de l'onglet et disparaît à sa fermeture.
- Les pages sont servies avec une CSP stricte (`script-src 'self'`, aucune ressource externe),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` et `Referrer-Policy: no-referrer`.
- Servez l'interface en HTTPS ([TLS intégré ou reverse proxy](../tls.md)) dès
  qu'elle n'écoute plus sur localhost : le jeton circule à chaque requête.

Le paquet publié et l'image Docker contiennent l'application déjà compilée. Si vous installez
depuis les sources sans la compiler, le serveur Controller ne sert que l'API REST et un avertissement est
journalisé. Voir [Contribuer](../../contributing/web-ui.md) pour la compiler.
