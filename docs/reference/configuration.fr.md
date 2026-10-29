# Configuration

Le serveur MCP et le serveur Controller lisent des variables d'environnement préfixées `SECREVIEW_`, ou
un fichier `.env` dans le répertoire courant (voir `.env.example`). Les variables sont groupées
ci-dessous selon le processus qui les lit : [les deux](#les-deux-processus), le
[serveur MCP](#serveur-mcp) (`security-review-mcp`), le [serveur Controller](#serveur-controller)
(`security-review-controller`) ou les [clients](#clients).

Certains réglages se définissent aussi dans l'[interface web](../usage/index.md#pages) :
langue des rapports, proxy sortant, connexion OIDC et serveur syslog du journal d'audit. **Une variable définie est toujours
prioritaire** sur la valeur de l'interface, qui ne s'applique que si la variable n'est pas
définie (la page verrouille alors le champ).

## Les deux processus

Lues par le serveur MCP et par le serveur Controller.

### Base de données et journaux

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_DATABASE_URL` | Fichier SQLite de l'utilisateur (voir [Base de données](../advanced/database.md)) | URL SQLAlchemy de la base, **partagée** par les deux processus |
| `SECREVIEW_DATABASE_ECHO` | `false` | Journalise les requêtes SQL |
| `SECREVIEW_DB_AUTO_UPGRADE` | `true` | Migre le schéma au démarrage du serveur Controller, du serveur MCP stdio et des commandes CLI ; à laisser tel quel, sauf si les migrations sont confiées à une [tâche dédiée](../advanced/database.md#tache-de-migration-dediee), où `false` leur fait seulement vérifier le schéma. Le serveur MCP HTTP ne migre jamais |
| `SECREVIEW_LOG_LEVEL` | `INFO` | Niveau de journalisation (sur stderr) |

### Écoute, TLS et reverse proxy

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_HOST` | `127.0.0.1` (`0.0.0.0` dans l'image Docker) | Adresse d'écoute (HTTP) du processus. Avec Docker, gardez la valeur de l'image et choisissez l'adresse de l'hôte dans les ports publiés (voir [Docker](../advanced/deployment/docker.md#docker-compose-avec-postgresql)) |
| `SECREVIEW_PORT` | `8000` | Port d'écoute (HTTP) |
| `SECREVIEW_TLS_CERTFILE` | — | Certificat : active le TLS |
| `SECREVIEW_TLS_KEYFILE` | — | Clé privée |
| `SECREVIEW_TLS_KEYFILE_PASSWORD` | — | Mot de passe de la clé privée |
| `SECREVIEW_TLS_CLIENT_CA` | — | CA cliente : active le TLS mutuel |
| `SECREVIEW_FORWARDED_ALLOW_IPS` | — | Reverse proxies (adresses IP ou plages CIDR séparées par des virgules, `*` pour tous) dont l'en-tête `X-Forwarded-For` donne l'adresse du client, utilisée par la limitation des connexions, le journal d'audit et les journaux ; sans elle, la valeur par défaut d'uvicorn (variable `FORWARDED_ALLOW_IPS`, sinon `127.0.0.1`). À définir derrière un Ingress ou un reverse proxy, sinon tous les clients partagent l'adresse du proxy |

### Limites communes

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` | `7` | Jours pendant lesquels un projet demandé par l'agent MCP d'un utilisateur (`request_project`) attend sa validation (1 à 365) avant d'être supprimé |
| `SECREVIEW_MAX_FINDINGS_PER_REPORT` | `500` | Nombre maximal de findings par rapport |
| `SECREVIEW_MAX_DEPENDENCY_CHARS` | `1000000` | Taille maximale d'un manifeste passé à `scan_dependencies` ou envoyé par `security-review-ci scan-deps` |
| `SECREVIEW_MAX_LIST_LIMIT` | `100` | Taille maximale d'une page de résultats |

## Serveur MCP

Lues par `security-review-mcp` uniquement.

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_TRANSPORT` | `streamable-http` | `streamable-http` (mode partagé) ou `stdio` (mode local) |
| `SECREVIEW_ALLOW_UNAUTHENTICATED` | `false` | Tant qu'aucun jeton n'existe, accepte toute requête sur `/mcp` même si le serveur n'écoute pas sur localhost (par défaut il reste alors fermé, voir [Jetons Bearer](../advanced/bearer-tokens.md)) ; à réserver aux tests sur un réseau isolé |
| `SECREVIEW_ENROLLMENT` | `true` | [Enrôlement](../advanced/architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet) : un client sans jeton atteint un serveur MCP restreint, sans aucun outil, qui invite l'utilisateur à créer un jeton MCP personnel dans l'interface web ; avec un jeton, `request_project` crée un nouveau projet pour un utilisateur portant `projects.create`, sinon le demande pour qu'un utilisateur portant `projects.create` le valide. `false` : `401` sans jeton, et aucune demande de projet |
| `SECREVIEW_REPORT_LANGUAGE` | — | [Langue des rapports](../review/prompts-tools.md#langue-des-rapports) demandée par les prompts de revue (`French`, `fr`...) quand l'argument `report_language` est absent ; définie (même vide : l'agent choisit), elle est prioritaire sur la langue choisie dans la page [**Langue des rapports**](../usage/index.md#pages) |
| `SECREVIEW_MAX_CONTENT_CHARS` | `200000` | Taille maximale du contenu passé à `scan_code`, et de chaque texte d'un rapport (`summary`, `scope`, `description`, `evidence`, `recommendation`) |
| `SECREVIEW_MAX_MCP_REQUEST_MB` | `16` | Taille maximale d'une requête d'un client MCP authentifié sur `/mcp` (`413` au-delà) ; un client sans jeton, dirigé vers le serveur d'enrôlement, est borné à 64 Kio |

## Serveur Controller

Lues par `security-review-controller` uniquement.

### Interface web et sessions

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_ADMIN_USERNAME` | `admin` | Nom du [premier administrateur](../advanced/architecture/controller.md#premier-administrateur), créé au premier démarrage tant qu'aucun compte n'existe (groupe `administrators`), avec un mot de passe aléatoire jamais journalisé : définissez-le avec `security-review-controller user reset-password` |
| `SECREVIEW_SECRET_KEY` | — | Secret de signature des sessions de l'interface web (comptes et OIDC), 32 caractères au moins, identique sur toutes les répliques ; non défini : un secret aléatoire à chaque démarrage (les sessions se terminent au redémarrage) |
| `SECREVIEW_PUBLIC_URL` | — | URL publique racine du serveur Controller (`https://…`, sans `/ui`), souvent la même adresse que `SECREVIEW_CONTROLLER_URL` de [`security-review-ci`](#clients). Recopiée en base à chaque démarrage ; le serveur MCP l'y lit (il ignore sa propre variable) et donne l'adresse de l'interface web (`/ui`) aux clients sans jeton valide (instructions et prompts du serveur d'enrôlement, `401` de `/mcp`), pour que l'utilisateur sache où se connecter et créer un jeton MCP personnel ; les connecteurs l'utilisent pour leurs liens. Non définie, elle se règle dans la page [**Général**](../usage/index.md#pages) ; sans aucune des deux, aucun lien n'est donné. `SECREVIEW_CONTROLLER_URL`, son ancien nom, est encore lu par le serveur Controller quand elle n'est pas définie, avec un avertissement |
| `SECREVIEW_SESSION_HOURS` | `8` | Durée d'une session de l'interface web (1 à 24 heures) |
| `SECREVIEW_WEB_UI` | `true` | Sert l'[interface web](../usage/index.md) sur `/ui` ; à `false`, seulement l'API REST |
| `SECREVIEW_WEB_UI_DIR` | — | Dossier d'une autre build de l'interface web |
| `SECREVIEW_SWAGGER_ENABLED` | `false` | Servir la documentation Swagger (`/api/docs`) et le schéma OpenAPI (`/api/openapi.json`), depuis les fichiers de la build de l'interface web |
| `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED` | `true` | Servir le client de pipeline sur `/api/ci-client/` (public), pour que les développeurs l'installent avec `uv --find-links`, sans PyPI ([depuis le serveur Controller](../advanced/architecture/ci.md#depuis-le-serveur-controller)) |
| `SECREVIEW_UPDATE_CHECK_ENABLED` | `false` | La page **À propos** cherche une nouvelle version sur GitHub (HTTPS, par le proxy sortant, mise en cache 6 heures, voir la [sécurité](security.md#securite-du-serveur-lui-meme)) |

### Limitation des requêtes

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_RATE_LIMIT_ENABLED` | `true` | Limiter les requêtes de chaque adresse cliente vers l'API REST (`429` au-delà) ; comptées en base, partagées par toutes les réplicas |
| `SECREVIEW_RATE_LIMIT_WINDOW_SECONDS` | `60` | Fenêtre des limites, en secondes (1 à 3600) |
| `SECREVIEW_RATE_LIMIT_MAX_REQUESTS` | `600` | Requêtes d'une adresse vers `/api/` par fenêtre |
| `SECREVIEW_RATE_LIMIT_AUTH_MAX_REQUESTS` | `30` | Requêtes d'une adresse vers les routes de connexion (`/api/v1/auth/`) par fenêtre |

### Connexion OIDC

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_OIDC_ENABLED` | `false` | Active la [connexion OIDC OpenID Connect](../advanced/oidc.md) à l'interface web. Toutes les variables `SECREVIEW_OIDC_*` sauf `SECREVIEW_OIDC_CAFILE` et `SECREVIEW_OIDC_ONLY` se définissent aussi dans la page **Connexions**, dont les valeurs enregistrées s'appliquent quand la variable n'est pas définie ([configurer le OIDC dans l'interface](../advanced/oidc.md#configurer-le-oidc-dans-linterface)) |
| `SECREVIEW_OIDC_ISSUER` | — | URL de l'émetteur (HTTPS ; HTTP seulement sur localhost), dont `/.well-known/openid-configuration` est lu |
| `SECREVIEW_OIDC_CLIENT_ID` | — | Identifiant du client déclaré chez le fournisseur |
| `SECREVIEW_OIDC_CLIENT_SECRET` | — | Secret du client ; vide pour un client public (PKCE seul) |
| `SECREVIEW_OIDC_REDIRECT_URI` | — | URL publique de `/api/v1/auth/oidc/callback`, déclarée chez le fournisseur |
| `SECREVIEW_OIDC_SCOPE` | `openid profile email` | Scopes demandés (doit contenir `openid`) |
| `SECREVIEW_OIDC_ROLES_CLAIM` | `groups` | Claim des groupes ou rôles, chemin pointé accepté (`realm_access.roles`) ; ses valeurs sont comparées aux noms des [groupes ouverts au OIDC](../advanced/oidc.md#groupes-du-fournisseur-didentite) |
| `SECREVIEW_OIDC_ADMIN_GROUPS` | — | Groupes OIDC, séparés par des virgules, créés ouverts au OIDC avec le rôle `admin` à la première connexion de l'un de leurs membres (premier administrateur) |
| `SECREVIEW_OIDC_DEFAULT_GROUP` | — | Groupe que tout utilisateur OIDC rejoint à chaque connexion, quel que soit son claim (vide : aucun) |
| `SECREVIEW_OIDC_USERNAME_CLAIM` | `preferred_username` | Claim qui nomme le [compte OIDC](../advanced/oidc.md#comptes-oidc) (comparaison exacte, sans repli) ; label de session `oidc:<valeur>` |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Crée le compte OIDC à sa première connexion si ses groupes lui donnent un rôle ; à `false`, un administrateur crée chaque compte OIDC dans **Utilisateurs** |
| `SECREVIEW_OIDC_DISPLAY_NAME` | `OIDC` | Nom affiché sur le bouton de connexion (40 caractères au plus) |
| `SECREVIEW_OIDC_CAFILE` | — | Bundle de CA pour joindre le fournisseur (CA interne) ; le proxy est celui de `HTTPS_PROXY` |
| `SECREVIEW_OIDC_ONLY` | `false` | Avec le OIDC activé, refuse la connexion par mot de passe des comptes locaux ([OIDC seul](../advanced/oidc.md#oidc-seul)) ; une variable uniquement, jamais modifiée dans l'interface |

### Connexion OAuth des clients MCP

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_MCP_OAUTH_ENABLED` | `false` | Active la [connexion OAuth des clients MCP](../advanced/mcp-oauth.md) : le serveur Controller devient leur serveur d'autorisation (routes `/authorize`, `/token`, `/register`, `/revoke` à la racine de `SECREVIEW_PUBLIC_URL`, qui doit être défini, en https hors localhost) et le serveur MCP y envoie un client sans jeton. Non définie, un administrateur peut l'activer dans l'interface web (page **Jetons**) |
| `SECREVIEW_MCP_URL` | — | URL publique du point d'accès MCP (`https://…/mcp`, en ASCII : punycode pour un hôte non ASCII), obligatoire avec OAuth : la ressource des jetons. Enregistrée en base au démarrage, où le serveur MCP la lit. Non définie, elle peut être saisie dans l'interface web (page **Jetons**) |
| `SECREVIEW_MCP_OAUTH_ACCESS_MINUTES` | `60` | Durée d'un jeton d'accès (5 à 1440 minutes) |
| `SECREVIEW_MCP_OAUTH_REFRESH_DAYS` | `30` | Durée d'un jeton de rafraîchissement (1 à 365 jours), prolongée à chaque rafraîchissement ; `SECREVIEW_TOKEN_MAX_DAYS`, s'il est défini, borne toute l'autorisation depuis son approbation |
| `SECREVIEW_MCP_OAUTH_MAX_CLIENTS` | `1000` | Clients enregistrés à la fois ; un client que personne n'a autorisé dans la journée est supprimé |
| `SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS` | — | Hôtes joints en https acceptés comme URI de redirection d'un client, séparés par des virgules (`vscode.dev`) ; vide : l'interface loopback seulement |
| `SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES` | — | Schémas d'URI personnalisés acceptés comme URI de redirection, séparés par des virgules (`cursor`) ; vide : aucun |

### Proxy sortant

| Variable | Défaut | Rôle |
|---|---|---|
| `HTTPS_PROXY` (sinon `HTTP_PROXY`) | — | Variable standard, sans le préfixe `SECREVIEW_` (nom en minuscules accepté) : proxy HTTP des connexions sortantes du serveur Controller, téléchargement OSV et fournisseur OIDC (`http://[utilisateur:mot de passe@]hôte:port`, `hôte:port` valant `http://hôte:port`) ; sans elle, la connexion est directe, ou passe par le proxy choisi dans la page [**Général**](../usage/index.md#pages). Définie (non vide), elle est prioritaire sur cette page |
| `NO_PROXY` | — | Variable standard : [hôtes joints sans le proxy](../review/analysis/dependencies.md#hotes-sans-proxy), séparés par des virgules : domaines (sous-domaines compris), adresses IP, `*` (pas de plages CIDR) ; la boucle locale est toujours directe. Définie (non vide), elle est prioritaire sur la liste de la page **Général** |

### Base OSV

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_OSV_AUTO_UPDATE` | `false` | [Mise à jour quotidienne](../review/analysis/dependencies.md#mise-a-jour-automatique-par-le-serveur-controller) de la base OSV par `serve` |
| `SECREVIEW_OSV_UPDATE_INTERVAL_HOURS` | `24` | Âge de la base au-delà duquel `serve` la met à jour (minimum `1`) |
| `SECREVIEW_OSV_URL` | `https://osv-vulnerabilities.storage.googleapis.com` | Source des exports `<URL>/<écosystème>/all.zip` (HTTPS uniquement, miroir possible) |
| `SECREVIEW_OSV_ECOSYSTEMS` | `PyPI,npm,Maven,Go,crates.io,NuGet` | Écosystèmes téléchargés, séparés par des virgules |
| `SECREVIEW_OSV_CAFILE` | — | Bundle de CA utilisé à la place de celui du système (miroir interne, proxy qui inspecte le TLS) |
| `SECREVIEW_OSV_MAX_DOWNLOAD_MB` | `1024` | Taille maximale d'une archive téléchargée |

### Findings, rapports et jetons

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` | `90` | Âge en jours au-delà duquel `serve` supprime les [rapports sans findings](../advanced/database.md#conservation-des-rapports-sans-findings) ; `0` conserve tous les rapports |
| `SECREVIEW_MAX_DISMISSAL_DAYS` | `365` | Validité maximale en jours d'une [décision](../usage/triage.md) `accepted` ou `false_positive` : sa date d'expiration ne peut pas être plus lointaine |
| `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED` | `true` | Une personne peut [accepter un risque](../usage/triage.md) **Sans expiration** : l'acceptation dure jusqu'à ce que quelqu'un rouvre le finding. `false` : toute acceptation exige une date d'expiration. Un faux positif n'en exige jamais |
| `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY` | `medium` | Gravité minimale (`critical`, `high`, `medium`, `low`, `info`) dont l'[acceptation de risque](../usage/triage.md) exige un motif et une date d'expiration. Un finding moins grave est accepté par une simple validation, qui le ferme sans motif ni date. Vide : toute acceptation les exige |
| `SECREVIEW_TOKEN_MAX_DAYS` | `0` | Validité maximale en jours d'un jeton Bearer créé ou [renouvelé](../advanced/bearer-tokens.md#expiration-et-renouvellement-des-jetons) (CLI, interface web), qui est aussi sa validité par défaut ; `0` : les jetons n'expirent pas, sauf validité demandée |
| `SECREVIEW_PERSONAL_TOKENS_PER_USER` | `1` | Jetons personnels qu'un utilisateur web peut détenir de chaque rôle, [API REST](../usage/tokens.md#jetons-api), [MCP et CI](../usage/tokens.md#jetons-mcp-et-ci-personnels), de `1` à `10` : révoquez-en un pour en créer un autre |
| `SECREVIEW_PERSONAL_TOKENS_ENABLED` | `true` | Toute l'application : chaque utilisateur web peut créer un [jeton MCP ou CI personnel](../usage/tokens.md#jetons-mcp-et-ci-personnels) et autoriser un client MCP par la [connexion OAuth](../advanced/mcp-oauth.md). `false` : aucun n'est créé ni autorisé, et les jetons MCP et CI personnels et les autorisations OAuth déjà données sont refusés par le serveur MCP et le serveur Controller (conservés : `true` les accepte de nouveau) ; les jetons API REST restent. Enregistré en base par le serveur Controller, où le serveur MCP le lit aussi : l'un des deux à `false` suffit à les refuser |
| `SECREVIEW_PERSONAL_MCP_TOKENS` | `true` | Un utilisateur web peut créer un jeton MCP personnel dans **Mon compte**. `false` avec la [connexion OAuth des clients MCP](../advanced/mcp-oauth.md) : aucun n'est proposé ni créé, et le serveur Controller révoque ceux qui restent au démarrage (audité) ; les jetons CI et API REST restent. Enregistré en base, où le serveur MCP le lit : un client sans jeton valide est alors invité à s'adresser à un administrateur (ou à la connexion OAuth) plutôt qu'à créer un jeton personnel |

### Audit et métriques

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_AUDIT_RETENTION_DAYS` | `365` | Âge en jours au-delà duquel `serve` supprime les événements du [journal d'audit](../advanced/audit-log.md) ; `0` conserve tous les événements |
| `SECREVIEW_AUDIT_MAX_EVENTS` | `0` | Nombre d'[événements d'audit](../advanced/audit-log.md#conservation) conservés au plus par la même purge quotidienne (les plus anciens sont supprimés) ; `0` : sans limite |
| `SECREVIEW_AUDIT_SYSLOG_ADDRESS` | — | [Envoie les événements d'audit à syslog](../advanced/audit-log.md#envoi-vers-syslog) : `udp://hôte:port`, `tcp://hôte:port`, `tls://hôte:port` (RFC 5425, port 6514 par défaut) ou `unix:///dev/log` (pas de proxy) ; désactivé si absent ; sans elle, le serveur défini sur la page **Journal d'audit** s'applique. Définie (non vide), elle est prioritaire sur cette page |
| `SECREVIEW_AUDIT_SYSLOG_FACILITY` | `local0` | *Facility* syslog de ces messages (`local0` à `local7`, `auth`, `authpriv`, `daemon`...) ; définie, elle est prioritaire sur celle choisie sur la page **Journal d'audit** |
| `SECREVIEW_AUDIT_SYSLOG_CAFILE` | — | Autorités de certification qui vérifient le certificat d'un serveur syslog `tls://` (autorité interne) ; par défaut, celles du système. Variable uniquement |
| `SECREVIEW_METRICS_ENABLED` | `true` | Sert les [métriques Prometheus](metrics.md) sur `/metrics` (jeton `metrics` ou `admin`) ; à `false`, `/metrics` répond 404 |

### Connecteurs

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_CONNECTORS_ENABLED` | `true` | Verrou des [connecteurs](../advanced/connectors.md#activation) (Jira, ServiceNow, tiers ; connexions sortantes du serveur Controller) : `true`, chacun s'active dans la page **Connecteurs** (tous désactivés par défaut) ; `false`, tous verrouillés |
| `SECREVIEW_CONNECTORS_INTERVAL_SECONDS` | `300` | Période de l'[envoi automatique](../usage/connectors/index.md#envoi-dun-finding) (30 à 86400) |
| `SECREVIEW_CONNECTORS_CAFILE` | — | Bundle de CA utilisé à la place de celui du système (autorité interne) |
| `SECREVIEW_CONNECTORS_PLUGINS` | — | [Connecteurs tiers](../usage/connectors/third-party.md) autorisés, par nom de point d'entrée, séparés par des virgules ; un connecteur installé mais non listé n'est jamais chargé |
| `SECREVIEW_JIRA_URL`, `SECREVIEW_JIRA_USERNAME`, `SECREVIEW_JIRA_API_TOKEN`, `SECREVIEW_JIRA_ISSUE_TYPE` (`Bug`) | — | [Connexion Jira](../advanced/connectors.md#jira) ; définies, elles sont prioritaires sur la page **Connecteurs** |
| `SECREVIEW_SERVICENOW_URL`, `SECREVIEW_SERVICENOW_USERNAME`, `SECREVIEW_SERVICENOW_PASSWORD`, `SECREVIEW_SERVICENOW_TABLE` (`incident`) | — | [Connexion ServiceNow](../advanced/connectors.md#servicenow) ; définies, elles sont prioritaires sur la page **Connecteurs** |
| `SECREVIEW_<TYPE>_<CHAMP>` | — | Champ de la connexion d'un [connecteur tiers](../usage/connectors/third-party.md) (`SECREVIEW_ACME_API_KEY`) |

### Limites des scans de pipeline

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_MAX_SCAN_REQUEST_MB` | `64` | Taille maximale d'une requête de [`security-review-ci scan-code` ou `scan-deps`](../review/analysis/code-scan.md#limites-du-serveur-controller) (`413` au-delà) |
| `SECREVIEW_MAX_SCAN_FILES` | `10000` | Nombre maximal de fichiers d'une requête de scan (`422` au-delà) |
| `SECREVIEW_MAX_SCAN_FILE_CHARS` | `1048576` | Taille au-delà de laquelle un fichier envoyé par `scan-code` n'est pas scanné (signalé comme ignoré) |

## Clients

Lues par le client de pipeline `security-review-ci` (`SECREVIEW_CI_TOKEN` jamais par les serveurs).

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_CI_TOKEN` | — | Jeton Bearer envoyé par [`security-review-ci`](../advanced/architecture/ci.md) au serveur Controller (jeton `ci`, personnel ou non) ; jamais utilisé par les serveurs. `SECREVIEW_TOKEN`, son ancien nom, est encore lu s'il n'est pas défini, avec un avertissement |
| `SECREVIEW_CONTROLLER_URL` | — | URL du serveur Controller utilisée par [`security-review-ci`](../advanced/architecture/ci.md) (valeur par défaut de `--url`) ; lue dans l'environnement uniquement, jamais dans `.env`. Le serveur Controller a sa propre variable pour [son URL publique](#interface-web-et-sessions), `SECREVIEW_PUBLIC_URL` |

Les jetons Bearer ne se configurent pas par variable : ils sont stockés en base et gérés avec
`security-review-controller token` (voir [Authentification et TLS](../advanced/bearer-tokens.md)).
Les règles internes non plus : elles sont stockées en base et gérées avec
`security-review-controller rules` (voir [Règles](../review/rules.md#commande-rules)).

## Base de données

SQLite ou PostgreSQL, migrations du schéma, conservation des rapports sans findings,
sauvegarde et mise à niveau : voir [Base de données](../advanced/database.md).
