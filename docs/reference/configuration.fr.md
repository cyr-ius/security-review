# Configuration

Le serveur MCP et le contrôleur lisent des variables d'environnement préfixées `SECREVIEW_`, ou
un fichier `.env` dans le répertoire courant (voir `.env.example`). La colonne **Processus**
indique qui utilise la variable : `MCP` (`security-review-mcp`), `Contrôleur`
(`security-review-controller`) ou les deux.

| Variable | Défaut | Processus | Rôle |
|---|---|---|---|
| `SECREVIEW_DATABASE_URL` | `sqlite:///./security_reports.db` | les deux | URL SQLAlchemy de la base, **partagée** par les deux processus |
| `SECREVIEW_DATABASE_ECHO` | `false` | les deux | Journalise les requêtes SQL |
| `SECREVIEW_DB_AUTO_UPGRADE` | `true` | les deux | Migre le schéma au démarrage du contrôleur, du serveur MCP stdio et des commandes CLI ; à `false`, ils vérifient seulement qu'il est à jour (voir [migrations](../advanced/architecture.md#migrations-du-schema)). Le serveur MCP HTTP ne migre jamais |
| `SECREVIEW_TRANSPORT` | `stdio` | MCP | `stdio` ou `streamable-http` |
| `SECREVIEW_HOST` | `127.0.0.1` | les deux | Adresse d'écoute (HTTP) |
| `SECREVIEW_PORT` | `8000` | les deux | Port d'écoute (HTTP) |
| `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` | `false` | Contrôleur | Crée le [compte `admin`](../usage/web-interface.md#premier-administrateur) au premier démarrage, tant qu'aucun compte n'existe ; son mot de passe aléatoire est journalisé une fois (empreinte scrypt seule en base) |
| `SECREVIEW_SESSION_SECRET` | — | Contrôleur | Secret de signature des sessions de l'interface web (comptes et SSO), 32 caractères au moins, identique sur toutes les répliques ; sans lui, aléatoire à chaque démarrage |
| `SECREVIEW_SESSION_HOURS` | `8` | Contrôleur | Durée d'une session de l'interface web (1 à 24 heures) |
| `SECREVIEW_ENROLLMENT` | `true` | MCP | [Enrôlement](../advanced/http.md#enrolement-un-projet-demande-son-jeton) : un client sans jeton peut demander un jeton de projet (serveur MCP restreint, `POST /api/v1/enroll`), actif après approbation sur le contrôleur |
| `SECREVIEW_SERVER_URL` | — | Client | URL du serveur MCP partagé utilisé par [`security-review-mcp scan-deps`](../advanced/dependencies.md#scan-avec-un-serveur-partage-hook-de-commit) (valeur par défaut de `--url`) ; jamais utilisée par les serveurs |
| `SECREVIEW_TOKEN` | — | Client | Jeton Bearer envoyé par `scan-deps` à ce serveur, et par [`security-review-ci`](../usage/gate.md#client-de-pipeline-security-review-ci) au contrôleur (jeton `ci`) ; jamais utilisé par les serveurs |
| `SECREVIEW_CONTROLLER_URL` | — | Client | URL du contrôleur utilisée par [`security-review-ci`](../usage/gate.md#client-de-pipeline-security-review-ci) (valeur par défaut de `--url`) ; lue dans l'environnement uniquement, jamais dans `.env` |
| `SECREVIEW_TLS_CERTFILE` | — | les deux | Certificat : active le TLS |
| `SECREVIEW_TLS_KEYFILE` | — | les deux | Clé privée |
| `SECREVIEW_TLS_KEYFILE_PASSWORD` | — | les deux | Mot de passe de la clé privée |
| `SECREVIEW_TLS_CLIENT_CA` | — | les deux | CA cliente : active le TLS mutuel |
| `SECREVIEW_FORWARDED_ALLOW_IPS` | — | les deux | Reverse proxies (adresses IP ou plages CIDR séparées par des virgules, `*` pour tous) dont l'en-tête `X-Forwarded-For` donne l'adresse du client, utilisée par la limitation des connexions, les limites d'enrôlement et les journaux ; sans elle, la valeur par défaut d'uvicorn (variable `FORWARDED_ALLOW_IPS`, sinon `127.0.0.1`). À définir derrière un Ingress ou un reverse proxy, sinon tous les clients partagent l'adresse du proxy |
| `SECREVIEW_WEB_UI` | `true` | Contrôleur | Sert l'[interface web](../usage/web-interface.md) sur `/ui` ; à `false`, seulement l'API REST |
| `SECREVIEW_WEB_UI_DIR` | — | Contrôleur | Dossier d'une autre build de l'interface web |
| `SECREVIEW_OIDC_ENABLED` | `false` | Contrôleur | Active la [connexion SSO OpenID Connect](../advanced/sso.md) à l'interface web. Toutes les variables `SECREVIEW_OIDC_*` sauf `SECREVIEW_OIDC_CAFILE` se modifient aussi dans l'écran **Rôles SSO**, dont les valeurs enregistrées les remplacent ([configurer le SSO dans l'interface](../advanced/sso.md#configurer-le-sso-dans-linterface)) |
| `SECREVIEW_OIDC_ISSUER` | — | Contrôleur | URL de l'émetteur (HTTPS ; HTTP seulement sur localhost), dont `/.well-known/openid-configuration` est lu |
| `SECREVIEW_OIDC_CLIENT_ID` | — | Contrôleur | Identifiant du client déclaré chez le fournisseur |
| `SECREVIEW_OIDC_CLIENT_SECRET` | — | Contrôleur | Secret du client ; vide pour un client public (PKCE seul) |
| `SECREVIEW_OIDC_REDIRECT_URI` | — | Contrôleur | URL publique de `/api/v1/auth/oidc/callback`, déclarée chez le fournisseur |
| `SECREVIEW_OIDC_SCOPES` | `openid profile email` | Contrôleur | Scopes demandés (doit contenir `openid`) |
| `SECREVIEW_OIDC_ROLES_CLAIM` | `groups` | Contrôleur | Claim des groupes ou rôles, chemin pointé accepté (`realm_access.roles`) |
| `SECREVIEW_OIDC_ADMIN_GROUPS` | — | Contrôleur | Groupes qui donnent le rôle `admin` sur tous les projets, séparés par des virgules, en plus des associations du [role mapping](../advanced/sso.md#role-mapping) gérées dans l'interface |
| `SECREVIEW_OIDC_TRIAGER_GROUPS` | — | Contrôleur | Groupes qui donnent le rôle `triager` (tous les projets) |
| `SECREVIEW_OIDC_READER_GROUPS` | — | Contrôleur | Groupes qui donnent le rôle `reader` (tous les projets) |
| `SECREVIEW_OIDC_DEFAULT_ROLE` | — | Contrôleur | Rôle de groupe (tous les projets) sans aucune association correspondante : `reader`, `triager` ou vide (seul le rôle attribué au compte s'applique) |
| `SECREVIEW_OIDC_USERNAME_CLAIM` | `preferred_username` | Contrôleur | Claim qui nomme le [compte SSO](../advanced/sso.md#comptes-sso) (comparaison exacte, sans repli) ; label de session `oidc:<valeur>` |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Contrôleur | Crée le compte SSO à sa première connexion si ses groupes lui donnent un rôle ; à `false`, un administrateur crée chaque compte SSO dans **Utilisateurs** |
| `SECREVIEW_OIDC_DISPLAY_NAME` | `SSO` | Contrôleur | Nom affiché sur le bouton de connexion (40 caractères au plus) |
| `SECREVIEW_OIDC_CAFILE` | — | Contrôleur | Bundle de CA pour joindre le fournisseur (CA interne) ; le proxy est celui de `SECREVIEW_PROXY` |
| `SECREVIEW_PROXY` | — | Contrôleur | Proxy HTTP des connexions sortantes du contrôleur, téléchargement OSV et fournisseur SSO (`http://[utilisateur:mot de passe@]hôte:port`) ; sans lui, `HTTPS_PROXY` / `NO_PROXY` s'appliquent. Remplacé par le proxy choisi dans l'écran [Paramètres](../usage/web-interface.md#ecrans) (ou la connexion directe) |
| `SECREVIEW_NO_PROXY` | — | Contrôleur | [Hôtes joints sans `SECREVIEW_PROXY`](../advanced/dependencies.md#hotes-sans-proxy), séparés par des virgules : domaines (sous-domaines compris), adresses IP, plages CIDR (`10.0.0.0/8`, `fd00::/8`), `*` ; la boucle locale est toujours directe. Remplacé par la liste de l'écran Paramètres |
| `SECREVIEW_OSV_AUTO_UPDATE` | `false` | Contrôleur | [Mise à jour quotidienne](../advanced/dependencies.md#mise-a-jour-automatique-par-le-controleur) de la base OSV par `serve` |
| `SECREVIEW_OSV_UPDATE_INTERVAL_HOURS` | `24` | Contrôleur | Âge de la base au-delà duquel `serve` la met à jour (minimum `1`) |
| `SECREVIEW_OSV_URL` | `https://osv-vulnerabilities.storage.googleapis.com` | Contrôleur | Source des exports `<URL>/<écosystème>/all.zip` (HTTPS uniquement, miroir possible) |
| `SECREVIEW_OSV_ECOSYSTEMS` | `PyPI,npm,Maven` | Contrôleur | Écosystèmes téléchargés, séparés par des virgules |
| `SECREVIEW_OSV_CAFILE` | — | Contrôleur | Bundle de CA utilisé à la place de celui du système (miroir interne, proxy qui inspecte le TLS) |
| `SECREVIEW_OSV_MAX_DOWNLOAD_MB` | `1024` | Contrôleur | Taille maximale d'une archive téléchargée |
| `SECREVIEW_REPORT_LANGUAGE` | — | MCP | [Langue des rapports](../usage/prompts-tools.md#langue-des-rapports) demandée par les prompts de revue (`French`, `fr`...) quand l'argument `report_language` est absent et qu'aucune langue n'est choisie dans l'écran [Paramètres](../usage/web-interface.md#ecrans) ; vide : l'agent choisit |
| `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` | `90` | Contrôleur | Âge en jours au-delà duquel `serve` supprime les [rapports sans findings](#conservation-des-rapports-sans-findings) ; `0` conserve tous les rapports |
| `SECREVIEW_MAX_DISMISSAL_DAYS` | `365` | Contrôleur | Validité maximale en jours d'une [décision](../usage/web-interface.md#triage-des-findings) `accepted` ou `false_positive` : sa date d'expiration ne peut pas être plus lointaine |
| `SECREVIEW_TOKEN_MAX_DAYS` | `0` | Contrôleur | Validité maximale en jours d'un jeton Bearer créé ou [renouvelé](../advanced/http.md#expiration-et-renouvellement-des-jetons) (CLI, interface web, enrôlement), qui est aussi sa validité par défaut ; `0` : les jetons n'expirent pas, sauf validité demandée |
| `SECREVIEW_AUDIT_RETENTION_DAYS` | `365` | Contrôleur | Âge en jours au-delà duquel `serve` supprime les événements du [journal d'audit](../advanced/audit-metrics.md#journal-daudit) ; `0` conserve tous les événements |
| `SECREVIEW_METRICS_ENABLED` | `true` | Contrôleur | Sert les [métriques Prometheus](../advanced/audit-metrics.md#metriques-prometheus) sur `/metrics` (jeton `metrics` ou `admin`) ; à `false`, `/metrics` répond 404 |
| `SECREVIEW_LOG_LEVEL` | `INFO` | les deux | Niveau de journalisation (sur stderr) |
| `SECREVIEW_MAX_CONTENT_CHARS` | `200000` | MCP | Taille maximale du contenu passé à `scan_code` |
| `SECREVIEW_MAX_FINDINGS_PER_REPORT` | `500` | les deux | Nombre maximal de findings par rapport |
| `SECREVIEW_MAX_DEPENDENCY_CHARS` | `1000000` | MCP | Taille maximale d'un manifeste passé à `scan_dependencies` |
| `SECREVIEW_MAX_LIST_LIMIT` | `100` | les deux | Taille maximale d'une page de résultats |

Les jetons Bearer ne se configurent pas par variable : ils sont stockés en base et gérés avec
`security-review-controller token` (voir [Serveur HTTP, authentification et TLS](../advanced/http.md)).
Les règles internes non plus : elles sont stockées en base et gérées avec
`security-review-controller rules` (voir [Règles internes](../advanced/rules.md)).

## Base de données

SQLite par défaut. Pour PostgreSQL (extra `postgres`) :

```bash
SECREVIEW_DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/secreview
```

Le schéma est géré par des migrations Alembic embarquées dans le paquet :
`security-review-controller db upgrade` crée ou migre la base et amorce les règles par défaut,
`db status` affiche la révision (code `1` si elle n'est pas à jour). Voir
[Migrations du schéma](../advanced/architecture.md#migrations-du-schema).

### Conservation des rapports sans findings

Une revue propre (rapport sans aucun finding) prouve seulement que rien n'a été trouvé à cette
date. Le contrôleur supprime ces rapports dès qu'ils ont plus de
`SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` jours (`90` par défaut) : au démarrage de `serve`, puis
chaque jour. Le dernier rapport de chaque projet est toujours conservé, si bien qu'un projet ne
disparaît jamais de la liste, et un rapport avec des findings n'est jamais supprimé, quel que
soit leur statut. `0` désactive la purge.

La même purge peut être lancée à la demande, par exemple depuis une tâche planifiée quand le
contrôleur ne tourne pas :

```bash
security-review-controller db prune              # conservation de SECREVIEW_EMPTY_REPORT_RETENTION_DAYS
security-review-controller db prune --days 30    # une autre durée, pour cette exécution seulement
# {"retention_days": 30, "deleted": 4}
```
