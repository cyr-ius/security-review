# Ligne de commande

Le paquet installe deux commandes, une par processus (voir
[Architecture et déploiement](../advanced/architecture.md)), et un client de pipeline :

- `security-review-mcp` : le **serveur MCP** (stdio ou HTTP), plus `enroll` et `scan-deps` côté client ;
- `security-review-controller` : le **contrôleur** (API REST et interface web), la base de
  données et l'administration ;
- `security-review-ci` : le **client de pipeline** de l'API REST du contrôleur (jeton `ci`,
  bibliothèque standard de Python uniquement, sans accès à la base) : gate, SARIF, tendance,
  scans du code et des dépendances.

## `security-review-mcp`

| Commande | Rôle | Page |
|---|---|---|
| `serve [--transport …] [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Lance le serveur MCP (stdio par défaut, `streamable-http` pour un serveur partagé) | [Installation](../getting-started/deploy.md) |
| `enroll --url URL --project P [--requested-by QUI] [--cafile CA] [--allow-http]` | Demande le projet sur un serveur partagé, validé par un administrateur (inchangé s'il existe ou est en attente ; demandeur : `--requested-by`, par défaut votre nom de connexion) ; aucun jeton n'est créé : la réponse donne l'URL de l'interface web où créer un jeton MCP personnel | [Enrôlement](../advanced/http.md#enrolement-demander-le-projet) |
| `scan-deps FICHIER… [--url URL] [--fail-on S] [--format json\|text] [--require-database] [--skip-unconfigured] [--token-stdin] [--cafile CA] [--allow-http]` | Analyse manifestes et lockfiles avec la base d'avis d'un serveur MCP partagé (jeton : `SECREVIEW_TOKEN`), pour un hook de commit | [Dépendances](../advanced/dependencies.md#scan-avec-un-serveur-partage-hook-de-commit) |

Sans commande, `security-review-mcp` affiche son aide sur stderr et sort avec le code `2`
(`security-review-mcp --help` l'affiche sur stdout) : un hôte MCP doit lancer `security-review-mcp serve`.

En stdio, le serveur migre lui-même sa base au démarrage (sauf `SECREVIEW_DB_AUTO_UPGRADE=false`).
En HTTP, il **vérifie seulement** le schéma : il refuse de démarrer (code `2`) tant que
`security-review-controller db upgrade` n'a pas été lancé.

!!! note "Anciennes sous-commandes"
    `security-review-mcp token|rules|advisories|db` sont dépréciées :
    elles affichent un avertissement sur stderr et exécutent la commande
    du contrôleur. Remplacez-les par `security-review-controller …`.

## `security-review-controller`

| Commande | Rôle | Page |
|---|---|---|
| `serve [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Sert l'API REST (`/api/v1`) et l'interface web (`/ui`) | [Serveur HTTP](../advanced/http.md) |
| `db upgrade` / `db status` | Migre le schéma (Alembic) et amorce les règles par défaut, ou affiche la révision | [Architecture et déploiement](../advanced/architecture.md#migrations-du-schema) |
| `db prune [--days N]` | Supprime les rapports sans findings de plus de `N` jours (par défaut `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS`), sauf le dernier de chaque projet | [Conservation](configuration.md#conservation-des-rapports-sans-findings) |
| `token create --label NOM [--role ROLE] [--project P …] [--expires-in-days N]` | Crée un jeton Bearer, éventuellement limité à plusieurs projets et avec une validité, et affiche son secret une fois | [Jetons Bearer](../advanced/http.md#jetons-bearer), [rôles](../usage/web-interface.md#roles) |
| `token list [--project P]` / `token revoke ID\|LABEL` | Liste ou révoque les jetons | [Jetons Bearer](../advanced/http.md#jetons-bearer) |
| `token rotate ID\|LABEL [--grace-hours H] [--expires-in-days N]` | Remplace le secret d'un jeton (même label, rôle et projets) et affiche le nouveau une fois ; l'ancien reste valable `H` heures (`0` à `168`) | [Expiration et renouvellement](../advanced/http.md#expiration-et-renouvellement-des-jetons) |
| `audit list [--action A] [--project P] [--actor QUI] [--since DATE] [--limit N] [--offset N]` / `audit prune [--days N] [--max-events N]` | Lit le journal d'audit (JSON, du plus récent au plus ancien) ou supprime les événements de plus de `N` jours (par défaut `SECREVIEW_AUDIT_RETENTION_DAYS`), puis les plus anciens au-delà de `--max-events` (par défaut `SECREVIEW_AUDIT_MAX_EVENTS`) | [Journal d'audit](../advanced/audit-metrics.md#journal-daudit) |
| `user create NOM [--sso] [--group G …] [--password-stdin]` | Crée un [compte de l'interface web](../usage/web-interface.md#comptes-utilisateurs), membre des groupes `G` (seule source de ses permissions) : local (sans `--password-stdin`, le mot de passe est généré et affiché une fois) ou OIDC avec `--sso` (sans mot de passe ; il rejoint aussi ses groupes OIDC à chaque connexion) | [Comptes utilisateurs](../usage/web-interface.md#comptes-utilisateurs) |
| `user list` / `user set-groups NOM [--group G …]` / `user delete NOM` | Liste les comptes (jamais leur empreinte) avec leurs groupes et permissions, remplace les groupes donnés à un compte (ses groupes OIDC sont gardés ; `administrators` est créé avec le rôle `admin` s'il manque, pour restaurer un administrateur) ou le supprime (un compte OIDC supprimé n'est plus recréé par une connexion) ; le dernier détenteur de `users.manage` est conservé | [Comptes utilisateurs](../usage/web-interface.md#comptes-utilisateurs) |
| `group list` / `group roles` | Liste les groupes (rôles, projets, membres) ou les rôles (permissions) ; ils se gèrent dans l'interface web | [Rôles, groupes et permissions](../advanced/access-control.md) |
| `project list` / `project approve ID` / `project reject ID` | Liste les projets demandés par un enrôlement (demandeur, adresse, expiration), en crée un (son groupe `project:<projet>`, sans aucun membre) ou supprime la demande | [Enrôlement](../advanced/http.md#enrolement-demander-le-projet) |
| `user reset-password NOM [--password-stdin]` | Remplace le mot de passe d'un compte local (généré par défaut) et ferme ses sessions | [Mot de passe perdu](../usage/web-interface.md#mot-de-passe-perdu) |
| `rules list` / `rules import PATH…` / `rules export` | Liste, importe (packs TOML) ou exporte les règles stockées en base | [Règles internes](../advanced/rules.md#commande-rules) |
| `rules enable ID…` / `rules disable ID…` / `rules delete ID…` | Active, désactive (règles par défaut ou personnalisées) ou supprime des règles personnalisées | [Règles internes](../advanced/rules.md#commande-rules) |
| `advisories import PATH` / `advisories status` | Gestion de la base OSV hors ligne | [Dépendances](../advanced/dependencies.md#base-de-vulnerabilites-hors-ligne-format-osv) |
| `advisories update [--ecosystem E …]` | Télécharge les exports OSV (`SECREVIEW_OSV_*`, proxy facultatif) et les importe ; code `2` si un écosystème échoue | [Mise à jour automatique](../advanced/dependencies.md#mise-a-jour-automatique-par-le-controleur) |

`serve` et les commandes qui lisent ou écrivent la base migrent d'abord le schéma, sauf avec
`SECREVIEW_DB_AUTO_UPGRADE=false` : elles vérifient alors seulement qu'il est à jour.

Les commandes de pipeline (gate, export SARIF, rapport de tendance, scans du code et des
dépendances) ne sont pas des commandes du contrôleur : elles sont exécutées par
[`security-review-ci`](#security-review-ci), par l'API REST.

## `security-review-ci`

Options de toutes les sous-commandes : `--project P` (obligatoire), `--url URL` (par défaut
`SECREVIEW_CONTROLLER_URL`), `--token-stdin` (par défaut : `SECREVIEW_TOKEN`), `--cafile CA`,
`--allow-http`, `--timeout S`. Sans argument, `security-review-ci` affiche son aide et sort
avec le code `2`.

| Commande | Rôle | Page |
|---|---|---|
| `gate --project P [--fail-on SEV] [--report-id N]` | Gate de déploiement par l'API REST | [Client de pipeline](../usage/gate.md#client-de-pipeline-security-review-ci) |
| `sarif --project P [--include-resolved] [-o FICHIER]` | Export SARIF 2.1.0 par l'API REST | [SARIF](../advanced/sarif.md) |
| `trend --project P [--days N] [--granularity G] [--format markdown\|json]` | Rapport de tendance par l'API REST | [Tendances](../advanced/trends.md) |
| `code-scan [PATH] --project P [--exclude GLOB …] [--max-file-bytes N] [--no-git] [--fail-on SEV] [--format text\|json\|sarif] [-o FICHIER] [--save]` | Lit les fichiers du dépôt et les fait scanner par le contrôleur avec ses règles ; `--save` enregistre un rapport | [Scan du code complet](../advanced/code-scan.md) |
| `deps-scan FICHIER… --project P [--fail-on SEV] [--format text\|json] [--require-database] [--save]` | Envoie des manifestes, lockfiles ou SBOM CycloneDX au contrôleur, qui les compare à sa base d'avis ; `--save` enregistre un rapport | [Dépendances](../advanced/dependencies.md#scan-dans-un-pipeline-security-review-ci-deps-scan) |

`code-scan` et `deps-scan` acceptent aussi `--repository`, `--branch`, `--commit` et `--author`,
enregistrés avec le rapport. Ils demandent un jeton `ci` ou `admin`.
## Codes de sortie

Les commandes de contrôle (`security-review-ci gate`, `code-scan` et `deps-scan`, `scan-deps`, `db status`) partagent la même
convention :

| Code | Signification |
|---|---|
| `0` | Passe |
| `1` | Bloqué : au moins un finding atteint le seuil `--fail-on` (ou, pour `db status`, schéma pas à jour) |
| `2` | Erreur (projet ou rapport introuvable, fichier illisible, schéma à migrer…) |

Les commandes d'administration (`token`, `enroll`, `rules`, `advisories`, `db upgrade`,
`db prune`)
renvoient `0` en cas de succès et `2` en cas d'erreur (identifiant inconnu, pack invalide…),
avec l'erreur en JSON sur stderr.

Chaque commande accepte `--help` pour la liste complète de ses options.
