# Ligne de commande

Le paquet installe deux commandes, une par processus (voir
[Architecture et déploiement](../advanced/architecture.md)), et un client de pipeline :

- `security-review-mcp` : le **serveur MCP** (stdio ou HTTP), plus `enroll` et `scan-deps` côté client ;
- `security-review-controller` : le **contrôleur** (API REST et interface web), la base de
  données, l'administration et les commandes de pipeline ;
- `security-review-ci` : le **client de pipeline** de l'API REST du contrôleur (jeton `ci`,
  bibliothèque standard de Python uniquement, sans accès à la base).

## `security-review-mcp`

| Commande | Rôle | Page |
|---|---|---|
| `security-review-mcp [--transport …] [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Lance le serveur MCP | [Installation](../getting-started/deploy.md) |
| `enroll --url URL --project P [--label L] [--requested-by QUI] [--token-stdin] [--cafile CA] [--allow-http]` | Demande un nouveau jeton (label : `--label`, par défaut votre nom de connexion) ou, avec `--token-stdin`, un accès complémentaire pour le jeton lu sur stdin | [Enrôlement](../advanced/http.md#enrolement-un-projet-demande-son-jeton) |
| `scan-deps FICHIER… [--url URL] [--fail-on S] [--format json\|text] [--require-database] [--skip-unconfigured] [--token-stdin] [--cafile CA] [--allow-http]` | Analyse manifestes et lockfiles avec la base d'avis d'un serveur MCP partagé (jeton : `SECREVIEW_TOKEN`), pour un hook de commit | [Dépendances](../advanced/dependencies.md#scan-avec-un-serveur-partage-hook-de-commit) |

En stdio, le serveur migre lui-même sa base au démarrage (sauf `SECREVIEW_DB_AUTO_UPGRADE=false`).
En HTTP, il **vérifie seulement** le schéma : il refuse de démarrer (code `2`) tant que
`security-review-controller db upgrade` n'a pas été lancé.

!!! note "Anciennes sous-commandes"
    `security-review-mcp token|rules|gate|sarif|trend|advisories|deps|code|db` fonctionnent encore
    pendant la version 2 : elles affichent un avertissement sur stderr et exécutent la commande
    du contrôleur. Remplacez-les par `security-review-controller …`.

## `security-review-controller`

| Commande | Rôle | Page |
|---|---|---|
| `serve [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Sert l'API REST (`/api/v1`) et l'interface web (`/ui`) | [Serveur HTTP](../advanced/http.md) |
| `db upgrade` / `db status` | Migre le schéma (Alembic) et amorce les règles par défaut, ou affiche la révision | [Architecture et déploiement](../advanced/architecture.md#migrations-du-schema) |
| `db prune [--days N]` | Supprime les rapports sans findings de plus de `N` jours (par défaut `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS`), sauf le dernier de chaque projet | [Conservation](configuration.md#conservation-des-rapports-sans-findings) |
| `token create --label NOM [--role ROLE] [--project P …] [--expires-in-days N]` | Crée un jeton Bearer, éventuellement limité à plusieurs projets et avec une validité, et affiche son secret une fois | [Jetons Bearer](../advanced/http.md#jetons-bearer), [rôles](../usage/web-interface.md#roles) |
| `token list [--project P] [--pending]` / `token revoke ID\|LABEL` | Liste (ou seulement les demandes d'enrôlement en attente) ou révoque les jetons | [Jetons Bearer](../advanced/http.md#jetons-bearer) |
| `token rotate ID\|LABEL [--grace-hours H] [--expires-in-days N]` | Remplace le secret d'un jeton (même label, rôle et projets) et affiche le nouveau une fois ; l'ancien reste valable `H` heures (`0` à `168`) | [Expiration et renouvellement](../advanced/http.md#expiration-et-renouvellement-des-jetons) |
| `token approve ID\|LABEL` / `token reject ID\|LABEL` | Approuve ou refuse une demande d'enrôlement ; `approve --portal-user NOM` donne aussi à ce compte utilisateur la lecture du projet dans le portail (avec le SSO activé, un nom inconnu devient un compte SSO) | [Enrôlement](../advanced/http.md#enrolement-un-projet-demande-son-jeton), [lecture à l'enrôlement](../advanced/sso.md#lecture-du-projet-a-lenrolement) |
| `audit list [--action A] [--project P] [--actor QUI] [--since DATE] [--limit N] [--offset N]` / `audit prune [--days N]` | Lit le journal d'audit (JSON, du plus récent au plus ancien) ou supprime les événements de plus de `N` jours (par défaut `SECREVIEW_AUDIT_RETENTION_DAYS`) | [Journal d'audit](../advanced/audit-metrics.md#journal-daudit) |
| `user create NOM [--sso] [--role ROLE\|none] [--project P …] [--password-stdin]` | Crée un [compte de l'interface web](../usage/web-interface.md#comptes-utilisateurs) : local (sans `--password-stdin`, le mot de passe est généré et affiché une fois) ou SSO avec `--sso` (sans mot de passe ; `--role none` : seul le rôle de ses groupes) | [Comptes utilisateurs](../usage/web-interface.md#comptes-utilisateurs) |
| `user list` / `user set-role NOM --role ROLE\|none [--project P …]` / `user delete NOM` | Liste les comptes (jamais leur empreinte) avec leur type `auth_source`, change leur rôle et leurs projets (`none` : compte SSO seulement) ou les supprime (un compte SSO supprimé n'est plus recréé par une connexion) ; le dernier administrateur, local ou SSO, est conservé | [Comptes utilisateurs](../usage/web-interface.md#comptes-utilisateurs) |
| `user reset-password NOM [--password-stdin]` | Remplace le mot de passe d'un compte local (généré par défaut) et ferme ses sessions | [Premier administrateur](../usage/web-interface.md#premier-administrateur) |
| `code scan [PATH]` | Scan du dépôt complet | [Scan du code complet](../advanced/code-scan.md) |
| `rules list` / `rules import PATH…` / `rules export` | Liste, importe (packs TOML) ou exporte les règles stockées en base | [Règles internes](../advanced/rules.md#commande-rules) |
| `rules enable ID…` / `rules disable ID…` / `rules delete ID…` | Active, désactive (règles par défaut ou personnalisées) ou supprime des règles personnalisées | [Règles internes](../advanced/rules.md#commande-rules) |
| `deps scan FICHIER…` | Analyse de manifestes / lockfiles / SBOM CycloneDX | [Dépendances](../advanced/dependencies.md) |
| `advisories import PATH` / `advisories status` | Gestion de la base OSV hors ligne | [Dépendances](../advanced/dependencies.md#base-de-vulnerabilites-hors-ligne-format-osv) |
| `advisories update [--ecosystem E …]` | Télécharge les exports OSV (`SECREVIEW_OSV_*`, proxy facultatif) et les importe ; code `2` si un écosystème échoue | [Mise à jour automatique](../advanced/dependencies.md#mise-a-jour-automatique-par-le-controleur) |
| `gate --project P --fail-on SEV` | Gate de déploiement | [Gate](../usage/gate.md) |
| `sarif --project P` / `--report-id N` | Export SARIF 2.1.0 | [SARIF](../advanced/sarif.md) |
| `trend --project P` | Rapport de tendance | [Tendances](../advanced/trends.md) |

`serve` et les commandes qui lisent ou écrivent la base migrent d'abord le schéma, sauf avec
`SECREVIEW_DB_AUTO_UPGRADE=false` : elles vérifient alors seulement qu'il est à jour.

## `security-review-ci`

Options de toutes les sous-commandes : `--project P` (obligatoire), `--url URL` (par défaut
`SECREVIEW_CONTROLLER_URL`), `--token-stdin` (par défaut : `SECREVIEW_TOKEN`), `--cafile CA`,
`--allow-http`, `--timeout S`.

| Commande | Rôle | Page |
|---|---|---|
| `gate --project P [--fail-on SEV] [--report-id N]` | Gate de déploiement par l'API REST | [Client de pipeline](../usage/gate.md#client-de-pipeline-security-review-ci) |
| `sarif --project P [--include-resolved] [-o FICHIER]` | Export SARIF 2.1.0 par l'API REST | [SARIF](../advanced/sarif.md) |
| `trend --project P [--days N] [--granularity G] [--format markdown\|json]` | Rapport de tendance par l'API REST | [Tendances](../advanced/trends.md) |

## Codes de sortie

Les commandes de contrôle (`code scan`, `deps scan`, `gate`, `security-review-ci gate`, `db status`) partagent la même
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
