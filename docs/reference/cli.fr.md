# Ligne de commande

Le paquet `security-review` installe deux commandes, une par processus (voir
[Architecture](../advanced/architecture/index.md)), et un client de pipeline :

- `security-review-mcp` : le **serveur MCP** (stdio ou HTTP) ;
- `security-review-controller` : le **contrôleur** (API REST et interface web), la base de
  données et l'administration ;
- `security-review-ci` : le **client de pipeline** de l'API REST du contrôleur (jeton `ci`,
  bibliothèque standard de Python uniquement, sans accès à la base) : gate, SARIF, tendance,
  scans du code et des dépendances. Il est aussi publié seul, sans le serveur, dans le paquet
  `security-review-ci` (Python 3.14, voir [Installation](../advanced/architecture/ci.md#installation)).

```bash
uv pip install security-review-ci
```

## `security-review-mcp`

| Commande | Rôle | Page |
|---|---|---|
| `serve [--transport …] [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Lance le serveur MCP (`streamable-http` par défaut, pour le mode partagé ; `--transport stdio` n'accepte qu'une base SQLite) | [Installation manuelle](../advanced/deployment/manual-install.md#5-lancer-le-serveur-mcp) |
| `local` | Lance le serveur MCP du mode local (stdio), sur la base SQLite locale : ignore les bases distantes, donc `SECREVIEW_DATABASE_URL` | [Mode local](../getting-started/stdio.md) |

Sans commande, `security-review-mcp` affiche son aide.

En stdio, le serveur migre lui-même sa base au démarrage (sauf `SECREVIEW_DB_AUTO_UPGRADE=false`).
En HTTP, il **vérifie seulement** le schéma : il refuse de démarrer (code `2`) tant que
`security-review-controller db upgrade` n'a pas été lancé.

## `security-review-controller`

| Commande | Rôle | Page |
|---|---|---|
| `serve [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Sert l'API REST (`/api/v1`) et l'interface web (`/ui`) | [Contrôleur](../advanced/architecture/controller.md), [TLS](../advanced/tls.md) |
| `db upgrade` / `db status` | Migre le schéma (Alembic) et amorce les règles par défaut, ou affiche la révision | [Migrations du schéma](../advanced/architecture/controller.md#migrations-du-schema) |
| `db prune [--days N]` | Supprime les rapports sans findings de plus de `N` jours (par défaut `SECREVIEW_EMPTY_REPORT_RETENTION_DAYS`), sauf le dernier de chaque projet | [Conservation](configuration.md#conservation-des-rapports-sans-findings) |
| `token create --label NOM [--role ROLE] [--project P …] [--expires-in-days N]` | Crée un jeton Bearer, éventuellement limité à plusieurs projets et avec une validité, et affiche son secret une fois | [Jetons Bearer](../advanced/bearer-tokens.md), [rôles](../usage/tokens.md) |
| `token list [--project P]` / `token revoke ID\|LABEL` | Liste ou révoque les jetons | [Jetons Bearer](../advanced/bearer-tokens.md) |
| `token rotate ID\|LABEL [--grace-hours H] [--expires-in-days N]` | Remplace le secret d'un jeton (même label, rôle et projets) et affiche le nouveau une fois ; l'ancien reste valable `H` heures (`0` à `168`) | [Expiration et renouvellement](../advanced/bearer-tokens.md#expiration-et-renouvellement-des-jetons) |
| `audit list [--action A] [--project P] [--actor QUI] [--since DATE] [--limit N] [--offset N]` / `audit prune [--days N] [--max-events N]` | Lit le journal d'audit (JSON, du plus récent au plus ancien) ou supprime les événements de plus de `N` jours (par défaut `SECREVIEW_AUDIT_RETENTION_DAYS`), puis les plus anciens au-delà de `--max-events` (par défaut `SECREVIEW_AUDIT_MAX_EVENTS`) | [Journal d'audit](../advanced/audit-log.md) |
| `user create NOM [--sso] [--group G …] [--password-stdin]` | Crée un [compte de l'interface web](../usage/user-accounts.md), membre des groupes `G` (seule source de ses permissions) : local (sans `--password-stdin`, le mot de passe est généré et affiché une fois) ou OIDC avec `--sso` (sans mot de passe ; il rejoint aussi ses groupes OIDC à chaque connexion) | [Comptes utilisateurs](../usage/user-accounts.md) |
| `user list` / `user set-groups NOM [--group G …]` / `user delete NOM` | Liste les comptes (jamais leur empreinte) avec leurs groupes et permissions, remplace les groupes donnés à un compte (ses groupes OIDC sont gardés ; `administrators` est créé avec le rôle `admin` s'il manque, pour restaurer un administrateur) ou le supprime (un compte OIDC supprimé n'est plus recréé par une connexion) ; le dernier détenteur de `users.manage` est conservé | [Comptes utilisateurs](../usage/user-accounts.md) |
| `group list` / `group roles` | Liste les groupes (rôles, projets, membres) ou les rôles (permissions) ; ils se gèrent dans l'interface web | [Rôles, groupes et permissions](../usage/access-control.md#groupes) |
| `project list` / `project approve ID` / `project reject ID` | Liste les projets demandés par les agents MCP des utilisateurs (demandeur, adresse, expiration ; `existing` : demande d'accès à un projet existant), ajoute le demandeur au groupe `project:<projet>` (créé pour un nouveau projet) ou supprime la demande | [Enrôlement](../advanced/architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet) |
| `user reset-password NOM [--password-stdin]` | Remplace le mot de passe d'un compte local (généré par défaut) et ferme ses sessions | [Mot de passe perdu](../advanced/architecture/controller.md#mot-de-passe-perdu) |
| `rules list` / `rules import PATH…` / `rules export` | Liste, importe (packs TOML) ou exporte les règles stockées en base | [Règles](../review/rules.md#commande-rules) |
| `rules enable ID…` / `rules disable ID…` / `rules delete ID…` | Active, désactive (règles par défaut ou personnalisées) ou supprime des règles personnalisées | [Règles](../review/rules.md#commande-rules) |
| `advisories import PATH` / `advisories status` | Gestion de la base OSV hors ligne | [Dépendances](../review/analysis/dependencies.md#base-de-vulnerabilites-hors-ligne-format-osv) |
| `advisories update [--ecosystem E …]` | Télécharge les exports OSV (`SECREVIEW_OSV_*`, proxy facultatif) et les importe ; code `2` si un écosystème échoue | [Mise à jour automatique](../review/analysis/dependencies.md#mise-a-jour-automatique-par-le-controleur) |

Lors de l'exécution de `serve`, la donnée de donnée est vérifier et la migration du schéma est réalisé si cela est nécessaire.
La variable `SECREVIEW_DB_AUTO_UPGRADE=false` désactive la migration du schéma.

## `security-review-ci`

Options de toutes les sous-commandes sauf `agent-review` : `--project P` (obligatoire), `--url URL` (par défaut
`SECREVIEW_CONTROLLER_URL`), `--token-stdin` (par défaut : `SECREVIEW_TOKEN`), `--cafile CA`,
`--allow-http`, `--timeout S`. Sans argument, `security-review-ci` affiche son aide et sort
avec le code `2`.

| Commande | Rôle | Page |
|---|---|---|
| `gate --project P [--fail-on SEV] [--report-id N]` | Gate de déploiement par l'API REST | [Client de pipeline](../advanced/architecture/ci.md) |
| `sarif --project P [--include-resolved] [-o FICHIER]` | Export SARIF 2.1.0 par l'API REST | [SARIF](../advanced/reports/sarif.md) |
| `trend --project P [--days N] [--granularity G] [--format markdown\|json]` | Rapport de tendance par l'API REST | [Tendances](../advanced/architecture/ci.md#rapport-de-tendance) |
| `scan-code [PATH] --project P [--exclude GLOB …] [--max-file-bytes N] [--no-git] [--fail-on SEV] [--format text\|json\|sarif] [-o FICHIER] [--save]` | Lit les fichiers du dépôt et les fait scanner par le contrôleur avec ses règles ; `--save` enregistre un rapport | [Scan du code complet](../review/analysis/code-scan.md) |
| `scan-deps FICHIER… --project P [--fail-on SEV] [--format text\|json] [--require-database] [--skip-unconfigured] [--save]` | Envoie des manifestes, lockfiles ou SBOM CycloneDX au contrôleur, qui les compare à sa base d'avis ; `--save` enregistre un rapport | [Dépendances](../review/analysis/dependencies.md#scan-dans-un-pipeline-security-review-ci-scan-deps) |
| `agent-review --project P [--agent claude\|copilot\|codex] [--mcp-config FICHIER] [--mcp-server NOM] [--foreground]` | Fait relire le dernier commit par l'agent de code du développeur avec le serveur MCP `security-review` de sa configuration MCP (hook post-commit) ; ne contacte jamais le contrôleur ; sort avec `0` quand la revue démarre ou est sautée, `2` hors d'un dépôt git | [Client de pipeline](../advanced/architecture/ci.md#revue-de-chaque-commit-par-un-agent) |

`scan-code` et `scan-deps` acceptent aussi `--repository`, `--branch`, `--commit` et `--author`,
enregistrés avec le rapport (`--author` est inutile avec un jeton personnel, dont l'utilisateur
est l'auteur). Ils demandent un jeton `ci` ou `admin` (sur un poste de travail, un
[jeton `mcp` ou `ci` personnel](../usage/tokens.md#jetons-mcp-et-ci-personnels)).
`--skip-unconfigured` sort avec `0` et un avertissement quand aucune URL de contrôleur n'est
définie (hook de commit).
## Codes de sortie

Les commandes de contrôle (`security-review-ci gate`, `scan-code` et `scan-deps`, `db status`) partagent la même
convention :

| Code | Signification |
|---|---|
| `0` | Passe |
| `1` | Bloqué : au moins un finding atteint le seuil `--fail-on` (ou, pour `db status`, schéma pas à jour) |
| `2` | Erreur (projet ou rapport introuvable, fichier illisible, schéma à migrer…) |

Les commandes d'administration (`token`, `rules`, `advisories`, `db upgrade`,
`db prune`)
renvoient `0` en cas de succès et `2` en cas d'erreur (identifiant inconnu, pack invalide…),
avec l'erreur en JSON sur stderr.

Chaque commande accepte `--help` pour la liste complète de ses options.
