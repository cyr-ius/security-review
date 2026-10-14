# Ligne de commande

Le paquet installe deux commandes, une par processus (voir
[Architecture et déploiement](../demarrage/kubernetes.md)) :

- `security-review-mcp` : le **serveur MCP** (stdio ou HTTP), plus `enroll` côté client ;
- `security-review-controller` : le **contrôleur** (API REST et interface web), la base de
  données, l'administration et les commandes de pipeline.

## `security-review-mcp`

| Commande | Rôle | Page |
|---|---|---|
| `security-review-mcp [--transport …] [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …] [--tls-self-signed]` | Lance le serveur MCP | [Installation](../demarrage/installation.md#lancement) |
| `enroll --url URL --project P [--label L] [--requested-by QUI] [--token-stdin] [--cafile CA] [--allow-http]` | Demande un nouveau jeton ou, avec `--token-stdin`, un accès complémentaire pour le jeton lu sur stdin | [Enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton) |

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
| `serve [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …] [--tls-self-signed]` | Sert l'API REST (`/api/v1`) et l'interface web (`/ui`) | [Serveur HTTP](../demarrage/http.md) |
| `db upgrade` / `db status` | Migre le schéma (Alembic) et amorce les règles par défaut, ou affiche la révision | [Architecture et déploiement](../demarrage/kubernetes.md#migrations-du-schema) |
| `token create --label NOM [--role ROLE] [--project P …]` | Crée un jeton Bearer, éventuellement limité à plusieurs projets, et affiche son secret une fois | [Jetons Bearer](../demarrage/http.md#jetons-bearer), [rôles](../utilisation/interface-web.md#roles) |
| `token list [--project P] [--pending]` / `token revoke ID\|LABEL` | Liste (ou seulement les demandes d'enrôlement en attente) ou révoque les jetons | [Jetons Bearer](../demarrage/http.md#jetons-bearer) |
| `token approve ID\|LABEL` / `token reject ID\|LABEL` | Approuve ou refuse une demande d'enrôlement ; `approve --portal-user NOM` donne aussi à cet utilisateur SSO la lecture du projet dans le portail | [Enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton), [accès nominatifs](../utilisation/interface-web.md#acces-nominatifs-enrolement) |
| `token reset-admin` | Remplace le mot de passe admin initial et l'affiche | [Mot de passe initial](../demarrage/http.md#mot-de-passe-administrateur-initial) |
| `code scan [PATH]` | Scan du dépôt complet | [Scan du code complet](../utilisation/code-scan.md) |
| `rules list` / `rules import PATH…` / `rules export` | Liste, importe (packs TOML) ou exporte les règles stockées en base | [Règles internes](../utilisation/regles.md#commande-rules) |
| `rules enable ID…` / `rules disable ID…` / `rules delete ID…` | Active, désactive (règles par défaut ou personnalisées) ou supprime des règles personnalisées | [Règles internes](../utilisation/regles.md#commande-rules) |
| `deps scan FICHIER…` | Analyse de manifestes / lockfiles | [Dépendances](../utilisation/dependances.md) |
| `advisories import PATH` / `advisories status` | Gestion de la base OSV hors ligne | [Dépendances](../utilisation/dependances.md#base-de-vulnerabilites-hors-ligne-format-osv) |
| `advisories update [--ecosystem E …]` | Télécharge les exports OSV (`SECREVIEW_OSV_*`, proxy facultatif) et les importe ; code `2` si un écosystème échoue | [Mise à jour automatique](../utilisation/dependances.md#mise-a-jour-automatique-par-le-controleur) |
| `gate --project P --fail-on SEV` | Gate de déploiement | [Gate](../ci-cd/gate.md) |
| `sarif --project P` / `--report-id N` | Export SARIF 2.1.0 | [SARIF](../ci-cd/sarif.md) |
| `trend --project P` | Rapport de tendance | [Tendances](../ci-cd/tendances.md) |

`serve` et les commandes qui lisent ou écrivent la base migrent d'abord le schéma, sauf avec
`SECREVIEW_DB_AUTO_UPGRADE=false` : elles vérifient alors seulement qu'il est à jour.

## Codes de sortie

Les commandes de contrôle (`code scan`, `deps scan`, `gate`, `db status`) partagent la même
convention :

| Code | Signification |
|---|---|
| `0` | Passe |
| `1` | Bloqué : au moins un finding atteint le seuil `--fail-on` (ou, pour `db status`, schéma pas à jour) |
| `2` | Erreur (projet ou rapport introuvable, fichier illisible, schéma à migrer…) |

Les commandes d'administration (`token`, `enroll`, `rules`, `advisories`, `db upgrade`)
renvoient `0` en cas de succès et `2` en cas d'erreur (identifiant inconnu, pack invalide…),
avec l'erreur en JSON sur stderr.

Chaque commande accepte `--help` pour la liste complète de ses options.
