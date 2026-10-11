# Ligne de commande

Sans sous-commande, `security-review-mcp` lance le serveur MCP. Les sous-commandes servent aux
pipelines et à l'administration.

| Commande | Rôle | Page |
|---|---|---|
| `security-review-mcp [--transport …] [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Lance le serveur MCP | [Installation](../demarrage/installation.md#lancement) |
| `token create --label NOM [--role ROLE] [--project P]` | Crée un jeton Bearer en base et affiche son secret une fois | [Jetons Bearer](../demarrage/http.md#jetons-bearer), [rôles](../utilisation/interface-web.md#roles) |
| `token list [--project P]` / `token revoke ID\|LABEL` | Liste ou révoque les jetons | [Jetons Bearer](../demarrage/http.md#jetons-bearer) |
| `token reset-admin` | Remplace le mot de passe admin initial et l'affiche | [Mot de passe initial](../demarrage/http.md#mot-de-passe-administrateur-initial) |
| `code scan [PATH]` | Scan du dépôt complet | [Scan du code complet](../utilisation/code-scan.md) |
| `rules list` / `rules import PATH…` / `rules export` | Liste, importe (packs TOML) ou exporte les règles stockées en base | [Règles internes](../utilisation/regles.md#commande-rules) |
| `rules enable ID…` / `rules disable ID…` / `rules delete ID…` | Active, désactive (règles par défaut ou personnalisées) ou supprime des règles personnalisées | [Règles internes](../utilisation/regles.md#commande-rules) |
| `deps scan FICHIER…` | Analyse de manifestes / lockfiles | [Dépendances](../utilisation/dependances.md) |
| `advisories import PATH` / `advisories status` | Gestion de la base OSV hors ligne | [Dépendances](../utilisation/dependances.md#base-de-vulnerabilites-hors-ligne-format-osv) |
| `gate --project P --fail-on SEV` | Gate de déploiement | [Gate](../ci-cd/gate.md) |
| `sarif --project P` / `--report-id N` | Export SARIF 2.1.0 | [SARIF](../ci-cd/sarif.md) |
| `trend --project P` | Rapport de tendance | [Tendances](../ci-cd/tendances.md) |

## Codes de sortie

Les commandes de contrôle (`code scan`, `deps scan`, `gate`) partagent la même convention :

| Code | Signification |
|---|---|
| `0` | Passe |
| `1` | Bloqué : au moins un finding atteint le seuil `--fail-on` |
| `2` | Erreur (projet ou rapport introuvable, fichier illisible…) |

Les commandes d'administration (`token`, `rules`, `advisories`) renvoient `0` en cas de succès
et `2` en cas d'erreur (identifiant inconnu, pack invalide…), avec l'erreur en JSON sur stderr.

Chaque commande accepte `--help` pour la liste complète de ses options.
