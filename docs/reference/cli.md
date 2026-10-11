# Ligne de commande

Sans sous-commande, `security-review-mcp` lance le serveur MCP. Les sous-commandes servent aux
pipelines et à l'administration.

| Commande | Rôle | Page |
|---|---|---|
| `security-review-mcp [--transport …] [--host …] [--port …] [--tls-certfile …] [--tls-keyfile …]` | Lance le serveur MCP | [Installation](../demarrage/installation.md#lancement) |
| `token --label NOM` | Génère un jeton Bearer et son entrée de configuration | [HTTP](../demarrage/http.md#jetons-bearer) |
| `code scan [PATH]` | Scan du dépôt complet | [Scan du code complet](../utilisation/code-scan.md) |
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

Chaque commande accepte `--help` pour la liste complète de ses options.
