# Jira

Le connecteur intégré **Jira** (type `jira`) crée un **ticket** pour chaque finding envoyé, dans
Jira Cloud ou Jira Data Center.

## Connexion

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_JIRA_URL` | — | Adresse de Jira, `https://` uniquement (`https://acme.atlassian.net`, ou l'URL de base d'un Data Center) |
| `SECREVIEW_JIRA_USERNAME` | — | Jira Cloud : adresse e-mail du compte, utilisée avec un jeton d'API. Vide : le jeton est un jeton d'accès personnel Data Center, envoyé comme jeton Bearer |
| `SECREVIEW_JIRA_API_TOKEN` | — | Jeton d'API (Cloud) ou jeton d'accès personnel (Data Center) |
| `SECREVIEW_JIRA_ISSUE_TYPE` | `Bug` | Type des tickets créés |

Le compte n'a besoin que de créer des tickets : les permissions *Parcourir les projets* et
*Créer des tickets* sur les projets utilisés.

## Destination

La destination d'un projet est la **clé du projet Jira** (`SEC`).

## Contenu d'un ticket

| Champ | Valeur |
|---|---|
| `summary` | `[HIGH] shop-api: SQL injection` |
| `description` | projet, sévérité, emplacement, règle, CWE, OWASP, branche, commit, lien vers le rapport, puis description, preuve et recommandation |
| `labels` | `security-review` et `severity-<sévérité>` |

Les textes du rapport sont placés dans des blocs `{noformat}` : écrits par un agent, ils ne sont
jamais interprétés comme du balisage wiki (liens, images chargées depuis un autre site).
