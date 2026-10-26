# Jira

Le connecteur **Jira** crée un **ticket** pour chaque finding envoyé, dans Jira Cloud ou Jira Data
Center. Les variables sont dans [Connecteurs en détail](../advanced/connectors.md#jira).

## Connexion

| Champ | Valeur |
|---|---|
| URL | L'adresse de Jira, en HTTPS (`https://acme.atlassian.net`, ou l'adresse d'un Data Center) |
| **Compte** | Jira Cloud : l'adresse e-mail du compte. Vide pour Data Center |
| **Jeton d'API** | Un jeton d'API (Cloud) ou un jeton d'accès personnel (Data Center) |
| **Type de ticket** | Le type des tickets créés (`Bug` par défaut) |

Le compte n'a besoin que de parcourir les projets Jira utilisés et d'y créer des tickets.

## Destination

La destination d'un projet est sa **clé du projet Jira** (`SEC`).

## Contenu d'un ticket

- **Résumé** : `[HIGH] shop-api: SQL injection` ;
- **Description** : le projet, la sévérité, l'emplacement, la règle, la CWE, la branche, le commit
  et un lien vers le rapport, puis la description, la preuve et la recommandation du finding ;
- **Étiquettes** : `security-review` et `severity-<sévérité>`, pour les filtrer dans Jira.

Les textes écrits par les agents sont affichés tels quels : jamais comme de la mise en forme Jira
(liens, images).
