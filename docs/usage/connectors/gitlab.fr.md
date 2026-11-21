# GitLab

Le connecteur **GitLab** ouvre un **ticket** pour chaque finding envoyé, sur gitlab.com ou un
GitLab autogéré. Les tickets sont **confidentiels** par défaut. Les variables sont dans
[Connecteurs en détail](../../advanced/connectors.md#gitlab).

## Connexion

| Champ | Valeur |
|---|---|
| URL | L'adresse de GitLab, en HTTPS (`https://gitlab.com`, ou l'adresse d'une instance autogérée) |
| **Jeton d'accès** | Un jeton d'accès personnel, de groupe ou de projet avec le scope `api`, d'un membre autorisé à créer des tickets (*Reporter* ou plus) |
| **Tickets confidentiels** | `true` (par défaut) : seuls les membres du projet autorisés à voir les tickets confidentiels les lisent ; `false` : visibles par quiconque lit le projet |

## Destination

La destination d'un projet est l'**ID du projet GitLab**, le nombre affiché sur la page du projet
(`42`). Son chemin (`groupe/projet`) n'est pas accepté : il serait envoyé encodé, ce que les
connecteurs refusent.

## Contenu d'un ticket

- **Titre** : `[HIGH] shop-api: SQL injection` ;
- **Description** : le projet, la criticité, l'emplacement, la règle, la CWE, la branche, le
  commit et un lien vers le rapport, puis la description, la preuve et la recommandation du
  finding ;
- **Labels** : `security-review` et `severity-<criticité>`.

Les textes écrits par les agents sont affichés comme du code : ils ne mentionnent jamais personne
(`@équipe`), ne chargent aucune image, n'ajoutent aucun lien et n'exécutent aucune commande rapide
(`/close`).
