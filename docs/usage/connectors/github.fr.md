# GitHub

Le connecteur **GitHub** ouvre une **issue** pour chaque finding envoyé, sur github.com ou GitHub
Enterprise Server. Les variables sont dans
[Connecteurs en détail](../../advanced/connectors.md#github).

## Connexion

| Champ | Valeur |
|---|---|
| URL | L'adresse de l'API GitHub, en HTTPS : `https://api.github.com`, ou `https://<hôte>/api/v3` pour GitHub Enterprise Server |
| **Jeton d'accès** | Un jeton d'accès personnel à granularité fine avec la permission *Issues : lecture et écriture* sur les dépôts utilisés (ou un jeton classique avec le scope `repo`) |

## Destination

La destination d'un projet est son **dépôt GitHub**, sous la forme `propriétaire/dépôt`
(`acme/shop`).

Les issues GitHub n'ont pas d'indicateur de confidentialité : quiconque lit le dépôt les lit.
Envoyez les findings vers un dépôt **privé**, lisible uniquement par les équipes qui les corrigent.

## Contenu d'une issue

- **Titre** : `[HIGH] shop-api: SQL injection` ;
- **Description** : le projet, la criticité, l'emplacement, la règle, la CWE, la branche, le
  commit et un lien vers le rapport, puis la description, la preuve et la recommandation du
  finding ;
- **Labels** : `security-review` et `severity-<criticité>` (GitHub les crée quand le jeton en a le
  droit).

Les textes écrits par les agents sont affichés comme du code : ils ne mentionnent jamais personne
(`@équipe`), ne chargent aucune image et n'ajoutent aucun lien.
