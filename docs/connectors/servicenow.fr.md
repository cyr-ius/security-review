# ServiceNow

Le connecteur **ServiceNow** crée un enregistrement pour chaque finding envoyé, un **incident** par
défaut. Les variables sont dans [Connecteurs en détail](../advanced/connectors.md#servicenow).

## Connexion

| Champ | Valeur |
|---|---|
| URL | L'adresse de l'instance, en HTTPS |
| **Compte** | Le compte qui crée les enregistrements |
| **Mot de passe** | Son mot de passe |
| **Table** | La table des enregistrements (`incident` par défaut) |

Le compte n'a besoin que de créer des enregistrements dans la table (le rôle `itil` pour
`incident`).

## Destination

La destination d'un projet est son **Groupe d'affectation** (facultatif, son nom).

## Contenu d'un enregistrement

- **Description courte** : `[HIGH] shop-api: SQL injection` ;
- **Description** : le projet, la sévérité, l'emplacement, la règle, la CWE, la branche, le commit
  et un lien vers le rapport, puis la description, la preuve et la recommandation du finding ;
- **Urgence** et **Impact** : selon la sévérité (`critical` donne 1 / 1, `low` et `info`
  3 / 3) ;
- **Groupe d'affectation** : la destination du projet.
