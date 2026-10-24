# ServiceNow

Le connecteur intégré **ServiceNow** (type `servicenow`) crée un enregistrement pour chaque
finding envoyé, dans la table `incident` par défaut. L'activation, les destinations et l'envoi
sont communs à tous les connecteurs : voir [Connecteurs](index.md).

## Connexion

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_SERVICENOW_URL` | — | Adresse de l'instance, `https://` uniquement |
| `SECREVIEW_SERVICENOW_USERNAME` | — | Compte (authentification basique) |
| `SECREVIEW_SERVICENOW_PASSWORD` | — | Son mot de passe |
| `SECREVIEW_SERVICENOW_TABLE` | `incident` | Table des enregistrements |

Le compte n'a besoin que du droit de créer des enregistrements dans la table (le rôle `itil`
pour `incident`).

## Destination

La destination d'un projet est le **groupe d'affectation** (facultatif, son nom).

## Contenu d'un enregistrement

| Champ | Valeur |
|---|---|
| `short_description` | `[HIGH] shop-api: SQL injection` |
| `description` | projet, sévérité, emplacement, règle, CWE, OWASP, branche, commit, lien vers le rapport, puis description, preuve et recommandation, en texte brut |
| `urgency`, `impact` | selon la sévérité : `critical` 1 / 1, `high` 1 / 2, `medium` 2 / 2, `low` et `info` 3 / 3 |
| `assignment_group` | la destination du projet |
| `correlation_id` | l'empreinte du problème |
