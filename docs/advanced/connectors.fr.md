# Connecteurs en détail

La page [connecteurs](../usage/connectors/index.md) décrit les connecteurs dans l'interface web.
Cette page donne les variables, l'envoi automatique, le contenu envoyé, les garanties et l'API
REST.

## Activation

La page **Connecteurs** (Administration, permission `settings.manage`) présente chaque connecteur
disponible sous forme de carte : son état, le nombre de projets qui l'utilisent, un
**interrupteur** et une **roue crantée** qui ouvre ses paramètres (onglets **Connexion** et
**Projets**).

Chaque connecteur est **désactivé par défaut** : rien ne passe par lui tant qu'un administrateur
ne l'a pas activé. Un connecteur ne peut être activé qu'une fois sa connexion configurée ; le
désactiver arrête aussitôt l'envoi à la main et l'envoi automatique. Chaque changement est
enregistré dans le journal d'audit (`connector.changed`, `{"enabled": true}`).

`SECREVIEW_CONNECTORS_ENABLED` est le verrou de l'opérateur :

| Valeur | Effet |
|---|---|
| `true` (défaut) | Les interrupteurs de la page décident ; chaque connecteur est désactivé tant qu'il n'a pas été activé |
| `false` | Tous les connecteurs sont verrouillés : rien n'est envoyé, les interrupteurs ne peuvent pas être activés, **Tester la connexion** est refusé |

```bash
SECREVIEW_CONNECTORS_INTERVAL_SECONDS=300   # période de l'envoi automatique
SECREVIEW_CONNECTORS_CAFILE=/etc/ssl/corp-ca.pem   # facultatif : autorité de certification interne
```

## Envoi d'un finding

Un utilisateur qui peut trier le projet (permission `findings.triage`) voit un bouton
**Envoyer vers** (un par connecteur) sur chaque carte de finding dont le projet a une
destination. Une fois l'enregistrement créé, la carte affiche sa clé, avec un lien
vers l'enregistrement. Un échec est affiché sur la carte avec sa raison (identifiants refusés,
clé de projet inconnue...).

L'envoi automatique a lieu toutes les `SECREVIEW_CONNECTORS_INTERVAL_SECONDS` (300 par défaut),
20 findings au plus par connecteur et par passage, les plus sévères d'abord. Un finding en échec
est réessayé 5 fois au plus, 15 minutes après le premier échec, puis avec un délai doublé.

### Un enregistrement par problème

Un finding retrouvé par un rapport ultérieur (même projet, règle, fichier et titre :
l'[empreinte SARIF](reports/sarif.md)) réutilise l'enregistrement de la première occurrence :
aucun nouvel enregistrement n'est créé. Envoyer un finding qui a déjà son enregistrement le
renvoie.

### Contenu envoyé

Chaque connecteur reçoit le même contenu : un titre (`[HIGH] shop-api: SQL injection`), le
projet, la sévérité, l'emplacement, la règle, la CWE, l'OWASP, la branche, le commit, le lien vers
le rapport (avec `SECREVIEW_PUBLIC_URL`), puis la description, la preuve et la recommandation, et
l'empreinte du problème. Les textes du rapport sont de nouveau masqués (secrets) avant de partir.
La page de chaque connecteur décrit où chaque champ arrive dans le système.

## Sécurité

- Connexions sortantes du **serveur Controller** uniquement, chaque connecteur désactivé par défaut
  (activé par un administrateur, ou verrouillé par `SECREVIEW_CONNECTORS_ENABLED=false`), en
  **HTTPS** avec vérification du certificat (`SECREVIEW_CONNECTORS_CAFILE` pour une autorité
  interne), par le [proxy sortant](../reference/configuration.md#proxy-sortant).
- **Les redirections sont refusées** : elles emporteraient les identifiants ailleurs. Délai de
  15 secondes, réponse bornée à 1 Mio.
- Les secrets saisis dans la page sont stockés en base **en clair**, comme le secret client
  OIDC : l'API ne les renvoie jamais (`***`), les journaux ne nomment que les réglages modifiés,
  l'événement d'audit les masque. Préférez les variables (secret Kubernetes) si la base n'est pas
  protégée comme un secret.
- Un échec conserve un code court et un extrait borné du message d'erreur du système, masqué et
  sans les identifiants.
- Un secret est lié à l'hôte de son URL : une nouvelle URL exige de ressaisir ses secrets, même
  après la suppression de l'URL, et un secret défini par une variable exige une URL définie par
  une variable, pour qu'un jeton enregistré ne parte jamais vers un autre hôte.
- Un connecteur tiers n'est chargé que si `SECREVIEW_CONNECTORS_PLUGINS` le nomme, et s'exécute
  avec les droits du serveur Controller : n'installez que du code de confiance.
- Événements d'audit : `connector.changed` (connexion ou interrupteur), `connector.target_changed`
  (destination d'un projet), `finding.exported` (enregistrement créé ou réutilisé, avec sa clé ;
  acteur `auto` pour l'envoi automatique).

## API REST

| Route | Permission | Rôle |
|---|---|---|
| `GET /api/v1/settings/connectors` | `settings.manage` | Chaque connecteur avec ses champs et sa connexion (secrets `***`) et son interrupteur (`enabled`), plugins autorisés, `SECREVIEW_CONNECTORS_ENABLED` (`enabled`) |
| `GET /api/v1/connectors` | toutes | Connecteurs disponibles (`kind`, `name`) |
| `PUT /api/v1/settings/connectors/{kind}` | `settings.manage` | Modifie des champs d'une connexion (`{"url": ..., "api_token": ...}`) ; `null` ou `""` supprime la valeur enregistrée ; `404` pour un connecteur inconnu |
| `PUT /api/v1/settings/connectors/{kind}/enabled` | `settings.manage` | Active ou désactive un connecteur (`{"enabled": true}`) ; `422` tant que sa connexion n'est pas configurée ou si `SECREVIEW_CONNECTORS_ENABLED=false` |
| `POST /api/v1/settings/connectors/{kind}/test` | `settings.manage` | Teste les valeurs enregistrées et celles du corps, non enregistrées, que le connecteur soit activé ou non |
| `GET /api/v1/connectors/targets` | `settings.manage` | Destinations des projets |
| `PUT /api/v1/projects/{project}/connector-targets/{kind}` | `settings.manage` | `{"destination": "SEC", "auto_min_severity": "high"}` (`null` : à la main uniquement) |
| `DELETE /api/v1/projects/{project}/connector-targets/{kind}` | `settings.manage` | Supprime une destination (les enregistrements sont conservés) |
| `GET /api/v1/connectors/destinations` | toutes | Projets et connecteurs par lesquels l'appelant peut envoyer des findings |
| `POST /api/v1/findings/{id}/exports/{kind}` | `findings.triage` | Envoie un finding : `201` avec son export ; `409` si le connecteur est désactivé, ou si la connexion ou la destination manque ; `502` si le système le refuse |

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://secreview.example.com/api/v1/findings/42/exports/jira
# {"kind": "jira", "state": "sent", "external_key": "SEC-12", "url": "https://acme.atlassian.net/browse/SEC-12", …}
```

Les exports d'un finding figurent aussi dans sa liste `exports`, dans les rapports et les listes
de findings (API REST et outils MCP).

## Jira

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_JIRA_URL` | — | Adresse de Jira, `https://` uniquement (`https://acme.atlassian.net`, ou l'URL de base d'un Data Center) |
| `SECREVIEW_JIRA_USERNAME` | — | Jira Cloud : adresse e-mail du compte, utilisée avec un jeton d'API. Vide : le jeton est un jeton d'accès personnel Data Center, envoyé comme jeton Bearer |
| `SECREVIEW_JIRA_API_TOKEN` | — | Jeton d'API (Cloud) ou jeton d'accès personnel (Data Center) |
| `SECREVIEW_JIRA_ISSUE_TYPE` | `Bug` | Type des tickets créés |

Le compte n'a besoin que de créer des tickets : les permissions *Parcourir les projets* et
*Créer des tickets* sur les projets utilisés.

Les textes du rapport sont placés dans des blocs `{noformat}` : écrits par un agent, ils ne sont
jamais interprétés comme du balisage wiki (liens, images chargées depuis un autre site).

## ServiceNow

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_SERVICENOW_URL` | — | Adresse de l'instance, `https://` uniquement |
| `SECREVIEW_SERVICENOW_USERNAME` | — | Compte (authentification basique) |
| `SECREVIEW_SERVICENOW_PASSWORD` | — | Son mot de passe |
| `SECREVIEW_SERVICENOW_TABLE` | `incident` | Table des enregistrements |

Le compte n'a besoin que du droit de créer des enregistrements dans la table (le rôle `itil`
pour `incident`).

## Connecteurs tiers

Un connecteur publié par un paquet Python (point d'entrée du groupe
`security_review_mcp.connectors`) s'installe à côté du serveur Controller, puis s'**autorise** par le nom
de son point d'entrée : installer un paquet ne suffit pas.

```bash
uv pip install secreview-acme-connector         # in the image or the environment of the Controller server
SECREVIEW_CONNECTORS_PLUGINS=acme               # comma separated
SECREVIEW_ACME_URL=https://risk.acme.example/api
SECREVIEW_ACME_API_KEY=...
```

Le serveur Controller charge les connecteurs autorisés au démarrage et refuse de démarrer si l'un
manque, est écrit pour une autre version de l'API, ou déclare une variable du serveur lui-même
(`SECREVIEW_<TYPE>_<CHAMP>` ne doit pas être un réglage existant). La page **Connecteurs**
l'affiche sous forme de carte marquée **Tiers**, désactivé tant qu'il n'a pas été activé. Un
connecteur s'exécute dans le serveur Controller avec ses droits : n'installez et n'autorisez que du code
de confiance, comme toute dépendance.
