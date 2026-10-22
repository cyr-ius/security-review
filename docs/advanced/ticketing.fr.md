# Ticketing : Jira et ServiceNow

Le contrôleur peut transformer un finding en ticket dans **Jira** (Cloud ou Data Center) ou
dans **ServiceNow** : à la main, depuis la carte d'un finding, ou automatiquement pour les
projets dotés d'un seuil de sévérité. L'envoi est **à sens unique** : la clé et le lien du ticket
sont conservés sur le finding, et son statut n'est jamais modifié depuis le ticket (une personne
le décide toujours, voir [triage des findings](../usage/web-interface.md#triage-des-findings)).

Chaque système est un **connecteur** : Jira et ServiceNow sont intégrés, et un paquet tiers peut
en ajouter d'autres (plateforme GRC, outil de suivi interne) : voir
[connecteurs tiers](#connecteurs-tiers) et [écrire un connecteur](#ecrire-un-connecteur).

Seul le contrôleur se connecte à ces systèmes et charge les connecteurs ; le serveur MCP jamais.

## Activation

Le ticketing est **désactivé par défaut** : définissez `SECREVIEW_TICKETING_ENABLED=true` sur le
contrôleur. D'ici là, les connexions et les destinations peuvent être préparées, mais rien n'est
envoyé.

```bash
SECREVIEW_TICKETING_ENABLED=true
SECREVIEW_TICKETING_INTERVAL_SECONDS=300   # période de l'envoi automatique
SECREVIEW_TICKETING_CAFILE=/etc/ssl/corp-ca.pem   # facultatif : autorité de certification interne
```

## Connexions

Chaque système a sa connexion, définie par ses variables ou dans l'écran **Ticketing**
(Administration, permission `settings.manage`). Une variable définie est prioritaire : son champ
est seulement affiché dans l'écran. Les secrets ne sont jamais réaffichés (`***`) ; renvoyer
`***` conserve celui qui est enregistré. **Tester la connexion** vérifie les valeurs saisies par
une requête en lecture seule, sans les enregistrer.

Chaque champ d'un connecteur a sa variable, `SECREVIEW_<TYPE>_<CHAMP>` : celles des connecteurs
intégrés sont ci-dessous. Un secret est lié à l'hôte de son URL : définir une URL d'un autre
hôte, ou une URL là où il n'y en avait pas (après l'avoir supprimée, par exemple), exige de
ressaisir les secrets dans la même modification. Un secret défini par une variable ne part que
vers une URL définie par une variable : l'écran refuse l'URL (sinon un jeton enregistré pourrait
partir vers un autre hôte).

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_JIRA_URL` | — | Adresse de Jira, `https://` uniquement (`https://acme.atlassian.net`, ou l'URL de base d'un Data Center) |
| `SECREVIEW_JIRA_USERNAME` | — | Jira Cloud : adresse e-mail du compte, utilisée avec un jeton d'API. Vide : le jeton est un jeton d'accès personnel Data Center, envoyé comme jeton Bearer |
| `SECREVIEW_JIRA_API_TOKEN` | — | Jeton d'API (Cloud) ou jeton d'accès personnel (Data Center) |
| `SECREVIEW_JIRA_ISSUE_TYPE` | `Bug` | Type des tickets |
| `SECREVIEW_SERVICENOW_URL` | — | Adresse de l'instance, `https://` uniquement |
| `SECREVIEW_SERVICENOW_USERNAME` | — | Compte (authentification basique) |
| `SECREVIEW_SERVICENOW_PASSWORD` | — | Son mot de passe |
| `SECREVIEW_SERVICENOW_TABLE` | `incident` | Table des enregistrements |

Le compte n'a besoin que de créer des tickets : dans Jira, les permissions *Parcourir les
projets* et *Créer des tickets* sur les projets utilisés ; dans ServiceNow, le droit de créer
des enregistrements dans la table (le rôle `itil` pour `incident`).

## Destinations des projets

Un projet a besoin d'une **destination** pour envoyer ses findings vers un système : la **clé du
projet Jira** (`SEC`), ou le **groupe d'affectation ServiceNow** (facultatif, son nom). Les
destinations se définissent en bas de l'écran **Ticketing**.

Chaque destination peut avoir un seuil d'**envoi automatique** : chaque nouveau finding
**ouvert** au moins aussi sévère est alors envoyé par le contrôleur. Le seuil ne s'applique
qu'aux rapports enregistrés **après** sa définition : les findings déjà enregistrés ne sont
envoyés qu'à la main.

## Envoi d'un finding

Un utilisateur qui peut trier le projet (permission `findings.triage`) voit un bouton
**Envoyer vers Jira** / **Envoyer vers ServiceNow** sur chaque carte de finding dont le projet a
une destination. Une fois le ticket créé, la carte affiche sa clé, avec un lien vers le ticket.
Un échec est affiché sur la carte avec sa raison (identifiants refusés, clé de projet
inconnue...).

L'envoi automatique a lieu toutes les `SECREVIEW_TICKETING_INTERVAL_SECONDS` (300 par défaut),
20 findings au plus par système et par passage, les plus sévères d'abord. Un finding en échec
est réessayé 5 fois au plus, 15 minutes après le premier échec, puis avec un délai doublé.

### Un ticket par problème

Un finding retrouvé par un rapport ultérieur (même projet, règle, fichier et titre :
l'[empreinte SARIF](sarif.md)) réutilise le ticket de la première occurrence : aucun nouveau
ticket n'est créé. Envoyer un finding qui a déjà son ticket le renvoie.

## Contenu d'un ticket

| | Jira | ServiceNow |
|---|---|---|
| Titre | `[HIGH] shop-api: SQL injection` (`summary`) | identique (`short_description`) |
| Description | projet, sévérité, emplacement, règle, CWE, OWASP, branche, commit, lien vers le rapport (avec `SECREVIEW_WEB_URL`), puis description, preuve et recommandation | identique, en texte brut |
| Autres champs | libellés `security-review` et `severity-<sévérité>` | `urgency` et `impact` selon la sévérité, `assignment_group`, `correlation_id` (l'empreinte) |

Urgence et impact ServiceNow : `critical` 1 / 1, `high` 1 / 2, `medium` 2 / 2, `low` et `info`
3 / 3.

Les textes du rapport sont de nouveau masqués (secrets) avant de partir. Dans Jira, ils sont
placés dans des blocs `{noformat}` : écrits par un agent, ils ne sont jamais interprétés comme
du balisage wiki (liens, images chargées depuis un autre site).

## Sécurité

- Connexions sortantes du **contrôleur** uniquement, désactivées par défaut, en **HTTPS** avec
  vérification du certificat (`SECREVIEW_TICKETING_CAFILE` pour une autorité interne), par le
  [proxy sortant](../reference/configuration.md#proxy-sortant).
- **Les redirections sont refusées** : elles emporteraient les identifiants ailleurs. Délai de
  15 secondes, réponse bornée à 1 Mio.
- Les secrets saisis dans l'écran sont stockés en base **en clair**, comme le secret client
  OIDC : l'API ne les renvoie jamais (`***`), les journaux ne nomment que les réglages modifiés,
  l'événement d'audit les masque. Préférez les variables (secret Kubernetes) si la base n'est pas
  protégée comme un secret.
- Un échec conserve un code court et un extrait borné du message d'erreur du système, masqué et
  sans les identifiants.
- Un secret est lié à l'hôte de son URL : une nouvelle URL exige de ressaisir ses secrets, même
  après la suppression de l'URL, et un secret défini par une variable exige une URL définie par
  une variable, pour qu'un jeton enregistré ne parte jamais vers un autre hôte.
- Un connecteur tiers n'est chargé que si `SECREVIEW_TICKETING_PLUGINS` le nomme, et
  s'exécute avec les droits du contrôleur : n'installez que du code de confiance.
- Événements d'audit : `ticketing.changed` (connexion), `ticketing.target_changed` (destination
  d'un projet), `finding.ticket_created` (ticket créé ou réutilisé, avec sa clé ; acteur `auto`
  pour l'envoi automatique).

## Connecteurs tiers

Un connecteur publié par un paquet Python (point d'entrée du groupe
`security_review_mcp.ticketing`) s'installe à côté du contrôleur, puis s'**autorise** par le nom
de son point d'entrée : installer un paquet ne suffit pas.

```bash
pip install secreview-acme-connector            # in the image or the environment of the controller
SECREVIEW_TICKETING_PLUGINS=acme                # comma separated
SECREVIEW_ACME_URL=https://risk.acme.example/api
SECREVIEW_ACME_API_KEY=...
```

Le contrôleur charge les connecteurs autorisés au démarrage et refuse de démarrer si l'un
manque, est écrit pour une autre version de l'API, ou déclare une variable du serveur lui-même
(`SECREVIEW_<TYPE>_<CHAMP>` ne doit pas être un réglage existant). L'écran **Ticketing** l'affiche
avec ses champs, marqué **Connecteur tiers**. Un connecteur s'exécute dans le contrôleur avec ses
droits : n'installez et n'autorisez que du code de confiance, comme toute dépendance.

## Écrire un connecteur

Un connecteur est une sous-classe de `TicketConnector` (module
`security_review_mcp.ticketing.api`, version `API_VERSION = 1`). L'exemple complet
[`examples/ticketing-connector`](https://github.com/cyr-ius/security-review-mcp/tree/master/examples/ticketing-connector)
est un paquet à copier.

```python
from security_review_mcp.ticketing.api import (
    Connection,
    ConnectorField,
    CreatedTicket,
    TicketConnector,
    TicketContent,
    TicketingError,
)


class AcmeConnector(TicketConnector):
    kind = "acme"  # identifier: tickets, URLs, SECREVIEW_ACME_* variables
    name = "Acme Risk"  # display name
    url_placeholder = "https://risk.acme.example/api"
    fields = (  # the URL field is added by the controller
        ConnectorField(
            name="api_key",
            label="API key",
            secret=True,
            required=True,
            translations={"fr": {"label": "Clé d'API"}},
        ),
    )
    destination = ConnectorField(
        name="destination", label="Risk register", required=True, pattern=r"[A-Z0-9_-]{1,40}"
    )

    def auth_headers(self, values):
        return {"X-Api-Key": values["api_key"]}

    def create_ticket(
        self, connection: Connection, destination: str, content: TicketContent
    ) -> CreatedTicket:
        answer = connection.http.request(
            "POST",
            f"/registers/{destination}/risks",
            json_body={"title": content.summary, "description": content.text()},
        )
        if not isinstance(answer.get("id"), str):
            raise TicketingError("invalid", "acme sent no risk id")
        return CreatedTicket(key=answer["id"], url=f"{connection.base_url}/risks/{answer['id']}")

    def test_connection(self, connection: Connection) -> None:
        connection.http.request("GET", "/me")
```

```toml
# pyproject.toml of the package
[project.entry-points."security_review_mcp.ticketing"]
acme = "acme_connector:AcmeConnector"
```

| Élément | Rôle |
|---|---|
| `kind` | Lettres minuscules, chiffres et `_` (2 à 20 caractères) ; enregistré avec les tickets |
| `fields` | `ConnectorField` : `name`, `label`, `secret`, `required`, `default`, `help`, `placeholder`, `pattern` (correspondance complète), `max_length`, `translations` (`{"fr": {"label": ..., "help": ...}}`) |
| `destination` | Ce qu'un administrateur choisit par projet ; surchargez `check_destination` pour la normaliser |
| `auth_headers(values)` | En-têtes d'authentification, ajoutés par le contrôleur à chaque requête |
| `create_ticket(connection, destination, content)` | Crée le ticket et renvoie `CreatedTicket(key, url)` (lien `https://`) |
| `test_connection(connection)` | Requête en lecture seule qui exige des identifiants valides |

Ce que le contrôleur garantit, quel que soit le connecteur :

- `connection.http.request(method, path, json_body=..., query=...)` est la seule sortie : `path`
  est relatif à l'URL configurée (aucun autre hôte), en HTTPS, par le proxy sortant, **sans suivre
  les redirections**, délai de 15 secondes, réponse JSON bornée à 1 Mio ; un échec lève
  `TicketingError` (`auth`, `refused`, `unreachable`, `invalid`) sans les secrets ;
- `content` est déjà masqué : `summary`, `facts`, `sections` (textes écrits par un agent :
  échappez-les si le système interprète un balisage), `text()` (description en texte brut),
  `fingerprint`, `report_url` ;
- la réservation (pas de ticket en double), la réutilisation du ticket d'un problème retrouvé, le
  résultat enregistré, l'audit et les nouvelles tentatives de l'envoi automatique ;
- toute autre exception du connecteur devient l'erreur `invalid`, sans son message (il pourrait
  contenir une valeur de la connexion).

Un connecteur ne doit jamais ouvrir de connexion lui-même, journaliser les valeurs de ses champs,
ni modifier autre chose que le ticket qu'il crée.

## API REST

| Route | Permission | Rôle |
|---|---|---|
| `GET /api/v1/settings/ticketing` | `settings.manage` | Chaque connecteur avec ses champs et sa connexion (secrets `***`), plugins autorisés, activation du ticketing |
| `GET /api/v1/ticketing/systems` | toutes | Systèmes disponibles (`kind`, `name`) |
| `PUT /api/v1/settings/ticketing/{kind}` | `settings.manage` | Modifie des champs d'une connexion (`{"url": ..., "api_token": ...}`) ; `null` ou `""` supprime la valeur enregistrée ; `404` pour un système inconnu |
| `POST /api/v1/settings/ticketing/{kind}/test` | `settings.manage` | Teste les valeurs enregistrées et celles du corps, non enregistrées |
| `GET /api/v1/ticketing/targets` | `settings.manage` | Destinations des projets |
| `PUT /api/v1/projects/{project}/ticket-targets/{kind}` | `settings.manage` | `{"destination": "SEC", "auto_min_severity": "high"}` (`null` : à la main uniquement) |
| `DELETE /api/v1/projects/{project}/ticket-targets/{kind}` | `settings.manage` | Supprime une destination (les tickets sont conservés) |
| `GET /api/v1/ticketing/destinations` | toutes | Projets et systèmes vers lesquels l'appelant peut envoyer des findings |
| `POST /api/v1/findings/{id}/tickets/{kind}` | `findings.triage` | Envoie un finding : `201` avec le ticket ; `409` si le ticketing, la connexion ou la destination manque ; `502` si le système le refuse |

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://secreview.example.com/api/v1/findings/42/tickets/jira
# {"kind": "jira", "state": "sent", "external_key": "SEC-12", "url": "https://acme.atlassian.net/browse/SEC-12", …}
```

Les tickets d'un finding figurent aussi dans sa liste `tickets`, dans les rapports et les listes
de findings (API REST et outils MCP).
