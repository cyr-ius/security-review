# Connecteurs tiers

Un paquet Python peut ajouter un connecteur vers n'importe quel autre système : un registre de
vulnérabilités, une plateforme GRC, un outil de suivi interne... Il a le même interrupteur, la
même connexion, les mêmes destinations et les mêmes garanties que les connecteurs intégrés (voir
[Connecteurs](index.md)).

## Installer un connecteur

Un connecteur publié par un paquet Python (point d'entrée du groupe
`security_review_mcp.connectors`) s'installe à côté du contrôleur, puis s'**autorise** par le nom
de son point d'entrée : installer un paquet ne suffit pas.

```bash
pip install secreview-acme-connector            # in the image or the environment of the controller
SECREVIEW_CONNECTORS_PLUGINS=acme               # comma separated
SECREVIEW_ACME_URL=https://risk.acme.example/api
SECREVIEW_ACME_API_KEY=...
```

Le contrôleur charge les connecteurs autorisés au démarrage et refuse de démarrer si l'un
manque, est écrit pour une autre version de l'API, ou déclare une variable du serveur lui-même
(`SECREVIEW_<TYPE>_<CHAMP>` ne doit pas être un réglage existant). L'écran **Connecteurs**
l'affiche sous forme de carte marquée **Tiers**, désactivé tant qu'il n'a pas été activé. Un
connecteur s'exécute dans le contrôleur avec ses droits : n'installez et n'autorisez que du code
de confiance, comme toute dépendance.

## Écrire un connecteur

Un connecteur est une sous-classe de `Connector` (module `security_review_mcp.connectors.api`,
version `API_VERSION = 2`). L'exemple complet
[`examples/connector`](https://github.com/cyr-ius/security-review-mcp/tree/master/examples/connector)
est un paquet à copier : il transforme chaque finding en risque d'un registre Acme.

```python
from security_review_mcp.connectors.api import (
    Connection,
    Connector,
    ConnectorError,
    ConnectorField,
    ExportedFinding,
    FindingContent,
)


class AcmeConnector(Connector):
    kind = "acme"  # identifier: exports, URLs, SECREVIEW_ACME_* variables
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

    def export_finding(
        self, connection: Connection, destination: str, content: FindingContent
    ) -> ExportedFinding:
        answer = connection.http.request(
            "POST",
            f"/registers/{destination}/risks",
            json_body={"title": content.summary, "description": content.text()},
        )
        if not isinstance(answer.get("id"), str):
            raise ConnectorError("invalid", "acme sent no risk id")
        return ExportedFinding(key=answer["id"], url=f"{connection.base_url}/risks/{answer['id']}")

    def test_connection(self, connection: Connection) -> None:
        connection.http.request("GET", "/me")
```

```toml
# pyproject.toml of the package
[project.entry-points."security_review_mcp.connectors"]
acme = "acme_connector:AcmeConnector"
```

| Élément | Rôle |
|---|---|
| `kind` | Lettres minuscules, chiffres et `_` (2 à 20 caractères, pas `connectors`) ; enregistré avec les exports |
| `fields` | `ConnectorField` : `name`, `label`, `secret`, `required`, `default`, `help`, `placeholder`, `pattern` (correspondance complète), `max_length`, `translations` (`{"fr": {"label": ..., "help": ...}}`) |
| `destination` | Ce qu'un administrateur choisit par projet ; surchargez `check_destination` pour la normaliser |
| `auth_headers(values)` | En-têtes d'authentification, ajoutés par le contrôleur à chaque requête |
| `export_finding(connection, destination, content)` | Crée l'enregistrement du finding et renvoie `ExportedFinding(key, url)` (lien `https://`) |
| `test_connection(connection)` | Requête en lecture seule qui exige des identifiants valides |

Ce que le contrôleur garantit, quel que soit le connecteur :

- `connection.http.request(method, path, json_body=..., query=...)` est la seule sortie : `path`
  est relatif à l'URL configurée (aucun autre hôte), en HTTPS, par le proxy sortant, **sans suivre
  les redirections**, délai de 15 secondes, réponse JSON bornée à 1 Mio ; un échec lève
  `ConnectorError` (`auth`, `refused`, `unreachable`, `invalid`) sans les secrets ;
- `content` est déjà masqué : `summary`, `facts`, `sections` (textes écrits par un agent :
  échappez-les si le système interprète un balisage), `text()` (description en texte brut),
  `fingerprint`, `report_url` ;
- la réservation (pas d'enregistrement en double), la réutilisation de l'enregistrement d'un
  problème retrouvé, le résultat enregistré, l'audit et les nouvelles tentatives de l'envoi
  automatique ;
- toute autre exception du connecteur devient l'erreur `invalid`, sans son message (il pourrait
  contenir une valeur de la connexion).

Un connecteur ne doit jamais ouvrir de connexion lui-même, journaliser les valeurs de ses champs,
ni modifier autre chose que l'enregistrement qu'il crée.
