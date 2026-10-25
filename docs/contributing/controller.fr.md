# Contrôleur (FastAPI)

Le contrôleur (`security-review-controller`) sert l'API REST `/api/v1`, l'interface web sur
`/ui/`, les migrations et les commandes d'administration. C'est une application FastAPI
construite par `web_api.create_app`, enveloppée par `http_server` (jetons Bearer, sessions,
TLS). Comme dans le serveur MCP, les routes restent minces : la logique métier est dans les
modules (`reports/services.py`, `auth/access_control.py`, `auth/token_store.py`…).

```bash
uv run security-review-controller db upgrade            # migre la base
uv run security-review-controller serve --port 8080     # API et interface web
uv run pytest tests/test_web_api.py                     # tests de l'API REST
```

## Organisation de `web_api/`

| Fichier | Rôle |
|---|---|
| `__init__.py` | `create_app` : assemblage des routeurs sous `/api/v1`, fichiers statiques de `/ui` |
| `schemas.py` | Modèles de requête et de réponse de chaque route |
| `deps.py` | Identité de l'appelant, permissions (`require`), périmètre des projets |
| `*_routes.py` | Un routeur par domaine (`report`, `rule`, `token`, `access`, `connector`…) |

## Routes

```python
@router.get("/project-tokens")
async def project_tokens(identity: TokensManager) -> list[ProjectToken]:
    """List project-token metadata without returning hashes or token values; only the tokens
    whose projects the caller reads."""
    tokens = await run_in_threadpool(token_store.list_project_tokens)
    return [token for token in tokens if _reaches(identity, token["projects"])]
```

- **Modèle de réponse** : chaque route JSON déclare son type de retour avec un modèle de
  `schemas.py`, jamais `-> dict`. FastAPI le documente dans OpenAPI et retire tout champ non
  déclaré (aucune empreinte ni secret ne fuit par erreur) ;
  `test_openapi_documents_the_response_of_every_json_route` échoue sur un `dict` brut.
- **Permissions** : l'identité vient d'une dépendance de `deps.py`, en général un alias
  construit avec `require(Permission.…)` (`TokensManager`, `Triager`, `RulesManager`…), qui
  répond `403` sans la permission. Restreignez les résultats aux projets de l'appelant
  (`permission_scope`, `scoped_project`, `check_report_scope`).
- **Sessions uniquement** : une action réservée à une personne (acceptation de risque, faux
  positif, création de jeton ou de projet) appelle `web_user_id(request)`, qui refuse tout jeton
  Bearer (`403`).
- **Appels synchrones** : l'ORM est synchrone ; appelez-le par `run_in_threadpool`.
- **Erreurs** : `HTTPException` avec le bon code ; `unprocessable(exc)` transforme la
  `ValueError` d'un module en `422`.
- **Aucune route d'écriture sans jeton** : toute route de `/api/v1` exige une identité
  authentifiée, et le contrôleur n'expose aucun endpoint MCP.

## Paramètres

Un nouveau paramètre s'ajoute dans `config.Settings` (préfixe `SECREVIEW_` automatique), avec un
commentaire, puis dans `.env.example` et la page [Configuration](../reference/configuration.md).
Lisez-le avec `get_settings()`, jamais avec `os.environ`. Un réglage qu'un administrateur
modifie dans l'interface (langue, proxy, OIDC) est stocké en base par `app_settings`.

## Ligne de commande

Les commandes du contrôleur sont dans `cli.py` (`CONTROLLER_COMMANDS`). Les codes de sortie sont
identiques partout : `0` succès, `1` bloqué (gate, findings au-dessus du seuil), `2` erreur
d'usage ou de données (`_fail` écrit l'erreur en JSON sur stderr). Seule la CLI écrit sur
stdout. Documentez toute commande ou option dans la
[référence de la ligne de commande](../reference/cli.md).

## Migrations du schéma

Toute modification d'un modèle de table (`models.py`) s'accompagne d'une révision Alembic dans
`src/security_review_mcp/storage/migrations/versions/`. Le test
`test_upgrade_creates_the_schema_of_the_models` (`tests/test_database.py`) échoue tant que les
migrations ne produisent pas exactement le schéma des modèles. Pour générer un brouillon de
révision à relire :

```bash
uv run python - <<'PY'
from alembic import command
from security_review_mcp.storage import database
with database.get_engine().begin() as connection:
    command.revision(
        database.alembic_config(connection), "describe the change", autogenerate=True, rev_id="0033"
    )
PY
```

Lancez-le avec `SECREVIEW_DATABASE_URL` pointant sur une base SQLite jetable déjà à jour
(`security-review-controller db upgrade`). Numérotez les révisions à la suite de la dernière de
`versions/`, relisez le fichier généré et ne modifiez jamais une révision déjà publiée. Le SQL
passe uniquement par l'ORM (SQLModel, paramètres liés), jamais par une chaîne.

## Connecteurs

`connectors/api.py` est le contrat des connecteurs tiers : ne le cassez pas sans incrémenter
`API_VERSION`. Un connecteur ne sort que par `connectors.transport` (HTTPS, URL configurée,
proxy, sans redirection, réponse bornée). Voir les
[connecteurs tiers](../connectors/third-party.md).

## Tests

`tests/test_web_api.py` fournit les fixtures de l'API :

| Fixture | Appelant |
|---|---|
| `client` | Un administrateur, sans la recherche du jeton |
| `secured` | Le contrôleur protégé par un jeton par rôle ; `auth("<role>")` donne l'en-tête |
| `web_sessions` | `secured` avec des utilisateurs web connectés (`reader`, `triager`), pour les routes réservées aux sessions |

Vérifiez le code de statut et le corps, et au moins un refus (`401`, `403` ou `404` hors du
périmètre) pour une nouvelle route. Voir aussi l'[interface web](../usage/web-interface.md) et
les [rôles et permissions](../advanced/access-control.md) tels que les utilisateurs les voient.
