# Controller (FastAPI)

The controller (`security-review-controller`) serves the REST API `/api/v1`, the web interface
on `/ui/`, the migrations and the administration commands. It is a FastAPI application built by
`web_api.create_app`, wrapped by `http_server` (Bearer tokens, sessions, TLS). As in the MCP
server, the routes stay thin: the business logic is in the modules (`reports/services.py`,
`auth/access_control.py`, `auth/token_store.py`…).

```bash
uv run security-review-controller db upgrade            # migrate the database
uv run security-review-controller serve --port 8080     # API and web interface
uv run pytest tests/test_web_api.py                     # REST API tests
```

## Layout of `web_api/`

| File | Role |
|---|---|
| `__init__.py` | `create_app`: assembly of the routers under `/api/v1`, static files of `/ui` |
| `schemas.py` | Request and response models of every route |
| `deps.py` | Identity of the caller, permissions (`require`), project scope |
| `*_routes.py` | One router per domain (`report`, `rule`, `token`, `access`, `connector`…) |

## Routes

```python
@router.get("/project-tokens")
async def project_tokens(identity: TokensManager) -> list[ProjectToken]:
    """List project-token metadata without returning hashes or token values; only the tokens
    whose projects the caller reads."""
    tokens = await run_in_threadpool(token_store.list_project_tokens)
    return [token for token in tokens if _reaches(identity, token["projects"])]
```

- **Response model**: every JSON route declares its return type with a model of `schemas.py`,
  never `-> dict`. FastAPI documents it in OpenAPI and drops any field that is not declared
  (no hash nor secret leaks by mistake);
  `test_openapi_documents_the_response_of_every_json_route` fails on a bare `dict`.
- **Permissions**: the identity comes from a dependency of `deps.py`, usually an alias built
  with `require(Permission.…)` (`TokensManager`, `Triager`, `RulesManager`…), which answers
  `403` without the permission. Restrict the results to the projects of the caller
  (`permission_scope`, `scoped_project`, `check_report_scope`).
- **Sessions only**: an action reserved to a person (risk acceptance, false positive, token or
  project creation) calls `web_user_id(request)`, which refuses any Bearer token (`403`).
- **Synchronous calls**: the ORM is synchronous; call it through `run_in_threadpool`.
- **Errors**: `HTTPException` with the right code; `unprocessable(exc)` turns a `ValueError`
  of a module into a `422`.
- **No write route without a token**: every route of `/api/v1` requires an authenticated
  identity, and the controller exposes no MCP endpoint.

## Settings

A new parameter goes into `config.Settings` (prefix `SECREVIEW_` added automatically), with a
comment, then into `.env.example` and [Configuration](../reference/configuration.md). Read it
with `get_settings()`, never with `os.environ`. A setting that an administrator changes in the
interface (language, proxy, OIDC) is stored in the database through `app_settings`.

## Command line

The controller commands are in `cli.py` (`CONTROLLER_COMMANDS`). Exit codes are the same
everywhere: `0` success, `1` blocked (gate, findings above the threshold), `2` usage or data
error (`_fail` writes the error as JSON on stderr). Only the CLI writes on stdout. Document any
command or option in the [command line reference](../reference/cli.md).

## Schema migrations

Every change of a table model (`models.py`) comes with an Alembic revision in
`src/security_review_mcp/storage/migrations/versions/`. The
`test_upgrade_creates_the_schema_of_the_models` test (`tests/test_database.py`) fails as long
as the migrations do not produce exactly the schema of the models. To generate a draft
revision to review:

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

Run it with `SECREVIEW_DATABASE_URL` pointing to a throwaway SQLite database already up to date
(`security-review-controller db upgrade`). Number the revisions in sequence after the last one
of `versions/`, review the generated file and never change a revision already published. The
SQL goes through the ORM only (SQLModel, bound parameters), never through a string.

## Connectors

`connectors/api.py` is the contract of the third-party connectors: do not break it without
incrementing `API_VERSION`. A connector only goes out through `connectors.transport` (HTTPS,
configured URL, proxy, no redirect, bounded response). See
[third-party connectors](../usage/connectors/third-party.md).

## Tests

`tests/test_web_api.py` provides the fixtures of the API:

| Fixture | Caller |
|---|---|
| `client` | An administrator, without the token lookup |
| `secured` | The controller protected by one token per role; `auth("<role>")` gives the header |
| `web_sessions` | `secured` with logged-in web users (`reader`, `triager`), for the routes reserved to sessions |

Check the status code and the body, and at least one refusal (`401`, `403` or `404` outside
the scope) for a new route. See also the [web interface](../usage/index.md) and the
[roles and permissions](../usage/access-control.md) as users see them.
