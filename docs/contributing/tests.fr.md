# Tests

Les tests tournent avec pytest, sans accès réseau, sur une base SQLite en mémoire.

```bash
uv run pytest tests/test_scanner.py -k python   # d'abord les tests du module modifié
uv run pytest                                   # puis toute la suite, une fois
```

## Quoi tester

Un test protège un contrat ou un invariant, pas une ligne de code, et il n'y a pas d'objectif de
couverture. Testez d'abord les invariants de sécurité, les contrats publics (outils et prompts
MCP, codes de sortie CLI, schéma REST, migrations) et chaque bug corrigé (un test de régression).
Ne testez pas ce que garantit déjà une bibliothèque, le détail d'implémentation ni le texte exact
d'un message. Avant d'ajouter un test, étendez celui qui couvre déjà le comportement (assertion
supplémentaire, ligne de `parametrize`) : un changement ajoute en général un à trois tests.

Un bug corrigé reçoit **un** test de régression qui échoue avant la correction. Un invariant de
sécurité est testé une fois, au plus près du module qui le garantit. Les tests d'un changement
sont dans le même commit que lui.

## Conventions

- Un fichier par module : `tests/test_<module>.py`. Ajoutez au fichier existant plutôt que d'en
  créer un nouveau.
- `tests/conftest.py` ignore le fichier `.env` du développeur et les variables `SECREVIEW_*` du
  shell : un test qui a besoin d'un réglage le définit lui-même (`monkeypatch.setenv`,
  `Settings(...)`).
- `tests/conftest.py` fournit à chaque test une base SQLite en mémoire et un registre de règles
  vide : n'utilisez jamais la base réelle. La fixture `import_pack` importe des règles internes
  (pack TOML), `triage` enregistre une décision comme le ferait une personne, `tmp_path` accueille
  les fichiers.
- Pas de réseau, pas de `sleep`, pas de dépendance à l'ordre des tests. Les clés et jetons sont
  factices.

## Tests par type de code

| Code | Test | Exemple |
|---|---|---|
| Outil, prompt ou ressource MCP | De bout en bout avec `mcp.client.Client(mcp)` (`pytestmark = pytest.mark.anyio`), avec un cas d'erreur représentatif (`result.is_error`) | `tests/test_server.py`, voir [Serveur MCP](mcp-server.md#tests) |
| Règle de scan | Au moins un cas **positif** (le motif vulnérable est détecté) et un cas **négatif** (le code sûr équivalent ne l'est pas) | `tests/test_scanner.py` |
| Route REST | `TestClient` avec les fixtures `client`, `secured` ou `web_sessions`, code de statut et corps, au moins un refus | `tests/test_web_api.py`, voir [Serveur Controller](controller.md#tests) |
| Commande CLI | `cli.run([...])` (ou `server.main([...])`), **code de sortie** et sortie (`capsys`) | `tests/test_cli_and_tools.py` |
| Modèle de table | Une nouvelle révision Alembic ; `test_upgrade_creates_the_schema_of_the_models` vérifie que les migrations produisent les modèles | `tests/test_database.py` |
| Interface Angular | Pas de test unitaire : `npm run build` vérifie les types et les clés de traduction ; le catalogue de l'audit est vérifié par `tests/test_audit.py` | [Interface web](web-ui.md#verifications) |

```python
def test_advisories_import_and_status(tmp_path, capsys):
    assert cli.run(["advisories", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["loaded"] is False
    assert cli.run(["advisories", "import", str(import_osv(tmp_path))]) == 0
    capsys.readouterr()
    assert cli.run(["advisories", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["advisories"] == 1
    assert cli.run(["advisories", "import", str(tmp_path / "nope.json")]) == cli.EXIT_ERROR
```

En CI, `tests.yml` lance la suite sur Python 3.14 et 3.15 (voir
[Vérifications, revues et publication](checks-and-releases.md)).
