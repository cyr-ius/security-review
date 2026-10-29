# Tests

The tests run with pytest, without network access, on an in-memory SQLite database, in
parallel (pytest-xdist, one worker per CPU; `-n0` runs them serially to debug).

```bash
uv run pytest tests/test_scanner.py -k python   # target the tests of the changed module first
uv run pytest                                   # then the whole suite, once
```

## What to test

A test protects a contract or an invariant, not a line of code, and there is no coverage
target. Test first the security invariants, the public contracts (MCP tools and prompts, CLI exit
codes, REST schema, migrations) and each fixed bug (one regression test). Do not test what a
library already guarantees, implementation details or the exact text of a message. Before adding
a test, extend the one that already covers the behavior (extra assertion, `parametrize` row): a
change usually adds one to three tests.

A fixed bug gets **one** regression test that fails before the fix. A security invariant is
tested once, as close as possible to the module that guarantees it. The tests of a change are in
the same commit as the change.

## Conventions

- One file per module: `tests/test_<module>.py`. Add to the existing file rather than creating a
  new one.
- `tests/conftest.py` ignores the `.env` file of the developer and the `SECREVIEW_*` variables
  of the shell: a test that needs a setting sets it itself (`monkeypatch.setenv`,
  `Settings(...)`).
- `tests/conftest.py` gives each test an in-memory SQLite database and an empty rule registry:
  never use the real database. The `import_pack` fixture imports internal rules (TOML pack),
  `triage` records a decision as a person would, `tmp_path` holds the files.
- `tests/conftest.py` hashes passwords with a tiny scrypt cost; a test that checks the production
  cost is marked `@pytest.mark.real_password_hashing`.
- No network, no `sleep`, no dependency on the order of the tests. Keys and tokens are fake.

## Tests by kind of code

| Code | Test | Example |
|---|---|---|
| MCP tool, prompt or resource | End to end with `mcp.client.Client(mcp)` (`pytestmark = pytest.mark.anyio`), with a representative error case (`result.is_error`) | `tests/test_server.py`, see [MCP server](mcp-server.md#tests) |
| Scan rule | At least one **positive** case (the vulnerable pattern is found) and one **negative** case (the equivalent safe code is not) | `tests/test_scanner.py` |
| REST route | `TestClient` with the `client`, `secured` or `web_sessions` fixtures, status code and body, at least one refusal | `tests/test_web_api.py`, see [Controller server](controller.md#tests) |
| CLI command | `cli.run([...])` (or `server.main([...])`), **exit code** and output (`capsys`) | `tests/test_cli_and_tools.py` |
| Table model | A new Alembic revision; `test_upgrade_creates_the_schema_of_the_models` checks that the migrations produce the models | `tests/test_database.py` |
| Angular interface | No unit test: `npm run build` checks the types and the translation keys; the audit catalog is checked by `tests/test_audit.py` | [Web interface](web-ui.md#checks) |

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

In CI, `tests.yml` runs the suite on Python 3.14 and 3.15 (see
[Checks, reviews and releases](checks-and-releases.md)).
