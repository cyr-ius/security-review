# MCP server

The MCP server (`security-review-mcp`) exposes the prompts, tools and resources used by the
host. It shares the database with the controller but never calls it. Its code is in
`server.py` (declarations), `prompts.py` (text of the prompts) and the business modules
(`reports/services.py`, `rules/`, `deps/`…): `server.py` stays a thin layer that validates the
inputs and calls these modules.

```bash
uv run security-review-mcp serve                         # stdio, as a host starts it
uv run security-review-mcp serve --transport streamable-http --port 8000
uv run pytest tests/test_server.py                       # end-to-end tests of the MCP layer
```

## Tools

Every tool carries `annotations=READ_ONLY` or `WRITE` and the `@_tool_errors` decorator, which
turns `ValueError` and `services.NotFoundError` into a `ToolError` that the model can read (the
SDK hides the message of any other exception). Raise these exceptions for the expected errors;
never return an error dictionary.

```python
@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def scan_code(
    content: Annotated[str, Field(description="Source or configuration text to scan")],
    language: Annotated[
        str, Field(description=f"One of: {', '.join(scanner.SUPPORTED_LANGUAGES)}")
    ],
) -> dict:
    """Quick pattern scan that returns suspicious lines to verify (not a full SAST)."""
    limit = get_settings().max_content_chars
    if len(content) > limit:
        raise ValueError(f"Content too large ({len(content)} chars); the limit is {limit}")
    ...
```

- Describe each parameter with `Annotated[..., Field(description=...)]` and the tool with its
  docstring: this is what the model of the host reads.
- Bound every text or list input with a setting of `Settings` (`max_content_chars`,
  `max_findings_per_report`, `max_list_limit`…).
- A new tool or prompt that changes how a review goes is cited in `INSTRUCTIONS`
  (`server.py`).
- No tool changes the status of a finding: `propose_finding_status` only records a proposal,
  approved by a person in the web interface.

## Prompts and resources

- A prompt is declared with `@mcp.prompt(name=..., title=..., description=...)`; its text is
  built in `prompts.py`, and its arguments are documented in the `Args:` section of the
  docstring.
- The content given by the user (code, diff, context) is wrapped with `prompts.fenced`, so that
  it cannot close the block and pass for instructions.
- The review prompts end with a single call to `save_security_report`.
- The resources use `@_resource_errors`, the equivalent of `@_tool_errors`.

## Security invariants

The MCP process runs next to the code of the developer, often in stdio: a deviation here is a
blocking bug.

- **stdout belongs to the MCP protocol**: no `print`, logs on stderr through
  `logging.getLogger("security_review_mcp")`.
- **No disk access from a client path**: the tools work on the content they receive.
- **No outgoing network call**: the vulnerability database is imported by the controller.
- **No module of the controller is loaded**, not even indirectly (`controller`,
  `deps/advisory_sync`, `auth/oidc`, `observability/audit_syslog`, `connectors`,
  `update_check`, `web_api`): `test_mcp_server_does_not_load_the_controller_modules` imports
  `server` in a fresh interpreter and checks it. A shared module imports them inside the
  function that needs them.
- **Secrets are masked** (`scanner.redact_secrets`) before storage and in the returned
  excerpts; a token, a password or a database URL with credentials is never logged.
- The HTTP MCP server never migrates the schema and only exposes `/mcp`, the public enrollment
  and `/healthz`.

## Scan rules

The default rules and checklists are in `src/security_review_mcp/rules/default_rules.toml`,
never in the Python code. They are copied into the database at first start, and a rule added or
fixed there reaches the existing databases at the next start, unless an administrator changed
it.

```toml
[[rules]]
id = "GEN-001"
title = "Hard-coded credential"
severity = "high"
cwe = "CWE-798"
languages = ["*"]
pattern = "(password|passwd|pwd|secret|api[_-]?key|token)\\s*[:=]\\s*[\\\"'][^\\\"'\\s]{6,}[\\\"']"
advice = "Move the secret to a vault or environment variable and rotate it."
```

- Identifiers `PREFIX-NNN` by family (`PY`, `JV`, `NG`, `CFG`, `GEN`, `FA`, `TS`…): never reuse
  or renumber one, users cite them in `secreview:ignore` and `disabled_rules`. Give the CWE when
  there is one.
- Avoid catastrophic backtracking: no nested quantifiers (`rules_loader` validates the internal
  rules).
- Document the rule in `docs/usage/rules` (or `usage/checklists` for a checklist), in both
  languages.

## Tests

- Tools, prompts and resources: end-to-end test with a real MCP client in memory, with a
  representative error case.

    ```python
    pytestmark = pytest.mark.anyio

    async def test_invalid_input_returns_a_tool_error():
        async with Client(mcp) as client:
            result = await client.call_tool("get_security_report", {"report_id": 424242})
        assert result.is_error
        assert "not found" in text_of(result).lower()
    ```

    A `ToolError` reaches the client as a result with `is_error` set, and its message in the
    text of the result.

- Scan rule: at least one **positive** case (the vulnerable pattern is found) and one
  **negative** case (the equivalent safe code is not), in `tests/test_scanner.py`.
- `tests/conftest.py` gives each test an in-memory SQLite database and an empty rule
  registry; the `import_pack` fixture loads internal rules.

See also the [prompts and tools](../usage/prompts-tools.md) as users see them, and the
[rules](../usage/rules.md).
