# Development standards

The **development standards** are the conventions of your organization for each technology
(Python, Angular, FastAPI, Spring…): naming, structure, typing, tests, error handling,
dependencies, security. Administrators write them in the
[web interface](web-interface.md#screens); the MCP server hands them to the developer's AI
assistant **before it writes code**, so that the code it produces follows them from the start.

They complete the security review: the standards guide the writing, the review prompts check
the result.

## Content of a standard

| Field | Role |
|---|---|
| Identifier (`slug`) | Short and stable name, in lower case: `python`, `angular`, `node.js`, `c++`. It is used in the URL of the `standard://<slug>` resource and cannot be changed |
| Title, description | Shown in the list and in the catalog handed to the assistant |
| Technologies | Recognized names and aliases, comma separated (`python, fastapi`). The identifier is always recognized |
| File patterns | Globs that reveal the technology (`*.py`, `pyproject.toml`, `angular.json`, `Dockerfile*`). Case insensitive; a pattern containing `/` (`.github/workflows/*`) is compared with the full path, the others with the file name |
| Content | The rules, in Markdown (50,000 characters at most) |
| Active | A disabled standard stays visible to administrators but is no longer served to the assistants |

Example content:

```markdown
### Style
- PEP 8, line length 100, `ruff format` formatting.
- Type annotations on every public function.

### Errors
- No silent `except Exception`: log then re-raise.

### Tests
- One `pytest` test per changed behavior; no network access.
```

Write **short, checkable and imperative** rules: the assistant receives the text as is. A
standard must never weaken security; the prompt also asks the assistant to keep the safe
behavior and to report the conflict if any.

## Developer side (MCP)

| Item | Role |
|---|---|
| `development-standards` prompt | Arguments `technologies` (e.g. `python, angular`), `files` (e.g. `pyproject.toml, angular.json`), `task`, `context`, all optional. With technologies or files, the prompt contains the matching standards; without an argument, it contains the catalog and asks the assistant to detect the stack of the workspace then to call `get_development_standards` |
| `list_development_standards` tool | Catalog of the active standards (without the content) |
| `get_development_standards` tool | Standards to apply for a list of `technologies` and/or `files` (Markdown by default, or JSON). Also gives the technologies that no standard covers |
| `standards://catalog` resource | Catalog, in Markdown |
| `standard://{slug}` resource | One standard, in Markdown |

Example request to the assistant: "Apply the development standards (`development-standards`
prompt) then add the search endpoint."

The standards are read from the database at every call: a change made in the web interface
applies immediately to every instance of the MCP server. They are not limited by project: any
client allowed on `/mcp` reads them.

## Management (web interface and REST API)

The **Standards** screen of the web interface lists the standards with their technologies and
file patterns, and lets you search and read each one. Like the rules and the checklists, it is
reserved for administrators, who create, edit, disable or delete them. The AI assistants get
the active standards through the MCP server (prompt and tools above), whatever the web role of
the user.

| Method | Route | Required role |
|---|---|---|
| `GET` | `/api/v1/standards` | `admin` (disabled standards included) |
| `GET` | `/api/v1/standards/{slug}` | `admin` |
| `POST` | `/api/v1/standards` | `admin` (`409` if the identifier already exists) |
| `PUT` | `/api/v1/standards/{slug}` | `admin` (the identifier does not change) |
| `DELETE` | `/api/v1/standards/{slug}` | `admin` |

```bash
curl -X POST https://secreview.example.com/api/v1/standards \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"slug": "python", "title": "Python standards", "technologies": ["python", "fastapi"],
       "file_patterns": ["*.py", "pyproject.toml"], "content": "- PEP 8, ruff, typing."}'
```

## Limits

- 200 standards at most; 32 technologies and 32 file patterns per standard.
- Lookup by the tool or the prompt: 50 technologies and 500 file names at most, and
  `SECREVIEW_MAX_CONTENT_CHARS` characters in total.
- The content is text handed to the assistant: put neither secrets nor sensitive data in it.
