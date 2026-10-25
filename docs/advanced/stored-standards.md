# Standards stored in the server

The [development standards](../usage/standards.md) live in the server, not in the repositories.
This page explains what that changes, and how to point an agent to them from `AGENTS.md`.

## What the server keeps

- The standards are stored **in the database**, like the rules. They are not in your
  repository.
- An administrator writes them in the **Standards** screen of the web interface. They can also
  be imported from a TOML file.
- Each standard lists its technologies and its file patterns (`*.py`, `angular.json`).
- Every project gets the same standards. An update applies at once to every agent.

The benefit: you write your conventions **once**, for the whole organization. No repository
needs to copy them anymore.

## How to mention them in `AGENTS.md`

- **Do not copy the standards** into `AGENTS.md`. The copies would soon drift apart.
- Tell the agent to ask the server for them before coding.
- Name the useful tools and resources: `get_development_standards`,
  `list_development_standards`, `standard://{slug}`.
- Keep in `AGENTS.md` what is **specific to the repository**: test commands, structure, local
  exceptions.
- Say who wins in case of conflict. For example: "`AGENTS.md` takes precedence over the
  standards of the server".

Example section:

```markdown
## Coding conventions
The development standards are provided by the `security-review` MCP server.
Read them before writing code:
- tool `get_development_standards` (by technology or by file);
- tool `list_development_standards` to see the catalog;
- resource `standard://python` to read one standard.
This file only keeps the rules specific to this repository. In case of conflict, it wins.
```

A standard can never weaken security. If it does, the agent keeps the safe behavior and
reports the conflict.
