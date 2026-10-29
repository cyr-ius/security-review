# Documentation

The documentation is written in Markdown in `docs/`, in **English and French**, and built with
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/) and the
[mkdocs-static-i18n](https://ultrabug.github.io/mkdocs-static-i18n/) plugin.

```bash
uv sync --extra docs
uv run mkdocs serve          # preview on http://127.0.0.1:8000, hot reload
uv run mkdocs build --strict # what the CI does: a broken link fails the build
```

- Every page exists twice, side by side: `page.md` in English (default language, served at the
  root of the site) and `page.fr.md` in French (served under `/fr/`). Change both in the same
  commit.
- Links between pages target the English file (`../reference/cli.md`): the plugin points them
  to the French page from a French page. Anchors follow the headings of each language
  (`#report-language` in English, `#langue-des-rapports` in French).
- The pages follow the order of a set-up: **Getting started** (`getting-started/`),
  **Security review** (how it works, prompts and tools, rules, checklists, standards, gate, in `review/`) and **Application** (web interface, triage, tokens, accounts, projects, roles and permissions, OIDC login, audit log, in `usage/`) only hold what is needed to work; **Connectors** (`usage/connectors/`, a sub-menu of **Application**) has one page per
  built-in connector; **Advanced** (`advanced/`) gathers the details and the optional features. Put a detailed explanation in `advanced/`, with at most a
  line and a link from the essential pages.
- To add a page, create both files in `docs/`, declare the English one in the `nav` section of
  `mkdocs.yml`, and translate its title in `nav_translations` (French language of the `i18n`
  plugin).
- To show a file of `examples/`, include it rather than copying it:
  `--8<-- "kubernetes/postgres.yaml"` (`pymdownx.snippets`, paths relative to `examples/`; a
  missing file fails the build). In a link to a file of the repository, write
  `\{{ release_tag }}` instead of `master`: the hook `scripts/mkdocs_hooks.py` replaces it with the
  tag of the version of `pyproject.toml` (`v3.0.0`), so that the copied commands fetch the files
  of the documented release.

## Writing rules

- Both versions of a page say the same thing: no section that exists in one language only. The
  examples (commands, outputs, JSON) are identical; only the text and the comments are
  translated.
- The web interface is translated (English, French, Spanish): each version quotes the labels of
  the interface in its language, as they are shown (**Tokens** in English, **Jetons** in
  French).
- The process that serves the web interface and the REST API is always named **Controller
  server** in English and **serveur Controller** in French: "Controller" keeps its English form
  and its capital C, and is never used alone. Commands, file names and identifiers
  (`security-review-controller`, `SECREVIEW_CONTROLLER_URL`) are unchanged.
- A view of the web interface is called a **page** (the **Tokens** page), never a "screen",
  except in "full screen".
- The examples can be copied as they are: options, variable names and outputs match the current
  code.
- A change of the code updates its documentation in the same commit. The table "Si vous
  modifiez..." of `AGENTS.md` gives the pages to update for each kind of change (MCP tool, scan
  rule, CLI option, `SECREVIEW_*` setting, REST API…).

## README

`README.md` (English, shown on PyPI and GitHub) and `README.fr.md` (French) are short
showcases, not a second documentation. They have the same content, translated, and only hold a
short description, the main capabilities (one line each), a minimal installation, an example of
host configuration and links to the documentation.

- Everything in the README is also in `docs/`; the reverse is not true.
- A visible capability added (tool, prompt, command, transport) gets **one line** in the README,
  with a link to its page; a capability removed or renamed is fixed there.
- Change both files together. The links target the published site:
  `https://cyr-ius.github.io/security-review/...` from `README.md`,
  `https://cyr-ius.github.io/security-review/fr/...` (French anchors) from `README.fr.md`.

## Publishing

The `.github/workflows/docs.yml` workflow:

- on a **pull request** that touches `docs/`, `mkdocs.yml`, `examples/`, `pyproject.toml` (version of
  the links) or the hook `scripts/mkdocs_hooks.py`: builds the site in `--strict`
  mode (check only);
- on a **push on `master`**: builds the site and publishes it on GitHub Pages.

One-time activation in the GitHub repository: **Settings → Pages → Build and deployment →
Source: GitHub Actions**.
