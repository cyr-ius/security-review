# Commit hooks

The security review on the workstation of each developer is done by two hooks, at every commit.
The hooks are run by [prek](https://prek.j178.dev) (or [pre-commit](https://pre-commit.com)).

| Hook | When | What it does | Blocks the commit |
|---|---|---|---|
| `scan-deps` | before the commit, when a manifest or a lockfile changes | Sends the dependency files to the controller, which checks them against its advisory database ([dependency analysis](../review/analysis/dependencies.md)) | Yes, when a vulnerable dependency reaches the threshold (`--fail-on`, default `high`) |
| `agent-review` | after the commit | Has the coding agent of the developer (Claude Code, GitHub Copilot or Codex) review the commit with the MCP server and save a report ([agent review](../advanced/architecture/ci.md#agent-review-of-each-commit)) | Never |

## 1. Prepare the workstation (once)

To set up the hooks, install the `uv` manager. `uv` and `uvx` are the Python equivalent of `npm`
and `npx`. They need no prerequisite: Python does not have to be installed on the workstation.

PyPI or the controller can distribute the `security-review-ci` package.

| What | How |
|---|---|
| uv/uvx | [Installation of uv](https://docs.astral.sh/uv/getting-started/installation/) |
| prek | `uv tool install prek` |
| Your personal `mcp` token | **My account** in the [web interface](../usage/tokens.md#personal-mcp-and-ci-tokens): it reaches the projects you may read, for both hooks |
| The CLI of your agent (for `agent-review`), signed in with your account | `npm install -g @anthropic-ai/claude-code`, `npm install -g @github/copilot` or `npm install -g @openai/codex` |

`scan-deps` sends the dependency files to the controller: to do so, set the URL of the server
and your token in the environment (your shell profile, never the `.env` file).

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_TOKEN=<personal mcp token>
```

`agent-review` relies on the declaration of your MCP server in the `.mcp.json` file at the root
of the repository. Keep it out of git: it holds your token.

```json
{
  "mcpServers": {
    "security-review": {
      "type": "http",
      "url": "https://secreview.example.com:8443/mcp",
      "headers": { "Authorization": "Bearer <personal mcp token>" }
    }
  }
}
```

```bash
echo ".mcp.json" >> .gitignore
```

## 2. Declare the hooks in the project (once per repository)

Here is an example of a `.pre-commit-config.yaml` file, committed at the root of your repository.
Replace `shop-api` with the name of the project, and the files of `scan-deps` with those of your
technologies.

=== "Client from the controller"

    The client is downloaded from the controller. To keep the address of your controller out of
    the pre-commit file, see the **Client from the controller (variable mode)** tab.

    ```yaml
    default_install_hook_types: [pre-commit, post-commit]
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: uvx --no-index --find-links https://my-security-controller.com:8443/api/ci-client/ security-review-ci@latest scan-deps --require-database --project shop-api
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
          - id: agent-review
            name: agent security review
            entry: uvx --no-index --find-links https://my-security-controller.com:8443/api/ci-client/ security-review-ci@latest agent-review --project shop-api
            language: system
            stages: [post-commit]
            always_run: true
            pass_filenames: false
    ```

=== "Client from PyPI"

    The client of PyPI, at the version of your controller (replace `X.Y.Z`).

    ```yaml
    default_install_hook_types: [pre-commit, post-commit]
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: uvx security-review-ci@X.Y.Z scan-deps --skip-unconfigured --require-database --project shop-api
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
          - id: agent-review
            name: agent security review
            entry: uvx security-review-ci@X.Y.Z agent-review --project shop-api
            language: system
            stages: [post-commit]
            always_run: true
            pass_filenames: false
    ```

=== "Client from the controller (variable mode)"

    The address of the controller is read from the `SECREVIEW_CONTROLLER_URL` variable of each
    developer: the file then holds no reference to your servers.

    ```yaml
    default_install_hook_types: [pre-commit, post-commit]
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: bash -c '[ -n "$SECREVIEW_CONTROLLER_URL" ] || { echo "scan-deps skipped (SECREVIEW_CONTROLLER_URL is not set)" >&2; exit 0; }; exec uvx --no-index --find-links "${SECREVIEW_CONTROLLER_URL%/}/api/ci-client/" security-review-ci@latest scan-deps --require-database --project shop-api "$@"' --
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
          - id: agent-review
            name: agent security review
            entry: bash -c '[ -n "$SECREVIEW_CONTROLLER_URL" ] || { echo "agent-review skipped (SECREVIEW_CONTROLLER_URL is not set)" >&2; exit 0; }; exec uvx --no-index --find-links "${SECREVIEW_CONTROLLER_URL%/}/api/ci-client/" security-review-ci@latest agent-review --project shop-api' --
            language: system
            stages: [post-commit]
            always_run: true
            pass_filenames: false
    ```

## 3. Install and check

Each developer runs, in their clone:

```bash
prek install                                   # installs the pre-commit and post-commit hooks
prek run scan-deps --all-files                 # dependency scan of the whole repository
prek run agent-review --hook-stage post-commit # review of the last commit, in the background
```

Then at every commit:

- `scan-deps` prints the vulnerable dependencies and stops the commit when one reaches the
  threshold (exit code `1`); fix the version, or have the finding accepted in the
  [triage](../usage/triage.md).
- `agent-review` prints `security review of <commit> by <agent> started in the background` and
  returns at once; the report appears in the web interface after a few minutes, and the log of
  the agent is in `.git/agent-review/<commit>.log`.

## Controller in HTTP without TLS

Serve the controller and the MCP server over HTTPS ([TLS](../advanced/tls.md)), or behind a
reverse proxy, when you can. Otherwise, HTTP works with these changes:

| Where | Change |
|---|---|
| `scan-deps` | Add `--allow-http`, otherwise the client refuses to send the token over HTTP to another host than `localhost` |
| `.mcp.json` | Write `http://` in the `url` of the MCP server |

```yaml
          - id: scan-deps
            name: dependency scan
            entry: uvx --no-index --find-links http://my-security-controller.com:8080/api/ci-client/ security-review-ci@latest scan-deps --allow-http --require-database --project shop-api
          - id: agent-review
            name: agent security review
            entry: uvx --no-index --find-links http://my-security-controller.com:8080/api/ci-client/ security-review-ci@latest agent-review --project shop-api
            language: system
            stages: [post-commit]
            always_run: true
            pass_filenames: false
```

!!! warning "What plain HTTP exposes"
    The token of each developer travels in clear (`scan-deps`, MCP server), and the client
    downloaded from the controller can be replaced on the way, SHA-256 included: the
    workstations would run that code at each commit. On such a network, prefer the client of
    PyPI (HTTPS) to the client of the controller.

## Skipping or troubleshooting

| Case | Behaviour |
|---|---|
| Skip a hook once | `SKIP=agent-review git commit …` (or `SKIP=scan-deps`) |
| `SECREVIEW_CONTROLLER_URL` not set | Both hooks let the commit through with a message (client of the controller); `scan-deps` too with `--skip-unconfigured` (client of PyPI) |
| No agent CLI, no `.mcp.json` or no `security-review` server in it | `agent-review` does nothing, with a warning |
| Commit with a `Security-Review: <report id>` trailer | `agent-review` does nothing: an agent already reviewed it in its session |
| Several agents installed | The first of `claude`, `copilot`, `codex`, or the one of `AGENT_REVIEW_CLI` |
| Token refused (`401`, `403`) or unknown project (`404`) | Check the token in **My account** and that it reaches the project (see [tokens](../usage/tokens.md)) |

The options of both commands are in [command line](../reference/cli.md#security-review-ci).
