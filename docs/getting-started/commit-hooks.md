# Commit hooks

Two hooks bring the security review to the workstation of each developer, at every commit:

| Hook | When | What it does | Blocks the commit |
|---|---|---|---|
| `scan-deps` | before the commit, when a manifest or a lockfile changes | Sends the dependency files to the controller, which checks them against its advisory database ([dependency analysis](../advanced/dependencies.md)) | Yes, when a vulnerable dependency reaches the threshold (`--fail-on`, default `high`) |
| `agent-review` | after the commit | Has the coding agent of the developer (Claude Code, GitHub Copilot or Codex) review the commit with the MCP server and save a report ([agent review](../advanced/ci.md#agent-review-of-each-commit)) | Never |

Both run `security-review-ci`, the client of the controller, which needs no Python: uv
downloads it, and a Python when none is installed. The hooks are run by
[prek](https://prek.j178.dev) (or [pre-commit](https://pre-commit.com)).

## 1. Prepare the workstation (once)

| What | How |
|---|---|
| uv | [Installation of uv](https://docs.astral.sh/uv/getting-started/installation/) |
| prek | `uv tool install prek` |
| A personal `mcp` token | **My account** in the [web interface](../usage/tokens.md#personal-mcp-and-ci-tokens): it reaches the projects you may read, for both hooks |
| The CLI of your agent (for `agent-review`), signed in with your account | `npm install -g @anthropic-ai/claude-code`, `npm install -g @github/copilot` or `npm install -g @openai/codex` |

`scan-deps` reads the controller and the token from the environment (your shell profile, never
the `.env` file):

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_TOKEN=<personal mcp token>
```

`agent-review` gives your agent the `security-review` MCP server of the `.mcp.json` file at the
root of the repository, the file that Claude Code and the Copilot CLI already read. Keep it out
of git: it holds your token.

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

`.pre-commit-config.yaml`, committed at the root of the repository. Replace `shop-api` with the
name of the project in the controller, and the files of `scan-deps` with those of your
technologies. `default_install_hook_types` makes `prek install` install the post-commit hook
too.

=== "Client from the controller"

    The controller serves its own client: no PyPI, no version to maintain (unless
    `SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED=false` on the controller, see
    [from the controller](../advanced/ci.md#from-the-controller)).

    ```yaml
    default_install_hook_types: [pre-commit, post-commit]
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: uvx --no-index --find-links https://secreview.example.com/api/ci-client/ security-review-ci@latest scan-deps --skip-unconfigured --require-database --project shop-api
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
          - id: agent-review
            name: agent security review
            entry: uvx --no-index --find-links https://secreview.example.com/api/ci-client/ security-review-ci@latest agent-review --project shop-api
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

prek passes the changed files to `scan-deps` (`files` selects them); `agent-review` takes no
file (`pass_filenames: false`) and reads the last commit.

## 3. Install and check

Each developer runs, in their clone:

```bash
prek install                                   # pre-commit and post-commit hooks
prek run scan-deps --all-files                 # dependency scan of the whole repository, now
prek run agent-review --hook-stage post-commit # review of the last commit, in the background
```

Then at every commit:

- `scan-deps` prints the vulnerable dependencies and stops the commit when one reaches the
  threshold (exit code `1`); fix the version, or have the finding accepted in the
  [triage](../usage/triage.md).
- `agent-review` prints `security review of <commit> by <agent> started in the background` and
  returns at once; the report appears in the web interface after a few minutes, and the log of
  the agent is in `.git/agent-review/<commit>.log`.

## Controller in plain HTTP

Serve the controller and the MCP server over HTTPS ([TLS](../advanced/tls.md), or a reverse
proxy). On a closed network (lab, local machine), plain HTTP works with these changes:

| Where | Change |
|---|---|
| `scan-deps` | Add `--allow-http` to its `entry`: the client refuses to send the token over plain HTTP to another host than `localhost` |
| Client from the controller | Write `http://` in `--find-links`: uv accepts it |
| `.mcp.json` | Write `http://` in the `url` of the MCP server |
| `agent-review` | Nothing: it does not contact the controller |

```yaml
          - id: scan-deps
            name: dependency scan
            entry: uvx --no-index --find-links http://secreview.lan:8080/api/ci-client/ security-review-ci@latest scan-deps --allow-http --skip-unconfigured --require-database --project shop-api
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
| `SECREVIEW_CONTROLLER_URL` not set | `scan-deps` lets the commit through with a warning (`--skip-unconfigured`) |
| No agent CLI, no `.mcp.json` or no `security-review` server in it | `agent-review` does nothing, with a warning |
| Commit with a `Security-Review: <report id>` trailer | `agent-review` does nothing: an agent already reviewed it in its session |
| Several agents installed | The first of `claude`, `copilot`, `codex`, or the one of `AGENT_REVIEW_CLI` |
| Token refused (`401`, `403`) or unknown project (`404`) | Check the token in **My account** and that it reaches the project (see [tokens](../usage/tokens.md)) |

The options of both commands are in [command line](../reference/cli.md#security-review-ci).
