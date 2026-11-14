# Commit hooks

On the workstation of each developer, a hook checks the dependencies before every commit. It is
run by [prek](https://prek.j178.dev) (or [pre-commit](https://pre-commit.com)). The security
review of the code itself is done by the coding agent, in its session, with the
[MCP server](../getting-started/host.md).

The hook is optional: during a review, the agent already checks the dependency files that
changed. The hook adds an automatic check at every commit, without an agent, and blocks the
commit above the threshold.

| Hook | When | What it does | Blocks the commit |
|---|---|---|---|
| `scan-deps` | before the commit, when a manifest or a lockfile changes | Sends the dependency files to the Controller server, which checks them against its advisory database ([dependency analysis](../review/analysis/dependencies.md)) | Yes, when a vulnerable dependency reaches the threshold (`--fail-on`, default `high`) |

## 1. Prepare the workstation (once)

To set up the hook, install the `uv` manager. `uv` and `uvx` are the Python equivalent of `npm`
and `npx`. They need no prerequisite: Python does not have to be installed on the workstation.

PyPI or the Controller server can distribute the `security-review-ci` package.

| What | How |
|---|---|
| uv/uvx | [Installation of uv](https://docs.astral.sh/uv/getting-started/installation/) |
| prek | `uv tool install prek` |
| Your personal `ci` token | **My account** in the [web interface](../usage/tokens.md#personal-mcp-and-ci-tokens); it reaches the projects you may read |

`scan-deps` sends the dependency files to the Controller server: to do so, set the URL of the server
and your token in the environment (your shell profile, never the `.env` file).

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_CI_TOKEN=<personal ci token>
```

## 2. Declare the hook in the project (once per repository)

Here is an example of a `.pre-commit-config.yaml` file, committed at the root of your repository.
Replace `shop-api` with the name of the project, and the files of `scan-deps` with those of your
technologies.

=== "Client from the Controller server"

    The client is downloaded from the Controller server. To keep the address of your Controller server out of
    the pre-commit file, see the **Client from the Controller server (variable mode)** tab.

    ```yaml
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: uvx --no-index --find-links https://my-security-controller.com:8443/api/ci-client/ security-review-ci@latest scan-deps --require-database --project shop-api
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
    ```

=== "Client from PyPI"

    The client of PyPI, at the version of your Controller server (replace `X.Y.Z`).

    ```yaml
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: uvx security-review-ci@X.Y.Z scan-deps --skip-unconfigured --require-database --project shop-api
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
    ```

=== "Client from the Controller server (variable mode)"

    The address of the Controller server is read from the `SECREVIEW_CONTROLLER_URL` variable of each
    developer: the file then holds no reference to your servers.

    ```yaml
    repos:
      - repo: local
        hooks:
          - id: scan-deps
            name: dependency scan
            entry: bash -c '[ -n "$SECREVIEW_CONTROLLER_URL" ] || { echo "scan-deps skipped (SECREVIEW_CONTROLLER_URL is not set)" >&2; exit 0; }; exec uvx --no-index --find-links "${SECREVIEW_CONTROLLER_URL%/}/api/ci-client/" security-review-ci@latest scan-deps --require-database --project shop-api "$@"' --
            language: system
            files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
    ```

## 3. Install and check

Each developer runs, in their clone:

```bash
prek install                    # installs the pre-commit hooks
prek run scan-deps --all-files  # dependency scan of the whole repository
```

Then at every commit, `scan-deps` prints the vulnerable dependencies and stops the commit when
one reaches the threshold (exit code `1`); fix the version, or have the finding accepted in the
[triage](../usage/triage.md).

## Controller server in HTTP without TLS

Serve the Controller server over HTTPS ([TLS](tls.md)), or behind a
reverse proxy, when you can. Otherwise, HTTP works with these changes:

| Where | Change |
|---|---|
| `scan-deps` | Add `--allow-http`, otherwise the client refuses to send the token over HTTP to another host than `localhost` |

```yaml
          - id: scan-deps
            name: dependency scan
            entry: uvx --no-index --find-links http://my-security-controller.com:8080/api/ci-client/ security-review-ci@latest scan-deps --allow-http --require-database --project shop-api
```

!!! warning "What plain HTTP exposes"
    The token of each developer travels in clear, and the client
    downloaded from the Controller server can be replaced on the way, SHA-256 included: the
    workstations would run that code at each commit. On such a network, prefer the client of
    PyPI (HTTPS) to the client of the Controller server.

## Skipping or troubleshooting

| Case | Behaviour |
|---|---|
| Skip the hook once | `SKIP=scan-deps git commit …` |
| `SECREVIEW_CONTROLLER_URL` not set | `scan-deps` lets the commit through with a message (client of the Controller server, or `--skip-unconfigured` with the client of PyPI) |
| Token refused (`401`, `403`) or unknown project (`404`) | Check the token in **My account** and that it reaches the project (see [tokens](../usage/tokens.md)) |

The options of the command are in [command line](../reference/cli.md#security-review-ci).
