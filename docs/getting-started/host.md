# Host configuration

Each developer declares the shared MCP server in their host (VS Code, IntelliJ, Claude Code…). The server must
already be running: see [Deploying the server](deploy.md).

## HTTP transport

The host connects to the server by its URL, ending with `/mcp`. Pick your host, then the
connection mode set up by the administrator:

=== "VS Code / GitHub Copilot"

    === "OAuth login"

        `.mcp.json` at the root of the repository:

        ```json
        {
          "mcpServers": {
            "security-review": {
              "type": "http",
              "url": "https://secreview.example.internal/mcp"
            }
          }
        }
        ```

        At the first connection, the host opens the browser: sign in and approve the request. No
        token to create or copy ([OAuth login of MCP clients](../advanced/mcp-oauth.md)).

    === "Personal token"

        `.vscode/mcp.json`, with the token asked at first start:

        ```json
        {
          "servers": {
            "security-review": {
              "type": "http",
              "url": "https://secreview.example.internal/mcp",
              "headers": { "Authorization": "Bearer ${input:secreview-token}" }
            }
          },
          "inputs": [
            { "id": "secreview-token", "type": "promptString", "description": "Token", "password": true }
          ]
        }
        ```

        Keep `.vscode/mcp.json` for a token: in `.mcp.json`, VS Code does not substitute
        variables yet, and the token would have to be written in clear.

    === "Without authentication"

        For a local server on `127.0.0.1`, or behind a reverse proxy that handles
        authentication. `.mcp.json` at the root of the repository:

        ```json
        {
          "mcpServers": {
            "security-review": {
              "type": "http",
              "url": "http://127.0.0.1:8000/mcp"
            }
          }
        }
        ```

=== "Claude Code"

    === "OAuth login"

        `.mcp.json` at the root of the repository:

        ```json
        {
          "mcpServers": {
            "security-review": {
              "type": "http",
              "url": "https://secreview.example.internal/mcp"
            }
          }
        }
        ```

        At the first connection, the host opens the browser: sign in and approve the request. No
        token to create or copy ([OAuth login of MCP clients](../advanced/mcp-oauth.md)).

    === "Personal token"

        `.mcp.json`, with the token read from the `SECURITY_REVIEW_TOKEN` environment variable of
        the workstation. While it does not exist, the header stays empty, which allows the
        [enrollment](#getting-a-token):

        ```json
        {
          "mcpServers": {
            "security-review": {
              "type": "http",
              "url": "https://secreview.example.internal/mcp",
              "headers": { "Authorization": "Bearer ${SECURITY_REVIEW_TOKEN:-}" }
            }
          }
        }
        ```

    === "Without authentication"

        For a local server on `127.0.0.1`, or behind a reverse proxy that handles
        authentication. `.mcp.json` at the root of the repository:

        ```json
        {
          "mcpServers": {
            "security-review": {
              "type": "http",
              "url": "http://127.0.0.1:8000/mcp"
            }
          }
        }
        ```

=== "IntelliJ / JetBrains"

    **GitHub Copilot** plugin: in the Copilot chat, in **Agent** mode, click the tools icon
    (**Configure your MCP server**) then **Add MCP Tools**. The IDE opens its `mcp.json` file,
    which belongs to your user profile.

    === "Personal token"

        ```json
        {
          "servers": {
            "security-review": {
              "url": "https://secreview.example.internal/mcp",
              "requestInit": {
                "headers": { "Authorization": "Bearer <token>" }
              }
            }
          }
        }
        ```

        The token is written in the file: never copy it into the repository. Leave out
        `requestInit` as long as you have no token (see [enrollment](#getting-a-token)).

    === "Without authentication"

        For a local server on `127.0.0.1`, or behind a reverse proxy that handles
        authentication.

        ```json
        {
          "servers": {
            "security-review": {
              "url": "http://127.0.0.1:8000/mcp"
            }
          }
        }
        ```

        **JetBrains AI Assistant**: **Settings** > **Tools** > **AI Assistant** > **Model Context
        Protocol (MCP)** > **Add**, then paste the same configuration. AI Assistant does not document
        custom headers: with a token, use the GitHub Copilot plugin.

    OAuth login: not documented for IntelliJ, use a personal token.

!!! tip
    Never write the token in clear in a versioned configuration file: use an input
    (`${input:...}`) or an environment variable.

## Getting a token

With the OAuth login, you need no token. Otherwise:

1. **Create an MCP token**: in the web interface, open **My account** > **Personal tokens** and
   create a token of usage **MCP**. It is shown **only once**: copy it.
2. **Save it in the host**, then restart the `security-review` server in the host:

    === "VS Code / GitHub Copilot"

        Restart the `security-review` server (**MCP: List Servers** command): VS Code asks for
        the token, paste it. If it does not ask, run **MCP: Reset Cached Inputs** first.

    === "Claude Code"

        Set the variable before starting Claude Code, for example in the shell profile:

        ```bash
        export SECURITY_REVIEW_TOKEN='Zq3…'
        ```

    === "IntelliJ / JetBrains"

        Add the `requestInit` block with the token in the `mcp.json` file of GitHub Copilot,
        then restart the `security-review` server from the MCP tools of the Copilot chat.

3. **Start a review.** The first time, the agent asks for access to the project. If an
   administrator must approve it, the agent tells you: start the review again once access is
   given.

A refused token (revoked or expired) is replaced the same way: create a new one and save it in
the host.

**Further reading:** [personal tokens](../usage/tokens.md#personal-mcp-and-ci-tokens),
[first start without a token](../advanced/architecture/mcp-server.md#enrollment-personal-token-and-project-requests).

## Other cases

- **Server certificate signed by an internal CA** (`unable to verify the first certificate`):
  see [Certificate authority](../advanced/tls.md#certificate-authority).
- **Local mode (stdio)**, without a server (the host starts the process itself): see
  [Local mode (stdio)](stdio.md).

**Next step:** run your first review with the [prompts and tools](../reference/prompts-tools.md).
