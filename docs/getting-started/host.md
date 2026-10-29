# Host configuration

Each developer declares the shared MCP server in their host (VS Code, IntelliJ, Claude…). The server must
already be running: see [Deploying the server](deploy.md).

## HTTP transport

In shared mode, with the server started with `serve --transport streamable-http`, the host connects to the
`/mcp` endpoint instead of starting a process. It sends the token in the
`Authorization: Bearer <token>` header (see [Bearer tokens](../advanced/bearer-tokens.md) and
[TLS](../advanced/tls.md)).

=== "VS Code / GitHub Copilot"

    `.vscode/mcp.json`, with a token asked to the user at first start:

    ```json
    {
      "servers": {
        "security-review": {
          "type": "http",
          "url": "https://secreview.example.internal:8443/mcp",
          "headers": { "Authorization": "Bearer ${input:secreview-token}" }
        }
      },
      "inputs": [
        { "id": "secreview-token", "type": "promptString", "description": "Token", "password": true }
      ]
    }
    ```

    VS Code now prefers the `.mcp.json` file at the root of the repository and marks
    `.vscode/mcp.json` as deprecated, but still reads it. Keep it for a server with a token:
    in `.mcp.json`, VS Code does not substitute variables yet (neither `${input:...}` nor
    environment variables), and the token would have to be written in clear.

=== "Claude"

    `.mcp.json`, with the token read from the `SECURITY_REVIEW_TOKEN` environment variable of
    the workstation (client side, distinct from the `SECREVIEW_*` settings of the server). `:-`
    gives an empty value while the variable does not exist, which allows the
    [enrollment](#getting-a-token):

    ```json
    {
      "mcpServers": {
        "security-review": {
          "type": "http",
          "url": "https://secreview.example.internal:8443/mcp",
          "headers": { "Authorization": "Bearer ${SECURITY_REVIEW_TOKEN:-}" }
        }
      }
    }
    ```

=== "IntelliJ / JetBrains"

    **GitHub Copilot** plugin: in the Copilot chat, in **Agent** mode, click the tools icon
    (**Configure your MCP server**) then **Add MCP Tools**. The IDE opens its `mcp.json` file,
    which belongs to your user profile and not to the repository:

    ```json
    {
      "servers": {
        "security-review": {
          "url": "https://secreview.example.internal:8443/mcp",
          "requestInit": {
            "headers": { "Authorization": "Bearer <token>" }
          }
        }
      }
    }
    ```

    This file does not substitute variables: the token is written in it, so never copy it into
    the repository. Leave out `requestInit` as long as you have no token (see
    [enrollment](#getting-a-token)).

    **JetBrains AI Assistant**: **Settings** > **Tools** > **AI Assistant** > **Model Context
    Protocol (MCP)** > **Add**, then paste the configuration of a server without
    authentication (example below). AI Assistant does not document custom
    headers: with a token, use the GitHub Copilot plugin.

Without authentication (local server on `127.0.0.1`, or authentication handled by a reverse
proxy), VS Code, GitHub Copilot and Claude share the same `.mcp.json` file at the root of the
repository, without `headers`:

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

!!! tip
    Never write the token in clear in a versioned configuration file: use an input
    (`${input:...}`) or an environment variable.

## Getting a token

If the administrator enabled the [OAuth login of MCP clients](../advanced/mcp-oauth.md), you need
no token: declare the server with its URL only, without `Authorization` header; at the first
connection the host opens the browser, where you sign in and approve it. Otherwise:

In shared mode, when the server requires a token, you use a **personal MCP token**, created in the web
interface. You do not need to ask an administrator for it before you start: configure the host
as above, **without a token**, and run your first review. The agent tells you where to create
your token, then requests the project at the next review (see
[enrollment](../advanced/architecture/mcp-server.md#enrollment-personal-token-and-project-requests)).

1. **Configure the host without a token.** With the examples of the
   [HTTP transport](#http-transport) section, leave the token input empty (VS Code), do not
   set `SECURITY_REVIEW_TOKEN` (Claude) or leave out `requestInit` (IntelliJ). A missing header or an empty `Bearer` leads to the
   enrollment server, which has the same `security-review` name.
2. **Run a review**, for example the `security-review` prompt. Instead of reading the code,
   the agent tells you to sign in to the web interface (its address is given when the
   administrator set it: `SECREVIEW_PUBLIC_URL` or **General** screen) and to create a personal MCP token. The server
   records nothing at this step.

3. **Create your personal MCP token**: sign in to the web interface, open **My
   account** > **Personal tokens** and create a token with the **MCP** usage (see
   [personal MCP tokens](../usage/tokens.md#personal-mcp-and-ci-tokens); your groups need the
   `mcp-user` role). It is shown **only once**.
4. **Store the token in the host**, then restart the MCP server in the host:

    === "VS Code / GitHub Copilot"

        If the input was already remembered empty, run the **MCP: Reset Cached Inputs**
        command, then restart the `security-review` server (**MCP: List Servers** command):
        VS Code asks for the token again, paste it. It is kept in the secure storage of
        VS Code.

    === "Claude"

        Set the variable before starting Claude, for example in the shell profile:

        ```bash
        export SECURITY_REVIEW_TOKEN='Zq3…'
        ```

    === "IntelliJ / JetBrains"

        Add the `requestInit` block with the token in the `mcp.json` file of GitHub Copilot,
        then restart the `security-review` server from the MCP tools of the Copilot chat.

5. **Run the review again.** The agent first calls `request_project` with the project name
   (usually the repository name). If you may create projects, a new project is created with you
   as its member and the review goes on. Otherwise the agent stops and tells you that the
   project is requested: an administrator approves it on the **Projects** screen, which gives you
   access to it. For a project that already exists, the request is an access request, approved
   the same way. Access applies at once: run the review again, without reconfiguring
   anything.

When the server refuses the token (unknown, revoked or expired), the host gets `401` with a
message that tells you to sign in to the web interface again and create a new personal MCP
token: replace it in the host as in step 4 (see
[rejected token](../advanced/architecture/mcp-server.md#rejected-token-sign-in-again)).

!!! note
    If the administrator disabled the enrollment (`SECREVIEW_ENROLLMENT=false`), a host without
    a token gets `401`, and `request_project` creates or requests no project: create your
    personal MCP token in the web interface directly, and ask an administrator for access to the
    project.

## Other cases

- **Server certificate signed by an internal CA** (`unable to verify the first certificate`):
  see [Certificate authority](../advanced/tls.md#certificate-authority).
- **Local mode (stdio)**, without a server (the host starts the process itself): see
  [Local mode (stdio)](stdio.md).

**Next step:** run your first review with the [prompts and tools](../review/prompts-tools.md).
