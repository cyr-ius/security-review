# Host configuration

Each developer declares the shared MCP server in their host (VS Code, Claude…). The server must
already be running: see [Deploying the server](deploy.md).

## HTTP transport

For a shared server, started with `serve --transport streamable-http`, the host connects to the
`/mcp` endpoint instead of starting a process. If authentication is enabled, it sends the
token in the `Authorization: Bearer <token>` header (token generation, TLS and server start:
see [HTTP server, authentication and TLS](../advanced/http.md)).

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

On a shared server that requires a token, you use a **personal MCP token**, created in the web
interface. You do not need to ask an administrator for it before you start: configure the host
as above, **without a token**, and run your first review. The agent requests the project, then
tells you where to create your token (see
[enrollment](../advanced/http.md#enrollment-request-the-project)).

1. **Configure the host without a token.** With the examples of the
   [HTTP transport](#http-transport) section, leave the token input empty (VS Code) or do not
   set `SECURITY_REVIEW_TOKEN` (Claude). A missing header or an empty `Bearer` leads to the
   enrollment server, which has the same `security-review` name.
2. **Run a review**, for example the `security-review` prompt. Instead of reading the code, the
   agent calls the `request_enrollment` tool with the project name (usually the repository
   name): a new project waits for an administrator to approve it, and **no token** is returned:

    ```json
    {
      "project": "shop-api",
      "web_url": "https://secreview.example.internal/ui",
      "next_steps": "No token is created by the enrollment. Ask the user to sign in to …"
    }
    ```

    Without an agent, enroll from the command line:

    ```bash
    security-review-mcp enroll --url https://secreview.example.internal:8443 \
        --project shop-api --requested-by "alice (shop team)"
    ```

3. **Create your personal MCP token**: sign in to the web interface (`web_url`), open **My
   account** > **Personal tokens** and create a token with the **MCP** usage (see
   [personal MCP tokens](../usage/web-interface.md#personal-mcp-tokens); your groups need the
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

5. **Get access to the project.** The token reaches the projects your account may read: ask an
   administrator to approve the project (**Projects** screen) and to add you to its group
   `project:<project>` (an approved project has no member). Access applies at once: run the review again, without
   reconfiguring anything.

When the server refuses the token (unknown, revoked or expired), the host gets `401` with a
message that tells you to sign in to the web interface again and create a new personal MCP
token: replace it in the host as in step 4 (see
[rejected token](../advanced/http.md#rejected-token-sign-in-again)).

!!! note
    If the administrator disabled the enrollment (`SECREVIEW_ENROLLMENT=false`), a host without
    a token gets `401`: create your personal MCP token in the web interface directly, and ask an
    administrator to create the project if it is new.

## Other cases

- **Server certificate signed by an internal CA** (`unable to verify the first certificate`):
  see [HTTPS server with an internal CA](../advanced/http.md#https-server-with-an-internal-ca).
- **Local mode, without a shared server** (the host starts the process itself): see
  [Local mode (stdio)](../advanced/stdio.md).

**Next step:** run your first review with the [prompts and tools](../usage/prompts-tools.md).
