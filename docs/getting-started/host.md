# Host configuration

Each developer declares the shared MCP server in their host (VS Code, Claude…). The server must
already be running: see [Deploying the server](deploy.md).

## HTTP transport

For a shared server, started with `--transport streamable-http`, the host connects to the
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
    [enrollment](#getting-a-token-enrollment):

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

## Getting a token (enrollment)

On a shared server that requires a token, you do not need to ask the administrator for one
before you start: configure the host as above, **without a token**, and run your first review.
The token is requested along the way, then approved by an administrator (see
[enrollment](../advanced/http.md#enrollment-a-project-requests-its-token)).

1. **Configure the host without a token.** With the examples of the
   [HTTP transport](#http-transport) section, leave the token input empty (VS Code) or do not
   set `SECURITY_REVIEW_TOKEN` (Claude). A missing header or an empty `Bearer` leads to the
   enrollment server, which has the same `security-review` name.
2. **Run a review**, for example the `security-review` prompt. Instead of reading the code, the
   agent calls the `request_enrollment` tool with the project name (usually the repository
   name) and your username as label (the token is personal), and shows you the token, **only once**:

    ```json
    {
      "label": "alice-3fa9c1",
      "project": "shop-api",
      "status": "pending",
      "token": "UJB7…"
    }
    ```

    Without an agent, request it from the command line:

    ```bash
    security-review-mcp enroll --url https://secreview.example.internal:8443 \
        --project shop-api --requested-by "alice (shop team)"
    ```

3. **Store the token in the host**, then restart the MCP server in the host:

    === "VS Code / GitHub Copilot"

        If the input was already remembered empty, run the **MCP: Reset Cached Inputs**
        command, then restart the `security-review` server (**MCP: List Servers** command):
        VS Code asks for the token again, paste it. It is kept in the secure storage of
        VS Code.

    === "Claude"

        Set the variable before starting Claude, for example in the shell profile:

        ```bash
        export SECURITY_REVIEW_TOKEN='UJB7…'
        ```

4. **Wait for the approval.** Tell the administrator the label of the token. While the request
   is pending, the host stays on the enrollment server: the `get_enrollment_status` tool
   answers `pending`. As soon as the administrator approves it (**Tokens** screen of the web
   interface, or `security-review-controller token approve <label>`), the same token gives
   access to the review tools. Run the review again, without reconfiguring anything.

The token you get has the `mcp` role and is
[restricted to the requested project](../advanced/http.md#tokens-restricted-to-a-project): it only saves
and reads the reports of that project. For another project, the agent can request a new token
with `request_enrollment`; `save_security_report` suggests it when it refuses the project.

!!! note
    If the administrator disabled the enrollment (`SECREVIEW_ENROLLMENT=false`), a host without
    a token gets `401`: ask them for a token created with
    `security-review-controller token create`.

## Other cases

- **Server certificate signed by an internal CA** (`unable to verify the first certificate`):
  see [HTTPS server with an internal CA](../advanced/http.md#https-server-with-an-internal-ca).
- **Local mode, without a shared server** (the host starts the process itself): see
  [Local mode (stdio)](../advanced/stdio.md).

**Next step:** run your first review with the [prompts and tools](../usage/prompts-tools.md).
