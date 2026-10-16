# Host configuration

## stdio transport

With the **stdio** transport, the host (VS Code, Claude…) starts the server process itself.
Give the path of the executable and, if needed, the `SECREVIEW_*` variables
(see [Configuration](../reference/configuration.md)).

=== "VS Code / GitHub Copilot"

    `.vscode/mcp.json`:

    ```json
    {
      "servers": {
        "security-review": {
          "type": "stdio",
          "command": "/opt/security-review-mcp/venv/bin/security-review-mcp",
          "env": { "SECREVIEW_DATABASE_URL": "sqlite:////data/security_reports.db" }
        }
      }
    }
    ```

=== "Claude"

    `.mcp.json`:

    ```json
    {
      "mcpServers": {
        "security-review": {
          "command": "/opt/security-review-mcp/venv/bin/security-review-mcp",
          "env": { "SECREVIEW_DATABASE_URL": "sqlite:////data/security_reports.db" }
        }
      }
    }
    ```

To run the server from a container, see [Docker](docker.md#developer-workstation-stdio).

## HTTP transport

For a shared server, started with `--transport streamable-http`, the host connects to the
`/mcp` endpoint instead of starting a process. If authentication is enabled, it sends the
token in the `Authorization: Bearer <token>` header (token generation, TLS and server start:
see [HTTP server, authentication and TLS](http.md)).

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
proxy), leave out `headers` and `inputs`, for example `"url": "http://127.0.0.1:8000/mcp"`.

!!! tip
    Never write the token in clear in a versioned configuration file: use an input
    (`${input:...}`) or an environment variable.

## Self-signed HTTPS server or internal CA

When the server uses a [self-signed certificate](http.md#self-signed-certificate) or one signed
by an internal CA, the host refuses the connection (`self signed certificate`,
`DEPTH_ZERO_SELF_SIGNED_CERT`, `unable to verify the first certificate`). Neither VS Code nor
Claude has a per-server TLS option in its MCP configuration: the certificate is added to the
trusted authorities of the host **process**. Claude Code and VS Code run on Node.js, which reads
the `NODE_EXTRA_CA_CERTS` environment variable (PEM file) for this, **when the process starts**.

1. Fetch the certificate and compare its fingerprint with the one in the server log
   (`Self-signed TLS certificate generated ... SHA-256 fingerprint`) or with
   `openssl x509 -in cert.pem -noout -fingerprint -sha256` on the server:

    ```bash
    openssl s_client -connect 192.168.1.1:8000 </dev/null 2>/dev/null \
        | openssl x509 > ~/.config/secreview/ca.pem
    openssl x509 -in ~/.config/secreview/ca.pem -noout -fingerprint -sha256
    ```

    For an internal CA, use its certificate directly. Also check that the name or address of
    the MCP `url` is in the certificate
    (`openssl x509 -in ~/.config/secreview/ca.pem -noout -ext subjectAltName`): otherwise, see
    `SECREVIEW_TLS_SELF_SIGNED_HOSTS`.

2. Declare it to the host, then **restart it**:

=== "Claude Code"

    In the shell profile (`~/.bashrc`, `~/.zshrc`), before starting `claude`:

    ```bash
    export NODE_EXTRA_CA_CERTS="$HOME/.config/secreview/ca.pem"
    ```

    The [Claude Code documentation](https://code.claude.com/docs/en/network-config) also gives
    the `env` key of `settings.json`
    (`"env": { "NODE_EXTRA_CA_CERTS": "/home/me/.config/secreview/ca.pem" }`). The variable
    applies to every connection of Claude Code, not only to the MCP server.

=== "VS Code / GitHub Copilot"

    Start VS Code from a shell where the variable is set (`code .`), or set it at system
    level:

    ```bash
    export NODE_EXTRA_CA_CERTS="$HOME/.config/secreview/ca.pem"
    code .
    ```

    Another option: add the certificate to the certificate store of the system (Windows:
    *Trusted Root Certification Authorities*; macOS: Keychain, *Always Trust*; Linux:
    `/usr/local/share/ca-certificates/` then `sudo update-ca-certificates`). VS Code loads the
    system certificates (`http.systemCertificates` setting, enabled by default).

    In a **dev container**, the connection leaves from the container: mount the file and set
    the variable in `devcontainer.json` (`"remoteEnv": { "NODE_EXTRA_CA_CERTS": "..." }`), then
    rebuild or reload the window.

!!! warning
    Do not use `NODE_TLS_REJECT_UNAUTHORIZED=0`: it disables the verification of **every**
    connection of the process (API, extensions, updates), not only the one to the MCP server,
    and lets an interception through.

With a self-signed certificate generated at start-up, the key changes **at every restart of
the server**: both steps must be done again. For lasting use, generate a
[stable certificate](http.md#stable-certificate) or use an internal CA.

The remote connectors added from the Claude web interface (claude.ai, Claude Desktop) are
contacted from Anthropic's infrastructure, not from the workstation: they require a server
reachable from the Internet with a publicly trusted certificate, which rules out a self-signed
certificate.

For the enrollment from the CLI, `security-review-mcp enroll` accepts `--cafile` directly (see
below).

## Getting a token (enrollment)

On a shared server that requires a token, you do not need to ask the administrator for one
before you start: configure the host as above, **without a token**, and run your first review.
The token is requested along the way, then approved by an administrator (see
[enrollment](http.md#enrollment-a-project-requests-its-token)).

1. **Configure the host without a token.** With the examples of the
   [HTTP transport](#http-transport) section, leave the token input empty (VS Code) or do not
   set `SECURITY_REVIEW_TOKEN` (Claude). A missing header or an empty `Bearer` leads to the
   enrollment server, which has the same `security-review` name.
2. **Run a review**, for example the `security-review` prompt. Instead of reading the code, the
   agent calls the `request_enrollment` tool with the project name (usually the repository
   name) and shows you the token, **only once**:

    ```json
    {
      "label": "shop-api-enroll-3fa9c1",
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
[restricted to the requested project](http.md#tokens-restricted-to-a-project): it only saves
and reads the reports of that project. For another project, the agent can request a new token
with `request_enrollment`; `save_security_report` suggests it when it refuses the project.

!!! note
    If the administrator disabled the enrollment (`SECREVIEW_ENROLLMENT=false`), a host without
    a token gets `401`: ask them for a token created with
    `security-review-controller token create`.
