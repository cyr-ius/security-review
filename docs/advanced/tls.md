# TLS

The [MCP server](mcp-server.md) and the [controller](controller.md) serve HTTPS themselves, or
behind a reverse proxy that terminates TLS.

Uvicorn serves HTTPS directly when a certificate is given, for the MCP server as for the
controller (same options, same variables):

```bash
security-review-mcp serve --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
security-review-controller serve --host 0.0.0.0 --port 9443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# or SECREVIEW_TLS_CERTFILE / SECREVIEW_TLS_KEYFILE (+ SECREVIEW_TLS_KEYFILE_PASSWORD)
```

`SECREVIEW_TLS_CLIENT_CA` also enables **mutual TLS**: only the clients presenting a
certificate signed by this CA can connect.

## Certificate authority

The server never generates a certificate: provide one signed by a certificate authority
trusted by the clients, a public CA (for example Let's Encrypt, or cert-manager in Kubernetes)
or the **internal CA** of your organization. Its `subjectAltName` must contain the names and
addresses used by the clients (for example `DNS:secreview.lan,IP:192.168.1.1`); otherwise the
clients refuse the connection even when they trust the CA. The key file (`key.pem`) never
leaves the server: keep it readable by the server account only (`chmod 600`).

With an internal CA, the clients must trust its certificate: see
[HTTPS server with an internal CA](#https-server-with-an-internal-ca).

## HTTPS server with an internal CA

When the server certificate is signed by an
[internal CA](#certificate-authority), the host refuses the connection
(`unable to verify the first certificate`, `unable to get local issuer certificate`). Neither VS Code nor
Claude has a per-server TLS option in its MCP configuration: the certificate is added to the
trusted authorities of the host **process**. Claude Code and VS Code run on Node.js, which reads
the `NODE_EXTRA_CA_CERTS` environment variable (PEM file) for this, **when the process starts**.

1. Get the certificate of the internal CA (PEM) from its administrators, save it as
   `~/.config/secreview/ca.pem`, and check that the name or address of the MCP `url` is in the
   server certificate:

    ```bash
    openssl s_client -connect 192.168.1.1:8000 -CAfile ~/.config/secreview/ca.pem </dev/null \
        2>/dev/null | openssl x509 -noout -ext subjectAltName
    ```

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

The remote connectors added from the Claude web interface (claude.ai, Claude Desktop) are
contacted from Anthropic's infrastructure, not from the workstation: they require a server
reachable from the Internet with a publicly trusted certificate, which rules out an internal
CA.

`security-review-ci` accepts `--cafile` directly (see the [CLI](../reference/cli.md)). The MCP
configuration of the host
itself is in [Host configuration](../getting-started/host.md#http-transport).

## Behind a reverse proxy

A reverse proxy or an Ingress can terminate TLS instead (leave the `SECREVIEW_TLS_*` variables
empty). Then set `SECREVIEW_FORWARDED_ALLOW_IPS` to its address, so that the client address is
read from `X-Forwarded-For` for the login throttling, the rate limit and the audit log
(see the exposure of the [MCP server](mcp-server.md#exposure-and-replicas) and of the
[controller](controller.md#exposure)).

!!! warning
    If a process listens elsewhere than on localhost without TLS, a warning is logged: the
    tokens and the sessions would travel in clear. Behind a reverse proxy that terminates TLS,
    the warning is expected, as long as only the proxy reaches the process.
