# TLS and certificates

The [MCP server](architecture/mcp-server.md) and the [Controller server](architecture/controller.md) serve HTTPS themselves, or
behind a reverse proxy that terminates TLS.

Uvicorn serves HTTPS directly when a certificate is given, for the MCP server as for the
Controller server (same options, same variables):

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

With an internal CA, the clients must trust its certificate.

## Behind a reverse proxy

A reverse proxy or an Ingress can terminate TLS instead (leave the `SECREVIEW_TLS_*` variables
empty). Then set `SECREVIEW_FORWARDED_ALLOW_IPS` to its address, so that the client address is
read from `X-Forwarded-For` for the login throttling, the rate limit and the audit log
(see the exposure of the [MCP server](architecture/mcp-server.md#exposure-and-replicas) and of the
[Controller server](architecture/controller.md#exposure)).

!!! warning
    If a process listens elsewhere than on localhost without TLS, a warning is logged: the
    tokens and the sessions would travel in clear. Behind a reverse proxy that terminates TLS,
    the warning is expected, as long as only the proxy reaches the process.
