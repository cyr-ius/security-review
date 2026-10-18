# HTTP server, authentication and TLS

A shared server (team, CI/CD) is made of **two processes** sharing the same database (see
[Architecture and deployment](architecture.md)):

- the **MCP server** (`security-review-mcp --transport streamable-http`): `/mcp` endpoint,
  public enrollment (`/api/v1/enroll`) and `/healthz` probe; it is the one exposed to the agents
  and to the CI;
- the **controller** (`security-review-controller serve`): `/api/v1` REST API, `/ui/` web
  interface and `/healthz` probe; it can stay on an internal network.

MCP authentication and TLS are **optional** and independent; the controller API always requires
a token. With stdio, the host starts the process itself and the controller is not needed.

```bash
security-review-controller db upgrade                        # creates or migrates the schema
security-review-controller serve --host 127.0.0.1 --port 8080
# web interface: http://127.0.0.1:8080/ui/
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
# MCP endpoint: http://127.0.0.1:8000/mcp
```

With SQLite, both processes must run on the same machine (same file); use PostgreSQL as soon
as they are on different machines or pods.

## Bearer tokens

Tokens are stored in the database (`apitoken` table): only their SHA-256 digest is kept, the
secret is shown only once, at creation. Manage them with the `token` command (see the
[CLI](../reference/cli.md)):

```bash
security-review-controller token create --label ci                      # mcp role by default
security-review-controller token create --label jenkins --role ci --project shop-api
security-review-controller token create --label ops-script --role admin
# {"id": "6f1c…", "label": "ci", "role": "mcp", "project": null, "created_at": "…", "token": "UJB7…"}
security-review-controller token list [--project shop-api]             # never the secret nor the digest
security-review-controller token revoke ci                              # by label or by id
```

Projects can also request their token themselves: see
[enrollment](#enrollment-a-project-requests-its-token).

- Give `token` to the client; the unique `label` appears in the logs.
- `--role` is `mcp` by default (MCP server); `admin` reaches the MCP server and the whole REST
  API of the controller, never the web interface; `ci` (always with `--project`) only reaches the pipeline routes used by
  [`security-review-ci`](../usage/gate.md#pipeline-client-security-review-ci): see the
  [roles](../usage/web-interface.md#roles); `metrics` (never with `--project`) only reaches the
  [Prometheus metrics](audit-metrics.md#prometheus-metrics) of the controller. Tokens are for
  machines: there is no `reader` or `triager` token, a person reads and triages with a
  [user account](../usage/web-interface.md#user-accounts) and its
  [groups](access-control.md).
- `--expires-in-days` sets the validity of the token: see
  [expiry and rotation](#expiry-and-rotation-of-tokens).
- `--project` limits the token to one or more projects (repeat the option), for the MCP tools
  and the pipeline routes (`mcp` and `ci` roles; refused for `admin` and `metrics`). See
  [tokens restricted to a project](#tokens-restricted-to-a-project). Administrators can also
  create and revoke restricted `mcp` and `ci` tokens from the **Tokens** screen.
- The server reads the database at every request: a creation or a revocation applies
  immediately, including to the other instances sharing the same PostgreSQL database.

The MCP endpoint and the controller API require `Authorization: Bearer <token>`. Still public: `/healthz` on both processes, `/api/v1/enroll`
on the MCP server, and on the controller the static files of `/ui/`, the `/api/favicon.svg`
icon, the `/api/health` liveness of the API and, with `SECREVIEW_SWAGGER_ENABLED=true` (disabled by default), the Swagger
documentation (`/api/docs`, `/api/openapi.json` schema, `/api/swagger/` files). While no token exists, the controller API answers `503` and the MCP server **stays closed**: a
client without a token only reaches [enrollment](#enrollment-a-project-requests-its-token), any
other request gets `401`, whatever the bearer value (a warning is logged at start-up). `/mcp` is
only open in that case when the server listens on localhost (`127.0.0.1`, `::1`) or when
`SECREVIEW_ALLOW_UNAUTHENTICATED=true`, to keep for tests on an isolated network: as soon as a
token exists, it is required in every case. `token revoke` warns on stderr when it deletes the
last token.

Every creation, rotation and revocation of a token, and every enrollment request and decision,
is written to the [audit log](audit-metrics.md#audit-log), with who made it.

### Expiry and rotation of tokens

A token may expire: after its expiry date it authenticates nothing (`401`, `error="invalid_token"`,
description `The bearer token has expired`, or the [enrollment server](#rejected-token-new-enrollment)
on `/mcp`), but it stays listed so that an administrator
rotates or revokes it. `SECREVIEW_TOKEN_MAX_DAYS` (default `0`) sets the longest validity of a
token created or rotated, and its default validity; with `0`, tokens do not expire unless a
validity is asked for.

```bash
security-review-controller token create --label shop-ci --project shop-api --expires-in-days 90
security-review-controller token rotate shop-ci --grace-hours 24     # new secret, shown once
# {"id": "6f1c…", "label": "shop-ci", …, "expires_at": "…", "rotated_at": "…", "grace_until": "…", "token": "pX4q…"}
```

A rotation replaces the secret of a token: it keeps its id, label, role and projects, and gets a
new validity (`--expires-in-days`, default as at creation). During `--grace-hours` (`0` by
default, at most `168`) the previous secret keeps working, the time to update the clients
(`grace_until` in `token list`); after that, only the new one authenticates. The previous secret
of an expired token never comes back. After a leak, rotate without a grace period (or revoke):
the leaked secret then stops at once. An enrollment request still waiting for approval cannot
be rotated. In the web interface, the **Tokens** screen rotates the project tokens (button
**Rotate**, grace period chosen above the list).

Expired tokens still count as configured tokens: a server whose tokens have all expired stays
closed, it never becomes open.

### Tokens restricted to a project

On a server shared by several teams, give each pipeline a token limited to its project:

```bash
security-review-controller token create --label shop-ci --project shop-api            # mcp role
security-review-controller token create --label shop-gate --role ci --project shop-api
```

A token without `--project` reaches every project. In the web interface, the
[**Tokens**](../usage/web-interface.md#screens) screen creates a token for some projects
or for **All projects**, and changes the projects of an existing token (except `admin` and
`metrics`; a `ci` token always keeps at least one project). A restricted token:

- only saves reports (`save_security_report`) for its project;
- only reads, lists, exports and proposes a status for (`propose_finding_status`) the
  reports and findings of its project; `list_security_reports` without a filter only returns
  those;
- gets, for any other project, report or finding, the same "not found" error as for a missing
  object, so as not to reveal the other projects;
- cannot call `reload_rules`.

The restriction also applies to the `report://` resource and to the `triage-report` prompt.
With stdio, there is no token, hence no restriction.

### Initial administrator password

At its first start, the **controller** creates the `admin`
[account](../usage/web-interface.md#user-accounts) of the web interface
(`SECREVIEW_ADMIN_USERNAME`), with a random password that nobody knows: set it with the CLI,
which prints it once (the old one is invalidated at once), see the
[first administrator](../usage/web-interface.md#first-administrator). This account only opens
the web interface and the REST API, never `/mcp`: for an agent, create a token
(`token create`).

```bash
security-review-controller user reset-password admin
```

### Enrollment: a project requests its token

Rather than creating every token in advance, let the projects **request** theirs, then approve
the request. It is enabled by default (`SECREVIEW_ENROLLMENT=true`), even before the first token is
created (except on an [open server](#bearer-tokens), which needs no token).

1. **Request.** The client gets at once a token with the `mcp` role, restricted to the
   requested project, but **pending**: it does not give access to anything yet. A token is
   personal (it may later reach other projects), so its label is the **developer's username**:
   the login name with `enroll`, the username passed by the agent; without a label, the project
   name followed by `-enroll`. A random suffix is added. The token stays configured on a
   device, which other people may use: each report therefore also names its developer (see
   [author of a report](../usage/prompts-tools.md#author-of-a-report)). Three ways to request:
    - **From the agent, at the first review.** An MCP client that connects **without** an
      `Authorization` header is not rejected: it reaches a restricted MCP server (same
      `security-review` name) that only exposes the `request_enrollment` and
      `get_enrollment_status` tools, and prompts named like the reviews (`security-review`,
      `codebase-review`…) that explain the steps. The agent calls `request_enrollment` with the
      project name and the developer's username, and hands the token to the user.
    - **From the command line**, from the developer workstation or the CI:

        ```bash
        security-review-mcp enroll --url https://secreview.example.internal:8443 \
            --project shop-api --requested-by "alice (shop team)"
        # {"id": "…", "label": "alice-3fa9c1", "status": "pending", "token": "UJB7…", …}
        ```

    - **Through the MCP server API**: `POST /api/v1/enroll` (without a token) with
      `{"project": "shop-api"}`. The controller does not serve this endpoint: it exposes no
      unauthenticated write route.
2. **Configuration.** The user puts the token at once in the
   [host configuration](../getting-started/host.md#getting-a-token-enrollment). While it is pending, the client
   stays on the enrollment server (`get_enrollment_status` answers `pending`) and the web API
   answers `403 enrollment_pending`.
3. **Approval.** An administrator approves or rejects the request in the **Tokens** screen of
   the [web interface](../usage/web-interface.md), or from the CLI:

    ```bash
    security-review-controller token list --pending           # requester, address, date
    security-review-controller token approve alice-3fa9c1
    security-review-controller token reject alice-3fa9c1
    ```

    Once approved, the token works from the next request on, without reconfiguration. The
    approval can also give the developer **read access to the project in the portal**, on
    their user account (**Read access in the portal** column of the interface, or
    `token approve ID --portal-user alice` from the CLI); with the
    [OIDC login](sso.md), an unknown name becomes an
    OIDC account. See
    [project read access at enrollment](sso.md#project-read-access-at-enrollment).

### Rejected token: new enrollment

When the enrollment is enabled, a client whose token is **unknown, revoked or expired** does
not get `401` on `/mcp`: like a client without a token, it reaches the enrollment server, which
only exposes `request_enrollment` and `get_enrollment_status`. `get_enrollment_status` then
answers `token_rejected` with the reason (`invalid_token` or `token_expired`), and the agent
offers the user to enroll again; the new token replaces the rejected one in the
[host configuration](../getting-started/host.md#getting-a-token-enrollment), once approved. The
rejection is still logged as a warning by the MCP server (`Rejected unauthenticated request` /
`Rejected expired token`); the controller API and the `/api/v1/enroll` endpoint keep answering `401`.

`security-review-mcp scan-deps` recognizes this case and suggests running
`security-review-mcp enroll`.

### Additional enrollment

A host that already has an active token restricted to one or more projects can request an
additional project with **the same token**. The token keeps working for its current projects
while the request is pending; no new secret is created. After approval, the project is added
to its rights.

- **From an MCP agent**: connected with the existing token, call `request_enrollment` for the
  new project. `save_security_report` suggests this call if the requested project is not
  allowed.
- **From the command line**: pass the token on stdin, never as an argument:

    ```bash
    printf '%s\n' "$SECURITY_REVIEW_TOKEN" | security-review-mcp enroll \
        --url https://secreview.example.internal:8443 --project billing \
        --requested-by "alice (billing team)" --token-stdin
    ```

  The answer confirms the pending request without showing a new token. An administrator
  approves or rejects it in the web interface or with
  `security-review-controller token approve ID` / `security-review-controller token reject ID`.
  The `token list --pending` command shows the requested project and the token concerned.

An unrestricted token already reaches every project: it cannot make an additional enrollment.
Create a restricted token if you need to limit its access.

Safeguards: at most 20 pending requests at a time, 3 per client address (behind a reverse
proxy, set [`SECREVIEW_FORWARDED_ALLOW_IPS`](../reference/configuration.md)), a request left unprocessed expires after
7 days, a token with an invalid secret never reaches the review tools (only the
[enrollment server](#rejected-token-new-enrollment)) and pending requests never enable
the authentication of an open server. Check the requester before approving: any client that
reaches the server can file a request. To disable the enrollment:
`SECREVIEW_ENROLLMENT=false` (clients without a token, or with a rejected token, then get
`401`).

`--url` is the URL of the **MCP server** (with or without `/mcp`): it receives the requests.

!!! tip
    The `token` commands run on the controller side (or in its container), with the same
    `SECREVIEW_DATABASE_URL` as the controller. Tokens are never passed as command-line
    arguments.

## TLS

Uvicorn serves HTTPS directly when a certificate is given, for the MCP server as for the
controller (same options, same variables):

```bash
security-review-mcp --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
security-review-controller serve --host 0.0.0.0 --port 9443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# or SECREVIEW_TLS_CERTFILE / SECREVIEW_TLS_KEYFILE (+ SECREVIEW_TLS_KEYFILE_PASSWORD)
```

`SECREVIEW_TLS_CLIENT_CA` also enables **mutual TLS**: only the clients presenting a
certificate signed by this CA can connect.

### Certificate authority

The server never generates a certificate: provide one signed by a certificate authority
trusted by the clients, a public CA (for example Let's Encrypt, or cert-manager in Kubernetes)
or the **internal CA** of your organization. Its `subjectAltName` must contain the names and
addresses used by the clients (for example `DNS:secreview.lan,IP:192.168.1.1`); otherwise the
clients refuse the connection even when they trust the CA. The key file (`key.pem`) never
leaves the server: keep it readable by the server account only (`chmod 600`).

With an internal CA, the clients must trust its certificate: see
[Host configuration](http.md#https-server-with-an-internal-ca).

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

For the enrollment from the CLI, `security-review-mcp enroll` accepts `--cafile` directly (see
below).

## Client configuration

VS Code, with a token asked to the user (`.vscode/mcp.json`, see
[Host configuration](../getting-started/host.md#http-transport)):

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

For Claude and to get a token by enrollment from the host, see
[Host configuration](../getting-started/host.md#getting-a-token-enrollment).

## Behind a reverse proxy

A reverse proxy (TLS, OIDC, rate limiting) remains a valid option: in that case, leave these
variables empty.

!!! warning
    If the server listens elsewhere than on localhost without authentication or without TLS, a
    warning is logged. Any token with the `mcp` or `admin` role gives access to **every** tool.
