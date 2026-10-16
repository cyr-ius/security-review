# HTTP server, authentication and TLS

A shared server (team, CI/CD) is made of **two processes** sharing the same database (see
[Architecture and deployment](kubernetes.md)):

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
security-review-controller token create --label triage-bot --role triager
security-review-controller token create --label shop-ci --role reader --project shop-api
# {"id": "6f1c…", "label": "ci", "role": "mcp", "project": null, "created_at": "…", "token": "UJB7…"}
security-review-controller token list [--project shop-api]             # never the secret nor the digest
security-review-controller token revoke ci                              # by label or by id
```

Projects can also request their token themselves: see
[enrollment](#enrollment-a-project-requests-its-token).

- Give `token` to the client; the unique `label` appears in the logs.
- `--role` is `mcp` by default (MCP server); `reader` (read only) and `triager` (read and
  triage) give access to the REST API of the controller, never to the web interface: see the
  [roles](../usage/web-interface.md#roles).
- `--project` limits the token to one or more projects (repeat the option), for the MCP tools
  as for the REST API (`mcp`, `reader` and `triager` roles; refused for `admin`). See
  [tokens restricted to a project](#tokens-restricted-to-a-project). Administrators can also
  create and revoke restricted `reader` tokens from the **Tokens** screen.
- The server reads the database at every request: a creation or a revocation applies
  immediately, including to the other instances sharing the same PostgreSQL database.

As soon as a token exists in the database, the MCP endpoint and the controller API require
`Authorization: Bearer <token>`. Still public: `/healthz` on both processes, `/api/v1/enroll`
on the MCP server, and on the controller the static files of `/ui/` and the Swagger
documentation (`/api/docs`, `/api/openapi.json` schema, `/api/favicon.svg` icon). While no token exists, `/mcp` is open
(a warning is logged if it does not listen on localhost) and the controller API answers `503`.
`token revoke` warns on stderr when it deletes the last token.

### Tokens restricted to a project

On a server shared by several teams, give each pipeline a token limited to its project:

```bash
security-review-controller token create --label shop-ci --project shop-api            # mcp role
security-review-controller token create --label shop-triage --role triager --project shop-api
```

A token without `--project` reaches every project. A restricted token:

- only saves reports (`save_security_report`) for its project;
- only reads, lists, exports and triages (`update_finding_status`, `PATCH` of the web API) the
  reports and findings of its project; `list_security_reports` without a filter only returns
  those;
- gets, for any other project, report or finding, the same "not found" error as for a missing
  object, so as not to reveal the other projects;
- cannot call `reload_rules`.

The restriction also applies to the `report://` resource and to the `triage-report` prompt.
With stdio, there is no token, hence no restriction.

### Initial administrator password

With `SECREVIEW_AUTH_BOOTSTRAP_ADMIN=true` (the case in the Docker image), the **controller**
creates at first start the `admin` [account](../usage/web-interface.md#user-accounts) of the
web interface, with a random password shown only once in its logs. This account only opens
the web interface and the REST API, never `/mcp`: for an agent, create a token
(`token create`). If it is lost, replace the password (the old one is invalidated at once):

```bash
security-review-controller user reset-password admin
```

### Enrollment: a project requests its token

Rather than creating every token in advance, let the projects **request** theirs, then approve
the request. It is enabled by default (`SECREVIEW_ENROLLMENT=true`) as soon as a token exists.

1. **Request.** The client gets at once a token with the `mcp` role, restricted to the
   requested project, but **pending**: it does not give access to anything yet. A token is
   personal (it may later reach other projects), so its label is the **developer's username**:
   the login name with `enroll`, the username passed by the agent; without a label, the project
   name followed by `-enroll`. A random suffix is added. Three ways to request:
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
   [host configuration](host.md#getting-a-token-enrollment). While it is pending, the client
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
    [SSO login](../usage/web-interface.md#openid-connect-sso-login), an unknown name becomes an
    SSO account. See
    [project read access at enrollment](../usage/web-interface.md#project-read-access-at-enrollment).

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
7 days, a token with an invalid secret stays refused (`401`) and pending requests never enable
the authentication of an open server. Check the requester before approving: any client that
reaches the server can file a request. To disable the enrollment:
`SECREVIEW_ENROLLMENT=false` (clients without a token then get `401`).

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
[Host configuration](host.md#https-server-with-an-internal-ca).

## Client configuration

VS Code, with a token asked to the user:

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
[Host configuration](host.md#getting-a-token-enrollment).

## Behind a reverse proxy

A reverse proxy (TLS, SSO, rate limiting) remains a valid option: in that case, leave these
variables empty.

!!! warning
    If the server listens elsewhere than on localhost without authentication or without TLS, a
    warning is logged. Any token with the `mcp` or `admin` role gives access to **every** tool.
