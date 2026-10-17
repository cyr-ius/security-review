# Security and limits

## Security of the server itself

- **Two processes**: the MCP server (exposed to the agents) and the controller (REST API, web
  interface, administration) run separately and only share the database (see
  [Architecture and deployment](../getting-started/kubernetes.md)). The MCP server only accepts
  the `mcp` and `admin` roles, the controller only `reader`, `triager` and `admin`, plus `ci`
  on its read-only pipeline routes (`/api/v1/ci/`) and nowhere else. The
  controller exposes no write route without a token: it can stay on an internal network, and the
  compromise of the exposed MCP server gives no access to the administration interface.
- **HTTP transport**: MCP authentication by Bearer token and TLS are built in but optional (see
  [HTTP server, authentication and TLS](../getting-started/http.md)). Tokens are stored in the
  database and only their SHA-256 digests are kept. Every request looks up the digest of the
  presented token, which reveals nothing usable without a preimage, then checks it in constant
  time: a revocation is therefore immediate on every instance. A token created with `--project`
  is limited to that project in the MCP tools and the web API: any other project, report or
  finding is handled as missing (see
  [tokens restricted to a project](../getting-started/http.md#tokens-restricted-to-a-project)).
  If it does not listen on localhost, a warning is logged when authentication or TLS is missing.
  The server never generates a TLS certificate: HTTPS uses the certificate given by the
  operator, signed by a [certificate authority](../getting-started/http.md#certificate-authority).
  There is no rate limiting.
  Every token has a [role](../usage/web-interface.md#roles) (`mcp`, `reader`, `triager`,
  `admin`, `ci`); an `mcp` token without a project reaches every MCP tool and every project.
- **Pipeline tokens** (`ci`): always restricted to projects (a `ci` token without a project
  cannot be created, and one found without a project reaches none). It only reads the gate, the
  SARIF log and the trend of its projects; the other routes of the controller, `/mcp` and the
  web interface answer `403`, the other projects `404`. The pipeline client
  ([`security-review-ci`](../ci-cd/gate.md#pipeline-client-security-review-ci)) opens no
  database, reads the token from the environment or stdin only, refuses plain HTTP outside
  localhost, credentials in the URL and redirects, and bounds the answers.
- **Enrollment** (enabled by default, `SECREVIEW_ENROLLMENT`): a client without a token reaches
  a restricted MCP server that only lets it file a request, and `POST /api/v1/enroll` is public
  on the MCP server (body limited to 4 KiB). The approval happens on the controller. A request
  is an `mcp` token restricted to the project, **pending**: it gives access to nothing before
  the approval of an administrator, and pending requests never enable the authentication of an
  open server. The number of pending requests is bounded (20 in all, 3 per client address) and a
  request left unprocessed
  expires after 7 days; the free text of the requester is masked and truncated. Any client that
  reaches the server can file a request: check the requester and the address shown before
  approving, or disable the enrollment. See
  [enrollment](../getting-started/http.md#enrollment-a-project-requests-its-token).
- **Outgoing network calls**: the MCP server makes none. The `security-review-mcp enroll` and
  `scan-deps` commands contact, at the request of the operator, the URL they give (`scan-deps`
  sends the dependency files given on its command line, never through a symbolic link); they
  refuse plain HTTP
  outside localhost (unless `--allow-http`), credentials in the URL and redirects. The
  controller only downloads the OSV advisories if an administrator enables it
  (`SECREVIEW_OSV_AUTO_UPDATE` or `advisories update`): only from `SECREVIEW_OSV_URL` over
  HTTPS with certificate verification, redirects limited to HTTPS, bounded size
  (`SECREVIEW_OSV_MAX_DOWNLOAD_MB`), optional proxy whose credentials are never logged. The
  **Update now** button of the web interface (`admin` role) is only accepted if
  `SECREVIEW_OSV_AUTO_UPDATE=true`. The outgoing proxy (`SECREVIEW_PROXY`, or the **Settings**
  screen) serves the OSV download and the SSO provider; only the name of the changed settings
  is logged. A proxy set in the web interface is stored in the database **with its credentials,
  in clear**: the API never returns them (password replaced by `***`) and the error messages of
  the history are scrubbed of them, but prefer `SECREVIEW_PROXY` (Kubernetes secret) if the
  database is not protected like a secret. See the
  [automatic update](../usage/dependencies.md#automatic-update-by-the-controller). With the
  [SSO login](../usage/web-interface.md#openid-connect-sso-login) (`SECREVIEW_OIDC_ENABLED`,
  disabled by default), the controller also contacts the configured identity provider: HTTPS
  only (HTTP only on localhost), redirects limited to HTTPS, answers bounded to 1 MiB, 10 second
  timeout. This configuration can also be
  [changed in the interface](../usage/web-interface.md#configuring-sso-in-the-interface) by an
  administrator, with the same checks (an invalid configuration is refused); the **Test the
  connection** button contacts the entered issuer, under the same conditions. The **client
  secret** entered in the interface is stored in the database **in clear**: the API never
  returns it (`***`) and the logs only name the changed settings; prefer
  `SECREVIEW_OIDC_CLIENT_SECRET` (Kubernetes secret) if the database is not protected like a
  secret.
- **Web interface** (controller): the REST API always requires a session or a token with a web
  role; without a user or a token, it answers `503` instead of granting anonymous rights. Only
  `triager` and `admin` change the status of a finding (action logged with the label of the
  token). Pages are served with a strict CSP and the anti-clickjacking headers; the token is
  kept in the `sessionStorage` of the tab. The Swagger documentation and its OpenAPI schema
  are public, but the data routes stay protected. The check is made twice: by the Bearer
  middleware, then by every route of the API, which refuses (`401`) any request without an
  authenticated identity. The API thus never grants rights by default, even if it is served
  without the middleware.
- **User accounts** ([user name and password](../usage/web-interface.md#user-accounts)): only
  a salted **scrypt** digest (N=2¹⁴, r=8, p=5, random 16-byte salt) is stored; a stored digest
  with out-of-bounds parameters is refused instead of exhausting the memory. Passwords of 12 to
  256 characters, user names limited to `[A-Za-z0-9._@-]`. The check takes the same time
  whether the user name exists or not (dummy digest), and a failure always returns the same
  `401`. Failures are limited in memory (5 per user name and address, 20 per address, over
  15 minutes, then `429`); behind a reverse proxy, the client address is only read from
  `X-Forwarded-For` for the proxies listed in `SECREVIEW_FORWARDED_ALLOW_IPS` (`*` lets any
  client choose its address and get round the limits). Only valid user names are logged, never passwords. The session is a
  token signed with `SECREVIEW_SESSION_SECRET`, like the SSO one, but the account is **read
  again from the database at every request**: deletion, new role or new projects apply
  immediately, and a password change draws a new random session version that invalidates every
  previous session. The session must also carry the identifier of the account: it never opens
  an account created again under the same internal number. The last administrator, local or
  SSO (by its role or the role of its groups), can be neither deleted nor demoted. The password
  of the initial `admin` account appears once in the logs of the controller: protect them and
  change it at the first login.
- **SSO login (OpenID Connect)**, optional: *authorization code* flow with `S256` PKCE, state
  bound to the browser by a signed `HttpOnly` / `SameSite=Lax` cookie of 10 minutes, nonce,
  verified ID token (signature by the JWKS keys of the provider, asymmetric algorithms only,
  never `none` nor HMAC; issuer, audience, `azp`, expiry). The role comes from the groups of the
  user ([role mapping](../usage/web-interface.md#role-mapping), managed by the administrators,
  possibly restricted to projects) and from the role given to their
  [SSO account](../usage/web-interface.md#sso-accounts); neither the `admin` role by default nor
  the `mcp` role are possible. The account is named by the exact identifier of the
  `SECREVIEW_OIDC_USERNAME_CLAIM` claim (no fallback to `email` or `sub`, value refused if it is
  not a valid user name): choose a claim that the user cannot change at the provider. By
  default (`SECREVIEW_OIDC_AUTO_CREATE_USERS=false`), only an SSO account created by an
  administrator can log in. An SSO login never opens a local account of the same name, and the
  account is bound to the `sub` of its first login: another `sub` is refused. A deleted SSO
  account is revoked: the automatic creation does not create it again, until an administrator
  creates it again or allows it again. Check the requester of an enrollment (free text, not
  verified) before giving them read access to the project. A session restricted to projects is
  restricted like a `--project` token. The session is a signed token (HMAC-SHA256, key derived
  from `SECREVIEW_SESSION_SECRET`) that names the account, read again at every request: the
  deletion of the account cuts it at once. It is accepted by the controller only, never by the
  MCP server. The return URL after login is limited to local paths. Codes, tokens and secrets
  are never logged by the controller; the authorization code does appear in the access logs of
  a reverse proxy or of uvicorn, which is harmless: it is single-use and useless without the
  PKCE verifier of the cookie.
- **No disk access on the MCP side**: `scan_code` only works on the given content; the server
  reads no file from the disk, which avoids path traversals. The whole repository scan is
  reserved for the CLI (`code scan`), run by the operator on a folder they choose; it does not
  follow symbolic links.
- **Database**: SQL queries go through the ORM (bound parameters); input sizes, the number of
  findings and the pagination are bounded. The schema is migrated by Alembic; the HTTP MCP
  server never changes it and refuses to serve a database that is not at the expected
  revision.
- **Scan rules**: the default rules (`default_rules.toml`) are copied into the database at first
  start. If the database cannot be reached or was never initialized, the server applies this
  file directly: the scan never runs without rules. A default rule can be edited or disabled by
  an administrator, but not deleted (see [Internal rules](../usage/rules.md#default-rules)).
- **Development standards**: their content is handed as is to the AI assistant as instructions;
  only the administrators of the controller write them (validated and bounded fields, 200
  standards of 50,000 characters at most). The MCP server only reads them, and the task given to
  the `development-standards` prompt is fenced so that it cannot escape. The prompt reminds that
  a standard never prevails over security (see
  [Development standards](../usage/standards.md)).
- **Logs** on stderr (stdout is reserved for the protocol with stdio).

!!! warning "Protect the database"
    The reports hold sensitive information about your vulnerabilities: protect the database
    (file permissions, dedicated PostgreSQL account, encrypted backups).

## Known limits

- The pattern scan produces leads and false positives; it replaces neither a SAST, nor a full
  SCA analysis (no transitive resolution of the manifests, database to keep up to date), nor a
  human review.
- Rules are line-by-line patterns: they see neither the data flow nor the missing checks
  (missing authorization, for example). This work remains the agent's, guided by the
  checklists, and your SAST/SCA tools'.
