# Security and limits

## Security of the server itself

- **Two processes**: the MCP server (exposed to the agents) and the controller (REST API, web
  interface, administration) run separately and only share the database (see
  [Architecture and deployment](../advanced/architecture.md)). The MCP server only accepts
  the `mcp` and `admin` tokens, the controller only web sessions and `admin` and `api` tokens, plus `ci`
  on its pipeline routes (`/api/v1/ci/`: gate, SARIF and trend in read only, scans that store
  reports of its projects) and nowhere else. The
  controller exposes no write route without a token: it can stay on an internal network, and the
  compromise of the exposed MCP server gives no access to the administration interface.
- **HTTP transport**: MCP authentication by Bearer token and TLS are built in but optional (see
  [HTTP server, authentication and TLS](../advanced/http.md)). Tokens are stored in the
  database and only their SHA-256 digests are kept. Every request looks up the digest of the
  presented token, which reveals nothing usable without a preimage, then checks it in constant
  time: a revocation is therefore immediate on every instance. A token created with `--project`
  is limited to that project in the MCP tools and the pipeline routes: any other project, report
  or finding is handled as missing (see
  [tokens restricted to a project](../advanced/http.md#tokens-restricted-to-a-project)).
  While no token exists, the MCP server stays closed (fail closed: only enrollment is reachable),
  unless it listens on localhost or `SECREVIEW_ALLOW_UNAUTHENTICATED=true`.
  If it does not listen on localhost, a warning is logged when authentication or TLS is missing.
  The server never generates a TLS certificate: HTTPS uses the certificate given by the
  operator, signed by a [certificate authority](../advanced/http.md#certificate-authority).
  There is no rate limiting.
  Every token has a [role](../usage/web-interface.md#roles) (`mcp`, `api`, `admin`, `ci`,
  `metrics`). An `api` token only holds rights of the access control, read at each request: those
  of its user (personal token, deleted with the user, never rotated by someone else, whose new
  secret would carry the rights of the user) or of its role on its projects (role token, whose
  creator must hold each permission). A token never creates another personal token. An `mcp`
  token without a project reaches every MCP tool and every project; a personal `mcp` token
  reaches the projects its user may read now, none when the user has none (never every project
  by default), and stops when the user is deleted or must change a password set by an
  administrator. A web user holds at most
  `SECREVIEW_PERSONAL_TOKENS_PER_USER` personal tokens of each role (1 by default).
- **Expiry and rotation of tokens**: an expired token authenticates nothing (`401`), and
  `SECREVIEW_TOKEN_MAX_DAYS` bounds the validity of every token created or rotated. Expired
  tokens still count as configured: a server whose tokens have all expired stays closed. A
  rotation stores the digest of the new secret only; the previous digest is kept during the grace
  period (at most 168 hours), compared in constant time like the current one, and the previous
  secret of an expired token never comes back (see
  [expiry and rotation](../advanced/http.md#expiry-and-rotation-of-tokens)).
- **Rejected tokens on `/mcp`**: an unknown, revoked or expired token gets a `401` whose
  description tells the user to sign in to the web interface and create a new personal MCP
  token (see [rejected token](../advanced/http.md#rejected-token-sign-in-again)); it never
  reaches the enrollment server. Each rejection is also logged as a warning by the MCP server
  (`Rejected unauthenticated request` / `Rejected expired token`, with the client address); the
  `secreview_auth_rejections_total` [metric](../advanced/audit-metrics.md) only counts the
  rejections of the controller. `SECREVIEW_WEB_URL`, given in that description, is a public URL:
  it holds no credentials (refused at start-up).
- **Audit log**: triage decisions, agent proposals, creations, rotations and revocations of
  tokens and enrollments are written in the same transaction as the change,
  with their actor (`user:`, `token:`, `cli`, `anonymous`). The details are bounded and masked,
  and never hold a token or a password; no tool nor route edits an event, only the purge of
  `SECREVIEW_AUDIT_RETENTION_DAYS` deletes them (see [audit log](../advanced/audit-metrics.md#audit-log)).
- **Metrics**: `/metrics` exists on the controller only (the MCP server keeps `/mcp`,
  `/api/v1/enroll` and `/healthz`), behind a `metrics` or `admin` token; a `metrics` token
  reaches nothing else. The answer holds counts and project names, never a finding, a token
  label or a secret, and every label value is escaped (see
  [Prometheus metrics](../advanced/audit-metrics.md#prometheus-metrics)).
- **Pipeline tokens** (`ci`): always restricted to projects (a `ci` token without a project
  cannot be created, and one found without a project reaches none); a personal `ci` token
  reaches the projects its user may read now, like a personal `mcp` token, which also acts as a
`ci` token on the pipeline routes (never an administrator's `mcp` token). It only reads the gate, the
  SARIF log and the trend of its projects; the other routes of the controller, `/mcp` and the
  web interface answer `403`, the other projects `404`. The pipeline client
  ([`security-review-ci`](../usage/gate.md#pipeline-client-security-review-ci)) opens no
  database, reads the token from the environment or stdin only, refuses plain HTTP outside
  localhost, credentials in the URL and redirects, and bounds the answers.
- **Enrollment** (enabled by default, `SECREVIEW_ENROLLMENT`): a client without a token reaches
  a restricted MCP server that only lets it request its project, and `POST /api/v1/enroll` is
  public on the MCP server (body limited to 4 KiB). The enrollment **never creates a token** and
  never gives any access: a requested project is **pending** until a user with
  `projects.create` approves it on the controller, which creates its project group without any
  member; only an administrator adds a user to it, and the developer creates a personal MCP
  token in the web interface, after logging in. The answer is the same whether the project
  existed or not. The enrollments are bounded (20 pending projects, 5 per client address and
  per hour, `429` beyond), a request nobody approved within
  `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` is deleted, and the free text of the requester is
  masked and truncated: check the requester and the address before approving. Every enrollment is audited. See
  [enrollment](../advanced/http.md#enrollment-request-the-project).
- **Outgoing network calls**: the MCP server makes none, and does not even load the modules
  of the controller that make them (advisory download, OIDC, syslog, tickets, version check):
  a test checks it. The `security-review-mcp enroll` command contacts, at the request of the
  operator, the URL it gives; it refuses plain HTTP
  outside localhost (unless `--allow-http`), credentials in the URL and redirects. The
  controller only downloads the OSV advisories if an administrator enables it
  (`SECREVIEW_OSV_AUTO_UPDATE` or `advisories update`): only from `SECREVIEW_OSV_URL` over
  HTTPS with certificate verification, redirects limited to HTTPS, bounded size
  (`SECREVIEW_OSV_MAX_DOWNLOAD_MB`), optional proxy whose credentials are never logged. The
  **Update now** button of the web interface (`settings.manage` permission) is only accepted if
  `SECREVIEW_OSV_AUTO_UPDATE=true`. The outgoing proxy (`HTTPS_PROXY` / `NO_PROXY`, or the **Outgoing proxy**
  screen) serves the OSV download and the OIDC provider; only the name of the changed settings
  is logged. A proxy set in the web interface is stored in the database **with its credentials,
  in clear**: the API never returns them (password replaced by `***`) and the error messages of
  the history are scrubbed of them, but prefer `HTTPS_PROXY` (Kubernetes secret) if the
  database is not protected like a secret. See the
  [automatic update](../advanced/dependencies.md#automatic-update-by-the-controller). With the
  [OIDC login](../advanced/sso.md) (`SECREVIEW_OIDC_ENABLED`,
  disabled by default), the controller also contacts the configured identity provider: HTTPS
  only (HTTP only on localhost), redirects limited to HTTPS, answers bounded to 1 MiB, 10 second
  timeout. This configuration can also be
  [changed in the interface](../advanced/sso.md#configuring-oidc-in-the-interface) by an
  administrator, with the same checks (an invalid configuration is refused); the **Test the
  connection** button contacts the entered issuer, under the same conditions. The **client
  secret** entered in the interface is stored in the database **in clear**: the API never
  returns it (`***`) and the logs only name the changed settings; prefer
  `SECREVIEW_OIDC_CLIENT_SECRET` (Kubernetes secret) if the database is not protected like a
  secret. With `SECREVIEW_UPDATE_CHECK_ENABLED=true` (disabled by default), the **About** page
  asks `api.github.com` for the latest release of the repository: HTTPS only, through the
  outgoing proxy, redirects limited to HTTPS, answer bounded to 512 KiB, 10 second timeout, at
  most one request per controller process every 6 hours (15 minutes after a failure); only the
  version and the link of the release are kept (a link outside the releases of the repository
  is replaced), and the page only gets a short error code. Once a
  connector is switched on in the **Connectors** screen (every one off by default, all locked
  off by `SECREVIEW_TICKETING_ENABLED=false`), the controller creates tickets in the configured
  Jira and ServiceNow: HTTPS only, through the outgoing proxy, **no redirect**,
  answer bounded to 1 MiB, 15 second timeout; the texts sent are masked again and, in Jira,
  never read as wiki markup; the secrets entered in the **Connectors** screen are stored in clear
  and never returned (`***`) and stay bound to the host of their URL; a third-party connector
  is only loaded when `SECREVIEW_TICKETING_PLUGINS` names it and only reaches its configured
  URL through the client of the controller, see [ticketing](../advanced/ticketing.md#security). With
  `SECREVIEW_AUDIT_SYSLOG_ADDRESS` or a server set on the **Audit log** page (disabled by
  default; `settings.manage` permission, `udp://`, `tcp://` or `tls://` only, the change
  audited), the controller sends the
  [audit events](../advanced/audit-metrics.md#forwarding-to-syslog) to that syslog server (UDP
  or TCP in clear, TLS with the certificate and host name of the server verified, or Unix
  socket; no proxy); the events hold no secret (masked details), and the MCP server still
  connects nowhere.
- **Initial administrator**: created by the controller at its first start with a random
  password that nobody knows, never logged nor passed through a variable; the only way to a
  password is `security-review-controller user reset-password`, run by an operator, which
  prints it once. With `SECREVIEW_OIDC_ONLY=true` and OIDC enabled, the
  password login of the local accounts is refused (`403`); a disabled or invalid OIDC
  configuration never locks the local accounts out.
- **Web interface** (controller): the REST API always requires a session or an `admin` or `api`
  token;
  without a user or a token, it answers `503` instead of granting anonymous rights. Only a
  session or an `api` token with the `findings.triage` permission, or an `admin` token, changes the status of a
  finding (action logged with the user or the label of the token), and only a person logged in to the interface (session) accepts a risk or marks a false
  positive: a bearer token is refused (`403`), even `admin`. An acceptance needs a reason and
  an expiry date (at most `SECREVIEW_MAX_DISMISSAL_DAYS` days); the approver is the logged-in
  user, and the finding counts as open again once the date has passed. A false positive needs
  neither (its reason is optional) and still records the logged-in user as approver. An
  acceptance may have no expiry date, unless `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false`:
  set it to force a periodic review of every accepted risk. A risk less severe than
  `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY` (`medium` by default) is accepted with no reason nor
  date, still by a logged-in person who is recorded as approver; leave the variable empty to
  require them for every acceptance. Comments on a finding follow the
  same rule (session with `findings.triage`) and are append-only: no route edits or deletes one.
  So does raising the severity of a finding: with a justification, logged, never below the
  severity of the report (lowering a finding goes through a risk acceptance).
- **Agents never close a finding**: the MCP server only offers `propose_finding_status`, which
  stores a proposal (reason masked and bounded, author taken from the token) without changing
  the status nor the gate. The reviewed code is untrusted: a prompt injection cannot dismiss a
  finding. A decision carried to the same issue raised by a later report (same project, rule,
  file and title: [finding reported again](../usage/web-interface.md#finding-reported-again))
  keeps its approver and its expiry date: a new report never extends it. Pages are served with a strict CSP and the anti-clickjacking headers, and every
  answer of the controller (API, refusals included) carries `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, a closed CSP when the route sets
  none and, over HTTPS (TLS of the controller, or `X-Forwarded-Proto` of a proxy listed in
  `SECREVIEW_FORWARDED_ALLOW_IPS`), `Strict-Transport-Security: max-age=31536000`; the token is
  kept in the `sessionStorage` of the tab. The Swagger documentation and its OpenAPI schema
  are disabled by default (`SECREVIEW_SWAGGER_ENABLED`); once enabled they are public, served
  from local files only with a strict CSP, and the data routes stay protected. The check is made twice: by the Bearer
  middleware, then by every route of the API, which refuses (`401`) any request without an
  authenticated identity. The API thus never grants rights by default, even if it is served
  without the middleware. Every JSON answer goes through its declared response model: a field
  a service would add by mistake (a digest, a secret) is dropped instead of being returned. The
  answers that hold a secret (session, new or rotated token, generated password) are sent with
  `Cache-Control: no-store`.
- **Prompt injection through the reviewed code**: the content that the server hands back to a
  model is marked as data. The code of the prompts and the stored evidence of a finding are
  wrapped in a code fence longer than any backtick run they contain, so they cannot close their
  block. Invisible characters (zero-width, bidirectional controls, Unicode tags and supplementary
  variation selectors) are replaced with a visible `<U+XXXX>` marker in these blocks, in the
  excerpts of `scan_code` and in the summary, description, evidence and recommendation stored
  in a report (then cut again at `SECREVIEW_MAX_CONTENT_CHARS`): nothing is removed, the hidden
  text becomes readable. The
  [`AI-*` rules](../usage/rules.md#default-rules-by-platform) report hidden characters and
  text addressed to an AI assistant, so the gate can block them. The server only sees what the
  agent sends: it cannot filter the files that the host reads with its own tools; the
  [read guard](../advanced/read-guard.md), a host-side hook, checks them before the assistant
  reads them.
- **User accounts** ([user name and password](../usage/web-interface.md#user-accounts)): only
  a salted **scrypt** digest (N=2¹⁴, r=8, p=5, random 16-byte salt) is stored; a stored digest
  with out-of-bounds parameters is refused instead of exhausting the memory. Passwords of 12 to
  256 characters, with a lowercase letter, an uppercase letter, a digit and a character that is
  neither (checked by the controller, generated passwords included); a password set by someone
  else (first administrator, creation or reset by an administrator) must be changed at the first
  login: until then the session only reaches **My account** (`403` elsewhere), user names limited to `[A-Za-z0-9._@-]`. The check takes the same time
  whether the user name exists or not (dummy digest), and a failure always returns the same
  `401`. Failures are limited in the database, shared by every replica (5 per user name and
  address, 20 per address, over 15 minutes, then `429`), and so are the requests of an address
  to the REST API (`SECREVIEW_RATE_LIMIT_*`, counted before the token is checked, so that
  guessing tokens is limited too; the counters store SHA-256 digests, never the addresses); behind a reverse proxy, the client address is only read from
  `X-Forwarded-For` for the proxies listed in `SECREVIEW_FORWARDED_ALLOW_IPS` (`*` lets any
  client choose its address and get round the limits). Only valid user names are logged, never passwords. The session is a
  token signed with `SECREVIEW_SECRET_KEY`, like the OIDC one, but the account is **read
  again from the database at every request**: deletion, new role or new projects apply
  immediately, and a password change draws a new random session version that invalidates every
  previous session. The session must also carry the identifier of the account: it never opens
  an account created again under the same internal number. The last administrator, local or
  OIDC (by its role or the role of its groups), can be neither deleted nor demoted. The password
  of the initial `admin` account appears once in the logs of the controller: protect them and
  change it at the first login.
- **OIDC login (OpenID Connect)**, optional: *authorization code* flow with `S256` PKCE, state
  bound to the browser by a signed `HttpOnly` / `SameSite=Lax` cookie of 10 minutes, nonce,
  verified ID token (signature by the JWKS keys of the provider, asymmetric algorithms only,
  never `none` nor HMAC; issuer, audience, `azp`, expiry). The permissions come from the
  [groups](../advanced/access-control.md) of the account: those given by an administrator and the
  groups open to OIDC whose name is exactly a value of the groups claim (other values are
  ignored, a group not open to OIDC is never joined through the claim); an OIDC session never
  opens `/mcp`. The account is identified by the issuer and the `sub` of its first login (unique
  in the database), never by a name: a name changed at the provider keeps the account. It is
  named at its creation by the exact identifier of the `SECREVIEW_OIDC_USERNAME_CLAIM` claim (no
  fallback to `email` or `sub`, value refused if it is not a valid user name), which also binds
  an account created beforehand by an administrator: choose a claim that the user cannot change
  at the provider. By
  default (`SECREVIEW_OIDC_AUTO_CREATE_USERS=false`), only an OIDC account created by an
  administrator can log in. An OIDC login never opens a local account of the same name, and the
  account is bound to the issuer and the `sub` of its first login: another `sub` or another
  issuer is refused. A deleted OIDC
  account is revoked, by its name and its issuer and `sub`: the automatic creation does not create it again, until an administrator
  creates it again or allows it again. Check the requester of an enrollment (free text, not
  verified) before giving them read access to the project. A session restricted to projects is
  restricted like a `--project` token. The session is a signed token (HMAC-SHA256, key derived
  from `SECREVIEW_SECRET_KEY`) that names the account, read again at every request: the
  deletion of the account cuts it at once. It is accepted by the controller only, never by the
  MCP server. The return URL after login is limited to local paths. Codes, tokens and secrets
  are never logged by the controller; the authorization code does appear in the access logs of
  a reverse proxy or of uvicorn, which is harmless: it is single-use and useless without the
  PKCE verifier of the cookie. The secret settings (`SECREVIEW_SECRET_KEY`,
  `SECREVIEW_OIDC_CLIENT_SECRET`, `SECREVIEW_TLS_KEYFILE_PASSWORD`, `SECREVIEW_DATABASE_URL`)
  are typed as secrets: they never appear in a dump of the settings. Without
  `SECREVIEW_SECRET_KEY`, the controller draws a random session secret at every start, kept in
  memory only (a warning is logged): sessions end at restart.
- **No disk access on the MCP side**: `scan_code` only works on the given content; the server
  reads no file from the disk, which avoids path traversals. For the whole repository scan,
  the pipeline client (`security-review-ci scan-code`), run by the operator on a folder they
  choose, reads the files without following symbolic links and sends their content to the
  controller, which scans it without reading its own disk.
- **Pipeline scans**: `POST /api/v1/ci/scan/code` and `/scan/deps` need a `ci` or `admin`
  token (a web session is refused) and stay within the projects
  of the token; they store a report only with `save`. The request body is bounded
  (`SECREVIEW_MAX_SCAN_REQUEST_MB`, `413` beyond, read after the token check), as are the
  number of files (`SECREVIEW_MAX_SCAN_FILES`) and their size; secrets are masked in the
  excerpts and in the stored report.
- **Request bodies of the controller**: every body is bounded before it is parsed, `413`
  beyond: 512 KiB for the JSON routes, public ones included (login, SSO), 8 MiB for the
  pack imports and `SECREVIEW_MAX_SCAN_REQUEST_MB` for the pipeline scans. The declared
  `Content-Length` is checked first, a chunked body as it is read.
- **Request bodies of the MCP server**: a body on `/mcp` is read only after the token check
  and bounded (`413` beyond): `SECREVIEW_MAX_MCP_REQUEST_MB` for an authenticated client,
  64 KiB for a client without a token served by the enrollment server. A rejected token gets
  its `401` before its body is read.
- **Database**: SQL queries go through the ORM (bound parameters); input sizes, the number of
  findings and the pagination are bounded. Every project name is
  [normalized](../usage/prompts-tools.md#project-name) before use: only letters, digits and
  single dashes reach the database, the logs, the metric labels and the file names. The schema is migrated by Alembic; the HTTP MCP
  server never changes it and refuses to serve a database that is not at the expected
  revision.
- **Scan rules**: the default rules (`default_rules.toml`) are copied into the database at first
  start. If the database cannot be reached or was never initialized, the server applies this
  file directly: the scan never runs without rules. A default rule can be edited or disabled by
  an administrator, but not deleted (see [Rules](../usage/rules.md#default-rules)).
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
- The few [Tree-sitter analyses](../usage/rules.md#default-rules) (`PY-026`, `JV-019`,
  `NG-021`, `GO-019`, `CS-021`, `RS-015`, `TS-016`) only follow simple flows inside one file.
  They are bounded so that a crafted file cannot block a scan: each function is analyzed once
  per input state, and code nested too deeply is only checked by the patterns.
- The [coverage of a review](../usage/prompts-tools.md#review-coverage) (checklist results,
  rules of the scan leads) is declared by the agent: the server only keeps the ids it knows and
  marks the skipped items `not_covered`, it cannot check that the agent really read the code.
- The `author` of a report (developer username) is the user of the personal token that saved
  it, set by the server whatever the client passes. With a token without a user (enrolled
  device, token created by an administrator), it is declared by the client: anyone holding such
  a token of the project can name someone else. `submitted_by`, the label of the token that
  saved the report, is always set by the server (see
  [author of a report](../usage/prompts-tools.md#author-of-a-report)). An `author` is often an
  email address, that is personal data, kept as long as the report: in the web interface and
  the REST API, only a holder of `users.manage` or `tokens.manage` sees it (nor can the others
  find it by the filter, the search or the sort); the MCP tools, resources and prompts never
  return it, nor filter by it.
