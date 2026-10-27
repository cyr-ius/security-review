# OAuth login of MCP clients

By default, a developer creates a personal MCP token in **My account** and copies it into the
configuration of their host (see [Host configuration](../getting-started/host.md)). With the
OAuth login, the host needs no token: at the first connection it opens the browser, the
developer signs in to the web interface (local account or [OIDC](oidc.md)) and approves the
client, and the host receives its tokens and renews them by itself.

The flow follows the [authorization of the MCP specification](https://modelcontextprotocol.io/specification/latest/basic/authorization)
(OAuth 2.1, authorization code with PKCE `S256`, dynamic client registration, protected
resource metadata). The controller is the authorization server; the MCP server only checks the
tokens. The personal MCP tokens keep working alongside.

## Enabling it

On the **controller** only:

```bash
SECREVIEW_MCP_OAUTH_ENABLED=true
SECREVIEW_MCP_URL=https://mcp.example.com/mcp          # public URL of the MCP endpoint
SECREVIEW_CONTROLLER_URL=https://secreview.example.com # issuer (https, http on localhost only)
```

At start, the controller stores `SECREVIEW_MCP_URL` in the database; the MCP server reads it
there (within 30 seconds), as it reads the controller URL: it needs no new variable. Unset
`SECREVIEW_MCP_OAUTH_ENABLED` and restart the controller to turn it off: it then revokes every
grant, so that the tokens already issued stop at once. The issuer is fixed at
start: after a change of the controller URL in **General**, restart the controller.

Behind a reverse proxy, publish these public paths:

| Path | Process |
|---|---|
| `/.well-known/oauth-protected-resource/mcp` (protected resource metadata, RFC 9728) | MCP server |
| `/.well-known/oauth-authorization-server` (metadata, RFC 8414), `/authorize`, `/token`, `/register`, `/revoke` | controller |

By default a client may only send the browser back to the loopback interface of the
workstation, which is what Claude Code and VS Code use. A client that comes back through a web
site or its own URI scheme needs its host or scheme listed:

```bash
SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS=vscode.dev     # https only
SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES=cursor
```

The other OAuth settings (token lifetimes, number of clients) are listed in
[Configuration](../reference/configuration.md#oauth-login-of-mcp-clients).

## Host configuration

The server is declared with its URL only, without `Authorization` header:

```json
{
  "mcpServers": {
    "security-review": {
      "type": "http",
      "url": "https://mcp.example.com/mcp"
    }
  }
}
```

In Claude Code, `/mcp` then shows the server as needing an authentication: choose it to open the
browser. VS Code proposes the login at the first start of the server.

## Flow

1. The host calls `/mcp` without a token: the MCP server answers `401` with
   `WWW-Authenticate: Bearer …, resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`.
   This document names the controller as authorization server.
2. The host registers itself at `/register` (dynamic registration, RFC 7591).
3. It opens `/authorize` in the browser, which goes to the **Connect an MCP client** screen of the
   web interface, behind the usual login.
4. The developer approves (or denies) the client there; the browser goes back to the host with
   a single-use code, valid 60 seconds.
5. The host exchanges the code and its PKCE verifier at `/token` for an access token and a
   refresh token, then calls `/mcp` with the access token.

A request left without an answer expires after 10 minutes.

## What a token gives

An access token acts as a [personal MCP token](../usage/tokens.md#personal-mcp-and-ci-tokens) of
the user who approved the client: the projects the user may read, read at each request, the
`request_project` tool, the reports signed with the name of the user. It only reaches the MCP
server: neither the REST API nor the pipeline routes of the controller (keep a personal token
for `security-review-ci`).

Approving a client needs the `mcp_tokens.create` permission, like creating a personal MCP
token, and a web session: a Bearer token never approves a client.

| Token | Lifetime | Renewal |
|---|---|---|
| Access token | `SECREVIEW_MCP_OAUTH_ACCESS_MINUTES` (60 minutes) | by the refresh token, without the browser |
| Refresh token | `SECREVIEW_MCP_OAUTH_REFRESH_DAYS` (30 days) | each refresh issues a new pair and extends it; when `SECREVIEW_TOKEN_MAX_DAYS` is set, the whole grant ends that many days after the approval, and the client logs in again |

Only the SHA-256 digests of the tokens are stored. A refresh token already replaced and
presented again (a copy, maybe stolen) revokes the whole grant: the host must log in again.

## Connected clients

**My account** lists the **Connected MCP clients** of the user (name given by the client, dates
of approval, of last use and of expiry) and revokes them: the tokens stop working at once.
Deleting a user deletes its clients. A user keeps at most 20 clients; beyond, the oldest is
revoked.

## Registered clients

Anyone may register a client, so every client is **public**: the server replaces a requested
secret-based method with `none`, issues no secret and relies on PKCE. The redirect URIs must
point to the loopback interface (`127.0.0.1`, `localhost`, `::1`, in http or https), to a host
of `SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS` in https, or use a scheme of
`SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES`. Any other site is refused: otherwise, anyone could
register a client that sends the browser back to their own site, and receive the code of a user
who follows their link to `/authorize`. At most `SECREVIEW_MCP_OAUTH_MAX_CLIENTS` clients exist at once; a
client nobody approved within a day is deleted at the next registration. The OAuth routes count
in the [rate limiting](../reference/configuration.md#rate-limiting) of the login routes.

The consent screen shows the name chosen by the client and the host it goes back to: only
approve a client you started yourself.

## Enrollment and clients without OAuth

While the OAuth login is on, a client without a token gets the `401` that starts the login,
not the [enrollment server](architecture/mcp-server.md#enrollment-personal-token-and-project-requests):
a host that does not support OAuth uses a personal MCP token, as before. The description of
the `401` says both.

## Audit

Registrations (`oauth.client_registered`), approvals (`oauth.grant_approved`), refusals
(`oauth.grant_denied`), revocations (`oauth.grant_revoked`) and reused refresh tokens
(`oauth.refresh_reused`) are written to the [audit log](audit-log.md), never with a token.

## Troubleshooting

| Symptom | Cause |
|---|---|
| The host still shows the enrollment server | OAuth off on the controller, or the MCP server has not read the setting yet (30 seconds) |
| The controller does not start: `needs the public URL of the controller` | `SECREVIEW_CONTROLLER_URL` missing |
| The controller does not start: `Issuer URL must be HTTPS` | controller URL in `http://` outside localhost |
| `invalid_redirect_uri` at registration | redirect URI outside the loopback interface: add its host to `SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS` (https) or its scheme to `SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES` |
| `invalid_target` back in the host | the host asks for a resource other than `SECREVIEW_MCP_URL`: check that this URL is the one configured in the host |
| **Connect an MCP client** says the request expired | more than 10 minutes, or already answered: restart the login from the host |
