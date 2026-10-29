# OAuth login of MCP clients

By default, a developer creates a personal MCP token in **My account** and copies it into the
configuration of their agent (see [Agent configuration](../getting-started/host.md)).

With the **OAuth login**, the developer no longer needs a token. At the first connection, the
agent opens the browser, the developer signs in to the web interface (local account or
[OIDC](oidc.md)) and approves the client, then the agent receives its tokens and renews them by
itself.

The flow follows the [authorization of the MCP specification](https://modelcontextprotocol.io/specification/latest/basic/authorization)
(OAuth 2.1, authorization code with PKCE `S256`, dynamic client registration, protected
resource metadata).

The Controller server is the authorization server. The MCP server only checks the tokens.
The personal MCP tokens keep working, unless an administrator turns them off with `SECREVIEW_PERSONAL_MCP_TOKENS=false`.

## Enabling it

In the web interface, an administrator with the `settings.manage` permission must enter the public
URL of the MCP server in the **MCP clients (OAuth login)** section of the **Tokens** page and
turn on the **Enable OAuth login** switch.

The public URL of the Controller server is also needed, through the setting on the **General** page.

The change applies at once, with no restart. Turning the login off asks for confirmation and revokes every grant.
Each change is recorded in the audit log (`mcp_oauth.changed`).

The OAuth routes follow the settings at each request. A change of the Controller server URL in **General** changes the issuer with no restart.

If you would rather not use the web interface, here are the environment variables to pass to the **Controller server**:

```bash
SECREVIEW_MCP_OAUTH_ENABLED=true
SECREVIEW_MCP_URL=https://mcp.example.com/mcp          # public URL of the MCP endpoint
SECREVIEW_PUBLIC_URL=https://secreview.example.com # issuer (https, http on localhost only)
```

Whatever the method used, the MCP server picks up the changes (within 30 seconds).
When you turn the MCP OAuth login off, the server revokes every grant, so that the tokens already issued stop working at once.

Behind a reverse proxy, publish these public paths:

| Path | Process |
|---|---|
| `/.well-known/oauth-protected-resource/mcp` (protected resource metadata, RFC 9728) | MCP server |
| `/.well-known/oauth-authorization-server` (metadata, RFC 8414), `/authorize`, `/token`, `/register`, `/revoke` | Controller server |

The issuer must be in `https`: the Controller server refuses to start with an `http` URL outside localhost.

By default, a client may only send the browser back to the loopback interface of the workstation (`127.0.0.1`,
`localhost`, `::1`, in http or https). When the callback address is not on the loopback interface
(for example `https://vscode.dev/redirect`), its host names can be listed in `SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS`.
The return scheme may also be neither http nor https, for example **cursor**://localhost/redirect:
such schemes are listed in `SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES`.

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

## Flow

1. The host calls `/mcp` without a token. The MCP server answers `401` with
   `WWW-Authenticate: Bearer …, resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`.
   This document names the Controller server as authorization server.
2. The host registers itself at `/register` (dynamic registration, RFC 7591).
3. It opens `/authorize` in the browser, which goes to the **Connect an MCP client** page of the
   web interface, behind the usual login.
4. The developer approves (or denies) the client there, the browser goes back to the host with
   a single-use code, valid 60 seconds.
5. The host exchanges the code and its PKCE verifier at `/token` for an access token and a
   refresh token, then calls `/mcp` with the access token.

A request left without an answer expires after 10 minutes.

## What a token gives

An access token acts as a [personal MCP token](../usage/tokens.md#personal-mcp-and-ci-tokens) of
the user who approved the client: the projects the user may read.
The rights are read again at each request.

Approving a client needs the `mcp_tokens.create` permission, like creating a personal MCP
token, and a web session: a Bearer token never approves a client.

| Token | Lifetime | Renewal |
|---|---|---|
| Access token | `SECREVIEW_MCP_OAUTH_ACCESS_MINUTES` (60 minutes) | by the refresh token, without the browser |
| Refresh token | `SECREVIEW_MCP_OAUTH_REFRESH_DAYS` (30 days) | each refresh issues a new pair and extends it; when `SECREVIEW_TOKEN_MAX_DAYS` is set, the whole grant ends that many days after the approval, and the client logs in again |

Only the SHA-256 digests of the tokens are stored. A refresh token already replaced and
presented again (a copy, maybe stolen) revokes the whole grant: the host must log in again.

## Connected clients

As soon as the login is on, the **My account** page lists the **Connected MCP clients** of the user (name given by the client, dates
of approval, of last use and of expiry) and revokes them (the tokens stop working at once).

Deleting a user deletes its clients. A user keeps at most 20 clients; beyond, the oldest is revoked.

## Administration

With the `tokens.manage` permission, the **Tokens** page shows a **MCP clients (OAuth login)** section.

 - **Revoke** cuts one user of a client.

 - **Delete** removes a client with all its grants, and the client must register again.


## Registered clients

Anyone may register a client, so every client is **public**. The server replaces the secret-based
method with `none`, issues no secret and relies on PKCE.

At most `SECREVIEW_MCP_OAUTH_MAX_CLIENTS` clients can exist at once. A client nobody approved
within a day is deleted at the next registration. The OAuth routes are subject to the
[rate limiting](../reference/configuration.md#rate-limiting) of the login routes.

The consent page shows the name chosen by the client and the host it goes back to.
Only approve a client you started yourself.

## Enrollment and clients without OAuth

While the OAuth login is on, a client without a token gets the `401` that starts the login,
not the [enrollment server](architecture/mcp-server.md#enrollment-personal-token-and-project-requests).
A host that does not support OAuth uses a personal MCP token, as before. The description of
the `401` says both.

## Audit

Registrations (`oauth.client_registered`), approvals (`oauth.grant_approved`), refusals
(`oauth.grant_denied`), revocations (`oauth.grant_revoked`) and reused refresh tokens
(`oauth.refresh_reused`) are written to the [audit log](audit-log.md), never with a token.

## Troubleshooting

| Symptom | Cause |
|---|---|
| The host still shows the enrollment server | OAuth off on the Controller server, or the MCP server has not read the setting yet (30 seconds) |
| The Controller server does not start: `needs the public URL of the controller` | `SECREVIEW_PUBLIC_URL` missing |
| The Controller server does not start: `Issuer URL must be HTTPS` | Controller server URL in `http://` outside localhost |
| `invalid_redirect_uri` at registration, or VS Code asks for a client ID ("Dynamic client registration not supported") | no redirect URI on the loopback interface: add its host to `SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS` (https) or its scheme to `SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES` |
| `invalid_target` back in the host | the host asks for a resource other than `SECREVIEW_MCP_URL`: check that this URL is the one configured in the host |
| **Connect an MCP client** says the request expired | more than 10 minutes, or already answered: restart the login from the host |
