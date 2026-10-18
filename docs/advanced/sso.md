# SSO login (OpenID Connect)

This page is optional: the [local accounts](../usage/web-interface.md#user-accounts) are enough
to start. Use it to let people log in to the web interface with your identity provider.

The controller can delegate the login to the interface to an OpenID Connect identity provider
(Keycloak, Microsoft Entra ID, Okta, Authentik, Dex...). The login page then shows a
**Log in with SSO** button above the form of the local accounts, which
stays available (initial `admin` account, fallback accounts).

The flow is *authorization code* with PKCE (`S256`), state and nonce:

1. `GET /api/v1/auth/oidc/login` redirects the browser to the provider;
2. the provider sends back to `GET /api/v1/auth/oidc/callback`; the controller exchanges the
   code (server-to-server call), checks the ID token (signature by the JWKS keys of the
   provider, issuer, audience, expiry, nonce), finds the [SSO account](#sso-accounts) of the
   user (or creates it) and records the groups named by its groups claim;
3. it hands the interface a signed **session token**, valid `SECREVIEW_SESSION_HOURS` hours,
   that the tab uses like a Bearer token.

## Declaring the client at the provider

Create a *confidential* OIDC client (or a public one, without a secret: PKCE is enough) with:

- **Redirect URL**: `https://<controller>/api/v1/auth/oidc/callback`, the exact public URL seen
  by the browser (behind a reverse proxy, the proxy's);
- a claim holding the groups or roles of the user in the ID token (or, failing that, in the
  *userinfo* answer, which the controller reads when the ID token does not contain it).

Keycloak example (realm roles):

```bash
SECREVIEW_OIDC_ENABLED=true
SECREVIEW_OIDC_ISSUER=https://sso.example.com/realms/acme
SECREVIEW_OIDC_CLIENT_ID=security-review
SECREVIEW_OIDC_CLIENT_SECRET=...            # empty for a public client
SECREVIEW_OIDC_REDIRECT_URI=https://secreview.example.com/api/v1/auth/oidc/callback
SECREVIEW_OIDC_ROLES_CLAIM=realm_access.roles   # "groups" by default
SECREVIEW_OIDC_ADMIN_GROUPS=secreview-admins   # created with the admin role (first administrator)
SECREVIEW_OIDC_AUTO_CREATE_USERS=true       # otherwise, create every SSO account in Utilisateurs
SECREVIEW_SESSION_SECRET=$(openssl rand -base64 48)
SECREVIEW_OIDC_DISPLAY_NAME=Keycloak
```

The issuer must use HTTPS (HTTP is only accepted on `localhost`, for development); its
`/.well-known/openid-configuration` document must announce the same `issuer`. If the provider
uses an internal CA, give it with `SECREVIEW_OIDC_CAFILE`. The controller reaches the provider
through its outgoing proxy (`SECREVIEW_PROXY` / `SECREVIEW_NO_PROXY`, or the **Outgoing proxy**
screen), else through `HTTPS_PROXY` / `NO_PROXY`.

## Configuring SSO in the interface

The same settings can be changed in the **SSO** screen (`users.manage` permission: the SSO
settings decide who joins which group), without restarting the controller. As for
the **Outgoing proxy** screen, a value stored in the database **replaces its
`SECREVIEW_OIDC_*` variable**, field by field; a field never changed follows its variable:

- every field has the **Variable** badge (the variable applies, its value is shown under the
  field) or **Interface web** (stored value); the **Variable** link of a stored field deletes
  the stored value and applies the variable again;
- the **client secret** is never shown again: left empty, the current secret is kept;
  **Delete** stores an empty secret (public client, PKCE only);
- **Test the connection** contacts the provider with the values of the
  form, without storing them: reading of the `/.well-known/openid-configuration` document (same
  `issuer`, HTTPS endpoints), then of the signing keys (JWKS);
- **Save** refuses (`422`) a configuration that would enable an invalid login
  (missing or non-HTTPS issuer, scopes without `openid`...): nothing is
  stored then. An incomplete configuration can be prepared while SSO stays disabled.

The change applies to the next login, on every replica (the controller reads the configuration
again at every login and rebuilds the OIDC flow when it changes). Sessions already open stay
valid until they expire. Still variables only: `SECREVIEW_OIDC_CAFILE` (a file of the
deployment) and the session settings (`SECREVIEW_SESSION_SECRET`, `SECREVIEW_SESSION_HOURS`).
If a variable changed later makes the combination with the stored values invalid, the
controller starts anyway: the SSO login is disabled and the error logged, to be fixed in the
screen.

Through the API (`/api/v1/oidc/settings`, `users.manage` permission): `GET` describes every setting (stored
`value` or `null`, `env`, `effective`; a set secret reads `***`), `PUT` changes the sent fields
(`null` applies the variable again, a missing field is unchanged) and
`POST /api/v1/oidc/settings/test` tests the provider without storing anything:

```bash
curl -X PUT https://secreview.example.com/api/v1/oidc/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled": true, "issuer": "https://sso.example.com/realms/acme",
       "client_id": "security-review", "client_secret": "...",
       "redirect_uri": "https://secreview.example.com/api/v1/auth/oidc/callback",
       "display_name": null}'
```

## SSO accounts

Every SSO user is an account of the **Users** screen (**SSO** badge), named by
the value of the `SECREVIEW_OIDC_USERNAME_CLAIM` claim (`preferred_username` by default),
compared exactly, case included. There is no fallback to `email` or `sub`, and a value that is
not a valid user name (control or invisible character, space, more than 64 characters) is
refused.

At login, the controller looks for this account:

| Situation | Result |
|---|---|
| Existing SSO account | Login, with the permissions of its groups (below) |
| No account, `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` | The account is **created** (`created_by`: `oidc`) if its groups give it a permission; otherwise refused, without creation |
| No account, `SECREVIEW_OIDC_AUTO_CREATE_USERS=false` (default) | **Refused**: an administrator must first create the SSO account |
| **Local** account with the same name | **Refused**: an SSO login never opens a local account |
| SSO account bound to another `sub` or another issuer | **Refused** (see below) |
| SSO account deleted by an administrator | **Refused**, even with the automatic creation (see below) |

At the first login, the account is **bound** to the issuer and to the `sub` claim of the
provider: the account is identified by both. A later login with the same user name but another
`sub` (provider account deleted then created again, renamed...) or from another issuer (another
identity provider, which could reuse the same `sub`) is refused. An account bound when only
the `sub` was recorded gets the issuer of its next login. To give the user name to someone else, delete then create the account
again.

What an SSO account may do comes from its [groups](access-control.md): those an administrator
gave it (**Users** or **Groups** screen, approval of an enrollment) and the groups open to SSO
named by its groups claim, recorded at every login (see
[groups of the identity provider](#groups-of-the-identity-provider)). An account without any
permission is refused and its open sessions are closed. A change of its given groups applies at
once; a change of its groups at the provider, at the next login.

**Deleting an SSO account** (**Utilisateurs** screen, `DELETE /api/v1/users/{id}` or
`security-review-controller user delete NAME`) closes its sessions at once and **revokes** its
user name: an SSO login no longer creates it again, even with the automatic creation and groups
that give it a permission ("compte supprimé" message, account deleted, on the login page). To give it
access back, an administrator creates the account again (by hand or at the approval of an
enrollment), or lifts the revocation (**Autoriser à nouveau**, Allow again,
`DELETE /api/v1/users/revoked/{username}`): the account is then created again at its next
login. `GET /api/v1/users/revoked` lists the revoked accounts, with the author and the date of
the deletion.

The [last holder](access-control.md#the-last-administrator) of the `users.manage` permission
can be neither deleted nor lose it. Preferably keep a local administrator: if the identity
provider becomes unreachable, it remains the only access, besides the CLI.

```
INFO security_review_mcp.web: SSO web user alice created at its first login
INFO security_review_mcp.web: OIDC login of oidc:alice with role reader through 1 SSO group(s)
WARNING security_review_mcp.web: OIDC login of oidc:bob refused: no web user bob
INFO security_review_mcp.web: Web user carol (oidc) deleted by admin
WARNING security_review_mcp.web: OIDC login of oidc:carol refused: web user carol was deleted
```

## Groups of the identity provider

The values of the `SECREVIEW_OIDC_ROLES_CLAIM` claim (list or string, dotted path accepted) are
compared with the **names of the groups** of the **Groups** screen: at each login, the user joins
every group **open to SSO** whose name is **exactly** one of these values (case included), and
leaves the SSO groups it no longer has. The other values are ignored: create a group of the same
name to use one. The roles of the group, and their projects, then apply (see
[Roles, groups and permissions](access-control.md)).

| Setting | Effect |
|---|---|
| `SECREVIEW_OIDC_ADMIN_GROUPS` | Comma-separated groups that hold the `admin` role: such a group, missing at the login of one of its members, is created open to SSO with the `admin` role. An existing group is left as administrators changed it. Used to name the first administrator |
| `SECREVIEW_OIDC_DEFAULT_GROUP` | Name of a group every SSO user joins at each login, whatever its claim (empty by default: none). A missing group gives nothing |

A group **not open to SSO** (for example `administrators`) is never joined through the claim, even when a value has its name. A restricted session behaves
like a [token restricted to a project](http.md#tokens-restricted-to-a-project): the other
projects, their reports and their findings are handled as missing.

Example: with the claim `["payments-team", "staff"]`, a group `payments-team` open to SSO with the
`triager` role on `billing`, and no `staff` group, the user triages `billing` only.

The label of an SSO session is `oidc:<username>`: it is the one that appears in the logs and
in the triage history.

## Project read access at enrollment

At the approval of an [enrollment](http.md#enrollment-a-project-requests-its-token)
request, the administrator can also give the developer read access to the project in the
portal, on their **user account**: the developer who requested an MCP token for a project then
browses its reports.

- In the **Project tokens** screen, the **Read access in the portal** column is prefilled with the requester (`requested_by`) when it is given, and
  ticked when SSO is enabled. This field is declared by the client and **is not verified**:
  check or correct it before approving, or untick the box.
- The name designates an account of the **Users** screen, local or SSO. With SSO
  enabled, an unknown name becomes an **SSO account**, ready for its first login; without SSO,
  the account must exist. Giving this access needs the `users.manage` permission.
- An account that already reads every project is unchanged. Otherwise the project is added to
  its [direct](access-control.md#direct-roles-and-projects-of-an-account) `reader` role (given on
  this project only when missing). An approved additional request for the same user adds the
  project the same way.

The access then shows on the account, where it is changed like the others. It is independent of
the MCP token: revoking the token does not remove it.

```bash
# Approve a request and give the "alice" user read access to the project
curl -X POST https://secreview.example.com/api/v1/enrollments/$REQUEST_ID/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"portal_user": "alice"}'
```

The answer then contains `portal_user`, the updated account. An invalid user name, an unknown
account without SSO or a reached limit are refused (`422`) before the approval: the request
stays pending. The log of the controller records the access:

```
INFO security_review_mcp.web: Web access to shop-api given to web user alice by admin
```

!!! note "Upgrading from the named accesses"
    Previous versions stored these accesses apart ("named accesses",
    `/api/v1/oidc/user-grants` API). Schema migration `0006` turns them into `reader` SSO
    accounts on the same projects, then deletes the table. An access whose name is not a valid
    user name or that bears the name of a local account is dropped, with a warning in the log of
    the migration.

## Sessions

- The session token is signed (HMAC-SHA256) with a key derived from `SECREVIEW_SESSION_SECRET`
  (at least 32 characters), like the one of the [local accounts](../usage/web-interface.md#login-and-sessions), and
  names the SSO account, read again at every request: deleting the account or changing its
  groups or their roles applies at once. Every replica of the controller must share this secret; without
  it, a random secret is drawn at every start and the sessions end at restart (a warning is
  logged).
- A group change at the provider only applies at the next login. To cut every session before it
  expires, delete the account, or change `SECREVIEW_SESSION_SECRET` and restart the controller
  (every session is cut).
- **Log out** clears the session of the tab, not the one of the identity
  provider.

On failure, the login page gives the cause (access denied at the provider, no permission, SSO account
not created yet or deleted, user name taken by a local account or bound to another account,
missing user name, expired state, invalid token, unreachable provider); the detail is logged by
the controller, without code or token.
