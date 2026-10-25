# OIDC login (OpenID Connect)

This page is optional: the [local accounts](../usage/user-accounts.md) are enough
to start. Use it to let people log in to the web interface with your identity provider.

The controller can delegate the login to the interface to an OpenID Connect identity provider
(Keycloak, Microsoft Entra ID, Okta, Authentik, Dex...). The login page then shows a
**Log in with OIDC** button above the form of the local accounts, which
stays available (initial `admin` account, fallback accounts).

The flow is *authorization code* with PKCE (`S256`), state and nonce:

1. `GET /api/v1/auth/oidc/login` redirects the browser to the provider;
2. the provider sends back to `GET /api/v1/auth/oidc/callback`; the controller exchanges the
   code (server-to-server call), checks the ID token (signature by the JWKS keys of the
   provider, issuer, audience, expiry, nonce), finds the [OIDC account](#oidc-accounts) of the
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
SECREVIEW_OIDC_AUTO_CREATE_USERS=true       # otherwise, create every OIDC account in Utilisateurs
SECREVIEW_SECRET_KEY=$(openssl rand -base64 48)
SECREVIEW_OIDC_DISPLAY_NAME=Keycloak
```

The issuer must use HTTPS (HTTP is only accepted on `localhost`, for development); its
`/.well-known/openid-configuration` document must announce the same `issuer`. If the provider
uses an internal CA, give it with `SECREVIEW_OIDC_CAFILE`. The controller reaches the provider
through its outgoing proxy (`HTTPS_PROXY` / `NO_PROXY`, or the **Outgoing proxy** screen).

## Configuring OIDC in the interface

The same settings can be changed in the **OIDC** screen (`users.manage` permission: the OIDC
settings decide who joins which group), without restarting the controller. As for
the **Outgoing proxy** screen, **a `SECREVIEW_OIDC_*` variable that is set always takes
precedence**, field by field; a value stored in the database applies only to the fields whose
variable is not set:

- a field whose variable is set has the **Variable** badge (with a lock): it shows the
  variable and cannot be changed; a value stored before the variable was set is marked
  *value set here ignored*, with a **Delete** link;
- otherwise the field has the **Web interface** badge (stored value; **Reset** deletes it and
  the default applies again) or **Default**;
- the **client secret** is never shown again: left empty, the current secret is kept;
  **Delete** stores an empty secret (public client, PKCE only);
- **Test the connection** contacts the provider with the values of the
  form, without storing them: reading of the `/.well-known/openid-configuration` document (same
  `issuer`, HTTPS endpoints), then of the signing keys (JWKS);
- **Save** refuses (`422`) a configuration that would enable an invalid login
  (missing or non-HTTPS issuer, scopes without `openid`...): nothing is
  stored then. An incomplete configuration can be prepared while OIDC stays disabled.

The change applies to the next login, on every replica (the controller reads the configuration
again at every login and rebuilds the OIDC flow when it changes). Sessions already open stay
valid until they expire. Still variables only: `SECREVIEW_OIDC_CAFILE` (a file of the
deployment) and the session settings (`SECREVIEW_SECRET_KEY`, `SECREVIEW_SESSION_HOURS`).
If a variable changed later makes the combination with the stored values invalid, the
controller starts anyway: the OIDC login is disabled and the error logged, to be fixed in the
screen or in the variables.

Through the API (`/api/v1/oidc/settings`, `users.manage` permission): `GET` describes every setting (stored
`value` or `null`, `env`, `env_set`: the variable is set and takes precedence, `effective`; a
set secret reads `***`), `PUT` changes the sent fields (`null` deletes the stored value, a
missing field is unchanged, a field whose variable is set is refused with `422`) and
`POST /api/v1/oidc/settings/test` tests the provider without storing anything:

```bash
curl -X PUT https://secreview.example.com/api/v1/oidc/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled": true, "issuer": "https://sso.example.com/realms/acme",
       "client_id": "security-review", "client_secret": "...",
       "redirect_uri": "https://secreview.example.com/api/v1/auth/oidc/callback",
       "display_name": null}'
```

## OIDC accounts

Every OIDC user is an account of the **Users** screen (**OIDC** badge), **identified by the
issuer and the `sub` claim** bound at its first login, never by a name. It is named at its
creation by the value of the `SECREVIEW_OIDC_USERNAME_CLAIM` claim (`preferred_username` by default),
compared exactly, case included. There is no fallback to `email` or `sub`, and a value that is
not a valid user name (control or invisible character, space, more than 64 characters) is
refused.

At login, the controller first looks for the account bound to the issuer and the `sub` of the
login: it opens, whatever the username claim says now (a name changed at the provider keeps the
account and its user name). Only an identity bound to no account is looked up by its user name:

| Situation | Result |
|---|---|
| Account bound to this issuer and `sub` | Login, with the permissions of its groups (below), even if the username claim changed |
| OIDC account of this name, not bound yet (created by an administrator) | The account is **bound** to the issuer and `sub`, then login |
| No account, `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` | The account is **created** (`created_by`: `oidc`) if its groups give it a permission; otherwise refused, without creation |
| No account, `SECREVIEW_OIDC_AUTO_CREATE_USERS=false` (default) | **Refused**: an administrator must first create the OIDC account |
| **Local** account with the same name | **Refused**: an OIDC login never opens a local account |
| OIDC account bound to another `sub` or another issuer | **Refused** (see below) |
| OIDC account deleted by an administrator | **Refused**, even with the automatic creation (see below) |

At the first login, the account is **bound** to the issuer and to the `sub` claim of the
provider: the account is identified by both, and no two accounts share them. A later login
with the same user name but another `sub` (provider account deleted then created again...) or
from another issuer (another identity provider, which could reuse the same `sub`) is refused.
An account bound when only the `sub` was recorded gets the issuer of its next login. To give
the user name to someone else, delete then create the account again.

What an OIDC account may do comes from its [groups](access-control.md#groups): those an administrator
gave it (**Users** or **Groups** screen) and the groups open to OIDC
named by its groups claim, recorded at every login (see
[groups of the identity provider](#groups-of-the-identity-provider)). An account without any
permission is refused and its open sessions are closed. A change of its given groups applies at
once; a change of its groups at the provider, at the next login.

**Deleting an OIDC account** (**Utilisateurs** screen, `DELETE /api/v1/users/{id}` or
`security-review-controller user delete NAME`) closes its sessions at once and **revokes** its
user name and its identity (issuer and `sub`): an OIDC login no longer creates it again, under
that name or another one (name changed at the provider), even with the automatic creation and
groups that give it a permission ("compte supprimé" message, account deleted, on the login page). To give it
access back, an administrator creates the account again, or lifts the revocation (**Autoriser à nouveau**, Allow again,
`DELETE /api/v1/users/revoked/{username}`): the account is then created again at its next
login. `GET /api/v1/users/revoked` lists the revoked accounts, with the author and the date of
the deletion.

The [last holder](access-control.md#the-last-administrator) of the `users.manage` permission
can be neither deleted nor lose it. Preferably keep a local administrator: if the identity
provider becomes unreachable, it remains the only access, besides the CLI.

```
INFO security_review_mcp.web: OIDC web user alice created at its first login
INFO security_review_mcp.web: OIDC login of oidc:alice with role reader through 1 OIDC group(s)
WARNING security_review_mcp.web: OIDC login of oidc:bob refused: no web user bob
INFO security_review_mcp.web: Web user carol (oidc) deleted by admin
WARNING security_review_mcp.web: OIDC login of oidc:carol refused: web user carol was deleted
```

## Groups of the identity provider

The values of the `SECREVIEW_OIDC_ROLES_CLAIM` claim (list or string, dotted path accepted) are
compared with the **names of the groups** of the **Groups** screen: at each login, the user joins
every group **open to OIDC** whose name is **exactly** one of these values (case included), and
leaves the OIDC groups it no longer has. The other values are ignored: create a group of the same
name to use one. The roles of the group, and their projects, then apply (see
[Roles, groups and permissions](access-control.md)).

| Setting | Effect |
|---|---|
| `SECREVIEW_OIDC_ADMIN_GROUPS` | Comma-separated groups that hold the `admin` role: such a group, missing at the login of one of its members, is created open to OIDC with the `admin` role. An existing group is left as administrators changed it. Used to name the first administrator |
| `SECREVIEW_OIDC_DEFAULT_GROUP` | Name of a group every OIDC user joins at each login, whatever its claim (empty by default: none). A missing group gives nothing |

A group **not open to OIDC** (for example `administrators`) is never joined through the claim, even when a value has its name. A restricted session behaves
like a [token restricted to a project](bearer-tokens.md#tokens-restricted-to-a-project): the other
projects, their reports and their findings are handled as missing.

Example: with the claim `["payments-team", "staff"]`, a group `payments-team` open to OIDC with the
`triager` role on `billing`, and no `staff` group, the user triages `billing` only.

The label of an OIDC session is `oidc:<username>`: it is the one that appears in the logs and
in the triage history.

## Project read access

The approval of an [enrollment](mcp-server.md#enrollment-request-the-project) creates the project
with its [project group](access-control.md#project-groups) `project:<project>`, without any
member, and never a token nor an account. To let a developer read the project (and their personal MCP token
reach it), an administrator adds their account to that group, from the **Groups** screen (or
**Users**). With OIDC, the account exists once the developer has logged in (with
`SECREVIEW_OIDC_AUTO_CREATE_USERS=true`), or an administrator creates it beforehand in **Users**.
The access then shows in the groups of the account, where it is changed like the others.

## OIDC only

With `SECREVIEW_OIDC_ONLY=true`, the identity provider becomes the only way in: the login page
only offers its button, and `POST /api/v1/auth/login` refuses the user name and password of the
local accounts (`403`, logged). The sessions already open stay valid until they expire.

```bash
SECREVIEW_OIDC_ENABLED=true
SECREVIEW_OIDC_ONLY=true
```

It applies only while OIDC works: with OIDC disabled, or with settings refused at their check,
the local accounts log in again, so that nobody is locked out. `SECREVIEW_OIDC_ONLY` is a
variable only, never changed in the interface: if the provider is unavailable, unset it and
restart the controller, then log in with a local account (its password can be set with
`security-review-controller user reset-password`).

## Sessions

- The session token is signed (HMAC-SHA256) with a key derived from `SECREVIEW_SECRET_KEY`
  (at least 32 characters), like the one of the [local accounts](controller.md#login-and-sessions), and
  names the OIDC account, read again at every request: deleting the account or changing its
  groups or their roles applies at once. Every replica of the controller must share this secret; without
  it, a random secret is drawn at every start and sessions end at restart.
- A group change at the provider only applies at the next login. To cut every session before it
  expires, delete the account, or change `SECREVIEW_SECRET_KEY` and restart the controller
  (every session is cut).
- **Log out** clears the session of the tab, not the one of the identity
  provider.

On failure, the login page gives the cause (access denied at the provider, no permission, OIDC account
not created yet or deleted, user name taken by a local account or bound to another account,
missing user name, expired state, invalid token, unreachable provider); the detail is logged by
the controller, without code or token.
