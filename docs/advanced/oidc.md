# OIDC login in detail

The [OIDC login](../usage/sso.md) page describes the setup in the web interface. This page
gives the flow, the variables, the API and the detailed rules.

The Controller server can delegate the login to the interface to an OpenID Connect identity provider
(Keycloak, Microsoft Entra ID, Okta, Authentik, Dex...). The login page then shows a
**Log in with OIDC** button above the form of the local accounts, which
stays available (initial `admin` account, fallback accounts).

The flow is *authorization code* with PKCE (`S256`), state and nonce:

1. `GET /api/v1/auth/oidc/login` redirects the browser to the provider;
2. the provider sends back to `GET /api/v1/auth/oidc/callback`; the Controller server exchanges the
   code (server-to-server call), checks the ID token (signature by the JWKS keys of the
   provider, issuer, audience, expiry, nonce), finds the [OIDC account](#oidc-accounts) of the
   user (or creates it) and keeps the values of its roles claim that an
   [OIDC mapping](#oidc-mappings) names;
3. it hands the interface a signed **session token**, valid `SECREVIEW_SESSION_HOURS` hours,
   that the tab uses like a Bearer token.

## Declaring the client at the provider

Create a *confidential* OIDC client (or a public one, without a secret: PKCE is enough) with:

- **Redirect URL**: `https://<controller>/api/v1/auth/oidc/callback`, the exact public URL seen
  by the browser (behind a reverse proxy, the proxy's);
- a claim holding the groups or roles of the user in the ID token (or, failing that, in the
  *userinfo* answer, which the Controller server reads when the ID token does not contain it).

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
uses an internal CA, give it with `SECREVIEW_OIDC_CAFILE`. The Controller server reaches the provider
through its outgoing proxy (`HTTPS_PROXY` / `NO_PROXY`, or the **General** page).

## Configuring OIDC in the interface

The same settings can be changed on the **Sign-in** page (`users.manage` permission: the OIDC
settings decide who gets which role), without restarting the Controller server. As for
the proxy of the **General** page, **a `SECREVIEW_OIDC_*` variable that is set always takes
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

The change applies to the next login, on every replica (the Controller server reads the configuration
again at every login and rebuilds the OIDC flow when it changes). Sessions already open stay
valid until they expire. Still variables only: `SECREVIEW_OIDC_CAFILE` (a file of the
deployment) and the session settings (`SECREVIEW_SECRET_KEY`, `SECREVIEW_SESSION_HOURS`).
If a variable changed later makes the combination with the stored values invalid, the
Controller server starts anyway: the OIDC login is disabled and the error logged, to be fixed on the
page or in the variables.

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

Every OIDC user is an account of the **Users** page (**OIDC** badge), **identified by the
issuer and the `sub` claim** bound at its first login, never by a name. It is named at its
creation by the value of the `SECREVIEW_OIDC_USERNAME_CLAIM` claim (`preferred_username` by default),
compared exactly, case included. There is no fallback to `email` or `sub`, and a value that is
not a valid user name (control or invisible character, space, more than 64 characters) is
refused.

At login, the Controller server first looks for the account bound to the issuer and the `sub` of the
login: it opens, whatever the username claim says now (a name changed at the provider keeps the
account and its user name). Only an identity bound to no account is looked up by its user name:

| Situation | Result |
|---|---|
| Account bound to this issuer and `sub` | Login, with the permissions of its roles (below), even if the username claim changed |
| OIDC account of this name, not bound yet (created by an administrator) | The account is **bound** to the issuer and `sub`, then login |
| No account, `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` | The account is **created** (`created_by`: `oidc`) if its mappings give it a permission; otherwise refused, without creation |
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

What an OIDC account may do comes from its [roles and projects](../usage/access-control.md):
those an administrator gave it (**Users** page or members of a project) and those of the OIDC
mappings of the values of its roles claim, recorded at every login (see
[OIDC mappings](#oidc-mappings)). An account without any permission is refused and its open
sessions are closed. A change of its roles, its projects or the mappings applies at once; a
change of its groups at the provider, at the next login.

**Deleting an OIDC account** (**Utilisateurs** page, `DELETE /api/v1/users/{id}` or
`security-review-controller user delete NAME`) closes its sessions at once and **revokes** its
user name and its identity (issuer and `sub`): an OIDC login no longer creates it again, under
that name or another one (name changed at the provider), even with the automatic creation and
mappings that give it a permission ("compte supprimé" message, account deleted, on the login page). To give it
access back, an administrator creates the account again, or lifts the revocation (**Autoriser à nouveau**, Allow again,
`DELETE /api/v1/users/revoked/{username}`): the account is then created again at its next
login. `GET /api/v1/users/revoked` lists the revoked accounts, with the author and the date of
the deletion.

The [last holder](../usage/access-control.md#the-last-administrator) of the `users.manage` permission
can be neither deleted nor lose it. Preferably keep a local administrator: if the identity
provider becomes unreachable, it remains the only access, besides the CLI.

```
INFO security_review_mcp.web: OIDC web user alice created at its first login
INFO security_review_mcp.web: OIDC login of oidc:alice through 1 mapped claim(s)
WARNING security_review_mcp.web: OIDC login of oidc:bob refused: no web user bob
INFO security_review_mcp.web: Web user carol (oidc) deleted by admin
WARNING security_review_mcp.web: OIDC login of oidc:carol refused: web user carol was deleted
```

## OIDC mappings

The values of the `SECREVIEW_OIDC_ROLES_CLAIM` claim (list or string, dotted path accepted) are
compared with the **OIDC mappings** of the **Sign-in** page. A mapping, one per value, gives
**roles** (permissions on the whole Controller server), per-project permissions on every project
and **projects** with their per-project permissions to the users whose claim holds **exactly** its
value (case included). At each login, the values of the claim named by a mapping are kept for the
account; the other values are ignored. They add up with the roles and projects given to the
account (see [Roles and permissions](../usage/access-control.md)).

- A change of the mappings applies at once, to every OIDC account, through the values of its last
  login; a value that no mapping names any more is forgotten.
- A project not created yet is ignored until it is, never created by the identity provider. A
  deleted project is removed from the mappings; a mapping left giving nothing is deleted.
- A login never removes the last holder of `users.manage`: the values of the claim that gave it
  are kept, with a warning in the logs and a `user.roles_changed` event. Removing such a mapping
  in the interface is refused.

| Setting | Effect |
|---|---|
| `SECREVIEW_OIDC_ADMIN_GROUPS` | Comma-separated values of the claim that hold the `admin` role: such a value, without any mapping at the login of a user who holds it, gets a mapping to `admin` with the reading and the triage of every project. A mapping that already names it is left as administrators changed it. Used to name the first administrator |

```bash
# Every OIDC mapping, replaced at once
curl -X PUT https://secreview.example.com/api/v1/oidc/mappings \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"mappings": [{"claim": "secreview-admins", "role_ids": [1], "all_projects_permissions": ["reports.read", "findings.triage"]},
                    {"claim": "payments-team", "projects": [{"project": "billing", "permissions": ["reports.read", "findings.triage"]}]}]}'
```

A restricted session behaves like a
[token restricted to a project](bearer-tokens.md#tokens-restricted-to-a-project): the other
projects, their reports and their findings are handled as missing.

Example: with the claim `["payments-team", "staff"]`, a mapping of `payments-team` to the
project `billing` with the reading and the triage, and no mapping of `staff`, the user reads and
triages `billing` (and keeps the projects given to its account).

The label of an OIDC session is `oidc:<username>`: it is the one that appears in the logs and
in the triage history.

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
restart the Controller server, then log in with a local account (its password can be set with
`security-review-controller user reset-password`).

## Sessions

- The session token is signed (HMAC-SHA256) with a key derived from `SECREVIEW_SECRET_KEY`
  (at least 32 characters), like the one of the [local accounts](architecture/controller.md#login-and-sessions), and
  names the OIDC account, read again at every request: deleting the account or changing its
  roles or the OIDC mappings applies at once. Every replica of the Controller server must share this secret; without
  it, a random secret is drawn at every start and sessions end at restart.
- A group change at the provider only applies at the next login. To cut every session before it
  expires, delete the account, or change `SECREVIEW_SECRET_KEY` and restart the Controller server
  (every session is cut).
- **Log out** clears the session of the tab, not the one of the identity
  provider.

On failure, the login page gives the cause (access denied at the provider, no permission, OIDC account
not created yet or deleted, user name taken by a local account or bound to another account,
missing user name, expired state, invalid token, unreachable provider); the detail is logged by
the Controller server, without code or token.
