# OIDC login (OpenID Connect)

This page is optional: the [local accounts](user-accounts.md) are enough to start. The OIDC
login lets people sign in to the web interface with the identity provider of your company
(Keycloak, Microsoft Entra ID, Okta, Authentik, Dex...). The login page then shows a button for
the provider above the form of the local accounts, which stays available.

The variables, the API, the flow and the detailed rules are in
[OIDC login in detail](../advanced/oidc.md).

## Declaring the client at the provider

At your identity provider, create an OIDC client (with or without a secret) and give it:

- the **callback URL** `https://<controller>/api/v1/auth/oidc/callback`, exactly as the browser
  sees it (behind a reverse proxy, the address of the proxy);
- a claim that holds the **groups** or roles of the user (often `groups`).

The provider must be reachable in HTTPS by the Controller server, through the outgoing proxy if needed.

## Configuring OIDC in the interface

An administrator fills on the **Sign-in** page, without restarting the Controller server:

1. **Issuer**, **Client ID**, **Client secret** (empty for a public client) and **Callback URL**;
2. the **Roles claim**, and the **Administration groups** whose members become administrators;
3. **Create the users at their first login**, or leave it off and create each OIDC account in
   **Users**;
4. **Test the connection**, then **Enable OIDC login** and save.

A change applies at the next login. A field with the **Variable** badge (lock) is set by the
deployment and cannot be changed here. The client secret is never shown again: left empty, it
is kept.

## OIDC accounts

Each OIDC user is an account of the **Users** page, with the **OIDC** badge and no password.
It is bound at its first login to its identity at the provider: a name changed at the provider
keeps the same account.

| Situation at login | Result |
|---|---|
| Known account | Login |
| No account, automatic creation on | The account is created, if its mappings give it a permission |
| No account, automatic creation off | Refused: an administrator creates the OIDC account first |
| A **local** account has the same name | Refused: an OIDC login never opens a local account |
| Account deleted by an administrator | Refused until **Allow again** in **Users** |

## OIDC mappings

At the bottom of the **Sign-in** page, each **OIDC mapping** of a value gives **roles** and
**projects** (**All projects**, or a list) to the OIDC users whose identity provider sends
**exactly** this value (case included). They add up with the roles and projects given to the
account in **Users**. At each login, the values of the claim named by a mapping are kept; the
other values are ignored. A change of the mappings applies at once to the OIDC users, through
the values of their last login.

Example: the provider sends `["payments-team", "staff"]`; a mapping gives `payments-team` the
*Triager* role and the project `billing`, and no mapping names `staff`. The user then triages
`billing`, and the projects given to the account.

A mapping may give only roles (they apply to the projects of the account) or only projects (the
roles of the account apply there). A project not created yet is ignored until it is, never
created by the identity provider. Each value of the **Administration groups** gets a mapping to
`admin` and every project at the first login of a user who holds it; a mapping changed afterwards
is kept.

## Project read access

To let a developer read a project, give it to their OIDC account in **Users** or in the
[members](projects.md#members) of the project (with a role that reads, such as `reader`), map one
of their groups, or approve the access request of their agent in **Projects**. Giving a project
to an account needs it to exist first: the developer has logged in once (automatic creation), or
an administrator has created it in **Users**.

## OIDC only

The deployment may make the identity provider the **only** way in: the login page then only
offers its button. It applies only while OIDC works, so that nobody is locked out if the
provider is misconfigured ([OIDC only](../advanced/oidc.md#oidc-only)).

## Sessions

- A session lasts 8 hours by default. A change of groups at the provider applies at the next
  login; a change made in the interface (roles, mappings), at once.
- **Logging out** closes the session of the interface, not the one of the identity provider.
- On failure, the login page gives the cause (access refused, account not created yet or
  deleted, name taken by a local account...).

## Points to watch

- **Keep a local administrator**: if the provider becomes unreachable, it remains the only
  access, besides the command line.
- **The values of a mapping must match exactly** the groups sent by the provider, case
  included.
- **Deleting an OIDC account** prevents it from being created again at its next login, even
  with automatic creation; **Allow again** lifts this.
- **A user whose roles, projects and mappings give no permission** cannot log in: a project not
  created yet gives nothing.
