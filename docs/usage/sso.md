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
- a claim that holds the **groups** of the user (often `groups`).

The provider must be reachable in HTTPS by the Controller server, through the outgoing proxy if needed.

## Configuring OIDC in the interface

An administrator fills on the **Sign-in** page, without restarting the Controller server:

1. **Issuer**, **Client ID**, **Client secret** (empty for a public client) and **Callback URL**;
2. the **Groups claim**, and the **Administration groups** whose members become administrators;
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
| No account, automatic creation on | The account is created, if its groups give it a permission |
| No account, automatic creation off | Refused: an administrator creates the OIDC account first |
| A **local** account has the same name | Refused: an OIDC login never opens a local account |
| Account deleted by an administrator | Refused until **Allow again** in **Users** |

## Groups of the identity provider

At each login, the user joins every group **Open to OIDC** whose name is **exactly** one of the
groups sent by the provider (case included), and leaves those it no longer has. The other
values are ignored: create a group of the same name to use one.

Example: the provider sends `["payments-team", "staff"]`; a group `payments-team` open to OIDC
gives the `triager` role on `billing`, and no group is named `staff`. The user then triages
`billing` only.

A group not open to OIDC (for example `administrators`) is never joined this way.

## Project read access

To let a developer read a project, add their OIDC account to the
[project group](projects.md#project-group) in **Groups** or **Users**, or approve the access
request of their agent in **Projects**. The account must exist first: the developer has logged
in once (automatic creation), or an administrator has created it in **Users**.

## OIDC only

The deployment may make the identity provider the **only** way in: the login page then only
offers its button. It applies only while OIDC works, so that nobody is locked out if the
provider is misconfigured ([OIDC only](../advanced/oidc.md#oidc-only)).

## Sessions

- A session lasts 8 hours by default. A change of groups at the provider applies at the next
  login; a change made in the interface, at once.
- **Logging out** closes the session of the interface, not the one of the identity provider.
- On failure, the login page gives the cause (access refused, account not created yet or
  deleted, name taken by a local account...).

## Points to watch

- **Keep a local administrator**: if the provider becomes unreachable, it remains the only
  access, besides the command line.
- **Group names must match exactly**, case included, and the group must be **Open to OIDC**.
- **Deleting an OIDC account** prevents it from being created again at its next login, even
  with automatic creation; **Allow again** lifts this.
- **A user whose groups give no permission** cannot log in.
