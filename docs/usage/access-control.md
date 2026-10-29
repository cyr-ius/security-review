# Roles and permissions

What a [user account](user-accounts.md) may do comes only from its **roles**. A role is a set of
**permissions**; an administrator gives it to an account **on every project** or **on a
project**. An OIDC account also holds the roles of the [OIDC mappings](sso.md#oidc-mappings)
of its identity provider groups. Administrators manage all this in the **Users**, **Roles** and
**Sign-in** pages, and on the page of each project ([members](projects.md#members)).

The REST API, the limits and the detailed rules are in
[Access control through the REST API](../advanced/access-control-api.md). The tokens of the
machines keep a fixed role ([tokens](tokens.md)).

## Permissions

| Permission | Allows | Per project |
|---|---|---|
| `reports.read` | Read the projects, reports and findings | ✅ |
| `findings.triage` | [Triage](triage.md) the findings | ✅ |
| `rules.manage` | Edit the scan rules and the checklists | |
| `standards.manage` | Edit the development standards | |
| `tokens.manage` | Manage the project tokens | |
| `settings.manage` | Change the general settings, the outgoing proxy and the OSV database | |
| `users.manage` | Manage the users and their roles, the roles, the OIDC mappings and the OIDC login | |
| `audit.read` | Read the audit log | |
| `projects.create` | [Create a project](projects.md#creating-a-project), approve the projects requested by the agents and [block the autojoin](projects.md#blocking-the-autojoin) of a project it reads | |
| `projects.delete` | [Delete a project](projects.md#deleting-a-project) | |
| `projects.autojoin` | [Join an existing project](projects.md#joining-a-project) at once, as a reader, when the agent requests it, unless [its autojoin is blocked](projects.md#blocking-the-autojoin) | |

A permission marked **per project** applies to the projects of the role; the others apply to the
whole Controller server. No permission is needed for the
[personal MCP and CI tokens](tokens.md#personal-mcp-and-ci-tokens): every account may create
them, unless `SECREVIEW_PERSONAL_TOKENS_ENABLED=false`.

## Roles

| Role | Permissions | Note |
|---|---|---|
| `reader` | `reports.read` | Built in, cannot be changed: given on a project to its creator and to the users who join it |
| `admin` | Every permission, including those of later versions | Built in, cannot be changed: the role of the first administrator |

Administrators create other roles, for example a *Triager* role with `reports.read` and
`findings.triage`, or an *Auditor* role with `audit.read` and `reports.read`.

## Every project or one project

A role is given to an account in two ways, in **Users**:

- **on every project** (**Roles on every project**): all its permissions apply everywhere, also to the
  projects created later, the sensitive ones included;
- **on a project**: only its **per-project** permissions apply, on that project. An `admin` role
  given on a project gives reading and triage there, nothing more. The interface warns about
  the permissions of a role that do not apply on a project: to give one of them (`audit.read`
  for instance), give a role that holds it on every project.

Several projects are added at once: search them, tick them, choose the role (`reader` by
default) and add them. An account may hold several roles on the same project.

## What a user may do

The permissions of a user add up across **all its roles**, each with its projects. For example,
a user who is `reader` on every project and *Triager* on `crm` reads every project and triages
`crm` only. An account without any role sees nothing, and cannot log in. **My account** and the
**Users** page show these permissions.

A change of the roles of a user, of a role or of an OIDC mapping applies at once to the open
sessions.

## The last administrator

At least one account keeps `users.manage`: deleting it, taking that permission away from it, or
removing the OIDC mapping that gives it, is refused. An OIDC login never removes it either: when
the identity provider no longer names the group that made the last administrator, the account
keeps it (the event is logged and audited). Keep a local administrator preferably.

## Points to watch

- **`users.manage` opens everything**: its holder can give itself every other permission. Give
  it only to administrators.
- **Accepting a risk or marking a false positive** needs a person signed in, never a token,
  even with `findings.triage`.
- **A role on every project** reaches every project, the sensitive ones included: prefer roles on
  projects for the developers.
- **Deleting a role** removes it from the accounts and from the OIDC mappings that give it.
