# Roles and permissions

What a [user account](user-accounts.md) may do comes only from its **roles** and its
**projects**. A role is a set of **permissions**: those marked *per project* apply to the
projects of the account (or every project), the others to the whole Controller server. An OIDC
account also holds the roles and projects of the [OIDC mappings](sso.md#oidc-mappings) of its
identity provider groups. Administrators manage all this in the **Users**, **Roles** and
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

A permission marked **per project** applies to the projects of the account; the others apply to
the whole Controller server. No permission is needed for the
[personal MCP and CI tokens](tokens.md#personal-mcp-and-ci-tokens): every account may create
them, unless `SECREVIEW_PERSONAL_TOKENS_ENABLED=false`.

## Roles

| Role | Permissions | Note |
|---|---|---|
| `reader` | `reports.read` | Built in, cannot be changed: ticked by default for a new account |
| `admin` | Every permission, including those of later versions | Built in, cannot be changed: the role of the first administrator, with every project |

Administrators create other roles, for example a *Triager* role with `reports.read` and
`findings.triage`, or an *Auditor* role with `audit.read` and `reports.read`.

## Roles and projects of an account

In **Users**, the form of an account gives:

- its **Roles**: `reader` is ticked by default;
- its **Projects**: **All projects**, or a list of projects. Several projects are added at once:
  search them, tick them and add them. A project in **Read only** is only read, whatever the
  roles.

The per-project permissions of all its roles apply to all its projects. For example, an account
with the roles `reader` and *Triager* and the projects `shop` and `crm` reads and triages both. To
read `shop` and triage only `crm`, put `shop` in read only. An account with roles but no project
(and without **All projects**) reads no project, and an account without any role sees nothing
and cannot log in.

A project that an account creates, joins or obtains by the approval of a request of its agent
is added **in read only**: the account reads it, never more.

The permissions on the whole Controller server (`audit.read`, `users.manage`...) apply whatever
the projects. **My account** and the **Users** page show the permissions of each account. A
change of the roles or projects of an account, of a role or of an OIDC mapping applies at once
to the open sessions.

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
- **All projects** reaches every project, the sensitive ones included: prefer a list of projects
  for the developers.
- **Deleting a role** removes it from the accounts and from the OIDC mappings that give it.
