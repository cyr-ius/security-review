# Roles, groups and permissions

What a [user account](user-accounts.md) may do comes only from its **groups**. A group gives
**roles**, each on every project or on some [projects](projects.md); a role is a set of
**permissions**. An account never holds a role of its own: to give a person access, add them to
a group. Administrators manage all this in the **Groups**, **Roles** and **Users** pages.

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
| `users.manage` | Manage the users, groups, roles and the OIDC login | |
| `audit.read` | Read the audit log | |
| `projects.create` | [Create a project](projects.md#creating-a-project), approve the projects requested by the agents and [block the autojoin](projects.md#blocking-the-autojoin) of a project it reads | |
| `projects.delete` | [Delete a project](projects.md#deleting-a-project) | |
| `projects.autojoin` | [Join an existing project](projects.md#joining-a-project) at once, as a reader, when the agent requests it, unless [its autojoin is blocked](projects.md#blocking-the-autojoin) | |

A permission marked **per project** may be limited to some projects; the others apply to the
whole Controller server. No permission is needed for the
[personal MCP and CI tokens](tokens.md#personal-mcp-and-ci-tokens): every account may create
them, unless `SECREVIEW_PERSONAL_TOKENS_ENABLED=false`.

## Roles

| Role | Permissions | Note |
|---|---|---|
| `reader` | `reports.read` | Built in, cannot be changed: used by the [project groups](projects.md#project-group) |
| `admin` | Every permission, including those of later versions | Built in, cannot be changed: the role of the `administrators` group |
| `triager` | `reports.read`, `findings.triage` | Created with the database, can be changed |

Administrators create other roles, for example an *Auditor* role with `audit.read` and
`reports.read`.

## Groups

A group has a name, roles and members. Each role of a group applies **to every project**, or
**to some projects** when it holds only per-project permissions.

Members come from two sources:

- **local**: added by an administrator, in **Groups** or **Users**;
- **OIDC**: when the group is **Open to OIDC**, the OIDC users whose identity provider names
  exactly this group join it at each login (see
  [groups of the identity provider](sso.md#groups-of-the-identity-provider)).

## What a user may do

The permissions of a user add up across **all its groups**, each with its own projects. For
example, a user who is `reader` on every project through one group and `triager` on `crm`
through another reads every project and triages `crm` only. **My account** and the **Users**
page show these permissions.

A change of a group or of a role applies at once to the open sessions. An account without any
permission cannot log in.

## The last administrator

At least one account keeps `users.manage`: deleting it, or taking that permission away from
it, is refused. An OIDC login is the exception: the identity provider may remove the last
administrator from its group. Keep a local administrator preferably.

## Points to watch

- **`users.manage` opens everything**: its holder can give itself every other permission. Give
  it only to administrators.
- **Accepting a risk or marking a false positive** needs a person signed in, never a token,
  even with `findings.triage`.
- **Renaming a group, or closing it to OIDC**, removes its OIDC members at once.
- **Deleting a role** removes it from its groups: their members lose its permissions.
