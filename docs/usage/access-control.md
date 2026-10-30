# Roles and permissions

What a [user account](user-accounts.md) may do comes only from its **roles** and its
**projects**. A role holds permissions on the whole Controller server (rules, tokens, users,
audit...). Each project of an account holds its own **per-project permissions** (reading,
writing, triage), as does **All projects**. An OIDC account also holds the roles and projects of the
[OIDC mappings](sso.md#oidc-mappings) of its identity provider groups. Administrators manage all
this in the **Users**, **Roles** and **Sign-in** pages, and on the page of each project
([members](projects.md#members)).

The REST API, the limits and the detailed rules are in
[Access control through the REST API](../advanced/access-control-api.md). The tokens of the
machines keep a fixed role ([tokens](tokens.md)).

## Permissions

| Permission | Allows | Per project |
|---|---|---|
| `reports.read` | Read the projects, reports and findings | ✅ |
| `reports.write` | Save reports and propose a status for a finding with a [personal MCP or CI token](tokens.md#personal-mcp-and-ci-tokens) or an MCP client logged in with OAuth (includes `reports.read`) | ✅ |
| `findings.triage` | [Triage](triage.md) the findings | ✅ |
| `rules.read` | Read the scan rules and the checklists, and export them | |
| `rules.manage` | Edit the scan rules and the checklists (includes `rules.read`) | |
| `standards.read` | Read the development standards, and export them | |
| `standards.manage` | Edit the development standards (includes `standards.read`) | |
| `tokens.manage` | Manage the project tokens | |
| `settings.manage` | Change the general settings, the outgoing proxy and the OSV database | |
| `users.manage` | Manage the users and their roles, the roles, the OIDC mappings and the OIDC login | |
| `audit.read` | Read the audit log | |
| `projects.create` | [Create a project](projects.md#creating-a-project), approve the projects requested by the agents and [block the autojoin](projects.md#blocking-the-autojoin) of a project it reads | |
| `projects.delete` | [Delete a project](projects.md#deleting-a-project) | |
| `projects.autojoin` | [Join an existing project](projects.md#joining-a-project) at once, with `reports.read` and `reports.write`, when the agent requests it, unless [its autojoin is blocked](projects.md#blocking-the-autojoin) | |

A permission marked **per project** is given with a project (or with every project), never by a
role; the others are given by the roles and apply to the whole Controller server. No permission is needed for the
[personal MCP and CI tokens](tokens.md#personal-mcp-and-ci-tokens): every account may create
them, unless `SECREVIEW_PERSONAL_TOKENS_ENABLED=false`. They read the projects of `reports.read`
and save reports or propose a status only on those of `reports.write`: an account that only
reads a project cannot write to it through its agent.

## Roles

| Role | Permissions | Note |
|---|---|---|
| `admin` | Every permission on the whole Controller server, including those of later versions | Built in, cannot be changed: the role of the first administrator, who also reads, writes and triages every project |

Administrators create other roles, for example an *Auditor* role with `audit.read`. A role never
holds `reports.read`, `reports.write` nor `findings.triage`.

## Roles and projects of an account

In **Users**, the form of an account gives:

- its **Roles**: permissions on the whole Controller server;
- its per-project permissions on **All projects** (none by default);
- its **Projects**, each with its own per-project permissions, chosen in a multiple choice.
  Several projects are added at once: search them, tick them and add them (with their reading),
  then choose the permissions of each.

For example, an account with the *Auditor* role, **Read the reports** on `shop` and **Read the
reports** and **Triage the findings** on `crm` reads the audit log, reads both projects and
triages `crm` only. An account without any permission sees nothing and cannot log in.

A project that an account creates, joins or obtains by the approval of a request of its agent is
added with `reports.read` and `reports.write`, never more, so that its agent reviews it. An
account that reads a project without `reports.write` asks for it through its agent like a new
access: `projects.autojoin` never adds it.

**My account** and the **Users** page show the permissions of each account. A change of the
roles or projects of an account, of a role or of an OIDC mapping applies at once to the open
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
- **All projects** reaches every project, the sensitive ones included: prefer a list of projects
  for the developers.
- **A role is for the whole Controller server**: to let someone read or triage, give them
  projects, not a role.
- **Deleting a role** removes it from the accounts and from the OIDC mappings that give it.
