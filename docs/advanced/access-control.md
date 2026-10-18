# Roles, groups and permissions

What a [user account](../usage/web-interface.md#user-accounts) may do in the web interface and the
REST API comes from **groups**: an account belongs to groups, a group has **roles**, a role is a
set of **permissions**. Administrators manage them in the **Groups** and **Roles** screens (`users.manage`
permission), or through the `/api/v1/groups` and `/api/v1/roles` API.

Bearer tokens are not concerned: they keep their fixed role (`mcp`, `reader`, `triager`, `admin`,
`ci`, `metrics`, see [Roles](../usage/web-interface.md#roles)).

## Permissions

| Permission | Allows | Per project |
|---|---|---|
| `reports.read` | Projects, reports, findings, posture, trend, SARIF | ✅ |
| `findings.triage` | Change the status of a finding, reject the proposal of an agent | ✅ |
| `rules.manage` | Scan rules and checklists | |
| `standards.manage` | Development standards | |
| `tokens.manage` | Project tokens and enrollment requests | |
| `settings.manage` | Report language, outgoing proxy, advisory database | |
| `users.manage` | Users, groups, roles and SSO settings (they decide who joins which group) | |
| `audit.read` | Audit log | |

`users.manage` lets its holder give itself every other permission: give it only to
administrators. Accepting a risk or marking a false positive also needs a session of the web
interface, never a token (see [triage of findings](../usage/web-interface.md#triage-of-findings)).

## Roles

A role is a name, a description and at least one permission. Three **system** roles exist from
the start and can be neither changed nor deleted:

| System role | Permissions |
|---|---|
| `reader` | `reports.read` |
| `triager` | `reports.read`, `findings.triage` |
| `admin` | every permission |

Administrators create other roles (100 at most), for example an *Auditor* role with
`audit.read` and `reports.read`. A change of a role applies at once to the open sessions of the
members of its groups; deleting a role removes it from its groups.

## Groups

A group has a name (200 characters at most), a description, roles and members. Each role of a
group applies **to every project**, or only **to a list of projects** (50 at most) when the role
is made of per-project permissions only (`reports.read`, `findings.triage`). A role holding a
permission on the whole controller always applies to every project.

Members come from two sources:

- **local**: added by an administrator (**Groups** or **Users** screen, CLI, enrollment
  approval);
- **SSO**: when the group is **open to SSO**, the SSO users whose groups claim holds **exactly
  the name of the group** join it at each login (see [SSO](sso.md#groups-of-the-identity-provider)).
  The values of the claim that name no group are ignored.

Renaming a group, or closing it to SSO, removes its SSO members at once.

## What a user may do

The permissions of a user are the union of the permissions of the roles of **all its groups**.
Each permission keeps its own projects: it reaches every project when one of its roles does,
otherwise the union of their projects (200 at most per permission: beyond that, the account has
no access). A user who is `reader` on every project through one group and `triager` on `crm`
through another reads every project and triages `crm` only.

A change of a group (roles, members) or of a role applies at once to the open sessions. An
account without any permission cannot log in, and its open sessions stop.

`GET /api/v1/me` returns the permissions of the caller; `role` sums them up for the display:
`admin` with every permission on every project, `triager` with `findings.triage`, `reader`
otherwise.

```json
{"client": "alice", "role": "triager", "projects": null,
 "permissions": {"reports.read": null, "findings.triage": ["crm"]}, …}
```

## The last administrator

At least one account keeps `users.manage`: deleting this account, removing its group, the role
of its group or the permission of its role is refused (`409` or `422`). An SSO login that removes
the last holder from its SSO group is not blocked: the identity provider remains the authority.
Preferably keep a local administrator.

## Tokens created from the interface

A token never grants more than its creator holds: creating a token, changing its projects,
rotating its secret, revoking it, or approving or rejecting an enrollment request needs
`reports.read` on every project of the token, before and after a change of its projects (and
`findings.triage` for a `triager` token); the
**Tokens** screen only lists the tokens and requests of the projects the user reads. Giving a user read access at the
approval of an enrollment also needs `users.manage`.

## API

```bash
# A role and a group that gives it on the "billing" project, open to SSO
curl -X POST https://secreview.example.com/api/v1/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Auditor", "description": "Reads the log", "permissions": ["audit.read", "reports.read"]}'
curl -X POST https://secreview.example.com/api/v1/groups \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "payments-team", "description": "", "sso": true}'
curl -X PUT https://secreview.example.com/api/v1/groups/4/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"roles": [{"role_id": 2, "projects": ["billing"]}]}'
curl -X PUT https://secreview.example.com/api/v1/groups/4/members \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"user_ids": [7, 9]}'
```

| Route | Effect |
|---|---|
| `GET /api/v1/permissions` | Permissions a role may hold, and whether they can be limited to projects |
| `GET`, `POST /api/v1/roles`; `PUT`, `DELETE /api/v1/roles/{id}` | Roles |
| `GET`, `POST /api/v1/groups`; `PUT`, `DELETE /api/v1/groups/{id}` | Groups (`GET` also returns the SSO settings that use them) |
| `PUT /api/v1/groups/{id}/roles` | Replaces the roles of a group |
| `PUT /api/v1/groups/{id}/members` | Replaces the local members of a group (SSO members are kept) |
| `PUT /api/v1/users/{id}` | Replaces the local groups of a user: `{"group_ids": [4]}` |

Every change is written to the [audit log](audit-metrics.md#audit-log) (`role.*`, `group.*`,
`user.groups_changed`). From the CLI, `security-review-controller user set-groups` changes the
groups of an account and `security-review-controller group list` / `group roles` lists the groups
and the roles (see [CLI](../reference/cli.md)).

## Upgrading from the fixed roles

Schema migration `0013` moves the former access into groups:

- each OIDC role mapping becomes a group open to SSO named after its group, with the role of the
  mapping on the same projects;
- each account with a role of its own joins `administrators`, `triagers` or `readers` (groups not
  open to SSO) when it reached every project, otherwise a personal group `user:<name>`.

The role given to an SSO account by its groups at its last login is computed again at its next
login. The `SECREVIEW_OIDC_TRIAGER_GROUPS`, `SECREVIEW_OIDC_READER_GROUPS` and
`SECREVIEW_OIDC_DEFAULT_ROLE` variables are gone: create the groups of the same names with the
`triager` or `reader` role, and use `SECREVIEW_OIDC_DEFAULT_GROUP` instead of the default role.
