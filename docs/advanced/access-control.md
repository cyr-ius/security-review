# Roles, groups and permissions

What a [user account](../usage/web-interface.md#user-accounts) may do in the web interface and the
REST API comes only from **roles**, a role being a set of **permissions**, given to its
**groups**, each on every project or on a list of projects. An account never holds a role or a
project of its own: to give a person access, add them to a group. Administrators manage them in the **Groups**, **Roles** and **Users** screens (`users.manage`
permission), or through the `/api/v1/groups`, `/api/v1/roles` and `/api/v1/users` API.

Bearer tokens are for machines and keep their fixed role (`mcp`, `admin`, `ci`, `metrics`, see
[Roles](../usage/web-interface.md#roles)), except the `api` tokens of the REST API and its
Swagger, which follow this model (see [API tokens](../usage/web-interface.md#api-tokens)): a
personal token holds the current rights of its user, a role token the permissions of one role on
its projects. A person gets read or triage access through the groups of their account.

## Permissions

| Permission | Allows | Per project |
|---|---|---|
| `reports.read` | Projects, reports, findings, posture, trend, SARIF | ✅ |
| `findings.triage` | Change the status of a finding, reject the proposal of an agent | ✅ |
| `rules.manage` | Scan rules and checklists | |
| `standards.manage` | Development standards | |
| `tokens.manage` | Project tokens and enrollment requests | |
| `settings.manage` | Report language, outgoing proxy, advisory database | |
| `users.manage` | Users, groups, roles and OIDC settings (they decide who joins which group) | |
| `audit.read` | Audit log | |

`users.manage` lets its holder give itself every other permission: give it only to
administrators. Accepting a risk or marking a false positive also needs a session of the web
interface, never a token (see [triage of findings](../usage/web-interface.md#triage-of-findings)).

## Roles

A role is a name, a description and at least one permission. Two **built-in** roles exist from
the start and can be neither changed nor deleted, because the controller relies on them:

| Built-in role | Permissions | Used by |
|---|---|---|
| `reader` | `reports.read` | the [project groups](#project-groups) created at the approval of an enrollment |
| `admin` | every permission (including the ones a later version adds) | the `administrators` group of the first administrator, `SECREVIEW_OIDC_ADMIN_GROUPS` |

The `triager` role (`reports.read`, `findings.triage`) is also created with the database, but it
is an ordinary role: administrators change or delete it like any other.

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
- **OIDC**: when the group is **open to OIDC**, the OIDC users whose groups claim holds **exactly
  the name of the group** join it at each login (see [OIDC](sso.md#groups-of-the-identity-provider)).
  The values of the claim that name no group are ignored.

Renaming a group, or closing it to OIDC, removes its OIDC members at once.

## Project groups

The approval of an enrollment with read access in the portal (see
[OIDC](sso.md#project-read-access-at-enrollment)) adds the account, as a local member, to the
**project group** of the project: a group not open to OIDC whose only role is `reader` on that
project alone. An existing group of this kind is reused (even one made by an administrator,
whatever its name); otherwise the group `project:<project>` is created (with a number, such as
`project:shop (2)`, when another group already has this name). All the developers enrolled on a
project thus share one group, which an administrator manages like any other.

## What a user may do

The permissions of a user are the union of the permissions of the roles of **all its groups**.
Each permission keeps its own projects: it reaches every project when one of its roles does,
otherwise the union of their projects (200 at most per permission: beyond that, the account has
no access). A user who is `reader` on every project through one group and `triager` on `crm`
through another reads every project and triages `crm` only.

A change of a group (roles, members) or of a role applies at once to the open sessions. An
account without any permission cannot log in, and its open sessions stop.

A user holds no role of its own: `GET /api/v1/me` returns its permissions, each with its
projects (`null`: every project), and `role` is always `user` for a web session (the role of the
token otherwise). The **Users** screen and **My account** list these permissions as they are: a
user who only manages the tokens and the standards reads no project. A web session never passes
for an `admin` token, even with every permission: the routes reserved to tokens (`/metrics`, the
pipeline scans) refuse it.

```json
{"client": "alice", "role": "user", "projects": null,
 "permissions": {"reports.read": null, "findings.triage": ["crm"]}, …}
```

## The last administrator

At least one account keeps `users.manage`: deleting this account, removing its group, the role
of its group or the permission of its role is refused (`409` or `422`). An OIDC login that removes
the last holder from its OIDC group is not blocked: the identity provider remains the authority.
Preferably keep a local administrator.

## Tokens created from the interface

A token never grants more than its creator holds: creating a token, changing its projects,
rotating its secret, revoking it, or approving or rejecting an enrollment request needs
`reports.read` on every project of the token, before and after a change of its projects, and,
for a role `api` token, each permission of its role on these projects; the
**Tokens** screen only lists the tokens and requests of the projects the user reads. Giving a user read access at the
approval of an enrollment also needs `users.manage`.

## API

```bash
# A role and a group that gives it on the "billing" project, open to OIDC
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
# The local groups of account 7 (its OIDC groups are kept)
curl -X PUT https://secreview.example.com/api/v1/users/7 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"group_ids": [4]}'
```

| Route | Effect |
|---|---|
| `GET /api/v1/permissions` | Permissions a role may hold, and whether they can be limited to projects |
| `GET`, `POST /api/v1/roles`; `PUT`, `DELETE /api/v1/roles/{id}` | Roles |
| `GET`, `POST /api/v1/groups`; `PUT`, `DELETE /api/v1/groups/{id}` | Groups (`GET` also returns the OIDC settings that use them) |
| `PUT /api/v1/groups/{id}/roles` | Replaces the roles of a group |
| `PUT /api/v1/groups/{id}/members` | Replaces the local members of a group (OIDC members are kept) |
| `POST /api/v1/users` | Creates a user, member of the groups `group_ids` |
| `PUT /api/v1/users/{id}` | Replaces the local groups (`group_ids`) of a user; a missing field is left unchanged |

A `roles` field in the body of these two routes is refused (`422`): an account has no role of its
own.

Every change is written to the [audit log](audit-metrics.md#audit-log) (`role.*`, `group.*`,
`user.groups_changed`). From the CLI, `security-review-controller user set-groups` changes the
groups of an account, and `security-review-controller group list` / `group roles` lists the groups and the roles (see
[CLI](../reference/cli.md)).

## Upgrading from the fixed roles

Schema migration `0013` moves the former access into groups:

- each OIDC role mapping becomes a group open to OIDC named after its group, with the role of the
  mapping on the same projects;
- each account with a role of its own joins `administrators`, `triagers` or `readers` (groups not
  open to OIDC) when it reached every project, otherwise a personal group `user:<name>`.

Schema migration `0014` then turns each personal group `user:<name>` whose only member is that
account (added by an administrator) into direct roles of the account, on the same projects, and
deletes the group. A personal group with other members, or open to OIDC, is kept.

Schema migration `0018` removes these direct roles: each one becomes the local membership of a
group not open to OIDC holding the same role on the same projects, so that nobody loses or gains
any access (the last administrator included). A role on a list of projects gives one group per
project, `project:<project>` for `reader` (the [project group](#project-groups)), otherwise
`project:<project>:<role>`; a role on every project gives the group `role:<role>`. An existing
group not open to OIDC whose only role is the same one (such as `administrators` for `admin`) is
reused.

The role given to an OIDC account by its groups at its last login is computed again at its next
login. The `SECREVIEW_OIDC_TRIAGER_GROUPS`, `SECREVIEW_OIDC_READER_GROUPS` and
`SECREVIEW_OIDC_DEFAULT_ROLE` variables are gone: create the groups of the same names with the
`triager` or `reader` role, and use `SECREVIEW_OIDC_DEFAULT_GROUP` instead of the default role.

## Upgrading from the reader and triager tokens

Schema migration `0021` makes tokens machine-only:

- the `reader` and `triager` tokens are revoked; each revocation is written to the
  [audit log](audit-metrics.md) (`token.revoked`, actor `migration`). Give the people who used
  them a [user account](../usage/web-interface.md#user-accounts) in a group with the `reader` or
  `triager` role on the same projects; an administration script uses an `admin` token;
- the `triager` role stops being built in: it keeps its permissions and its groups, and can now
  be changed or deleted.
