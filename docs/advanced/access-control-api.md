# Access control through the REST API

The [roles, groups and permissions](../usage/access-control.md) and the
[projects](../usage/projects.md) pages describe the model in the web interface. This page gives
the limits, the detailed rules and the REST API calls (`users.manage` permission for the roles,
groups and users).

## Limits

| Element | Limit |
|---|---|
| Roles created by the administrators | 100 at most |
| Name of a group | 200 characters at most |
| Projects of a role in a group | 50 at most, only for a role made of per-project permissions (`reports.read`, `findings.triage`); a role holding a permission on the whole Controller server always applies to every project |
| Projects of a permission for a user | 200 at most, union of its groups: beyond that, the account has no access |

`users.manage` also covers the OIDC settings, since they decide who joins which group. The
`admin` role is also given to the groups named by `SECREVIEW_OIDC_ADMIN_GROUPS`
([OIDC](oidc.md)). A new group is not open to OIDC unless asked (`"sso": true`); the
values of the groups claim that name no group are ignored.

## Roles, groups and users

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
own. The built-in roles `reader` and `admin` can be neither changed nor deleted; deleting another
role removes it from its groups.

Every change is written to the [audit log](audit-log.md) (`role.*`, `group.*`,
`user.groups_changed`). From the CLI, `security-review-controller user set-groups` changes the
groups of an account, and `security-review-controller group list` / `group roles` lists the
groups and the roles (see [CLI](../reference/cli.md#security-review-controller)).

## Permissions of the caller

`GET /api/v1/me` returns the permissions of the caller, each with its projects (`null`: every
project), and `role` is always `user` for a web session (the role of the token otherwise). A
user who only manages the tokens and the standards reads no project. A web session never passes
for an `admin` token, even with every permission: the routes reserved to tokens (`/metrics`, the
pipeline scans) refuse it.

```json
{"client": "alice", "role": "user", "projects": null,
 "permissions": {"reports.read": null, "findings.triage": ["crm"]}, …}
```

An account without any permission cannot log in, and its open sessions stop. Removing the last
holder of `users.manage` (deleting its account, its group, the role of its group or the
permission of its role) is refused with `409` or `422`; an OIDC login that removes it from its
OIDC group is not blocked.

## Projects

### Project groups

The **project group** of a project is a group not open to OIDC whose only role is `reader` on
that project alone. The approval of a project requested by an agent
([enrollment](architecture/mcp-server.md#enrollment-personal-token-and-project-requests)) adds the requesting
user to it (creating it for a new project; for an existing project, the request is an access
request, which only a user holding `users.manage` approves), and creating a project creates it
with its creator. An existing group of this kind is reused (even one made by an administrator,
whatever its name); otherwise the group `project:<project>` is created (with a number, such as
`project:shop (2)`, when another group already has this name). See also
[project read access](../usage/sso.md#project-read-access).

### Creating a project

`POST /api/v1/projects` creates a project, from a session of the web interface only. The only
token that creates a project is the personal MCP token of a user holding `projects.create`,
through the `request_project` tool of its agent. The Controller server adds the account to the project
group as a local member.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/projects -d '{"project": "mobile-app"}'
# {"project": "mobile-app", "reports_total": 0, "last_report_at": null, …}
```

A name that already has a report, that a role of a group names (an approved project included),
or that a token reaches is refused (`409`). A project still pending is not known yet: creating
it settles the creator's own request (the requests of other users become access requests). Each
creation is written to the audit log (`project.created`).

### Autojoin of a project

A user holding `projects.autojoin` joins an existing project through the `request_project`
tool of its agent: the Controller server adds the account to the project group (reading only),
settles its pending request of the project and writes `project.joined` to the audit log. A
user who already reads 200 projects is refused. `PUT /api/v1/projects/{project}/autojoin`
blocks (`true`) or allows again (`false`) this autojoin, with `projects.create`, from a session
of the web interface only, for a project the caller reads (another one is `404`). A blocked
project shows `"autojoin_blocked": true` in `GET /api/v1/projects`; the users who already
joined it keep their access. Each change is written to the audit log
(`project.autojoin_changed`).

```bash
curl -X PUT -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/projects/mobile-app/autojoin -d '{"blocked": true}'
# {"project": "mobile-app", "autojoin_blocked": true}
```

### Deleting a project

`DELETE /api/v1/projects/{project}` deletes a project, from a session of the web interface only:
a token never deletes a project. The deletion runs in one transaction:

- its reports, with their findings and the comments of those findings;
- the project in the roles of the groups: a role left without project is removed (never left
  reaching every project), and a project group left without role is deleted with its members;
  any other group is kept;
- the project in the tokens: a token that reaches no other project is revoked (never left
  reaching every project), the others keep their other projects.

```bash
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/projects/mobile-app
# {"project": "mobile-app", "reports": 3, "findings": 12, "groups_deleted": ["project:mobile-app"], …}
```

The audit log keeps the events of the project and records `project.deleted`, with the counts in
its details; each group and token changed or deleted has its own event (`group.deleted`,
`group.roles_changed`, `token.revoked`, `token.projects_changed`). An unknown project gives `404`.
