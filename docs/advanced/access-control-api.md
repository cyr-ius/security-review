# Access control through the REST API

The [roles and permissions](../usage/access-control.md) and the
[projects](../usage/projects.md) pages describe the model in the web interface. This page gives
the limits, the detailed rules and the REST API calls (`users.manage` permission for the roles,
the roles and projects of the users, the members of the projects and the OIDC mappings).

## Limits

| Element | Limit |
|---|---|
| Roles created by the administrators | 100 at most |
| Roles of a user | 100 at most |
| Projects of a user | 200 at most; beyond that (with the OIDC mappings), the account has no access |
| Members set at once on a project | 500 at most |
| OIDC mappings | 500 at most, one per value of the claim (200 characters at most), each with 100 roles and 50 projects at most |

The permissions limited to projects (`reports.read`, `findings.triage`) of all the roles of a
user apply to all its projects (`all_projects`: every project); the others apply to the whole
Controller server. A project in `read_only` is only read, whatever the roles. Only a known
project may be given (`404` otherwise).

`users.manage` also covers the OIDC settings, since they decide who gets which role. The
`admin` role and every project are also given by a mapping created at the first login of a user
who holds a value of `SECREVIEW_OIDC_ADMIN_GROUPS` ([OIDC](oidc.md)); a mapping that already
names this value is left as an administrator changed it. The values of the roles claim that no
mapping names are ignored.

## Roles and users

```bash
# A role, then a user with it and the reader role, on the "billing" and "crm" projects
curl -X POST https://secreview.example.com/api/v1/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Triager", "description": "", "permissions": ["findings.triage", "reports.read"]}'
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "alice", "role_ids": [1, 3], "projects": [{"project": "billing"}, {"project": "crm", "read_only": true}]}'
# Every project for account 7 (its roles and its projects are kept)
curl -X PUT https://secreview.example.com/api/v1/users/7 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"all_projects": true}'
```

| Route | Effect |
|---|---|
| `GET /api/v1/permissions` | Permissions a role may hold, and whether they apply per project |
| `GET`, `POST /api/v1/roles`; `PUT`, `DELETE /api/v1/roles/{id}` | Roles, with the number of users and OIDC mappings that give each one |
| `POST /api/v1/users` | Creates a user with its roles (`role_ids`) and its projects (`projects`, each with `read_only`, or `all_projects`) |
| `PUT /api/v1/users/{id}` | Replaces the roles (`role_ids`), the projects (`projects`) or `all_projects` of a user; a missing field is left unchanged, those of its OIDC mappings are kept |
| `GET /api/v1/access/projects?search=&limit=` | Known projects whose name contains `search` (every project, also those the caller does not read), 200 at most |
| `GET`, `PUT /api/v1/access/projects/{project}/members` | Users who have a project, each with `read_only` (those who have every project and those of the OIDC mappings are not listed) |
| `GET`, `PUT /api/v1/oidc/mappings` | OIDC mappings, replaced all at once ([OIDC](oidc.md#oidc-mappings)) |

An unknown field (such as the former `group_ids`) is refused (`422`). The built-in roles
`reader` and `admin` can be neither changed nor deleted; deleting another role removes it from
the users and the OIDC mappings that give it (a role used by a token cannot be deleted).

```bash
curl -X PUT https://secreview.example.com/api/v1/access/projects/billing/members \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"members": [{"user_id": 7}, {"user_id": 9, "read_only": true}]}'
```

Every change is written to the [audit log](audit-log.md) (`role.*`, `user.roles_changed`,
`user.projects_changed`, `oidc.mappings_changed`). From the CLI,
`security-review-controller user set-access` changes the roles and projects of an account, and
`security-review-controller role list` / `role mappings` lists the roles and the OIDC mappings
(see [CLI](../reference/cli.md#security-review-controller)).

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
holder of `users.manage` (deleting its account, its role, the permission of its role or the
OIDC mapping that gives it) is refused with `409` or `422`. An OIDC login never removes it: the
values of the claim that gave it are kept, with a warning in the logs and a
`user.roles_changed` event.

## Projects

### Known projects

A project is known once it has a row in the database: created by its first report, a token that
reaches it, an approval or a creation in the web interface. A pending request does not make a
project known.

### Projects in read only

The approval of a project requested by an agent
([enrollment](architecture/mcp-server.md#enrollment-personal-token-and-project-requests)) adds
it to the projects of the requesting user in read only (creating the project when new; for an
existing project, the request is an access request, which only a user holding `users.manage`
approves), and creating a project adds it to its creator the same way. See also
[project read access](../usage/sso.md#project-read-access).

### Creating a project

`POST /api/v1/projects` creates a project, from a session of the web interface only. The only
token that creates a project is the personal MCP token of a user holding `projects.create`,
through the `request_project` tool of its agent. The Controller server adds the project to the
account in read only.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/projects -d '{"project": "mobile-app"}'
# {"project": "mobile-app", "reports_total": 0, "last_report_at": null, …}
```

A known project is refused (`409`). A project still pending is not known yet: creating it
settles the creator's own request (the requests of other users become access requests). Each
creation is written to the audit log (`project.created`).

### Autojoin of a project

A user holding `projects.autojoin` joins an existing project through the `request_project`
tool of its agent: the Controller server adds the project to the account in read only,
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
- the project in the projects of the users;
- the project in the OIDC mappings: a mapping left without project is deleted (never left
  reaching every project);
- the project in the tokens: a token that reaches no other project is revoked (never left
  reaching every project), the others keep their other projects.

```bash
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/projects/mobile-app
# {"project": "mobile-app", "reports": 3, "findings": 12, "members_removed": 2, "mappings_changed": [], …}
```

The audit log keeps the events of the project and records `project.deleted`, with the counts in
its details; the OIDC mappings and the tokens changed or deleted have their own events
(`oidc.mappings_changed`, `token.revoked`, `token.projects_changed`). An unknown project gives
`404`.
