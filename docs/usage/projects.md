# Projects

A **project** gathers everything about one application, usually one repository: its reports,
its findings, its trend and its gate, and who may read or triage it. Every review is saved in a
project.

The REST API and the detailed rules are in
[Access control through the REST API](../advanced/access-control-api.md#projects).

## Name of a project

The name is **normalized**: lowercase, the last segment of a repository URL, and a single `-`
between words. `Mobile App`, `mobile_app` and `git@github.com:acme/mobile-app.git` all give the
project `mobile-app`, so that the members of a team reach the same project whatever they type
(see [project name](../review/prompts-tools.md#project-name)).

## How a project appears

| Way | Who | Result |
|---|---|---|
| **New project** button of the **Projects** page | A person with `projects.create` | Created at once ([creating a project](#creating-a-project)) |
| The agent of a developer asks for it before a review | A developer with a [personal MCP token](tokens.md#personal-mcp-and-ci-tokens) | Created at once, read by the developer, if they may create projects (even when their token already reaches every project, unless `SECREVIEW_ENROLLMENT=false`); otherwise listed in **Pending projects**, to approve ([enrollment](../advanced/architecture/mcp-server.md#enrollment-personal-token-and-project-requests)) |
| First report saved for it | A token that reaches it (pipeline, token for **All projects**) | The project shows with its first report |

A project created without a report shows **No report yet** until its first review.

## Members

The **members** of a project are the accounts that have it in their projects, each with its
per-project permissions there (reading, writing, triage). Its creator, or the developer whose
request was approved, gets its reading and writing (`reports.read` and `reports.write`), never
its triage.

A person with `users.manage` sees the **Members** section at the bottom of the page of the
project, also opened by the people button of its row on the **Projects**
page: search accounts, tick them and add them (with the reading), choose the permissions of
each member (**Write the reports** for those whose agent saves reviews) or remove it, then **Save**. The same projects are given in **Users** ([roles and
projects of an account](access-control.md#roles-and-projects-of-an-account)), or by approving the
**Access request** filed by an agent in **Projects**. The accounts that have every project and
those of the [OIDC mappings](sso.md#oidc-mappings) are not listed there.

## Creating a project

With the `projects.create` permission, the **New project** button shows on the **Projects**
page. Creating a project adds it to your projects with its reading and writing: you read it at
once, and your agent can save its reviews there.

## Deleting a project

With the `projects.delete` permission, a trash button shows on each row of the **Projects**
page. The deletion **cannot be undone** and removes everything that refers to the project:

- its reports, findings and comments;
- the project in the projects of the users and of the OIDC mappings (a mapping left without
  project is deleted);
- the project in the tokens: a token that reached only this project is **revoked**, so a
  pipeline that used it stops.

The audit log keeps the events of the project. A confirmation is asked before the deletion.

## Joining a project

The agent of a developer may ask to join an existing project. Its request shows, waiting for
approval, in **Pending projects** on the **Projects** page.

A person with the `projects.create` and `users.manage` permissions may approve this request; a
person with `users.manage` may also give the project to the user ([members](#members)).

With the `projects.autojoin` permission, the developer **joins the project at once**, without
any request: their agent's request adds the project to theirs with its reading and writing, so
that their agent saves its review (never more: no triage). A developer who already reads the
project without **Write the reports** files a request instead: the autojoin never widens what an
administrator gave. This permission does not create a new
project: that takes `projects.create`.

## Blocking the autojoin

With the `users.manage` permission, a lock button shows on each row of the **Projects** page,
for the projects you read: `projects.create` alone neither blocks nor allows the autojoin. It **blocks the autojoin** of the project: the holders of
`projects.autojoin` then file a request that waits for approval, as the others do. The project
shows the **Autojoin blocked** badge; the unlock button allows the autojoin again. The users who
already joined the project keep their access: remove them from its [members](#members) if
needed.

## Points to watch

- **A pending request expires** after 7 days by default: the agent has to ask again.
- **Approving an access request** to an existing project also needs `users.manage`: creating
  projects never gives access to the others.
- **Deleting a project revokes its dedicated tokens**: warn the teams that use them.
- **`projects.autojoin` opens every project** whose autojoin is not blocked, and tells its
  holder which projects exist: block the autojoin of the sensitive projects.
- **A name is normalized**: `My.App` and `my-app` are the same project.
