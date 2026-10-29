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
| **New project** button of the **Projects** screen | A person with `projects.create` | Created at once ([creating a project](#creating-a-project)) |
| The agent of a developer asks for it before a review | A developer with a [personal MCP token](tokens.md#personal-mcp-and-ci-tokens) | Created at once if the developer may create projects; otherwise listed in **Pending projects**, to approve ([enrollment](../advanced/architecture/mcp-server.md#enrollment-personal-token-and-project-requests)) |
| First report saved for it | A token that reaches it (pipeline, token for **All projects**) | The project shows with its first report |

A project created without a report shows **No report yet** until its first review.

## Project group

Each project has its **project group**, `project:<project>`, which gives the reading of that
project alone (`reader` role). Its creator, or the developer whose request was approved, is its
first member.

To let a colleague read the project (and their agent review it), add their account to this
group in **Groups** or **Users**, or approve the **Access request** filed by their agent in
**Projects**. To let them triage, give them a group with the `triager` role on the project
([groups](access-control.md#groups)).

## Creating a project

With the `projects.create` permission, the **New project** button shows on the **Projects**
screen. Creating a project makes you a member of its project group: you read it at once, and
your agent can save its reviews there.

## Deleting a project

With the `projects.delete` permission, a trash button shows on each row of the **Projects**
screen. The deletion **cannot be undone** and removes everything that refers to the project:

- its reports, findings and comments;
- the project in the roles of the groups; its project group is deleted;
- the project in the tokens: a token that reached only this project is **revoked**, so a
  pipeline that used it stops.

The audit log keeps the events of the project. A confirmation is asked before the deletion.

## Joining a project

The agent of a developer may ask to join an existing project. Its request shows, waiting for
approval, in **Pending projects** on the **Projects** screen.

A person with the `projects.create` and `users.manage` permissions may approve this request; a
person with `users.manage` may also add the user to the project group.

## Points to watch

- **A pending request expires** after 7 days by default: the agent has to ask again.
- **Approving an access request** to an existing project also needs `users.manage`: creating
  projects never gives access to the others.
- **Deleting a project revokes its dedicated tokens**: warn the teams that use them.
- **A name is normalized**: `My.App` and `my-app` are the same project.
