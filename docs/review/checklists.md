# Checklists

A checklist lists the points that the agent checks **by hand**, one by one, during a review.
It covers what a [rule](rules.md) cannot see: business logic, access rights, flows across
files. Each item says what to look for, for example "every query is filtered by the tenant of
the token".

Like the rules, the checklists are stored in the **database**: every instance of the server
sharing the database uses the same items, and your security teams add or edit them **without
touching the code**.

## Domains

A checklist covers a **domain**. The server ships with default items, copied into the database
at first start, for these domains:

| Domain | Examples of points |
|---|---|
| `*` | Points that apply to every language: information disclosure through output, logs, errors or API responses; secrets kept out of logs (tokens, passwords, URLs with credentials) and masked before storage and in returned excerpts |
| `python`, `java`, `go`, `csharp`, `rust` | Language and framework pitfalls |
| `angular`, `node` | Front end, and TypeScript and JavaScript back end |
| `api` | Validation of OAuth/OIDC tokens, webhooks, sensitive business flows, HTTP desync, CRLF injection, file upload |
| `config` | Kubernetes hardening, RBAC, proxy headers, WAF, encrypted connections to back-end services (LDAPS...), instructions for AI assistants |
| `cicd` | Secrets and script injection in pipelines, runner isolation, security gates |
| `dependencies` | Known vulnerable versions, lockfile integrity, dependency confusion, install-time code |

`get_review_checklist` and the **Checklists** page of the web interface show them in full.

You can create any other domain (lowercase letters, digits, `-` and `_`, 31 characters at most).
Two domains are special and added to **every** review prompt, whatever the language:

- `*` holds the points that apply to every language (like a rule with `languages = ["*"]`);
- `company` holds the requirements of your organization.

## Checklists in review prompts

| Prompt | Embedded checklists |
|---|---|
| `security-review` | The checklists of `language` (`python`, `java`, `go`, `csharp`, `rust`, `angular` and `node` for `typescript` and `javascript`, `config` and `cicd` for pipelines), then `api` |
| `codebase-review` | The checklists of `languages`, then `api`, `config` and `cicd` |
| `api-security-review` | `api` |
| `configuration-review` | `config`, plus `cicd` when the files look like a pipeline |
| `dependency-review` | `dependencies` |

The `*` and `company` checklists are added to every prompt. The other domains, internal ones included, are
named at the end of the checklists: the agent fetches with `get_review_checklist` those that
apply to the code it reviews. Without a prompt, the agent calls `list_checklists` then
`get_review_checklist` itself (see [How a review works](index.md#how-the-system-picks-the-checklists)).

The agent then declares the outcome of each item it walked through in `save_security_report`;
an item of a domain it used but did not report is stored as `not_covered`
([review coverage](prompts-tools.md#review-coverage)).

## Creating a checklist item

An item has these fields:

| Field | Content |
|---|---|
| `domain` | Domain of the item (`*`, `company`, `python`, or a new domain) |
| `id` | Unique identifier, in capitals with at least one dash, for example `ACME-CL-01` (50 characters at most). The agents cite it in their reports: never reuse it for another point. It must be unique across all domains, and a new item cannot use the prefix of a default family (`PY`, `GEN`, `API`...: [reserved](rules.md#rules-command)) |
| `title` | Short name of the point (300 characters at most) |
| `what_to_look_for` | What the agent must check (5000 characters at most) |
| `cwe` | Optional, for example `CWE-639` |

### From the web interface

The **Checklists** page (`rules.read` permission) lists every item, with search, sort and
filters by domain and origin. Users with `rules.manage` create, edit or delete the custom items. A default
item can be edited, but not deleted; an edited default item is no longer updated by new
versions of the server. Every change is applied at once and included in the review prompts.

### With a TOML pack

The `[[checklist]]` entries of a [TOML pack](rules.md#pack-format) add or replace items by
identifier:

```toml
[[checklist]]
domain = "company"                           # "company" and "*" are added to EVERY review prompt
id = "ACME-CL-01"
title = "Tenant isolation"
what_to_look_for = "Every query is filtered by the tenant of the token."
cwe = "CWE-639"
```

```bash
security-review-controller rules import examples/rules/company.toml   # import a pack
security-review-controller rules delete ACME-CL-01                    # delete a custom item
```

The pack is imported with `security-review-controller rules import` or with the **Import** button
of the **Checklists** page, which also exports the custom or edited items
(`security-review-checklists.toml`); see
[import and export](rules.md#import-and-export-in-the-web-interface).

### With the REST API

| Method | Route | Role |
|---|---|---|
| `GET` | `/api/v1/checklists` | Lists the stored items (origin, edited or not) and the loading errors |
| `POST` | `/api/v1/checklists` | Creates an item: body `{"domain", "id", "title", "what_to_look_for", "cwe"}` |
| `PUT` | `/api/v1/checklists/{domain}/{id}` | Edits an item |
| `DELETE` | `/api/v1/checklists/{domain}/{id}` | Deletes a custom item |

`GET` needs the `rules.read` permission, the other routes `rules.manage`.

!!! warning "Trusted content"
    The text of the items is read by the agents during every review: like the rules, it is
    **trusted** content that only administrators change. Version your packs in a reviewed
    repository.
