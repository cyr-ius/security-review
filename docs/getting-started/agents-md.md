# The AGENTS.md file

The agent reads `AGENTS.md`, at the root of the repository, at the start of every session. This
is where you ask it to run the security reviews and to follow the standards of your
organization.

!!! danger "Without this file, no automatic review"
    The agent does not start the prompts by itself. Without instructions, it does not always
    think of the review, and the developer has to ask for it before each commit.

## What it contains

| Section | Why |
|---|---|
| **The project name** | Every report lands in the same place: the gate, the trends and the posture work on this name. Without it, each agent makes one up |
| **Before writing code** | The agent gets the [development standards](../review/standards.md) from the server |
| **Before finishing a task** | The agent runs the security review and saves the report |
| **What is specific to the repository** | Test commands, structure, local exceptions |

## Example

Copy this file to the root of the repository and only replace `<project-name>`. It suits every
language: the agent picks the standards and the checklists from the files it changes.

```markdown
# Instructions for AI agents

## Project
- Project name for the `security-review` MCP server: `<project-name>`.
- Always use this name in `save_security_report`.

## Before writing code
- Call `get_development_standards` with the files you are going to change
  (or the technologies of the change).
- Apply these standards. Report any deviation with its reason.
- Do not copy the standards here: the server provides them up to date.

## Before saying a task is done
1. Call `scan_code` on each changed file. Check each lead in the code.
2. Call `list_checklists`, then `get_review_checklist` for:
   - the language of each changed file and `*`;
   - `api` if routes or endpoints change;
   - `config` if a Dockerfile, a YAML or configuration file changes;
   - `cicd` if a CI/CD pipeline changes.
3. If a manifest, a lockfile or an SBOM changes, call `scan_dependencies` on each one
   and walk through the `dependencies` checklist.
4. Call `save_security_report` once: project `<project-name>`,
   `review_type` `security-review`, branch and commit, `checklist_results` and `scan_rules` filled in.
5. Fix the `critical` and `high` findings before finishing.
6. Never change a status. Use `propose_finding_status` with a reason.

If the `security-review` server does not answer, say so. Never claim the review was done.

## Specific to this repository
- Add your test commands and local exceptions here.
- In case of conflict with the standards of the server, this file wins.
```

## Other hosts

Some hosts read another file: `CLAUDE.md` for Claude Code, `.github/copilot-instructions.md`
for GitHub Copilot. Make them point to `AGENTS.md` to keep a single source. For example,
`CLAUDE.md`:

```markdown
The project instructions are in `AGENTS.md`. Follow them in full.

@AGENTS.md
```

## The standards stay in the server

Do not copy the standards into `AGENTS.md`: an administrator writes them once on the
**Standards** page, and an update applies at once to every agent. A standard can never weaken
security: in case of conflict, the agent keeps the safe behavior.

**Further reading:** [development standards](../review/standards.md),
[how a review works](../review/index.md).
