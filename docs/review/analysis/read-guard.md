# Read guard for AI assistants

The code that an assistant reads may try to take control of it: text hidden with invisible
characters, comments addressed to the assistant, requests to dismiss a finding. The MCP server
only sees what the agent sends it, after the assistant has read the files with its own tools.
To check a file **before** the assistant reads it, run the read guard on the host side: the
`guard` command of the [pipeline client](../../advanced/architecture/ci.md) `security-review-ci`,
called by a hook of the coding agent before each tool call.

## What it does

Before the tool call, `security-review-ci guard` reads the hook event on its standard input,
finds the files that the call reads and scans them locally with the
[`AI-*` rules](../rules.md#default-rules-by-platform) (no network access, no controller, no
token), then:

| Result | Decision | What the assistant gets |
|---|---|---|
| Nothing found | The call goes on | The file |
| Hidden text (`AI-001` to `AI-003`: Unicode tags, bidirectional controls, zero-width characters) | **Refused** (`deny`) | The matched lines only, hidden characters shown as `<U+XXXX>`, and the instruction to report a possible prompt injection |
| Text addressed to an assistant only (`AI-004`, `AI-005`) | **The person is asked** (`ask`) | The file once the person accepts; the matched lines and the warning in any case |

The files read by a call are:

- the `file_path` or `path` argument of a read tool (`Read` of Claude Code, `view` of Copilot
  CLI);
- the existing files given to a command that prints them (`cat`, `head`, `tail`, `less`,
  `more`, `nl`, `bat`, `sed`, `awk`, `grep`, `egrep`, `rg`) in the command line of a shell tool
  (`Bash`), at most 20; `sed -i`, which edits the file, is not checked, so that the file can
  be cleaned.

The file is never modified: the text is the evidence of the attack, and the person decides.
A `secreview:ignore` marker does not silence the guard: it is part of the untrusted file. Each
excerpt keeps 60 characters around the match, so that the rest of the line (a secret, for
example) does not reach the assistant. Files larger than 2 MiB are not scanned, and an error of
the guard (unreadable event, unreadable file) lets the call go on with exit code `0`: it is a
safety net, not a gate (the [gate](../gate.md) stays in the pipeline).

## Coding agents

`--agent` gives the format of the hook event and of the decision:

| `--agent` | Event read | Decision written |
|---|---|---|
| `claude` (default) | `tool_name`, `tool_input` of Claude Code | `hookSpecificOutput` with `permissionDecision` `deny` or `ask` |
| `copilot` | `toolName`, `toolArgs` of Copilot CLI (`tool_name` and `tool_input` are also accepted) | `permissionDecision` `deny` or `ask` |
| `codex` | `tool_name`, `tool_input` of Codex CLI, which reads files with its shell | `hookSpecificOutput` with `permissionDecision` `deny`; for text addressed to an assistant, `additionalContext` only: Codex cannot ask the person, so the read goes on with the warning |

## Installation

1. Install the client on the workstation: `uv tool install security-review-ci` (see
   [Installation](../../advanced/architecture/ci.md#installation)).
2. For Claude Code, merge `examples/agent-hooks/settings.json` into `.claude/settings.json` of
   the repository (or `~/.claude/settings.json` for every project):

    ```json
    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Read|Bash",
            "hooks": [
              {
                "type": "command",
                "command": "security-review-ci guard --agent claude",
                "timeout": 30
              }
            ]
          }
        ]
      }
    }
    ```

For Copilot CLI and Codex CLI, declare `security-review-ci guard --agent copilot` or
`--agent codex` as a pre-tool-use hook in the configuration of the agent; the repository only
ships the example of Claude Code.

## Limits

- Only the read tools and the reading commands of a shell tool are checked: a search tool, a
  file read by a script, a pipe from another command or a web page does not go through the
  guard.
- The rules are a copy of the default `AI-*` rules: a rule changed by an administrator in the
  web interface does not apply to the guard, which runs without the controller.
- The rules are a first pass: text addressed to an assistant can be worded in endless ways. The
  [untrusted data rule](../prompts-tools.md#status-of-a-finding) of the review prompts and
  the fact that [an agent never closes a finding](../../reference/security.md#security-of-the-server-itself)
  remain the main protections.
