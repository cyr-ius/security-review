# Read guard for AI assistants

The code that an assistant reads may try to take control of it: text hidden with invisible
characters, comments addressed to the assistant, requests to dismiss a finding. The MCP server
only sees what the agent sends it, after the assistant has read the files with its own tools.
To check a file **before** the assistant reads it, run the read guard on the host side: a
[Claude Code hook](https://code.claude.com/docs/en/hooks) shipped as an example in
`examples/agent-hooks/`.

## What it does

Before each `Read` of the assistant, the hook scans the file locally with the
[`AI-*` rules](../usage/rules.md#default-rules-by-platform) of the package (no network access, no
controller), then:

| Result | Decision | What the assistant gets |
|---|---|---|
| Nothing found | The read goes on | The file |
| Hidden text (`AI-001` to `AI-003`: Unicode tags, bidirectional controls, zero-width characters) | **Refused** (`deny`) | The matched lines only, hidden characters shown as `<U+XXXX>`, and the instruction to report a possible prompt injection |
| Text addressed to an assistant only (`AI-004`, `AI-005`) | **The person is asked** (`ask`) | The file once the person accepts; the matched lines and the warning in any case |

The file is never modified: the text is the evidence of the attack, and the person decides.
A `secreview:ignore` marker does not silence the guard: it is part of the untrusted file.
Files larger than 2 MiB are not scanned, and an error of the hook lets the read go on (a safety
net, not a gate: the [gate](../usage/gate.md) stays in the pipeline).

## Installation

1. Copy `examples/agent-hooks/read_guard.py` into `.claude/hooks/` of the repository (or of
   `~/.claude/` for every project).
2. Merge `examples/agent-hooks/settings.json` into `.claude/settings.json`:

    ```json
    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Read",
            "hooks": [
              {
                "type": "command",
                "command": "uv run --quiet --script \"$CLAUDE_PROJECT_DIR/.claude/hooks/read_guard.py\"",
                "timeout": 30
              }
            ]
          }
        ]
      }
    }
    ```

The script declares its dependency (`security-review`, version 3.0.0 or later) in its
header: `uv run --script` installs it in a cached environment. Without `uv`, or offline, run it
with the Python of an environment where the package is installed (`"command": "python3
.claude/hooks/read_guard.py"`).

## Limits

- Only the `Read` tool is checked: a file shown by a shell command (`cat`) or a search tool, or
  a web page, does not go through the hook.
- The rules are a first pass: text addressed to an assistant can be worded in endless ways. The
  [untrusted data rule](../usage/prompts-tools.md#status-of-a-finding) of the review prompts and
  the fact that [an agent never closes a finding](../reference/security.md#security-of-the-server-itself)
  remain the main protections.
- The example targets Claude Code. Another host with a hook before reading a file can reuse
  `check()`: it takes a path and returns the decision.
