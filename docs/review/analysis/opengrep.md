# OpenGrep engine

The Controller server runs OpenGrep as a second static-analysis engine during a
whole-codebase scan (`security-review-ci scan-code`). The built-in scanner remains enabled and
unchanged. Fragment scans (`scan_code`) do not start an external process.

## Docker image

The [`-opengrep` image](../../advanced/deployment/docker.md#published-images) (`latest-opengrep`,
`X.Y.Z-opengrep`) ships a pinned OpenGrep release in `/usr/local/bin/opengrep`, checked against its
SHA-256 digest at build time (`opengrep` target of the `Dockerfile`) and unpacked there, read-only,
so that a scan never extracts it: use it for the Controller server. The default image does not contain OpenGrep and sets `SECREVIEW_OPENGREP_ENABLED=false`. With an installation from
the PyPI package, install OpenGrep yourself and set `SECREVIEW_OPENGREP_BINARY` if it is not in
`/usr/local/bin`.

## Configuration

The engine is enabled by default (except in the default Docker image, without OpenGrep), but it only runs once at least one YAML rule is installed:
without any rule, `scan-code` runs the built-in scanner only. Set
`SECREVIEW_OPENGREP_ENABLED=false` to turn it off. Environment variables of the Controller server:

| Variable | Default | Description |
| --- | --- | --- |
| `SECREVIEW_OPENGREP_ENABLED` | `true` | Enable OpenGrep for whole-codebase scans |
| `SECREVIEW_OPENGREP_BINARY` | `/usr/local/bin/opengrep` | OpenGrep executable |
| `SECREVIEW_OPENGREP_RULES_DIR` | `/var/lib/secreview/rules/opengrep` | Directory containing OpenGrep YAML rule packs |
| `SECREVIEW_OPENGREP_TIMEOUT_SECONDS` | `600` | Maximum duration of one OpenGrep scan |
| `SECREVIEW_OPENGREP_MAX_CONCURRENT_SCANS` | `1` | OpenGrep scans running at the same time in one Controller server process; a scan beyond is refused with `503` and `Retry-After` |
| `SECREVIEW_OPENGREP_JOBS` | `2` | Cores used by one OpenGrep scan (`--jobs`) |
| `SECREVIEW_OPENGREP_MAX_MEMORY_MB` | `2048` | Memory in MiB of one OpenGrep scan (`--max-memory`, `0`: no limit) |

Install rule packs in the configured directory, for example by mounting an administrator-managed
directory at `/var/lib/secreview/rules/opengrep`. Rule packs are deliberately not downloaded
automatically and are not bundled into the application image. The directory must contain at
least one `.yml` or `.yaml` file.

When enabled, the controller writes the source files already received from the CI client into a
private temporary directory, invokes OpenGrep without a shell, parses its JSON output, and removes
the workspace. Findings are normalized into the existing report format and are included in the
same report and SARIF export as built-in findings. OpenGrep rule IDs are prefixed with
`OPENGREP:`.

## Operational security

- Run the controller as the existing unprivileged `secreview` user.
- Keep rule packs administrator-controlled; treat rule updates as security-sensitive changes.
- Use container-level CPU, memory and process limits for the controller. The scan timeout, the
  number of concurrent scans and the cores and memory of a scan are enforced by the adapter (on
  timeout, OpenGrep and its workers are killed); they are not a substitute for container
  resource limits.
- If OpenGrep is busy with other scans or unavailable, `scan-code` gets a `503` answer: retry
  later.
- Do not mount application secrets or unrelated host paths into the scan workspace.
- The controller does not execute scanned source files. It does write the received source payload
  to a temporary directory for OpenGrep to read.
- If rules are installed but the OpenGrep binary is missing, or the scan fails, the code scan
  fails rather than silently reporting a successful built-in-only scan.

## Managing rules from the web interface

The Controller exposes an authenticated rule-management page at `/ui/opengrep-rules`.
Users with `rules.read` can inspect the YAML files in `SECREVIEW_OPENGREP_RULES_DIR`;
users with `rules.manage` can create, edit, validate and delete them. Each managed YAML file
contains exactly one rule, and its rule id must match the file identifier. Writes are validated
with `opengrep validate <file>` before an atomic replacement. The Controller does not download
rule packs or follow remote rule sources on behalf of the administrator.
