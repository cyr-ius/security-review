# OpenGrep engine

The controller can optionally run OpenGrep as a second static-analysis engine during a
whole-codebase scan (`security-review-ci scan-code`). The built-in scanner remains enabled and
unchanged. Fragment scans (`scan_code`) do not start an external process.

## Build

OpenGrep is optional in the Docker image. Build with a pinned upstream release:

```sh
docker build --build-arg OPENGREP_VERSION=v1.16.0 -t security-review-mcp .
```

Choose and validate the release supported by your deployment before building. When the build
argument is empty, the image does not contain OpenGrep and the optional engine remains disabled.

## Enable

Set the following controller environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `SECREVIEW_OPENGREP_ENABLED` | `false` | Enable OpenGrep for whole-codebase scans |
| `SECREVIEW_OPENGREP_BINARY` | `/usr/local/bin/opengrep` | OpenGrep executable |
| `SECREVIEW_OPENGREP_RULES_DIR` | `/var/lib/secreview/rules/opengrep` | Directory containing OpenGrep YAML rule packs |
| `SECREVIEW_OPENGREP_TIMEOUT_SECONDS` | `600` | Maximum duration of one OpenGrep scan |

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
- Use container-level CPU, memory and process limits for the controller. The scan timeout is
  enforced by the adapter; it is not a substitute for container resource limits.
- Do not mount application secrets or unrelated host paths into the scan workspace.
- The controller does not execute scanned source files. It does write the received source payload
  to a temporary directory for OpenGrep to read.
- If OpenGrep is enabled but the binary or rule pack is missing, or the scan fails, the code scan
  fails rather than silently reporting a successful built-in-only scan.
