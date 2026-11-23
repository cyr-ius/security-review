# Security policy of Security Review

Security Review is a security tool: a vulnerability in it is treated as a blocking bug.

## Supported versions

Security fixes are made on the latest released version (the latest `vX.Y.Z` tag, published on
PyPI and as Docker images). Upgrade to it before reporting a problem found on an older one.

## Reporting a vulnerability

Do **not** open a public issue, pull request or discussion for a vulnerability.

Report it privately with GitHub's
[private vulnerability reporting](https://github.com/cyr-ius/security-review/security/advisories/new)
(**Security** tab of the repository, **Report a vulnerability**). Include:

- the affected version or commit and how it is deployed (stdio, HTTP MCP server, controller,
  Docker, Kubernetes);
- the steps to reproduce, or a proof of concept;
- the impact you expect (data read or changed, authentication bypassed, code executed...).

Never include a real token, password or private key: use test values.

## What happens next

- An acknowledgement within 7 days.
- An assessment, then a fix and a release, coordinated with you. A GitHub security advisory
  (with a CVE when relevant) is published with the release, crediting you unless you ask
  otherwise.
- Please keep the vulnerability private until the advisory is published.

## Vulnerable dependencies

Dependabot checks the Python, npm and GitHub Actions dependencies every week, and the project
reviews its own dependencies with `scan_dependencies`. When a public advisory affects a
dependency of a released version, the maintainers of the repository are responsible for it,
counted from the day the advisory or its Dependabot alert is published:

| Severity | Maximum delay to fix and release |
|---|---|
| critical | 7 days |
| high | 30 days |
| medium, low | next regular release |

When no fixed version exists, or the fix cannot be released within this delay, the finding is
not left open silently: a person decides a risk acceptance in the web interface, with a reason
and a short expiry date (at most the delay above), and a mitigation when one exists. When the
delay or the acceptance expires, the finding counts as open again and blocks the gate: no
version is released until it is fixed or a new decision is recorded.

## Scope

In scope: the Python package (MCP server, controller, CLI, `security-review-ci`), the web
interface, the Docker image and the deployment examples of this repository.

Out of scope: findings of the scan rules themselves (a false positive or a missed pattern is a
regular issue), vulnerabilities of third-party dependencies already published in a public
advisory (Dependabot proposes their updates), and deployments that disable the documented
protections (for example `SECREVIEW_ALLOW_UNAUTHENTICATED` on an exposed server).

The security guarantees and limits of the tool are described in the
[security reference](https://cyr-ius.github.io/security-review/reference/security/).
