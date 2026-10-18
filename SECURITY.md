# Security policy of security-review-mcp

`security-review-mcp` is a security tool: a vulnerability in it is treated as a blocking bug.

## Supported versions

Security fixes are made on the latest released version (the latest `vX.Y.Z` tag, published on
PyPI and as Docker images). Upgrade to it before reporting a problem found on an older one.

## Reporting a vulnerability

Do **not** open a public issue, pull request or discussion for a vulnerability.

Report it privately with GitHub's
[private vulnerability reporting](https://github.com/cyr-ius/security-review-mcp/security/advisories/new)
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

## Scope

In scope: the Python package (MCP server, controller, CLI, `security-review-ci`), the web
interface, the Docker image and the deployment examples of this repository.

Out of scope: findings of the scan rules themselves (a false positive or a missed pattern is a
regular issue), vulnerabilities of third-party dependencies already published in a public
advisory (Dependabot proposes their updates), and deployments that disable the documented
protections (for example `SECREVIEW_ALLOW_UNAUTHENTICATED` on an exposed server).

The security guarantees and limits of the tool are described in the
[security reference](https://cyr-ius.github.io/security-review-mcp/reference/security/).
