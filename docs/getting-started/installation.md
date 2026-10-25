# Installation

The **Security Review MCP** application is a single PyPI package, `security-review` (with a
`postgres` extra for the PostgreSQL driver). It installs two commands: `security-review-mcp`,
the MCP server used by the agents, and `security-review-controller`, the controller (web
interface, REST API, administration). Their roles: see
[Two services, two roles](../index.md#two-services-two-roles).

The recommended case is the **shared mode (HTTP)**, deployed on a server or in containers with
PostgreSQL; the [local mode (stdio)](stdio.md) is kept for trials on a single workstation.

## From PyPI

```bash
uv venv && source .venv/bin/activate   # uv pip installs into this virtual environment
uv pip install security-review
uv pip install "security-review[postgres]"   # with the PostgreSQL driver
```

!!! note "Formerly `security-review-mcp`"
    Up to version 2.0.0, the package was published on PyPI as `security-review-mcp`. Both
    packages install the same commands and the same Python module: uninstall the old one first
    (`uv pip uninstall security-review-mcp`), then install `security-review`. The commands,
    the settings and the database stay the same.

The PostgreSQL server itself is deployed with [Docker Compose](../advanced/docker.md#docker-compose-with-postgresql)
or [Kubernetes](../advanced/kubernetes.md#deployment).

## Docker Image

To run the server in containers, pull the published image (the `-pg` variant includes the PostgreSQL driver):

```bash
docker pull ghcr.io/cyr-ius/security-review-mcp:latest-pg    # or docker.io/cyrius44/security-review-mcp
```

The same image launches both the MCP server and the controller; see [Docker](../advanced/docker.md#published-images).

**Next step:** [Deploy the server](deploy.md).
