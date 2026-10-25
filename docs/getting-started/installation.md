# Installation

The **Security Review MCP** application is a single package, `security-review-mcp` (with a
`postgres` extra for the PostgreSQL driver). It installs two commands: `security-review-mcp`,
the MCP server used by the agents, and `security-review-controller`, the controller (web
interface, REST API, administration). Their roles: see
[Two services, two roles](../index.md#two-services-two-roles).

The recommended case is the **shared mode (HTTP)**, deployed on a server or in containers with
PostgreSQL; the [local mode (stdio)](stdio.md) is kept for trials on a single workstation.

## From PyPI

```bash
uv venv && source .venv/bin/activate   # uv pip installs into this virtual environment
uv pip install security-review-mcp
uv pip install "security-review-mcp[postgres]"   # with the PostgreSQL driver
```

The PostgreSQL server itself is deployed with [Docker Compose](../advanced/docker.md#docker-compose-with-postgresql)
or [Kubernetes](../advanced/kubernetes.md#deployment).

## Docker Image

To run the server in containers, pull the published image (the `-pg` variant includes the PostgreSQL driver):

```bash
docker pull ghcr.io/cyr-ius/security-review-mcp:latest-pg    # or docker.io/cyrius44/security-review-mcp
```

The same image launches both the MCP server and the controller; see [Docker](../advanced/docker.md#published-images).

**Next step:** [Deploy the server](deploy.md).
