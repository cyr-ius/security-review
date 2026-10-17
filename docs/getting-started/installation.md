# Installation

The package installs the two commands of the product, on the server that will host them:
`security-review-mcp` (MCP server, used by the agents) and `security-review-controller`
(controller: web interface, REST API, database and administration). See
[two services, two roles](../index.md#two-services-two-roles).

Python 3.14 or later. The project targets the `mcp` SDK **2.x** (`MCPServer`); with an internal
mirror limited to `mcp` 1.x, the `mcp.server.mcpserver` import will not work.

## From PyPI

```bash
pip install security-review-mcp
pip install "security-review-mcp[postgres]"   # with the PostgreSQL driver
```

The published package contains the web interface already built.

## Docker image

To run the server in containers, build the image from the repository (the `postgres` extra
adds the PostgreSQL driver):

```bash
docker build -t security-review-mcp:pg --build-arg EXTRAS=postgres .
```

The same image runs the MCP server and the controller: see [Docker](../advanced/docker.md).

## Other cases

Installation from the sources, without Internet access, or upgrade from version 1.x: see
[Installation: other cases](../advanced/installation.md).

**Next step:** [deploy the server](deploy.md).
