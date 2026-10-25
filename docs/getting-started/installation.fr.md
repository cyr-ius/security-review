# Installation

L'application **Security Review MCP** est un seul paquet, `security-review-mcp` (avec un extra
`postgres` pour le pilote PostgreSQL). Il installe deux commandes : `security-review-mcp`, le
serveur MCP utilisé par les agents, et `security-review-controller`, le contrôleur (interface
web, API REST, administration). Leurs rôles : voir
[deux services, deux rôles](../index.md#deux-services-deux-roles).

Le cas recommandé est le **mode partagé (HTTP)**, déployé sur un serveur ou dans des conteneurs
avec PostgreSQL ; le [mode local (stdio)](stdio.md) est réservé aux essais sur un seul poste.

## Depuis PyPI

```bash
uv venv && source .venv/bin/activate   # uv pip installe dans cet environnement virtuel
uv pip install security-review-mcp
uv pip install "security-review-mcp[postgres]"   # avec le pilote PostgreSQL
```

Le serveur PostgreSQL lui-même se déploie avec [Docker Compose](../advanced/docker.md#docker-compose-avec-postgresql)
ou [Kubernetes](../advanced/kubernetes.md#deploiement).

## Image Docker

Pour faire tourner le serveur dans des conteneurs, récupérez l'image publiée (la variante -pg contient le pilote PostgreSQL)

```bash
docker pull ghcr.io/cyr-ius/security-review-mcp:latest-pg    # or docker.io/cyrius44/security-review-mcp
```

La même image lance le serveur MCP et le contrôleur : voir [Docker](../advanced/docker.md#images-publiees).

**Étape suivante :** [mettre le serveur en service](deploy.md).
