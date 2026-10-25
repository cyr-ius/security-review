# Installation

L'application **Security Review MCP** est un seul paquet PyPI, `security-review` (avec un extra
`postgres` pour le pilote PostgreSQL). Il installe deux commandes : `security-review-mcp`, le
serveur MCP utilisé par les agents, et `security-review-controller`, le contrôleur (interface
web, API REST, administration). Leurs rôles : voir
[deux services, deux rôles](../index.md#deux-services-deux-roles).

Le cas recommandé est le **mode partagé (HTTP)**, déployé sur un serveur ou dans des conteneurs
avec PostgreSQL ; le [mode local (stdio)](stdio.md) est réservé aux essais sur un seul poste.

## Depuis PyPI

```bash
uv venv && source .venv/bin/activate   # uv pip installe dans cet environnement virtuel
uv pip install security-review
uv pip install "security-review[postgres]"   # avec le pilote PostgreSQL
```

!!! note "Anciennement `security-review-mcp`"
    Jusqu'à la version 2.0.0, le paquet était publié sur PyPI sous le nom `security-review-mcp`.
    Les deux paquets installent les mêmes commandes et le même module Python : désinstallez
    d'abord l'ancien (`uv pip uninstall security-review-mcp`), puis installez `security-review`.
    Les commandes, les paramètres et la base restent les mêmes.

Le serveur PostgreSQL lui-même se déploie avec [Docker Compose](../advanced/docker.md#docker-compose-avec-postgresql)
ou [Kubernetes](../advanced/kubernetes.md#deploiement).

## Image Docker

Pour faire tourner le serveur dans des conteneurs, récupérez l'image publiée (la variante -pg contient le pilote PostgreSQL)

```bash
docker pull ghcr.io/cyr-ius/security-review-mcp:latest-pg    # or docker.io/cyrius44/security-review-mcp
```

La même image lance le serveur MCP et le contrôleur : voir [Docker](../advanced/docker.md#images-publiees).

**Étape suivante :** [mettre le serveur en service](deploy.md).
