# Installation

Le paquet installe les deux commandes du produit, sur le serveur qui va les héberger :
`security-review-mcp` (serveur MCP, utilisé par les agents) et `security-review-controller`
(contrôleur : interface web, API REST, base et administration). Voir
[deux services, deux rôles](../index.md#deux-services-deux-roles).

Python 3.14 ou plus. Le projet cible le SDK `mcp` **2.x** (`MCPServer`) ; avec un miroir interne
limité à `mcp` 1.x, l'import `mcp.server.mcpserver` ne fonctionnera pas.

## Depuis PyPI

```bash
pip install security-review-mcp
pip install "security-review-mcp[postgres]"   # avec le pilote PostgreSQL
```

Le paquet publié contient l'interface web déjà compilée.

## Image Docker

Pour faire tourner le serveur dans des conteneurs, récupérez l'image publiée (la variante `-pg`
contient le pilote PostgreSQL), ou construisez-la depuis le dépôt :

```bash
docker pull ghcr.io/cyr-ius/security-review-mcp:latest-pg    # or docker.io/cyrius44/security-review-mcp
docker build -t security-review-mcp:pg --build-arg EXTRAS=postgres .
```

La même image lance le serveur MCP et le contrôleur : voir [Docker](../advanced/docker.md).

## Autres cas

Installation depuis les sources ou sans accès Internet : voir [Installation : autres cas](../advanced/installation.md).

**Étape suivante :** [mettre le serveur en service](deploy.md).
