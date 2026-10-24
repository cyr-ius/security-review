# Installation

L'application **Security Review MCP** est composé d'un seul paquet nommé `security-review-mcp`.
Ce paquet possède une variante intégrant un connecteur `postgres`

Une fois le paquet installé, deux binaires sont disponible:
 - `security-review-mcp` qui est le serveur MCP utilisé par les agents
 - `security-review-controller` qui est un serveur hébergeant les interface web, API REST, base et administration).
 Voir [deux services, deux rôles](../index.md#deux-services-deux-roles).

### Serveur MCP

Lors du démarrage du serveur MCP, une base de donnée SQLite est crée pour stocker les rapports
Avec la variante `postgres` vous pouvez indiquer une base de donnée PosgresSQL.

Bien que vous puissiez installer le serveur MCP de façon **autonome** sur un poste de dévellopeur. Voir [Mode autonome](../advanced/stdio.md)
Nous recommandons son déploiement sur un serveur ou dans un container associé à une base de donnée PosgresSQL.

Vous bénéficiez ainsi d'aucune adhérence à la technologie du MCP. Il suffit de paramétrer votre IDE sur le serveur MCP
en Http. Voir [Transport HTTP](../getting-started/host.md)

Pour des raisons de sécurité, il est nécessaire de soumettre un jeton d'authentification afin d'échanger avec celui-ci.
En l'absence de jeton, le serveur MCP informe votre agent IA sur la démarche à suivre pour obtenir un jeton (enrollment).

### Serveur Controller

Si vous exécutez le binaire `security-review-controller`, celui-ci va démarré un serveur d'application permettant de vous
connectez via un interface web à la base de donnée.

Grâce à cette application, vous pourrez :
  - Consulter les rapports émit par les agents de vos dévellopeurs
  - Proposer des nouvelles règles, checklists
  - Partager vos normes de dévellopements auprès des agents
  - Suivre les vulnérabilités, faire des revues de sécurité et acceptation de risque.

Le serveur Controller prend aussi en charge la fonction "scan-code" qui permet de scruter l'ensemble d'un repository
et bien plus encore...

## Mise en service rapide

Consulter l'étape suivante [Mette les serveurs MCP et Controller en service](deploy.md).

## Depuis PyPI

```bash
uv pip install security-review-mcp
uv pip install "security-review-mcp[postgres]"   # avec le pilote PostgreSQL
```

## Image Docker

Pour faire tourner le serveur dans des conteneurs, récupérez l'image publiée (la variante -pg contient le pilote PostgreSQL)

```bash
docker pull ghcr.io/cyr-ius/security-review-mcp:latest-pg    # or docker.io/cyrius44/security-review-mcp
```

La même image lance le serveur MCP et le contrôleur : voir [Docker](../advanced/docker.md).

**Étape suivante :** [mettre le serveur en service](deploy.md).
