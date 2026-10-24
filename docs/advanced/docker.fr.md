# Docker

## Images publiées

Chaque version est publiée pour `linux/amd64` et `linux/arm64` sur GitHub Container Registry et
Docker Hub, en deux variantes : SQLite seul, et `-pg` avec le pilote PostgreSQL.

```bash
docker pull ghcr.io/cyr-ius/security-review-mcp:latest-pg   # or docker.io/cyrius44/security-review-mcp
```

| Tag | Contenu |
|---|---|
| `X.Y.Z`, `X.Y`, `X`, `latest` | Version `X.Y.Z` (la dernière version stable pour `latest`) |
| `X.Y.Z-pg`, `X.Y-pg`, `X-pg`, `latest-pg` | Idem, avec le pilote PostgreSQL |
| `X.Y.ZrcN` (`a`, `b`, `rc`) | Préversion : ce tag seulement, jamais `latest` |

Les images portent un SBOM et une attestation de provenance (`docker buildx imagetools inspect --format '{{ json .Provenance }}' IMAGE`).
Dans les exemples de cette page, remplacez `security-review-mcp` et `security-review-mcp:pg` par
l'image publiée.

## Docker Compose avec PostgreSQL

Le fichier `docker-compose.yml` à la racine du dépôt démarre les deux processus avec une base
PostgreSQL :

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
docker compose up -d --build
docker compose exec controller security-review-controller user reset-password admin   # mot de passe admin initial
```

| Service | Rôle | Écoute |
|---|---|---|
| `db` | PostgreSQL, joignable seulement sur le réseau interne `backend` | — |
| `migrate` | `security-review-controller db upgrade`, puis s'arrête | — |
| `controller` | API REST et interface web (`/ui/`) | `127.0.0.1:8080` (`DOCKER_PUBLISH_ADDRESS`, `DOCKER_CONTROLLER_PORT`) |
| `mcp` | Serveur MCP (`/mcp`) et enrôlement public | `127.0.0.1:8000` (`DOCKER_PUBLISH_ADDRESS`, `DOCKER_MCP_PORT`) |

- L'image est construite avec l'extra `postgres` (`security-review-mcp:pg`). `migrate` attend
  que la base soit prête (`pg_isready`) ; `controller` et `mcp` attendent que `migrate` ait
  réussi. Seul `migrate` modifie le schéma (`SECREVIEW_DB_AUTO_UPGRADE=false` ailleurs).
- `POSTGRES_PASSWORD` est obligatoire et lu depuis `.env` (jamais commité). Il est inséré tel
  quel dans `SECREVIEW_DATABASE_URL` : utilisez des caractères hexadécimaux, ou encodez les
  caractères spéciaux (`@`, `:`, `/`...).
- Les ports ne sont publiés que sur `127.0.0.1` par défaut. Pour les exposer, activez le
  [TLS intégré](http.md) ou placez-les derrière un reverse proxy, puis indiquez l'adresse de
  l'hôte à utiliser dans `.env` : `DOCKER_PUBLISH_ADDRESS=192.168.1.10` (une interface) ou
  `DOCKER_PUBLISH_ADDRESS=0.0.0.0` (toutes les interfaces), et les ports de l'hôte dans
  `DOCKER_MCP_PORT` et `DOCKER_CONTROLLER_PORT`. Ces variables ne servent qu'à Compose : dans les
  conteneurs, les deux serveurs écoutent sur 8000. Le contrôleur n'expose aucune route
  d'écriture sans jeton : il peut rester interne.
- Les variables de `.env` ne servent qu'à Compose : ajoutez-les sous `environment` pour
  qu'elles atteignent les conteneurs (par exemple `SECREVIEW_TLS_CERTFILE` et
  `SECREVIEW_TLS_KEYFILE`, avec les fichiers du certificat montés en lecture seule, voir
  [Autorité de certification](http.md#autorite-de-certification)).
- La base d'avis de vulnérabilités est **vide** au premier démarrage : l'analyse de dépendances
  répond alors qu'aucune base n'est chargée. Pour que le contrôleur la télécharge au démarrage
  puis toutes les 24 h, ajoutez `SECREVIEW_OSV_AUTO_UPDATE=true` dans `.env` (et, si besoin,
  `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY` et `NO_PROXY`), que le fichier Compose transmet au seul
  contrôleur, puis `docker compose up -d`. Suivez l'import avec `docker compose logs -f
  controller` ou dans les paramètres de l'interface web. Sans accès Internet, importez une
  archive avec `advisories import` (voir [Dépendances](dependencies.md)).
- Les conteneurs tournent en système de fichiers en lecture seule, sans capacité Linux. Le
  volume `secreview-pg` contient les rapports, les comptes de l'interface web et les jetons :
  sauvegardez-le.
- Le service `db` utilise PostgreSQL 18, dont l'image range les données dans un répertoire par
  version majeure : le volume `secreview-pg` est monté sur `/var/lib/postgresql` (et non
  `/var/lib/postgresql/data`). Un volume créé par PostgreSQL 17 ne démarre pas avec cette image
  (`Error: in 18+, these Docker images are configured to store database data in a format...`) :
  voir [Mise à niveau de PostgreSQL](#mise-a-niveau-de-postgresql).

Pour ajouter le TLS ou des règles internes, complétez `environment` et `volumes` du service
concerné. Les commandes CLI s'exécutent dans le conteneur du contrôleur :

```bash
docker compose exec controller security-review-controller token list
```

## Mise à niveau de PostgreSQL

Une version majeure de PostgreSQL ne lit pas les fichiers de données de la précédente. Pour
passer un volume `secreview-pg` de PostgreSQL 17 à 18, exportez la base avec l'ancienne image,
recréez le volume puis restaurez l'export :

```bash
# 1. Avec le fichier Compose précédent (postgres:17-alpine, montage sur /var/lib/postgresql/data)
docker compose stop mcp controller
(umask 077 && docker compose exec -T db pg_dump -U secreview -d secreview -Fc > ~/secreview.dump)
docker compose down

# 2. Vérifier l'export (il liste les tables), puis recréer le volume : l'export est désormais
#    la seule copie des données
docker compose run --rm -T --no-deps --entrypoint pg_restore db --list < ~/secreview.dump | grep 'TABLE DATA'
docker volume rm security-review-mcp_secreview-pg

# 3. Avec le fichier Compose actuel (postgres:18-alpine, montage sur /var/lib/postgresql)
docker compose up -d db
docker compose exec -T db pg_restore -U secreview -d secreview --clean --if-exists --no-owner < ~/secreview.dump
docker compose up -d
```

Le service `migrate` applique ensuite les révisions Alembic en attente, s'il y en a. L'export
contient les rapports, les empreintes des mots de passe et des jetons : gardez-le hors du dépôt
(lisible par vous seul, `umask 077`) et supprimez-le une fois la restauration vérifiée.

## Règles internes et CLI

Les [règles](../usage/rules.md) sont stockées dans la base : importez un
dossier de packs TOML avec la CLI du contrôleur (les serveurs en cours d'exécution les
appliquent en quelques secondes) :

```bash
docker run --rm -v secreview-data:/var/lib/secreview -v ./rules.d:/rules:ro \
    --entrypoint security-review-controller security-review-mcp rules import /rules
```

Les autres commandes passent de la même façon :

```bash
docker run --rm -v secreview-data:/var/lib/secreview \
    --entrypoint security-review-controller security-review-mcp token list
```
