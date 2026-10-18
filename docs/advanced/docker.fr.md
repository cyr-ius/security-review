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

Fixez une version (`1.2.3-pg`) en production. Les images portent un SBOM et une attestation de
provenance (`docker buildx imagetools inspect --format '{{ json .Provenance }}' IMAGE`). Dans
les exemples de cette page, remplacez `security-review-mcp` et `security-review-mcp:pg` par
l'image publiée, ou construisez-la.

## Construire l'image

```bash
docker build -t security-review-mcp .
docker build -t security-review-mcp:pg --build-arg EXTRAS=postgres .   # pilote PostgreSQL
```

Le build compile aussi l'[interface web](../usage/web-interface.md) (étape Node.js) ;
elle est servie sur `/ui/` par le contrôleur.

L'image tourne sous un utilisateur non root (uid `10001`), sans sources ni outils de build. Son
`HEALTHCHECK` (`python -m security_review_mcp.healthcheck`, toutes les 30 secondes) interroge
`/healthz` du serveur MCP HTTP ou du contrôleur sur l'interface de bouclage, en HTTPS quand le
TLS est activé (en ne faisant confiance qu'au certificat du conteneur) ; en stdio, rien n'écoute
et le conteneur reste sain, et avec le TLS mutuel (`SECREVIEW_TLS_CLIENT_CA`) il n'interroge
rien : appuyez-vous sur les sondes de l'orchestrateur. La
base SQLite est dans le volume `/var/lib/secreview`. Le fichier `.env` n'est **pas** copié dans l'image :
passez la configuration avec `-e` ou `--env-file`.

## Serveur partagé (HTTP)

Une seule image, deux conteneurs qui partagent la base (voir
[Architecture et déploiement](architecture.md)) :

- le **serveur MCP**, point d'entrée par défaut de l'image (`security-review-mcp`) ;
- le **contrôleur** (API REST, interface web, administration), lancé avec
  `--entrypoint security-review-controller`.

Avec l'[authentification et le TLS intégrés](http.md) (ou derrière un reverse proxy qui s'en
charge) :

```bash
DB=postgresql+psycopg2://user:pass@db:5432/secreview

# 1. Schéma (Alembic) : à relancer après chaque mise à jour de l'image
docker run --rm -e SECREVIEW_DATABASE_URL=$DB \
    --entrypoint security-review-controller security-review-mcp:pg db upgrade

# 2. Contrôleur : interface web et API, de préférence sur un réseau interne
docker run -d --name secreview-controller -p 127.0.0.1:8080:8000 \
    -e SECREVIEW_DATABASE_URL=$DB -e SECREVIEW_DB_AUTO_UPGRADE=false \
    --entrypoint security-review-controller \
    security-review-mcp:pg serve --host 0.0.0.0 --port 8000

# 3. Serveur MCP : exposé aux agents et à la CI
docker run -d --name secreview-mcp -p 8443:8443 \
    -e SECREVIEW_DATABASE_URL=$DB \
    -v ./tls:/etc/secreview/tls:ro \
    -e SECREVIEW_TLS_CERTFILE=/etc/secreview/tls/cert.pem \
    -e SECREVIEW_TLS_KEYFILE=/etc/secreview/tls/key.pem \
    security-review-mcp:pg --transport streamable-http --host 0.0.0.0 --port 8443
```

Les fichiers montés doivent être lisibles par l'utilisateur du conteneur (uid `10001`). Le
serveur MCP refuse de démarrer tant que le schéma n'est pas migré. Au premier démarrage du
contrôleur, le compte `admin` est créé avec `SECREVIEW_ADMIN_PASSWORD`, ou un mot de passe
aléatoire que personne ne connaît ; seule son empreinte est conservée, dans la base de données.
Définissez-le avec
`docker exec secreview-controller security-review-controller user reset-password admin`
(affiché une fois), connectez-vous sur l'interface (`/ui/`) avec l'identifiant `admin`, puis
choisissez votre propre mot de passe dans **Mon compte**. Créez ensuite un compte par
personne dans l'écran **Utilisateurs** (voir les
[comptes utilisateurs](../usage/web-interface.md#comptes-utilisateurs)).

Les jetons projet créés depuis l'écran **Jetons** sont eux aussi stockés sous forme d'empreinte
dans la base, comme tous les jetons (voir [jetons Bearer](http.md#jetons-bearer)).

!!! warning "Gardez le mot de passe initial hors des journaux"
    Le mot de passe initial est un secret : passez `SECREVIEW_ADMIN_PASSWORD` comme un secret
    (jamais dans l'image), ou utilisez la CLI ci-dessus. `SECREVIEW_ADMIN_PASSWORD_LOG=true` écrit
    le mot de passe aléatoire dans les logs Docker : pour un premier essai seulement, limitez
    alors l'accès aux journaux. Si vous le perdez, relancez `user reset-password admin` (l'ancien
    est aussitôt invalidé).

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
  `DOCKER_PUBLISH_ADDRESS=0.0.0.0` (toutes les interfaces). Cette variable ne sert qu'à Compose. Le
  contrôleur n'expose aucune route d'écriture sans jeton : il peut rester interne.
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

## Poste développeur (stdio)

L'hôte lance le conteneur. `.mcp.json` à la racine du dépôt (VS Code, GitHub Copilot et
Claude) :

```json
{
  "mcpServers": {
    "security-review": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "--rm", "-v", "secreview-data:/var/lib/secreview", "security-review-mcp"]
    }
  }
}
```

!!! warning "`-i` mais pas `-t`"
    `-i` est indispensable (le protocole passe par stdin) ; ne mettez pas `-t`.

## Règles internes et CLI

Les [règles internes](rules.md) sont stockées dans la base : importez un
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
