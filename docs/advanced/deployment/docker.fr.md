# Docker

## Images publiées

Chaque version est publiée pour `linux/amd64` et `linux/arm64` sur GitHub Container Registry et
Docker Hub. La même image fonctionne avec SQLite et PostgreSQL : elle contient le pilote PostgreSQL.

```bash
docker pull ghcr.io/cyr-ius/security-review:latest   # or docker.io/cyrius44/security-review
```

| Tag | Contenu |
|---|---|
| `X.Y.Z`, `X.Y`, `X`, `latest` | Version `X.Y.Z` (la dernière version stable pour `latest`) |
| `X.Y.Z-pg`, `X.Y-pg`, `X-pg`, `latest-pg` | Dépréciés : alias de la même image, conservés jusqu'à la prochaine version majeure (ancienne variante PostgreSQL) |
| `X.Y.ZrcN` (`a`, `b`, `rc`) | Préversion : ce tag seulement, jamais `latest` |

Les images portent un SBOM et une attestation de provenance (`docker buildx imagetools inspect --format '{{ json .Provenance }}' IMAGE`).

## Docker Compose avec PostgreSQL

Un seul fichier,
[`examples/docker/docker-compose.yml`](https://github.com/cyr-ius/security-review/blob/{{ release_tag }}/examples/docker/docker-compose.yml),
démarre tout avec l'image publiée : PostgreSQL, la migration du schéma, le contrôleur et le
serveur MCP. Les commandes qui le téléchargent et le démarrent sont dans
[Mise en service du serveur](../../getting-started/deploy.md#avec-docker-compose).

La commande `printf` écrit le fichier `.env`, lisible par vous seul : le mot de passe de
PostgreSQL et le secret des sessions web, tirés au hasard. `docker compose up -d --wait` rend la
main une fois tous les services prêts. L'interface web répond sur `http://127.0.0.1:8080/ui/`,
l'endpoint MCP sur `http://127.0.0.1:8000/mcp`.

Contenu des fichiers de la version `{{ release_tag }}` :

=== "docker-compose.yml"

    ```yaml
    --8<-- "docker/docker-compose.yml"
    ```

=== ".env"

    ```bash
    POSTGRES_PASSWORD=<48 caractères hexadécimaux>
    SECREVIEW_SECRET_KEY=<64 caractères hexadécimaux>
    ```

| Service | Rôle | Écoute |
|---|---|---|
| `db` | PostgreSQL, joignable par les autres services seulement | — |
| `controller` | Interface web (`/ui/`) et API REST, pour les personnes ; crée ou met à jour les tables au démarrage | `8080` |
| `mcp` | Serveur MCP (`/mcp`), pour les agents | `8000` |

Bon à savoir :

- **Ordre de démarrage.** `controller` attend que PostgreSQL soit prêt, puis crée ou met à jour
  les tables ; `mcp`, qui les vérifie seulement, attend que `controller` soit en bonne santé.
  Après une mise à jour de l'image, `docker compose up -d` suffit : le contrôleur applique les
  nouvelles migrations.
- **Conservez `.env`.** Il contient le mot de passe de la base et le secret des sessions ; ne le
  commitez jamais. Le mot de passe est inséré tel quel dans l'URL de connexion : gardez des
  caractères hexadécimaux, comme ci-dessus.
- **Ouvrir à l'équipe.** Les ports sont publiés sur toutes les interfaces du serveur, en HTTP
  simple : activez le [TLS intégré](../tls.md) ou placez un [reverse proxy](reverse-proxy.md) devant avant que
  l'équipe se connecte. Pour garder un port sur le serveur seulement (derrière un reverse proxy
  sur la même machine, par exemple), préfixez-le par `127.0.0.1` (`"127.0.0.1:8000:8000"`).
  Seuls les `ports` décident de l'exposition : dans son conteneur, chaque
  processus écoute sur toutes les interfaces (`SECREVIEW_HOST=0.0.0.0`, fixée par l'image, à ne
  pas changer). Pour le TLS intégré,
  décommentez dans `controller` et `mcp` les variables TLS (`SECREVIEW_TLS_CERTFILE`,
  `SECREVIEW_TLS_KEYFILE`) et le `volumes` qui monte en lecture seule les fichiers du certificat
  depuis `./tls` (voir
  [Autorité de certification](../tls.md#autorite-de-certification)). Le contrôleur n'expose aucune
  route d'écriture sans jeton : il peut rester interne, sauf si la
  [connexion OAuth des clients MCP](../mcp-oauth.md) est active : les hôtes MCP atteignent alors
  ses routes OAuth (décommentez `SECREVIEW_MCP_OAUTH_ENABLED` et `SECREVIEW_MCP_URL` dans
  `controller` ; derrière un seul hôte de reverse proxy, routez `/mcp` et
  `/.well-known/oauth-protected-resource` vers `mcp`, tout le reste vers `controller`).
  Ajoutez à `.env` l'URL publique racine du contrôleur (`SECREVIEW_CONTROLLER_URL=https://…`) :
  le contrôleur la recopie en base au démarrage, pour que le serveur MCP donne le lien de
  l'interface web (`/ui`) à un agent sans jeton et que les connecteurs relient leurs tickets aux rapports. Sans elle, renseignez
  l'écran **Général**.
- **Avis de vulnérabilités.** La base OSV est **vide** au premier démarrage : l'analyse de
  dépendances répond qu'aucune base n'est chargée. Pour que le contrôleur la télécharge au
  démarrage puis toutes les 24 h, décommentez `SECREVIEW_OSV_AUTO_UPDATE` (et
  `SECREVIEW_OSV_ECOSYSTEMS`) dans le service `controller`, puis lancez `docker compose up -d`.
  Suivez l'import avec `docker compose logs -f controller`. Sans accès Internet, importez une
  archive avec `advisories import` (voir [Dépendances](../../review/analysis/dependencies.md#import-manuel)).
- **Durcissement.** Les conteneurs de security-review-mcp tournent en système de fichiers en
  lecture seule, sans capacité Linux.
- **Données.** Le volume `secreview-pg` contient les rapports, les comptes et les jetons :
  sauvegardez-le (voir [Sauvegarde de PostgreSQL](../database.md#sauvegarde-de-postgresql)). Il est monté sur
  `/var/lib/postgresql`, où PostgreSQL 18 range ses données ; un volume créé par PostgreSQL 17 ne
  démarre pas avec cette image (voir [Mise à niveau de PostgreSQL](../database.md#mise-a-niveau-de-postgresql)).

Les commandes d'administration s'exécutent dans le conteneur du contrôleur :

```bash
docker compose exec controller security-review-controller token list
```

## Sans Docker Compose

La même image lance chaque processus dans son propre conteneur, sur une base PostgreSQL
existante (voir [Architecture](../architecture/index.md)) :

- le **serveur MCP** est le point d'entrée par défaut de l'image (`security-review-mcp`,
  commande par défaut `serve`, en HTTP streamable ; ajoutez `--transport stdio` pour le mode local) ;
- le **contrôleur** (API REST, interface web, administration) se lance avec
  `--entrypoint security-review-controller`, avec les [jetons](../bearer-tokens.md) et le [TLS](../tls.md) intégrés
  ou derrière un reverse proxy qui s'en charge.

```bash
DB=postgresql+psycopg2://user:pass@db:5432/secreview

# 1. Contrôleur : interface web et API, de préférence sur un réseau interne ; crée ou met
#    à jour le schéma (Alembic) au démarrage, donc à lancer en premier
docker run -d --name secreview-controller -p 127.0.0.1:8080:8000 \
    -e SECREVIEW_DATABASE_URL=$DB \
    --entrypoint security-review-controller \
    ghcr.io/cyr-ius/security-review serve

# 2. Serveur MCP : exposé aux agents et à la CI
docker run -d --name secreview-mcp -p 8443:8443 \
    -e SECREVIEW_DATABASE_URL=$DB \
    -v ./tls:/etc/secreview/tls:ro \
    -e SECREVIEW_TLS_CERTFILE=/etc/secreview/tls/cert.pem \
    -e SECREVIEW_TLS_KEYFILE=/etc/secreview/tls/key.pem \
    ghcr.io/cyr-ius/security-review serve --port 8443

# 3. Mot de passe du compte admin, créé au premier démarrage du contrôleur
docker exec secreview-controller security-review-controller user reset-password admin
```

Dans l'image, les deux processus écoutent sur toutes les interfaces du conteneur
(`SECREVIEW_HOST=0.0.0.0`), sur le port `8000` sauf `--port` : l'option `-p` choisit l'adresse et
le port de l'hôte (`-p 127.0.0.1:8080:8000` : cette machine seulement). Les fichiers montés doivent être lisibles par l'utilisateur du conteneur (uid `10001`). Le
serveur MCP refuse de démarrer tant que le schéma n'est pas migré (étape 1).

## Règles internes et CLI

Les [règles](../../review/rules.md#commande-rules) sont stockées dans la base : importez un
dossier de packs TOML avec la CLI du contrôleur (les serveurs en cours d'exécution les
appliquent en quelques secondes) :

```bash
docker run --rm -v secreview-data:/var/lib/secreview -v ./rules.d:/rules:ro \
    --entrypoint security-review-controller ghcr.io/cyr-ius/security-review rules import /rules
```

Les autres commandes passent de la même façon :

```bash
docker run --rm -v secreview-data:/var/lib/secreview \
    --entrypoint security-review-controller ghcr.io/cyr-ius/security-review token list
```
