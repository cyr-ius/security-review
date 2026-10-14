# Docker

## Construire l'image

```bash
docker build -t security-review-mcp .
docker build -t security-review-mcp:pg --build-arg EXTRAS=postgres .   # pilote PostgreSQL
```

Le build compile aussi l'[interface web](../utilisation/interface-web.md) (étape Node.js) ;
elle est servie sur `/ui/` par le contrôleur.

L'image tourne sous un utilisateur non root (uid `10001`), sans sources ni outils de build. La
base SQLite est dans le volume `/data`. Le fichier `.env` n'est **pas** copié dans l'image :
passez la configuration avec `-e` ou `--env-file`.

## Poste développeur (stdio)

L'hôte lance le conteneur. `.vscode/mcp.json` :

```json
{
  "servers": {
    "security-review": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "--rm", "-v", "secreview-data:/data", "security-review-mcp"]
    }
  }
}
```

!!! warning "`-i` mais pas `-t`"
    `-i` est indispensable (le protocole passe par stdin) ; ne mettez pas `-t`.

Pour Claude (`.mcp.json`), même `command` / `args` sous `mcpServers`.

## Serveur partagé (HTTP)

Une seule image, deux conteneurs qui partagent la base (voir
[Architecture et déploiement](kubernetes.md)) :

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
contrôleur, un mot de passe aléatoire pour le rôle `admin` est généré et affiché une seule fois
dans ses logs. Seule son empreinte est conservée, dans la base de données. Récupérez-le avec
`docker logs secreview-controller` puis connectez-vous sur l'interface (`/ui/`). Ce rôle gère
les règles et le triage et donne aussi accès à `/mcp`. Ajoutez ensuite des jetons individuels
`reader` ou `triager` pour les équipes (voir les [rôles](../utilisation/interface-web.md#roles)).

Les jetons projet créés depuis l'écran **Jetons** sont eux aussi stockés sous forme d'empreinte
dans la base, comme tous les jetons (voir [jetons Bearer](http.md#jetons-bearer)).

!!! warning "Protégez les journaux"
    Le mot de passe initial est un secret : limitez l'accès aux logs Docker et à leur collecte
    centralisée. Si vous le perdez, générez-en un nouveau (l'ancien est aussitôt invalidé) :
    `docker exec secreview-controller security-review-controller token reset-admin`.

## Docker Compose avec PostgreSQL

Le fichier `docker-compose.yml` à la racine du dépôt démarre les deux processus avec une base
PostgreSQL :

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
docker compose up -d --build
docker compose logs controller   # mot de passe admin initial
```

| Service | Rôle | Écoute |
|---|---|---|
| `db` | PostgreSQL, joignable seulement sur le réseau interne `backend` | — |
| `migrate` | `security-review-controller db upgrade`, puis s'arrête | — |
| `controller` | API REST et interface web (`/ui/`) | `127.0.0.1:8080` (`SECREVIEW_CONTROLLER_PORT`) |
| `mcp` | Serveur MCP (`/mcp`) et enrôlement public | `127.0.0.1:8000` (`SECREVIEW_PORT`) |

- L'image est construite avec l'extra `postgres` (`security-review-mcp:pg`). `migrate` attend
  que la base soit prête (`pg_isready`) ; `controller` et `mcp` attendent que `migrate` ait
  réussi. Seul `migrate` modifie le schéma (`SECREVIEW_DB_AUTO_UPGRADE=false` ailleurs).
- `POSTGRES_PASSWORD` est obligatoire et lu depuis `.env` (jamais commité). Il est inséré tel
  quel dans `SECREVIEW_DATABASE_URL` : utilisez des caractères hexadécimaux, ou encodez les
  caractères spéciaux (`@`, `:`, `/`...).
- Les ports ne sont publiés que sur `127.0.0.1`. Pour les exposer, activez le
  [TLS intégré](http.md) ou placez-les derrière un reverse proxy. Le contrôleur n'expose aucune
  route d'écriture sans jeton : il peut rester interne.
- Pour un essai en HTTPS sans fichier à monter, ajoutez `SECREVIEW_TLS_SELF_SIGNED=true` et
  `SECREVIEW_TLS_SELF_SIGNED_HOSTS` (l'adresse ou le nom par lequel les clients joignent l'hôte
  Docker) dans `.env` : le fichier Compose transmet ces variables aux deux serveurs, qui génèrent un
  [certificat auto-signé](http.md#certificat-auto-signe) à chaque démarrage (dans le `tmpfs`
  `/tmp`). Les autres variables de `.env` ne servent qu'à Compose : ajoutez-les sous
  `environment` pour qu'elles atteignent les conteneurs.
- Les conteneurs tournent en système de fichiers en lecture seule, sans capacité Linux. Le
  volume `secreview-pg` contient les rapports et les jetons gérés (mot de passe admin et
  jetons projet) : sauvegardez-le.

Pour ajouter le TLS ou des règles internes, complétez `environment` et `volumes` du service
concerné. Les commandes CLI s'exécutent dans le conteneur du contrôleur :

```bash
docker compose exec controller security-review-controller gate --project portal --fail-on high
```

## Règles internes et CLI

Les [règles internes](../utilisation/regles.md) sont stockées dans la base : importez un
dossier de packs TOML avec la CLI du contrôleur (les serveurs en cours d'exécution les
appliquent en quelques secondes) :

```bash
docker run --rm -v secreview-data:/data -v ./rules.d:/rules:ro \
    --entrypoint security-review-controller security-review-mcp rules import /rules
```

Les autres commandes passent de la même façon :

```bash
docker run --rm -v secreview-data:/data \
    --entrypoint security-review-controller security-review-mcp gate --project portal --fail-on high
```
