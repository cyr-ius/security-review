# Docker

## Construire l'image

```bash
docker build -t security-review-mcp .
docker build -t security-review-mcp:pg --build-arg EXTRAS=postgres .   # pilote PostgreSQL
```

Le build compile aussi l'[interface web](../utilisation/interface-web.md) (étape Node.js) ;
elle est servie sur `/ui/` avec le transport HTTP.

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

Avec l'[authentification et le TLS intégrés](http.md) (ou derrière un reverse proxy qui s'en
charge) :

```bash
docker run -d --name security-review-mcp -p 8443:8443 \
  -v secreview-data:/data \
    -e SECREVIEW_DATABASE_URL=postgresql+psycopg2://user:pass@db:5432/secreview \
    -v ./tls:/etc/secreview/tls:ro \
    -e SECREVIEW_TLS_CERTFILE=/etc/secreview/tls/cert.pem \
    -e SECREVIEW_TLS_KEYFILE=/etc/secreview/tls/key.pem \
    security-review-mcp:pg --transport streamable-http --host 0.0.0.0 --port 8443
```

Les fichiers montés doivent être lisibles par l'utilisateur du conteneur (uid `10001`). Gardez
le volume `secreview-data` : au premier démarrage HTTP, un mot de passe aléatoire pour le rôle
`admin` est généré et affiché une seule fois dans les logs du conteneur. Seule son empreinte est
conservée, dans la base de données. Récupérez-le avec `docker logs security-review-mcp` puis
connectez-vous sur `https://<hôte>:8443/ui/`. Ce rôle gère les règles et le triage et donne aussi
accès à `/mcp`. Ajoutez ensuite des jetons individuels `reader` ou `triager` pour les équipes
(voir les [rôles](../utilisation/interface-web.md#roles)).

Les jetons projet créés depuis l'écran **Jetons** sont eux aussi stockés sous forme d'empreinte
dans la base, comme tous les jetons (voir [jetons Bearer](http.md#jetons-bearer)).

!!! warning "Protégez les journaux"
  Le mot de passe initial est un secret: limitez l'accès aux logs Docker et à leur collecte
  centralisée. Si vous le perdez, générez-en un nouveau (l'ancien est aussitôt invalidé) :
  `docker exec security-review-mcp security-review-mcp token reset-admin`.

## Docker Compose avec PostgreSQL

Le fichier `docker-compose.yml` à la racine du dépôt démarre le serveur HTTP (MCP sur `/mcp`,
interface web sur `/ui/`) avec une base PostgreSQL :

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
docker compose up -d --build
docker compose logs security-review-mcp   # mot de passe admin initial
```

- L'image est construite avec l'extra `postgres` (`security-review-mcp:pg`) et ne démarre
  qu'une fois la base prête (`pg_isready`). Les tables sont créées au premier démarrage.
- `POSTGRES_PASSWORD` est obligatoire et lu depuis `.env` (jamais commité). Il est inséré tel
  quel dans `SECREVIEW_DATABASE_URL` : utilisez des caractères hexadécimaux, ou encodez les
  caractères spéciaux (`@`, `:`, `/`...).
- PostgreSQL n'est pas publié sur l'hôte : il n'est joignable que par le serveur, sur le réseau
  interne `backend`.
- Le serveur écoute sur `127.0.0.1:8000` (port modifiable avec `SECREVIEW_PORT` dans `.env`).
  Pour l'exposer, activez le [TLS intégré](http.md) ou placez-le derrière un reverse proxy.
- Le conteneur du serveur tourne en système de fichiers en lecture seule, sans capacité Linux.
  Le volume `secreview-pg` contient les rapports et les jetons gérés (mot de passe admin et
  jetons projet) : sauvegardez-le.

Pour ajouter des jetons, le TLS ou des règles internes, complétez `environment` et `volumes`
du service `security-review-mcp` comme dans les exemples ci-dessus. Les commandes CLI
s'exécutent dans le conteneur :

```bash
docker compose exec security-review-mcp security-review-mcp gate --project portal --fail-on high
```

## Règles internes et CLI

Les [règles internes](../utilisation/regles.md) sont stockées dans la base : importez un
dossier de packs TOML avec la CLI (le serveur en cours d'exécution les applique en quelques
secondes) :

```bash
docker run --rm -v secreview-data:/data -v ./rules.d:/rules:ro security-review-mcp rules import /rules
```

Les commandes CLI passent aussi :

```bash
docker run --rm -v secreview-data:/data security-review-mcp gate --project portal --fail-on high
```
