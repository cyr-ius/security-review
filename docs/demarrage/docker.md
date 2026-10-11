# Docker

## Construire l'image

```bash
docker build -t security-review-mcp .
docker build -t security-review-mcp:pg --build-arg EXTRAS=postgres .   # pilote PostgreSQL
```

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
    -e SECREVIEW_DATABASE_URL=postgresql+psycopg2://user:pass@db:5432/secreview \
    -v ./tokens:/run/secrets/secreview-tokens:ro \
    -e SECREVIEW_AUTH_TOKENS_FILE=/run/secrets/secreview-tokens \
    -v ./tls:/etc/secreview/tls:ro \
    -e SECREVIEW_TLS_CERTFILE=/etc/secreview/tls/cert.pem \
    -e SECREVIEW_TLS_KEYFILE=/etc/secreview/tls/key.pem \
    security-review-mcp:pg --transport streamable-http --host 0.0.0.0 --port 8443
```

Les fichiers montés doivent être lisibles par l'utilisateur du conteneur (uid `10001`).

## Règles internes et CLI

Monter un dossier de [règles internes](../utilisation/regles.md) :

```bash
-v ./rules.d:/etc/security-review-mcp/rules.d:ro \
-e SECREVIEW_RULES_DIR=/etc/security-review-mcp/rules.d
```

Les commandes CLI passent aussi :

```bash
docker run --rm -v secreview-data:/data security-review-mcp gate --project portal --fail-on high
```
