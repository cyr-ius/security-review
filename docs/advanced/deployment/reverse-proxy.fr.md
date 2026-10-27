# Reverse proxy

Un reverse proxy placé devant les deux processus termine le TLS et les publie sous des noms
publics. Cette page indique ce qu'il doit faire, puis donne une configuration pour nginx,
Apache, HAProxy et Traefik.

## Ce que doit faire le proxy

**Router chaque chemin vers son processus.** Le serveur MCP et le contrôleur sont deux
processus (voir [Architecture](../architecture/index.md)) :

| Chemins | Processus | Port (fichiers Compose) |
|---|---|---|
| `/mcp`, `/.well-known/oauth-protected-resource/…` ([connexion OAuth](../mcp-oauth.md)) | serveur MCP | `8000` |
| tout le reste : `/ui`, `/api`, `/.well-known/oauth-authorization-server`, `/authorize`, `/token`, `/register`, `/revoke` | contrôleur | `8080` |

Avec **un hôte par processus** (`mcp.secreview.example.com` et `secreview.example.com`), chaque
hôte envoie tous ses chemins à son processus : aucune règle de chemin. Avec **un seul hôte**,
routez par chemin comme dans les exemples ci-dessous.

**Déclarer les URL publiques.** Les serveurs donnent aux clients des URL absolues construites à
partir des réglages, jamais de l'en-tête `Host` : ce doivent être celles du proxy, telles que
les postes les voient.

| Variable (contrôleur) | Un hôte par processus | Un seul hôte |
|---|---|---|
| `SECREVIEW_CONTROLLER_URL` | `https://secreview.example.com` | `https://secreview.example.com` |
| `SECREVIEW_MCP_URL` (connexion OAuth) | `https://mcp.secreview.example.com/mcp` | `https://secreview.example.com/mcp` |

Les hôtes utilisent alors la même adresse que `SECREVIEW_MCP_URL`.

**Garder les réponses MCP en flux.** `/mcp` peut répondre par des server-sent events : aucune
mise en mémoire tampon des réponses, et un délai de lecture assez long pour une revue (une heure
ci-dessous).

**Laisser passer les corps.** Un scan de `security-review-ci` envoie jusqu'à
`SECREVIEW_MAX_SCAN_REQUEST_MB` (64 Mio) au contrôleur, une requête MCP jusqu'à
`SECREVIEW_MAX_MCP_REQUEST_MB` (16 Mio) : la limite du proxy ne doit pas être plus basse.

**Transmettre l'adresse du client.** Le proxy envoie `X-Forwarded-For` et `X-Forwarded-Proto` ;
les deux processus ne les croient que depuis les adresses de `SECREVIEW_FORWARDED_ALLOW_IPS`
(limitation des connexions et des requêtes, journal d'audit, HSTS). Avec les fichiers Compose et
un proxy sur l'hôte, les conteneurs voient l'adresse du pont Docker, pas `127.0.0.1` : réglez
par exemple `SECREVIEW_FORWARDED_ALLOW_IPS=172.16.0.0/12` (la plage de vos réseaux Docker).

Les exemples utilisent un seul hôte `secreview.example.com`, le TLS terminé par le proxy et les
ports des fichiers Compose sur `127.0.0.1`. Pour un hôte par processus, gardez la partie
contrôleur sur `secreview.example.com` et donnez à la partie MCP son propre hôte, sans règle de
chemin. Quand le proxy tourne sur une autre machine que les processus, les jetons traverseraient
le réseau en clair : activez le [TLS intégré](../tls.md) des deux processus et pointez le proxy
vers `https://…` au lieu de `http://127.0.0.1`.

## nginx

```nginx
upstream secreview_controller { server 127.0.0.1:8080; }
upstream secreview_mcp { server 127.0.0.1:8000; }

server {
    listen 443 ssl;
    http2 on;
    server_name secreview.example.com;
    ssl_certificate     /etc/ssl/secreview/fullchain.pem;
    ssl_certificate_key /etc/ssl/secreview/privkey.pem;

    client_max_body_size 64m;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Serveur MCP : le point d'accès (réponses en flux) et ses métadonnées OAuth
    location /mcp {
        proxy_pass http://secreview_mcp;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
    location /.well-known/oauth-protected-resource {
        proxy_pass http://secreview_mcp;
    }

    # Contrôleur : interface web, API REST, serveur d'autorisation OAuth
    location / {
        proxy_pass http://secreview_controller;
    }
}
```

## Apache

Modules `proxy`, `proxy_http`, `ssl` et `headers` (`a2enmod proxy proxy_http ssl headers`).
`mod_proxy` ajoute lui-même `X-Forwarded-For`.

```apache
<VirtualHost *:443>
    ServerName secreview.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/secreview/fullchain.pem
    SSLCertificateKeyFile /etc/ssl/secreview/privkey.pem

    ProxyPreserveHost On
    ProxyTimeout 3600
    LimitRequestBody 67108864
    RequestHeader set X-Forwarded-Proto "https"
    # Pas de compression des réponses MCP en flux
    SetEnvIf Request_URI "^/mcp" no-gzip

    # Serveur MCP d'abord (les chemins les plus précis ne l'emportent que déclarés en premier)
    ProxyPass        /mcp http://127.0.0.1:8000/mcp flushpackets=on
    ProxyPassReverse /mcp http://127.0.0.1:8000/mcp
    ProxyPass        /.well-known/oauth-protected-resource http://127.0.0.1:8000/.well-known/oauth-protected-resource

    # Contrôleur : tout le reste
    ProxyPass        / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

## HAProxy

```haproxy
frontend secreview
    mode http
    bind :443 ssl crt /etc/haproxy/certs/secreview.pem alpn h2,http/1.1
    option forwardfor
    http-request set-header X-Forwarded-Proto https
    timeout client 1h

    acl to_mcp path /mcp
    acl to_mcp path_beg /mcp/ /.well-known/oauth-protected-resource
    use_backend secreview_mcp if to_mcp
    default_backend secreview_controller

backend secreview_mcp
    mode http
    option httpchk GET /healthz
    timeout server 1h
    server mcp 127.0.0.1:8000 check

backend secreview_controller
    mode http
    option httpchk GET /healthz
    timeout server 5m
    server controller 127.0.0.1:8080 check
```

HAProxy ne met pas les réponses en mémoire tampon et ne fixe aucune limite de corps par défaut.

## Traefik

Configuration dynamique (fournisseur de fichiers). Traefik envoie `X-Forwarded-*`, transmet les
server-sent events au fil de l'eau et donne la priorité à la règle la plus longue : le routeur
MCP l'emporte sur ses chemins.

```yaml
http:
  routers:
    secreview-mcp:
      rule: Host(`secreview.example.com`) && (PathPrefix(`/mcp`) || PathPrefix(`/.well-known/oauth-protected-resource`))
      entryPoints: [websecure]
      service: secreview-mcp
      tls:
        certResolver: letsencrypt
    secreview-controller:
      rule: Host(`secreview.example.com`)
      entryPoints: [websecure]
      service: secreview-controller
      tls:
        certResolver: letsencrypt
  services:
    secreview-mcp:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:8000
    secreview-controller:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:8080
```

Avec le fournisseur Docker, les mêmes routeurs vont dans les labels des services `mcp` et
`controller` (`traefik.http.routers.secreview-mcp.rule=…`), chacun avec
`traefik.http.services.<nom>.loadbalancer.server.port=8000`, le port dans le conteneur.

## Vérifier

```bash
curl -s https://secreview.example.com/.well-known/oauth-protected-resource/mcp   # serveur MCP (OAuth actif)
curl -s https://secreview.example.com/.well-known/oauth-authorization-server     # contrôleur (OAuth actif)
curl -si -X POST https://secreview.example.com/mcp | head -1                     # 401 (OAuth actif)
curl -s https://secreview.example.com/api/health                                 # {"status":"ok"}
```

L'`issuer` de la deuxième réponse doit être exactement `SECREVIEW_CONTROLLER_URL`, et les
`authorization_servers` de la première la même URL.
