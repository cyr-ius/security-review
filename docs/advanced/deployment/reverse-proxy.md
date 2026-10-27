# Reverse proxy

A reverse proxy in front of the two processes terminates TLS and publishes them under public
names. This page gives what it must do, then a configuration for nginx, Apache, HAProxy and
Traefik.

## What the proxy must do

**Route each path to its process.** The MCP server and the controller are two processes (see
[Architecture](../architecture/index.md)):

| Paths | Process | Port (Compose files) |
|---|---|---|
| `/mcp`, `/.well-known/oauth-protected-resource/…` ([OAuth login](../mcp-oauth.md)) | MCP server | `8000` |
| everything else: `/ui`, `/api`, `/.well-known/oauth-authorization-server`, `/authorize`, `/token`, `/register`, `/revoke` | controller | `8080` |

With **one host per process** (`mcp.secreview.example.com` and `secreview.example.com`), each host
sends every path to its process: no path rule. With **a single host**, route by path as in the
examples below.

**Declare the public URLs.** The servers give the clients absolute URLs built from the settings,
never from the `Host` header: they must be those of the proxy, as seen from the workstations.

| Variable (controller) | One host per process | Single host |
|---|---|---|
| `SECREVIEW_CONTROLLER_URL` | `https://secreview.example.com` | `https://secreview.example.com` |
| `SECREVIEW_MCP_URL` (OAuth login) | `https://mcp.secreview.example.com/mcp` | `https://secreview.example.com/mcp` |

The hosts then use the same address as `SECREVIEW_MCP_URL`.

**Keep the MCP answers streamed.** `/mcp` may answer with server-sent events: no response
buffering, and a read timeout long enough for a review (one hour below).

**Let the bodies through.** A scan of `security-review-ci` sends up to
`SECREVIEW_MAX_SCAN_REQUEST_MB` (64 MiB) to the controller, an MCP request up to
`SECREVIEW_MAX_MCP_REQUEST_MB` (16 MiB): the proxy limit must not be lower.

**Give the client address.** The proxy sends `X-Forwarded-For` and `X-Forwarded-Proto`; both
processes trust them only from the addresses of `SECREVIEW_FORWARDED_ALLOW_IPS` (login
throttling, rate limit, audit log, HSTS). With the Compose files and a proxy on the host, the
containers see the address of the Docker bridge, not `127.0.0.1`: set for instance
`SECREVIEW_FORWARDED_ALLOW_IPS=172.16.0.0/12` (the range of your Docker networks).

The examples use a single host `secreview.example.com`, TLS terminated by the proxy and the ports
of the Compose files on `127.0.0.1`. For one host per process, keep the controller part on
`secreview.example.com` and give the MCP part its own host, without path rule. When the proxy
runs on another machine than the processes, the tokens would cross the network in clear: enable
the [built-in TLS](../tls.md) of both processes and proxy to `https://…` instead of
`http://127.0.0.1`.

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

    # MCP server: the endpoint (streamed answers) and its OAuth metadata
    location /mcp {
        proxy_pass http://secreview_mcp;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
    location /.well-known/oauth-protected-resource {
        proxy_pass http://secreview_mcp;
    }

    # Controller: web interface, REST API, OAuth authorization server
    location / {
        proxy_pass http://secreview_controller;
    }
}
```

## Apache

Modules `proxy`, `proxy_http`, `ssl` and `headers` (`a2enmod proxy proxy_http ssl headers`).
`mod_proxy` adds `X-Forwarded-For` itself.

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
    # No compression of the streamed MCP answers
    SetEnvIf Request_URI "^/mcp" no-gzip

    # MCP server first (the most specific paths win only when declared first)
    ProxyPass        /mcp http://127.0.0.1:8000/mcp flushpackets=on
    ProxyPassReverse /mcp http://127.0.0.1:8000/mcp
    ProxyPass        /.well-known/oauth-protected-resource http://127.0.0.1:8000/.well-known/oauth-protected-resource

    # Controller: everything else
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

HAProxy does not buffer the answers and sets no body limit by default.

## Traefik

Dynamic configuration (file provider). Traefik sends `X-Forwarded-*`, streams the server-sent
events and gives the longer rule the higher priority: the MCP router wins on its paths.

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

With the Docker provider, the same routers go in the labels of the `mcp` and `controller`
services (`traefik.http.routers.secreview-mcp.rule=…`), each with
`traefik.http.services.<name>.loadbalancer.server.port=8000`, the port inside the container.

## Check

```bash
curl -s https://secreview.example.com/.well-known/oauth-protected-resource/mcp   # MCP server (OAuth on)
curl -s https://secreview.example.com/.well-known/oauth-authorization-server     # controller (OAuth on)
curl -si -X POST https://secreview.example.com/mcp | head -1                     # 401 (OAuth on)
curl -s https://secreview.example.com/api/health                                 # {"status":"ok"}
```

The `issuer` of the second answer must be `SECREVIEW_CONTROLLER_URL` exactly, and the
`authorization_servers` of the first one the same URL.
