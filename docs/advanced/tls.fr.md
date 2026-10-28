# TLS et certificats

Le [serveur MCP](architecture/mcp-server.md) et le [serveur Controller](architecture/controller.md) servent eux-mêmes le HTTPS,
ou derrière un reverse proxy qui termine le TLS.

Uvicorn sert directement en HTTPS quand un certificat est fourni, pour le serveur MCP comme pour
le serveur Controller (mêmes options, mêmes variables) :

```bash
security-review-mcp serve --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
security-review-controller serve --host 0.0.0.0 --port 9443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# ou SECREVIEW_TLS_CERTFILE / SECREVIEW_TLS_KEYFILE (+ SECREVIEW_TLS_KEYFILE_PASSWORD)
```

`SECREVIEW_TLS_CLIENT_CA` active en plus le **TLS mutuel** : seuls les clients présentant un
certificat signé par cette CA peuvent se connecter.

## Autorité de certification

Le serveur ne génère jamais de certificat : fournissez-en un signé par une autorité de
certification reconnue par les clients, une CA publique (par exemple Let's Encrypt, ou
cert-manager dans Kubernetes) ou la **CA interne** de votre organisation. Son `subjectAltName`
doit contenir les noms et adresses utilisés par les clients (par exemple
`DNS:secreview.lan,IP:192.168.1.1`) ; sinon les clients refusent la connexion même s'ils font
confiance à la CA. Le fichier de clé (`key.pem`) ne quitte jamais le serveur : gardez-le lisible
par le seul compte du serveur (`chmod 600`).

Avec une CA interne, les clients doivent faire confiance à son certificat.

## Derrière un reverse proxy

Un reverse proxy ou un Ingress peut terminer le TLS à la place (laissez les variables
`SECREVIEW_TLS_*` vides). Réglez alors `SECREVIEW_FORWARDED_ALLOW_IPS` sur son adresse, pour que
l'adresse du client soit lue dans `X-Forwarded-For` pour la limitation des connexions, la limite
de débit et le journal d'audit (voir l'exposition du
[serveur MCP](architecture/mcp-server.md#exposition-et-replicas) et du [serveur Controller](architecture/controller.md#exposition)).

!!! warning
    Si un processus écoute ailleurs que sur localhost sans TLS, un avertissement est journalisé :
    les jetons et les sessions circuleraient en clair. Derrière un reverse proxy qui termine le
    TLS, l'avertissement est attendu, tant que seul le proxy atteint le processus.
