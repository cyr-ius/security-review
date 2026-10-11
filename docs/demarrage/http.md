# Serveur HTTP, authentification et TLS

Le transport `streamable-http` sert un serveur partagé (équipe, CI/CD). L'authentification et
le TLS sont **facultatifs** et indépendants ; ils ne concernent que ce transport (en stdio,
l'hôte lance lui-même le processus).

```bash
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
# endpoint : http://127.0.0.1:8000/mcp
# interface web : http://127.0.0.1:8000/ui/
```

## Jetons Bearer

Générez un jeton par client :

```bash
security-review-mcp token --label ci
# {"token": "UJB7…", "config_entry": "ci:sha256:1f91…"}
```

- Donnez `token` au client.
- Mettez `config_entry` (seule l'empreinte SHA-256 est stockée) dans `SECREVIEW_AUTH_TOKENS`
  (entrées séparées par des virgules) ou, mieux, dans le fichier désigné par
  `SECREVIEW_AUTH_TOKENS_FILE` (une entrée par ligne, `#` pour les commentaires — pratique avec
  les secrets Docker / Kubernetes).

Une entrée vaut `[label[:rôle]:]jeton` ou `[label[:rôle]:]sha256:<hex>` ; un jeton en clair doit
faire au moins 24 caractères. Le rôle (`--role` de la commande `token`) vaut `mcp` par défaut :
voir les [rôles](../utilisation/interface-web.md#roles) pour donner accès à l'interface web.

Dès qu'un jeton est configuré, toute requête sans `Authorization: Bearer <jeton>` valide reçoit
un `401`. Le label du client apparaît dans les journaux.

L'image Docker configure `SECREVIEW_AUTH_BOOTSTRAP_FILE=/data/admin-token`. Au premier démarrage
en transport HTTP avec l'interface activée, un mot de passe aléatoire `web-admin` est créé et
affiché une seule fois dans les logs du conteneur. Seule son empreinte est conservée dans le
volume `/data`; gardez ce volume pour conserver le compte au redémarrage. Ce rôle admin est
limité à la Web UI et ne peut pas appeler `/mcp`. Les jetons d'équipe configurés restent valides
en parallèle.

!!! tip
    Les jetons ne passent jamais en argument de ligne de commande : utilisez les variables
    d'environnement ou le fichier de jetons.

## TLS

Uvicorn sert directement en HTTPS quand un certificat est fourni :

```bash
security-review-mcp --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# ou SECREVIEW_TLS_CERTFILE / SECREVIEW_TLS_KEYFILE (+ SECREVIEW_TLS_KEYFILE_PASSWORD)
```

`SECREVIEW_TLS_CLIENT_CA` active en plus le **TLS mutuel** : seuls les clients présentant un
certificat signé par cette CA peuvent se connecter.

## Configuration du client

VS Code, avec un jeton demandé à l'utilisateur :

```json
{
  "servers": {
    "security-review": {
      "type": "http",
      "url": "https://secreview.example.internal:8443/mcp",
      "headers": { "Authorization": "Bearer ${input:secreview-token}" }
    }
  },
  "inputs": [
    { "id": "secreview-token", "type": "promptString", "description": "Jeton", "password": true }
  ]
}
```

## Derrière un reverse proxy

Un reverse proxy (TLS, SSO, limitation de débit) reste une option valable : dans ce cas,
laissez ces variables vides.

!!! warning
    Si le serveur écoute ailleurs que sur localhost sans authentification ou sans TLS, un
    avertissement est journalisé. Tout jeton de rôle `mcp` ou `admin` donne accès à **tous** les
    outils.
