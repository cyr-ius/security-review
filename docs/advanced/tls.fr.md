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

Avec une CA interne, les clients doivent faire confiance à son certificat : voir
[Serveur HTTPS avec une CA interne](#serveur-https-avec-une-ca-interne).

## Serveur HTTPS avec une CA interne

Quand le certificat du serveur est signé par une
[CA interne](#autorite-de-certification), l'hôte refuse la connexion
(`unable to verify the first certificate`, `unable to get local issuer certificate`). Ni VS Code ni Claude
n'ont d'option TLS par serveur dans leur configuration MCP : on ajoute le certificat aux
autorités de confiance du **processus** de l'hôte. Claude Code et VS Code reposent sur Node.js,
qui lit pour cela la variable d'environnement `NODE_EXTRA_CA_CERTS` (fichier PEM) **au
démarrage** du processus.

1. Obtenez le certificat de la CA interne (PEM) auprès de ses administrateurs, enregistrez-le
   sous `~/.config/secreview/ca.pem`, et vérifiez que le nom ou l'adresse de l'`url` MCP figure
   dans le certificat du serveur :

    ```bash
    openssl s_client -connect 192.168.1.1:8000 -CAfile ~/.config/secreview/ca.pem </dev/null \
        2>/dev/null | openssl x509 -noout -ext subjectAltName
    ```

2. Déclarez-le à l'hôte, puis **redémarrez-le** :

=== "Claude Code"

    Dans le profil du shell (`~/.bashrc`, `~/.zshrc`), avant de lancer `claude` :

    ```bash
    export NODE_EXTRA_CA_CERTS="$HOME/.config/secreview/ca.pem"
    ```

    La [documentation de Claude Code](https://code.claude.com/docs/en/network-config) indique
    aussi la clé `env` de `settings.json`
    (`"env": { "NODE_EXTRA_CA_CERTS": "/home/moi/.config/secreview/ca.pem" }`). La variable
    s'applique à toutes les connexions de Claude Code, pas seulement au serveur MCP.

=== "VS Code / GitHub Copilot"

    Lancez VS Code depuis un shell où la variable est définie (`code .`), ou définissez-la au
    niveau du système :

    ```bash
    export NODE_EXTRA_CA_CERTS="$HOME/.config/secreview/ca.pem"
    code .
    ```

    Autre solution : ajoutez le certificat au magasin de certificats du système (Windows :
    *Autorités de certification racines de confiance* ; macOS : Trousseau, *Toujours approuver* ;
    Linux : `/usr/local/share/ca-certificates/` puis `sudo update-ca-certificates`). VS Code
    charge les certificats du système (paramètre `http.systemCertificates`, actif par défaut).

    Dans un **dev container**, la connexion part du conteneur : montez le fichier et définissez
    la variable dans `devcontainer.json` (`"remoteEnv": { "NODE_EXTRA_CA_CERTS": "..." }`), puis
    reconstruisez ou rechargez la fenêtre.

!!! warning
    N'utilisez pas `NODE_TLS_REJECT_UNAUTHORIZED=0` : il désactive la vérification de **toutes**
    les connexions du processus (API, extensions, mises à jour), pas seulement celle du serveur
    MCP, et laisse passer une interception.

Les connecteurs distants ajoutés depuis l'interface web de Claude (claude.ai, Claude Desktop)
sont contactés depuis l'infrastructure d'Anthropic, pas depuis le poste : ils exigent un
serveur joignable depuis Internet avec un certificat reconnu publiquement, ce qui exclut une CA
interne.

`security-review-ci` accepte directement `--cafile` (voir la [CLI](../reference/cli.md)). La
configuration MCP de l'hôte
elle-même est dans [Configuration de l'hôte](../getting-started/host.md#transport-http).

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
