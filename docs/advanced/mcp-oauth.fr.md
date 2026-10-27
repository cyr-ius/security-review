# Connexion OAuth des clients MCP

Par défaut, un développeur crée un jeton MCP personnel dans **Mon compte** et le copie dans la
configuration de son hôte (voir [Configuration de l'hôte](../getting-started/host.md)). Avec la
connexion OAuth, l'hôte n'a besoin d'aucun jeton : à la première connexion, il ouvre le
navigateur, le développeur se connecte à l'interface web (compte local ou [OIDC](oidc.md)) et
autorise le client, puis l'hôte reçoit ses jetons et les renouvelle seul.

Le flux suit l'[autorisation de la spécification MCP](https://modelcontextprotocol.io/specification/latest/basic/authorization)
(OAuth 2.1, code d'autorisation avec PKCE `S256`, enregistrement dynamique des clients,
métadonnées de la ressource protégée). Le contrôleur est le serveur d'autorisation ; le serveur
MCP ne fait que vérifier les jetons. Les jetons MCP personnels restent acceptés, sauf si un
administrateur les désactive par `SECREVIEW_PERSONAL_MCP_TOKENS=false` une fois que tous les
hôtes se connectent par OAuth.

## Activation

Sur le **contrôleur** seulement :

```bash
SECREVIEW_MCP_OAUTH_ENABLED=true
SECREVIEW_MCP_URL=https://mcp.example.com/mcp          # URL publique du point d'accès MCP
SECREVIEW_CONTROLLER_URL=https://secreview.example.com # issuer (https, http sur localhost seulement)
```

Au démarrage, le contrôleur enregistre `SECREVIEW_MCP_URL` en base ; le serveur MCP l'y lit
(sous 30 secondes), comme il y lit l'URL du contrôleur : il n'a besoin d'aucune nouvelle
variable. Retirez `SECREVIEW_MCP_OAUTH_ENABLED` et redémarrez le contrôleur pour la désactiver :
il révoque alors toutes les autorisations, pour que les jetons déjà émis cessent aussitôt de
fonctionner.
L'issuer est fixé au démarrage : après un changement de l'URL du contrôleur dans **Général**,
redémarrez le contrôleur.

Derrière un reverse proxy, publiez ces chemins publics :

| Chemin | Processus |
|---|---|
| `/.well-known/oauth-protected-resource/mcp` (métadonnées de la ressource protégée, RFC 9728) | serveur MCP |
| `/.well-known/oauth-authorization-server` (métadonnées, RFC 8414), `/authorize`, `/token`, `/register`, `/revoke` | contrôleur |

Avec un hôte par service (`mcp.example.com` vers le serveur MCP, `secreview.example.com` vers
le contrôleur, chacun avec tous ses chemins), comme le font les fichiers Compose et
l'[exemple d'Ingress Kubernetes](deployment/kubernetes.md#image-exposition-et-administration),
ces chemins arrivent déjà au bon processus : rien à ajouter. Avec un seul hôte pour les deux,
routez par chemin : `/mcp` et `/.well-known/oauth-protected-resource` vers le serveur MCP, tout
le reste vers le contrôleur (exemples nginx, Apache, HAProxy et Traefik :
[Reverse proxy](deployment/reverse-proxy.md)). L'issuer doit être en `https` : le contrôleur refuse de démarrer
avec une URL en `http` hors localhost.

Par défaut, un client ne peut renvoyer le navigateur que vers l'interface loopback du poste,
ce qu'utilisent Claude Code et VS Code. Un client qui revient par un site web ou par son propre
schéma d'URI demande que son hôte ou son schéma soit listé :

```bash
SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS=vscode.dev     # https seulement
SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES=cursor
```

Les autres paramètres OAuth (durées des jetons, nombre de clients) sont
dans [Configuration](../reference/configuration.md#connexion-oauth-des-clients-mcp).

## Configuration de l'hôte

Le serveur est déclaré avec sa seule URL, sans en-tête `Authorization` :

```json
{
  "mcpServers": {
    "security-review": {
      "type": "http",
      "url": "https://mcp.example.com/mcp"
    }
  }
}
```

Dans Claude Code, `/mcp` indique alors que le serveur demande une authentification :
choisissez-le pour ouvrir le navigateur. VS Code propose la connexion au premier démarrage du
serveur.

## Déroulé

1. L'hôte appelle `/mcp` sans jeton : le serveur MCP répond `401` avec
   `WWW-Authenticate: Bearer …, resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`.
   Ce document désigne le contrôleur comme serveur d'autorisation.
2. L'hôte s'enregistre sur `/register` (enregistrement dynamique, RFC 7591).
3. Il ouvre `/authorize` dans le navigateur, qui arrive sur l'écran **Connecter un client MCP**
   de l'interface web, derrière la connexion habituelle.
4. Le développeur y autorise (ou refuse) le client ; le navigateur revient vers l'hôte avec un
   code à usage unique, valable 60 secondes.
5. L'hôte échange le code et son vérificateur PKCE sur `/token` contre un jeton d'accès et un
   jeton de rafraîchissement, puis appelle `/mcp` avec le jeton d'accès.

Une demande restée sans réponse expire au bout de 10 minutes.

## Ce que donne un jeton

Un jeton d'accès agit comme un [jeton MCP personnel](../usage/tokens.md#jetons-mcp-et-ci-personnels)
de l'utilisateur qui a autorisé le client : les projets que l'utilisateur peut lire, relus à
chaque requête, l'outil `request_project`, les rapports signés du nom de l'utilisateur. Il
n'atteint que le serveur MCP : ni l'API REST ni les routes de pipeline du contrôleur (gardez un
jeton `ci` personnel pour `security-review-ci`).

Autoriser un client exige la permission `mcp_tokens.create`, comme créer un jeton MCP
personnel, et une session web : un jeton Bearer n'autorise jamais un client.

| Jeton | Durée | Renouvellement |
|---|---|---|
| Jeton d'accès | `SECREVIEW_MCP_OAUTH_ACCESS_MINUTES` (60 minutes) | par le jeton de rafraîchissement, sans navigateur |
| Jeton de rafraîchissement | `SECREVIEW_MCP_OAUTH_REFRESH_DAYS` (30 jours) | chaque rafraîchissement émet une nouvelle paire et le prolonge ; si `SECREVIEW_TOKEN_MAX_DAYS` est défini, toute l'autorisation prend fin ce nombre de jours après l'approbation, et le client se reconnecte |

Seules les empreintes SHA-256 des jetons sont conservées. Un jeton de rafraîchissement déjà
remplacé et présenté à nouveau (une copie, peut-être volée) révoque toute l'autorisation :
l'hôte doit se reconnecter.

## Clients connectés

**Mon compte** liste les **Clients MCP connectés** de l'utilisateur (nom donné par le client,
dates d'autorisation, de dernière utilisation et d'expiration) et permet de les révoquer : les
jetons cessent aussitôt de fonctionner. Supprimer un utilisateur supprime ses clients. Un
utilisateur garde au plus 20 clients ; au-delà, le plus ancien est révoqué.

## Administration

Avec la permission `tokens.manage`, l'écran **Jetons** affiche une section **Clients MCP
(connexion OAuth)** tant que la connexion est active : les réglages en vigueur (point d'accès
MCP, redirections acceptées, durée des jetons, nombre de clients), chaque client autorisé avec
son utilisateur, et chaque client enregistré. **Révoquer** coupe un utilisateur d'un client ;
**Supprimer** retire un client avec toutes ses autorisations, et le client devra se
réenregistrer. L'API REST offre la même chose : `GET /api/v1/oauth/clients`,
`DELETE /api/v1/oauth/grants/{id}`, `DELETE /api/v1/oauth/clients/{client_id}`.

## Clients enregistrés

N'importe qui peut enregistrer un client, donc tout client est **public** : le serveur remplace
une méthode à secret demandée par `none`, n'émet aucun secret et s'appuie sur PKCE. Les URI de
redirection doivent viser l'interface loopback (`127.0.0.1`, `localhost`, `::1`, en http ou
https), un hôte de `SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS` en https, ou utiliser un schéma de
`SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES`. Tout autre site est refusé : sinon, n'importe qui
pourrait enregistrer un client qui renvoie le navigateur vers son propre site, et recevoir le
code d'un utilisateur qui suit son lien vers `/authorize`. Au plus
`SECREVIEW_MCP_OAUTH_MAX_CLIENTS` clients existent à la fois ; un client que personne n'a
autorisé dans la journée est supprimé au prochain enregistrement. Les routes OAuth comptent dans
la [limitation des requêtes](../reference/configuration.md#limitation-des-requetes) des routes de
connexion.

L'écran de consentement affiche le nom choisi par le client et l'hôte vers lequel il revient :
n'autorisez qu'un client que vous venez de lancer vous-même.

## Enrôlement et clients sans OAuth

Tant que la connexion OAuth est active, un client sans jeton reçoit le `401` qui démarre la
connexion, et non le [serveur d'enrôlement](architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet) :
un hôte qui ne gère pas OAuth utilise un jeton MCP personnel, comme avant. La description du
`401` indique les deux.

## Audit

Les enregistrements (`oauth.client_registered`), autorisations (`oauth.grant_approved`), refus
(`oauth.grant_denied`), révocations (`oauth.grant_revoked`) et jetons de rafraîchissement
réutilisés (`oauth.refresh_reused`) sont écrits dans le [journal d'audit](audit-log.md), jamais
avec un jeton.

## Dépannage

| Symptôme | Cause |
|---|---|
| L'hôte affiche toujours le serveur d'enrôlement | OAuth désactivé sur le contrôleur, ou le serveur MCP n'a pas encore relu le réglage (30 secondes) |
| Le contrôleur ne démarre pas : `needs the public URL of the controller` | `SECREVIEW_CONTROLLER_URL` manquant |
| Le contrôleur ne démarre pas : `Issuer URL must be HTTPS` | URL du contrôleur en `http://` hors localhost |
| `invalid_redirect_uri` à l'enregistrement | URI de redirection hors loopback : ajoutez son hôte à `SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS` (https) ou son schéma à `SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES` |
| `invalid_target` au retour dans l'hôte | l'hôte demande une autre ressource que `SECREVIEW_MCP_URL` : vérifiez que cette URL est celle configurée dans l'hôte |
| **Connecter un client MCP** indique que la demande a expiré | plus de 10 minutes, ou déjà traitée : relancez la connexion depuis l'hôte |
