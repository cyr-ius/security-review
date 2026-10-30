# Connexion OAuth des clients MCP

Par défaut, un développeur crée un jeton MCP personnel dans **Mon compte** et le copie dans la
configuration de son agent (voir [Configuration de l'agent](../getting-started/host.md)).

Avec la **connexion OAuth**, le développeur n'a plus besoin de jeton. À la première connexion, l'agent ouvre le
navigateur, le développeur se connecte à l'interface web (compte local ou [OIDC](oidc.md)) et autorise le client,
puis l'agent reçoit ses jetons et les renouvelle seul.

Le flux suit l'[autorisation de la spécification MCP](https://modelcontextprotocol.io/specification/latest/basic/authorization)
(OAuth 2.1, code d'autorisation avec PKCE `S256`, enregistrement dynamique des clients,
métadonnées de la ressource protégée).

Le serveur Controller est le serveur d'autorisation. Le serveur MCP ne fait que vérifier les jetons.
Les jetons MCP personnels restent acceptés, sauf si un administrateur les désactive par `SECREVIEW_PERSONAL_MCP_TOKENS=false`.
`SECREVIEW_PERSONAL_TOKENS_ENABLED=false` désactive aussi la connexion OAuth : plus aucun client
n'est autorisé, et les clients déjà connectés sont refusés.

## Activation

Dans l'interface web, un administrateur qui a la permission `settings.manage` doit saisir l'URL
publique du serveur MCP dans la section **Clients MCP (connexion OAuth)** de la page
**Jetons** et activer l'interrupteur **Connexion OAuth**.

L'URL publique du serveur Controller est aussi nécessaire via le réglage sur la page **Général**.

Le changement s'applique aussitôt, sans redémarrage. La désactivation demande une confirmation et suspend les autorisations sans les révoquer.
Chaque changement est enregistré dans le journal d'audit (`mcp_oauth.changed`).

Les routes OAuth suivent les réglages à chaque requête. Un changement de l'URL du serveur Controller dans **Général** change l'issuer sans redémarrage.

Si vous ne souhaitez pas utiliser l'interface web, voici les variables d'environnement à passer au **serveur Controller** :

```bash
SECREVIEW_MCP_OAUTH_ENABLED=true
SECREVIEW_MCP_URL=https://mcp.example.com/mcp          # URL publique du point d'accès MCP
SECREVIEW_PUBLIC_URL=https://secreview.example.com # issuer (https, http sur localhost seulement)
```

Quelle que soit la méthode employée, le serveur MCP prend en compte les modifications (sous 30 secondes).
Activée sans l'URL du point d'accès MCP, la connexion est suspendue : le serveur Controller démarre, journalise un avertissement, et la page **Jetons** demande l'URL, dont l'enregistrement met la connexion en service.
Si vous désactivez la connexion OAuth des clients MCP, les autorisations sont suspendues : le serveur MCP refuse aussitôt les jetons déjà émis, et les accepte de nouveau à la réactivation (un client dont le jeton de rafraîchissement a expiré entre-temps doit se reconnecter). Pour couper définitivement tous les clients, utilisez **Tout révoquer** (voir [Administration](#administration)).

Derrière un reverse proxy, publiez ces chemins publics :

| Chemin | Processus |
|---|---|
| `/.well-known/oauth-protected-resource/mcp` (métadonnées de la ressource protégée, RFC 9728) | serveur MCP |
| `/.well-known/oauth-authorization-server` (métadonnées, RFC 8414), `/authorize`, `/token`, `/register`, `/revoke` | serveur Controller |


L'issuer doit être en `https` : le serveur Controller refuse de démarrer avec une URL en `http` hors localhost.

Par défaut, un client ne peut renvoyer le navigateur que vers l'interface loopback du poste (`127.0.0.1`, `localhost`,
`::1`, en http ou https). Aucun autre site ne reçoit de code : sinon, n'importe qui pourrait
enregistrer un client qui renvoie le navigateur vers son propre site, et recevoir le code d'un
utilisateur qui suit son lien vers `/authorize`.

Une adresse refusée est écartée, pas le client : VS Code enregistre aussi
`https://vscode.dev/redirect` à côté de son adresse loopback, qui est gardée ; VS Code et Claude
Code n'ont donc besoin d'aucune déclaration. Un client n'est refusé (`invalid_redirect_uri`) que
si aucune de ses adresses n'est acceptée.

Pour un client qui ne revient que par un site web, déclarez ses noms d'hôte dans
`SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS` (https seulement). Ne déclarez que des hôtes de confiance :
tous les chemins d'un hôte déclaré sont acceptés. Il peut arriver que le schéma de retour ne soit
ni http ni https, par exemple **cursor**://localhost/redirect : ces schémas se déclarent dans la
variable `SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES`.

```bash
SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS=mcp-client.example.com     # https seulement
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

## Déroulé

1. L'hôte appelle `/mcp` sans jeton. Le serveur MCP répond `401` avec
   `WWW-Authenticate: Bearer …, resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`.
   Ce document désigne le serveur Controller comme serveur d'autorisation.
2. L'hôte s'enregistre sur `/register` (enregistrement dynamique, RFC 7591).
3. Il ouvre `/authorize` dans le navigateur, qui arrive sur la page **Connecter un client MCP**
   de l'interface web, derrière la connexion habituelle.
4. Le développeur y autorise (ou refuse) le client, le navigateur revient vers l'hôte avec un
   code à usage unique, valable 60 secondes.
5. L'hôte échange le code et son vérificateur PKCE sur `/token` contre un jeton d'accès et un
   jeton de rafraîchissement, puis appelle `/mcp` avec le jeton d'accès.

Une demande restée sans réponse expire au bout de 10 minutes.

## Ce que donne un jeton

Un jeton d'accès agit comme un [jeton MCP personnel](../usage/tokens.md#jetons-mcp-et-ci-personnels)
de l'utilisateur qui a autorisé le client : les projets que l'utilisateur peut lire, les
rapports et propositions n'étant enregistrés que sur ceux de `reports.write`.
Les droits sont relus à chaque requête. Il n'atteint que le serveur MCP : ni l'API REST ni les
routes de pipeline du serveur Controller.

Autoriser un client exige une session web (un jeton Bearer n'autorise jamais un client), et est
refusé (`403`) avec `SECREVIEW_PERSONAL_TOKENS_ENABLED=false`, comme créer un jeton MCP personnel.

| Jeton | Durée | Renouvellement |
|---|---|---|
| Jeton d'accès | `SECREVIEW_MCP_OAUTH_ACCESS_MINUTES` (60 minutes) | par le jeton de rafraîchissement, sans navigateur |
| Jeton de rafraîchissement | `SECREVIEW_MCP_OAUTH_REFRESH_DAYS` (30 jours) | chaque rafraîchissement émet une nouvelle paire et le prolonge ; si `SECREVIEW_TOKEN_MAX_DAYS` est défini, toute l'autorisation prend fin ce nombre de jours après l'approbation, et le client se reconnecte |

Seules les empreintes SHA-256 des jetons sont conservées. Un jeton de rafraîchissement déjà
remplacé et présenté à nouveau (une copie, peut-être volée) révoque toute l'autorisation :
l'hôte doit se reconnecter.

## Clients connectés

Dès que la connexion est active, la page **Mon compte** liste les **Clients MCP connectés** de l'utilisateur (nom donné par le client,
dates d'autorisation, de dernière utilisation et d'expiration) et permet de les révoquer (les
jetons cessent aussitôt de fonctionner).

Supprimer un utilisateur supprime ses clients. Un utilisateur garde au plus 20 clients ; au-delà, le plus ancien est révoqué.

## Administration

Avec la permission `tokens.manage`, la page **Jetons** affiche une section **Clients MCP (connexion OAuth)**.

 - **Révoquer** coupe un utilisateur d'un client.

 - **Tout révoquer** coupe tous les utilisateurs de tous les clients : chaque client devra être autorisé de nouveau.

 - **Supprimer** retire un client avec toutes ses autorisations, et le client devra se réenregistrer.

La section reste disponible quand la connexion est désactivée : les autorisations, alors suspendues, peuvent toujours être révoquées.


## Clients enregistrés

N'importe qui peut enregistrer un client, donc tout client est **public**. Le serveur remplace
la méthode à secret par `none`, n'émet aucun secret et s'appuie sur PKCE.

Il ne peut exister plus de `SECREVIEW_MCP_OAUTH_MAX_CLIENTS` clients à la fois. Un client que personne n'a
autorisé dans la journée est supprimé au prochain enregistrement. Les routes OAuth sont soumises à la
[limitation des requêtes](../reference/configuration.md#limitation-des-requetes) des routes de connexion.

La page de consentement affiche le nom choisi par le client et l'hôte vers lequel il revient.
N'autorisez qu'un client que vous venez de lancer vous-même.

## Enrôlement et clients sans OAuth

Tant que la connexion OAuth est active, un client sans jeton reçoit le `401` qui démarre la
connexion, et non le [serveur d'enrôlement](architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet).
Un hôte qui ne gère pas OAuth utilise un jeton MCP personnel, comme avant. La description du
`401` indique les deux.

## Audit

Les enregistrements (`oauth.client_registered`), autorisations (`oauth.grant_approved`), refus
(`oauth.grant_denied`), révocations (`oauth.grant_revoked`) et jetons de rafraîchissement
réutilisés (`oauth.refresh_reused`) sont écrits dans le [journal d'audit](audit-log.md), jamais
avec un jeton.

## Dépannage

| Symptôme | Cause |
|---|---|
| L'hôte affiche toujours le serveur d'enrôlement | OAuth désactivé sur le serveur Controller, ou le serveur MCP n'a pas encore relu le réglage (30 secondes) |
| **Jetons** indique que la connexion OAuth est suspendue (avertissement `OAuth login of the MCP clients suspended` dans les journaux) | `SECREVIEW_MCP_URL` manquant : définissez-le, ou saisissez l'URL sur la page **Jetons** |
| Le serveur Controller ne démarre pas : `needs the public URL of the controller` | `SECREVIEW_PUBLIC_URL` manquant |
| Le serveur Controller ne démarre pas : `Issuer URL must be HTTPS` | URL du serveur Controller en `http://` hors localhost |
| `invalid_redirect_uri` à l'enregistrement, ou VS Code demande un ID client (« Enregistrement client dynamique non pris en charge ») | aucune URI de redirection sur l'interface loopback : ajoutez son hôte à `SECREVIEW_MCP_OAUTH_REDIRECT_HOSTS` (https) ou son schéma à `SECREVIEW_MCP_OAUTH_REDIRECT_SCHEMES` |
| `invalid_target` au retour dans l'hôte | l'hôte demande une autre ressource que `SECREVIEW_MCP_URL` : vérifiez que cette URL est celle configurée dans l'hôte |
| **Connecter un client MCP** indique que la demande a expiré | plus de 10 minutes, ou déjà traitée : relancez la connexion depuis l'hôte |
