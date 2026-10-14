# Interface web

L'interface web permet aux équipes sécurité de consulter les rapports enregistrés par les agents
et de **trier les findings** (corrigé, risque accepté, faux positif) sans passer par un client
MCP. Elle est servie par le **contrôleur**, un processus distinct du serveur MCP qui partage sa
base de données (voir [Architecture et déploiement](../demarrage/kubernetes.md)) :

| Chemin | Contenu |
|---|---|
| `/ui/` | Application web (Angular) |
| `/api/v1/…` | API REST utilisée par l'application |
| `/api/docs` | Documentation OpenAPI de l'API REST (publique, sans données) |
| `/healthz` | Sonde de vie (publique) |

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# interface : http://127.0.0.1:8080/ui/
```

## Écrans

Les écrans sont accessibles depuis la barre latérale : **Supervision** (projets, rapports) pour
tous les rôles, **Administration** (règles, checklists, jetons, rôles SSO, paramètres) pour le rôle `admin`. Le bas de
la barre affiche le client connecté, son rôle et la version, avec le bouton de déconnexion ; sur
petit écran, la barre s'ouvre avec le bouton de menu. Le thème clair ou sombre se choisit en haut
à droite, y compris sur la page de connexion, et reste mémorisé dans le navigateur.

- **Projets** : tous les projets avec leurs findings ouverts par sévérité, triés par risque,
  activité ou nom.
- **Projet** : findings ouverts, tendance sur 30 jours à 1 an (graphique et tableau), délai
  moyen de correction, plus ancien finding ouvert, CWE les plus fréquentes, derniers rapports et
  export SARIF.
- **Rapports** : liste filtrable par projet et niveau de risque (les filtres sont dans l'URL, on
  peut donc partager un lien).
- **Rapport** : résumé, contexte (dépôt, branche, commit), findings avec emplacement, CWE,
  extrait de code et recommandation ; téléchargement Markdown et SARIF. Les utilisateurs qui ont
  le rôle `triager` ou `admin` changent le statut d'un finding directement depuis cet écran.
- **Checklists** : les administrateurs consultent les items de contrôle par domaine, filtrent la
  liste et créent, modifient ou suppriment les items personnalisés. Les items par défaut peuvent
  être modifiés, mais pas supprimés. Toute modification est rechargée immédiatement par le serveur
  et intégrée aux prompts de revue.
- **Règles** : les administrateurs consultent toutes les [règles](regles.md) stockées en base,
  filtrables par origine (par défaut ou personnalisée). Ils créent, modifient (dans une fenêtre
  modale, sans quitter la position dans la liste), activent ou désactivent les règles, et
  suppriment les règles personnalisées. Une règle par défaut peut être
  modifiée (badge « Par défaut, modifiée ») ou désactivée, mais pas supprimée. Le bouton
  **Recharger** applique immédiatement un changement fait avec la CLI
  `security-review-controller rules`.
- **Jetons** : les administrateurs créent et révoquent des jetons de rôle `reader`, `triager` ou
  `mcp`, limités à un ou plusieurs projets. Le rôle `admin` reste non restreint et se crée par la
  CLI. Le secret n'est montré qu'une fois ; seule son empreinte est enregistrée, dans la base de
  données. Une révocation prend effet à la requête suivante. La section
  **Demandes en attente** distingue les nouveaux jetons des demandes d'accès à un projet
  supplémentaire ([enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton)) :
  **Approuver** active le nouveau jeton ou ajoute le projet au jeton existant ; **Refuser** ne
  supprime que la demande. Les projets autorisés et les ajouts encore en attente sont affichés
  pour chaque jeton. Avec la [connexion SSO](#connexion-sso-openid-connect), la colonne
  **Lecture dans le portail** permet de donner en même temps au développeur la lecture du projet
  dans l'interface web (voir [accès nominatifs](#acces-nominatifs-enrolement)).
- **Rôles SSO** : les administrateurs associent les groupes ou rôles du fournisseur d'identité
  à un rôle web et, pour `reader` et `triager`, à une liste de projets
  (voir [role mapping](#role-mapping)). Les groupes des variables `SECREVIEW_OIDC_*_GROUPS`
  sont affichés en lecture seule. La section **Accès nominatifs en lecture** liste les
  utilisateurs SSO qui lisent des projets à titre individuel ; on peut en ajouter, retirer un
  projet ou supprimer l'accès.
- **Paramètres** : réglages enregistrés en base, prioritaires sur les variables d'environnement
  et partagés par le serveur MCP et le contrôleur.
    - **Langue des rapports** : variable `SECREVIEW_REPORT_LANGUAGE`, choix laissé à l'agent ou
      langue définie ici (`French`, `fr`, `pt-BR`…). Elle s'applique aux prochains prompts de
      revue ; l'argument `report_language` d'un prompt reste prioritaire
      ([langue des rapports](prompts-outils.md#langue-des-rapports)).
    - **Proxy du téléchargement OSV** : proxy de l'environnement du contrôleur
      (`SECREVIEW_OSV_PROXY`, sinon `HTTPS_PROXY` / `NO_PROXY`, affichés en lecture seule),
      proxy défini ici, ou connexion directe. Le proxy appliqué et son origine sont affichés.
      Les mots de passe ne sont jamais réaffichés (`***`) : renvoyer `***` conserve celui
      enregistré.
    - **Base de vulnérabilités OSV** : nombre d'avis par écosystème, date et âge du dernier
      import, configuration du téléchargement, historique des 50 dernières mises à jour
      (planifiée, CLI ou interface web, avec statut, durée et résultat par écosystème) et bouton
      **Mettre à jour maintenant**, disponible seulement si `SECREVIEW_OSV_AUTO_UPDATE=true`
      ([mise à jour par le contrôleur](dependances.md#mise-a-jour-automatique-par-le-controleur)).

## Rôles

Chaque jeton porte un rôle, qui détermine les endpoints accessibles :

| Rôle | `/mcp` | Interface web (lecture) | Changement de statut |
|---|---|---|---|
| `mcp` (défaut) | ✅ | — | — |
| `reader` | — | ✅ | — |
| `triager` | — | ✅ | ✅ |
| `admin` | ✅ | ✅ | ✅ |

Un jeton `mcp`, `reader` ou `triager` restreint avec `--project` ne voit et ne trie que les
projets autorisés ; l'option peut être répétée (voir
[jetons restreints à un projet](../demarrage/http.md#jetons-restreints-a-un-projet)).

Dans l'image Docker, un mot de passe `admin` est généré au premier démarrage du contrôleur et
affiché une seule fois dans ses logs. Son empreinte est enregistrée dans la base de données, comme celle
de tous les jetons (voir [jetons Bearer](../demarrage/http.md#jetons-bearer)). Ce rôle peut gérer les
règles internes, trier les findings et accéder à `/mcp`. Un jeton créé sans rôle reste `mcp` : les jetons des agents
et de la CI gardent leur accès mais ne peuvent pas utiliser l'interface web. Le rôle `triager`
conserve uniquement le triage des findings. Générez un jeton par personne :

Le mot de passe affiché dans les logs doit être traité comme un secret: restreignez l'accès aux
journaux. S'il est perdu, générez-en un nouveau (l'ancien est aussitôt invalidé) :
`security-review-controller token reset-admin`.

```bash
security-review-controller token create --label alice --role triager
# {"id": "…", "label": "alice", "role": "triager", "project": null, "created_at": "…", "token": "UJB7…"}
```

Transmettez `token` à la personne, qui le colle sur la page de connexion. Révoquez-le avec
`security-review-controller token revoke alice`. Chaque changement de statut est journalisé avec
le label du jeton :

```
INFO security_review_mcp.web: Finding 42 set to accepted by alice
```

!!! warning "Authentification requise pour la Web UI"
  L'API de l'interface refuse les requêtes avec le statut `503` si aucun jeton n'est configuré;
  la mire de connexion reste affichée et indique que l'authentification doit être configurée.
  Créez un jeton avec `security-review-controller token create` ou activez
  `SECREVIEW_AUTH_BOOTSTRAP_ADMIN`. Cette restriction
  concerne la Web UI; l'authentification MCP reste indépendante.
  Avec la [connexion SSO](#connexion-sso-openid-connect), l'API demande une connexion (`401`)
  même sans jeton en base.

## Connexion SSO (OpenID Connect)

Le contrôleur peut déléguer la connexion à l'interface à un fournisseur d'identité OpenID
Connect (Keycloak, Microsoft Entra ID, Okta, Authentik, Dex...). La page de connexion affiche
alors un bouton **Se connecter avec SSO** à côté du champ mot de passe ou jeton, qui reste
disponible (mot de passe admin initial, jetons personnels).

Le flux utilisé est le *authorization code* avec PKCE (`S256`), state et nonce :

1. `GET /api/v1/auth/oidc/login` redirige le navigateur vers le fournisseur ;
2. le fournisseur renvoie sur `GET /api/v1/auth/oidc/callback` ; le contrôleur échange le code
   (appel serveur à serveur), vérifie l'ID token (signature par les clés JWKS du fournisseur,
   émetteur, audience, expiration, nonce) et en déduit un rôle à partir des groupes ;
3. il remet à l'interface un **jeton de session** signé, valable
   `SECREVIEW_OIDC_SESSION_HOURS` heures, que l'onglet utilise comme un jeton Bearer.

### Déclarer le client chez le fournisseur

Créez un client OIDC *confidentiel* (ou public, sans secret : PKCE suffit) avec :

- **URL de redirection** : `https://<contrôleur>/api/v1/auth/oidc/callback`, l'URL publique
  exacte vue par le navigateur (derrière un reverse proxy, celle du proxy) ;
- un claim contenant les groupes ou rôles de l'utilisateur dans l'ID token (ou, à défaut, dans
  la réponse *userinfo*, que le contrôleur consulte quand l'ID token ne le contient pas).

Exemple avec Keycloak (rôles de realm) :

```bash
SECREVIEW_OIDC_ENABLED=true
SECREVIEW_OIDC_ISSUER=https://sso.example.com/realms/acme
SECREVIEW_OIDC_CLIENT_ID=security-review
SECREVIEW_OIDC_CLIENT_SECRET=...            # vide pour un client public
SECREVIEW_OIDC_REDIRECT_URI=https://secreview.example.com/api/v1/auth/oidc/callback
SECREVIEW_OIDC_ROLES_CLAIM=realm_access.roles   # "groups" par défaut
SECREVIEW_OIDC_ADMIN_GROUPS=secreview-admins
SECREVIEW_OIDC_TRIAGER_GROUPS=secreview-triagers
SECREVIEW_OIDC_READER_GROUPS=developers,qa
SECREVIEW_OIDC_SESSION_SECRET=$(openssl rand -base64 48)
SECREVIEW_OIDC_DISPLAY_NAME=Keycloak
```

L'émetteur doit être en HTTPS (HTTP n'est accepté que sur `localhost`, pour le développement) ;
son document `/.well-known/openid-configuration` doit annoncer le même `issuer`. Si le
fournisseur utilise une CA interne, indiquez-la avec `SECREVIEW_OIDC_CAFILE` ; un proxy sortant
se configure avec `HTTPS_PROXY` / `NO_PROXY`.

### Role mapping

Le *role mapping* décide du rôle web, et des projets, d'un utilisateur SSO à partir des valeurs
du claim `SECREVIEW_OIDC_ROLES_CLAIM` (liste ou chaîne, chemin pointé accepté, comparaison
exacte, sensible à la casse). Une **association** relie une de ces valeurs (un groupe ou un
rôle du fournisseur) à :

- un rôle web : `reader`, `triager` ou `admin` (jamais `mcp` : une session OIDC n'ouvre que
  l'interface web, pas `/mcp`) ;
- pour `reader` et `triager`, une liste facultative de projets (50 au plus) ; sans liste, tous
  les projets. Une association `admin` porte toujours sur tous les projets.

Les associations ont deux origines :

| Origine | Gestion | Projets |
|---|---|---|
| Base de données | Écran **Rôles SSO** ou API `/api/v1/oidc/role-mappings` (rôle `admin`) | Tous ou une liste |
| Variables `SECREVIEW_OIDC_ADMIN_GROUPS`, `..._TRIAGER_GROUPS`, `..._READER_GROUPS` | Configuration du contrôleur (lecture seule dans l'interface) | Tous |

Les variables servent surtout à désigner le premier administrateur, qui crée ensuite les autres
associations dans l'interface.

À la connexion :

1. le **rôle le plus élevé** parmi les associations qui correspondent aux groupes de
   l'utilisateur l'emporte (`admin` > `triager` > `reader`) ;
2. la session voit **tous les projets** si l'une des associations de ce rôle n'est pas
   restreinte ; sinon l'**union** de leurs projets (200 au plus : au-delà, la connexion est
   refusée). Les projets des associations d'un rôle
   inférieur ne sont pas ajoutés : un utilisateur `triager` sur `shop-api` et `reader` sur
   `billing` est `triager` sur `shop-api` seulement ;
3. sans aucune association de groupe, `SECREVIEW_OIDC_DEFAULT_ROLE` s'applique (`reader` ou
   `triager`, tous les projets) ; vide (défaut), seul un
   [accès nominatif](#acces-nominatifs-enrolement) permet encore la connexion, sinon elle est
   **refusée**. Le rôle `admin` ne peut pas être attribué par défaut.

Une session restreinte se comporte comme un
[jeton restreint à un projet](../demarrage/http.md#jetons-restreints-a-un-projet) : les autres
projets, leurs rapports et leurs findings sont traités comme inexistants. Un projet peut être
cité avant d'exister (l'écran propose les projets connus). Un changement d'association
s'applique à la **prochaine connexion** de l'utilisateur ; les sessions ouvertes gardent leurs
droits jusqu'à leur expiration (voir [Sessions](#sessions)). Chaque création, modification ou
suppression est journalisée avec le label de l'administrateur :

```
INFO security_review_mcp.web: Role mapping payments -> triager (billing) created by oidc:alice
```

Exemple avec l'API :

```bash
curl -X POST https://secreview.example.com/api/v1/oidc/role-mappings \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"claim_value": "payments-team", "role": "triager", "projects": ["billing"]}'
```

Le label d'une session est `oidc:<identifiant>` (claim `SECREVIEW_OIDC_USERNAME_CLAIM`, sinon
`email`, sinon `sub`) : c'est lui qui apparaît dans les journaux et l'historique du triage.

### Accès nominatifs (enrôlement)

Un **accès nominatif** donne le rôle `reader` sur une liste de projets (50 au plus) à **un**
utilisateur SSO, désigné par son identifiant : la valeur du claim
`SECREVIEW_OIDC_USERNAME_CLAIM`, comparée exactement, casse comprise. Contrairement au label de
session, il n'y a pas de repli sur `email` ou `sub` : sans ce claim (ou avec un caractère de
contrôle ou invisible), aucun accès nominatif ne s'applique. Il sert surtout à l'[enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton) :
le développeur qui a demandé un jeton MCP pour un projet en consulte aussi les rapports dans le
portail.

- **À l'approbation** d'une demande (écran **Jetons de projet**), la case **Lecture dans le
  portail** est cochée et l'identifiant prérempli avec le demandeur (`requested_by`) quand il est
  renseigné. Ce champ est déclaré par le client et **n'est pas vérifié** : contrôlez-le ou
  corrigez-le avant d'approuver, ou décochez la case. Une demande complémentaire approuvée pour
  le même utilisateur ajoute le projet à son accès.
- **À la main**, section **Accès nominatifs en lecture** de l'écran **Rôles SSO**, ou par l'API
  `/api/v1/oidc/user-grants` (rôle `admin`).

À la connexion, ces projets s'ajoutent à ceux des associations `reader` de l'utilisateur, et au
rôle par défaut s'il s'applique. Comme pour les associations, le **rôle le plus élevé**
l'emporte : un utilisateur que ses groupes rendent `triager` sur `billing` reste `triager` sur
`billing` seulement, sans lire les projets de son accès nominatif. L'accès est indépendant du
jeton MCP : révoquer le jeton ne le supprime pas.

```bash
# Approuver une demande en donnant la lecture du projet à l'utilisateur SSO « alice »
curl -X POST https://secreview.example.com/api/v1/enrollments/$REQUEST_ID/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"portal_user": "alice"}'
```

La réponse contient alors `portal_grant`. Un identifiant invalide est refusé (`422`) avant
l'approbation : la demande reste en attente. Le journal du contrôleur trace l'accès :

```
INFO security_review_mcp.web: Web reader access to shop-api granted to oidc user alice by admin
```

### Sessions

- Rien n'est stocké en base : le jeton de session est signé (HMAC-SHA256) avec une clé dérivée
  de `SECREVIEW_OIDC_SESSION_SECRET` (32 caractères au moins). Toutes les répliques du
  contrôleur doivent partager ce secret ; sans lui, un secret aléatoire est tiré à chaque
  démarrage et les sessions se terminent au redémarrage (un avertissement est journalisé).
- Un changement de groupe chez le fournisseur ne s'applique qu'à la connexion suivante. Pour
  couper toutes les sessions avant leur expiration, changez `SECREVIEW_OIDC_SESSION_SECRET` et
  redémarrez le contrôleur.
- **Se déconnecter** efface la session de l'onglet, pas celle du fournisseur d'identité.

En cas d'échec, la page de connexion indique la cause (accès refusé chez le fournisseur, aucun
groupe autorisé, état expiré, jeton invalide, fournisseur injoignable) ; le détail est journalisé
par le contrôleur, sans code ni jeton.

## Sécurité

- Les fichiers statiques de `/ui/` sont publics (ils ne contiennent aucune donnée) ; l'API
  `/api/v1/` exige un jeton `reader`, `triager` ou `admin`. La documentation Swagger (`/api/docs`)
  et son schéma (`/api/openapi.json`) sont publics et ne donnent accès à aucune donnée.
  Dans Swagger, le cadenas d'une route indique qu'elle exige un jeton : il reste **ouvert**
  tant que vous n'avez pas saisi de jeton avec **Authorize**, et ne veut pas dire que la route
  est accessible sans jeton.
- Le contrôleur n'expose aucune route d'écriture sans jeton. Les demandes
  d'[enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton) sont déposées sur
  le **serveur MCP** (`POST /api/v1/enroll`, public) ; le contrôleur les liste et les traite
  (`GET /api/v1/enrollments`, `POST /api/v1/enrollments/{id}/approve`,
  `DELETE /api/v1/enrollments/{id}`, rôle `admin`). Il peut donc rester sur un réseau interne.
- Le jeton est envoyé dans l'en-tête `Authorization` : pas de cookie, donc pas de CSRF.
  Seule la [connexion SSO](#connexion-sso-openid-connect) pose un cookie, `HttpOnly`,
  `SameSite=Lax`, `Secure` en HTTPS, limité à l'URL de retour et valable 10 minutes : il lie le
  retour du fournisseur au navigateur qui a lancé la connexion (protection contre le *login
  CSRF*). Le jeton de session est remis dans le fragment d'URL (`#session=...`), jamais envoyé à
  un serveur, et l'interface l'efface aussitôt de la barre d'adresse et de l'historique.
- Il est conservé dans le `sessionStorage` de l'onglet et disparaît à sa fermeture.
- Les pages sont servies avec une CSP stricte (`script-src 'self'`, aucune ressource externe),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` et `Referrer-Policy: no-referrer`.
- Servez l'interface en HTTPS ([TLS intégré ou reverse proxy](../demarrage/http.md#tls)) dès
  qu'elle n'écoute plus sur localhost : le jeton circule à chaque requête.

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_WEB_UI` | `true` | Sert l'interface sur `/ui` ; à `false`, le contrôleur ne sert que l'API REST |
| `SECREVIEW_WEB_UI_DIR` | — | Dossier d'une autre build de l'application (défaut : celle du paquet) |
| `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` | `false` | Génère le mot de passe admin initial (stocké en base) au démarrage du contrôleur ; `true` dans Docker |
| `SECREVIEW_ENROLLMENT` | `true` | Demandes de jetons par les projets (sur le serveur MCP), validées dans l'écran **Jetons** |
| `SECREVIEW_OIDC_*` | — | [Connexion SSO](#connexion-sso-openid-connect), voir la [référence](../reference/configuration.md) |

Le paquet publié et l'image Docker contiennent l'application déjà compilée. Si vous installez
depuis les sources sans la compiler, le contrôleur ne sert que l'API REST et un avertissement est
journalisé. Voir [Contribuer](../contribuer.md#interface-web) pour la compiler.
