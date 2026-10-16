# Interface web

L'interface web permet aux équipes sécurité de consulter les rapports enregistrés par les agents
et de **trier les findings** (corrigé, risque accepté, faux positif) sans passer par un client
MCP. Elle est servie par le **contrôleur**, un processus distinct du serveur MCP qui partage sa
base de données (voir [Architecture et déploiement](../getting-started/kubernetes.md)) :

| Chemin | Contenu |
|---|---|
| `/ui/` | Application web (Angular) |
| `/api/v1/…` | API REST utilisée par l'application |
| `/api/docs` | Documentation OpenAPI de l'API REST (publique, sans données) |
| `/api/favicon.svg` | Icône de l'interface web et de la documentation Swagger (publique) |
| `/healthz` | Sonde de vie (publique) |

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# interface : http://127.0.0.1:8080/ui/
```

## Écrans

Les écrans sont accessibles depuis la barre latérale : **Supervision** (projets, rapports) pour
tous les rôles, puis **Référentiel** (règles, checklists, normes) et **Administration**
(utilisateurs, jetons, rôles SSO, paramètres) pour le rôle `admin`. Le bas de la barre affiche le client connecté, son rôle et la
version, avec les boutons **Mon compte** et de déconnexion ; sur petit écran, la barre s'ouvre avec le bouton de menu. Le thème clair ou sombre se choisit en haut
à droite, y compris sur la page de connexion, et reste mémorisé dans le navigateur.

L'interface est proposée en **anglais**, **français** et **espagnol**. La langue se choisit dans
le sélecteur en haut à droite, y compris sur la page de connexion. Le changement est immédiat et
reste mémorisé dans le navigateur ; à la première visite, l'interface suit la langue du
navigateur, ou l'anglais si elle n'en propose aucune. Ce choix ne concerne que l'interface : la
langue des rapports de revue se règle dans **Paramètres**, et les messages d'erreur détaillés
renvoyés par l'API restent en anglais.

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
- **Normes** : les [normes de développement](standards.md) transmises aux assistants IA par le
  prompt `development-standards`. Les administrateurs les recherchent, les lisent, les créent,
  les modifient (technologies, motifs de fichiers, contenu Markdown), les désactivent ou les
  suppriment. Un changement s'applique immédiatement.
- **Checklists** : les administrateurs consultent les items de contrôle par domaine, filtrent la
  liste et créent, modifient ou suppriment les items personnalisés. Les items par défaut peuvent
  être modifiés, mais pas supprimés. Toute modification est rechargée immédiatement par le serveur
  et intégrée aux prompts de revue.
- **Règles** : les administrateurs consultent toutes les [règles](rules.md) stockées en base,
  filtrables par origine (par défaut ou personnalisée). Ils créent, modifient (dans une fenêtre
  modale, sans quitter la position dans la liste), activent ou désactivent les règles, et
  suppriment les règles personnalisées. Une règle par défaut peut être
  modifiée (badge « Par défaut, modifiée ») ou désactivée, mais pas supprimée. Le bouton
  **Recharger** applique immédiatement un changement fait avec la CLI
  `security-review-controller rules`.
- **Utilisateurs** : les administrateurs gèrent les [comptes](#comptes-utilisateurs), seuls
  à ouvrir l'interface. Chaque compte est **Local** (identifiant et mot de passe, saisi ou généré
  et affiché une seule fois) ou **SSO** (connexion par le fournisseur d'identité, sans mot de
  passe), avec un badge dans la liste. L'administrateur choisit le rôle `reader`, `triager` ou
  `admin` et, pour `reader` et `triager`, les projets. Un compte SSO peut n'avoir aucun rôle
  propre : la colonne **Rôle des groupes** montre alors le rôle que ses groupes lui ont donné à sa
  dernière connexion. L'administrateur change le rôle et les projets d'un compte, réinitialise le
  mot de passe d'un compte local ou supprime un compte. Un compte SSO supprimé n'est plus recréé
  à sa connexion : la section **Comptes SSO supprimés** les liste, avec le bouton **Autoriser à
  nouveau**. Le dernier administrateur, local ou SSO, ne peut être ni supprimé ni rétrogradé.
- **Mon compte** : affiche le type du compte. Un utilisateur local y change son mot de passe (ses
  autres sessions sont fermées) ; celui d'un utilisateur SSO est géré par le fournisseur
  d'identité.
- **Jetons** : les administrateurs créent et révoquent des jetons limités à un ou plusieurs
  projets. Le champ **Usage** choisit **MCP** (rôle `mcp`) ou **API REST** ; pour l'API REST,
  **Droits API** choisit **Lecture seule** (`reader`) ou **Lecture et triage** (`triager`). La
  liste affiche l'usage de chaque jeton. Un jeton n'ouvre jamais l'interface web. Le rôle `admin` reste non restreint et se crée par la
  CLI. Le secret n'est montré qu'une fois ; seule son empreinte est enregistrée, dans la base de
  données. Une révocation prend effet à la requête suivante. La section
  **Demandes en attente** distingue les nouveaux jetons des demandes d'accès à un projet
  supplémentaire ([enrôlement](../getting-started/http.md#enrolement-un-projet-demande-son-jeton)) :
  **Approuver** active le nouveau jeton ou ajoute le projet au jeton existant ; **Refuser** ne
  supprime que la demande. Les projets autorisés et les ajouts encore en attente sont affichés
  pour chaque jeton. La colonne **Lecture dans le portail** permet de donner en même temps au
  développeur la lecture du projet dans l'interface web, sur son compte utilisateur (voir
  [lecture du projet à l'enrôlement](#lecture-du-projet-a-lenrolement)).
- **Rôles SSO** : les administrateurs [configurent la connexion SSO](#configurer-le-sso-dans-linterface)
  (chaque valeur enregistrée remplace sa variable `SECREVIEW_OIDC_*`, avec un test de connexion
  au fournisseur) et associent les groupes ou rôles du fournisseur d'identité à un rôle web et,
  pour `reader` et `triager`, à une liste de projets (voir [role mapping](#role-mapping)). Les
  groupes de la configuration SSO (`*_GROUPS`) sont affichés en lecture seule dans la liste des
  associations. Les utilisateurs SSO eux-mêmes se gèrent dans l'écran **Utilisateurs**.
- **Paramètres** : réglages enregistrés en base, prioritaires sur les variables d'environnement
  et partagés par le serveur MCP et le contrôleur.
    - **Langue des rapports** : variable `SECREVIEW_REPORT_LANGUAGE`, choix laissé à l'agent ou
      langue définie ici (`French`, `fr`, `pt-BR`…). Elle s'applique aux prochains prompts de
      revue ; l'argument `report_language` d'un prompt reste prioritaire
      ([langue des rapports](prompts-tools.md#langue-des-rapports)).
    - **Proxy sortant du contrôleur** : proxy du téléchargement OSV **et** de la
      [connexion SSO](#connexion-sso-openid-connect). Comme pour la configuration SSO, chaque
      valeur définie ici remplace sa variable (badges **Variable** / **Interface web**) :
      l'URL suit `SECREVIEW_PROXY` (sinon `HTTPS_PROXY` / `NO_PROXY`), est définie ici, ou force
      la connexion directe ; les **hôtes sans proxy** suivent `SECREVIEW_NO_PROXY` ou sont
      définis ici (voir [hôtes sans proxy](dependencies.md#hotes-sans-proxy) : domaines, adresses
      IP, plages CIDR, `*`). Le changement s'applique au prochain
      téléchargement et à la prochaine connexion SSO, sans redémarrage. Le proxy appliqué, son
      origine et les variables de l'environnement sont affichés ; les mots de passe ne sont
      jamais réaffichés (`***`) : renvoyer `***` conserve celui enregistré. Par l'API :
      `PUT /api/v1/settings/proxy` avec `url` et `no_proxy` (`null` applique de nouveau la
      variable, `"url": ""` force la connexion directe, un champ absent est inchangé).
    - **Base de vulnérabilités OSV** : nombre d'avis par écosystème, date et âge du dernier
      import, configuration du téléchargement, historique des 50 dernières mises à jour
      (planifiée, CLI ou interface web, avec statut, durée et résultat par écosystème) et bouton
      **Mettre à jour maintenant**, disponible seulement si `SECREVIEW_OSV_AUTO_UPDATE=true`
      ([mise à jour par le contrôleur](dependencies.md#mise-a-jour-automatique-par-le-controleur)).

## Rôles

Les **jetons** donnent accès au serveur MCP et à l'API REST (agents, CI, scripts) ; les
**utilisateurs** (comptes locaux ou SSO) sont les seuls à ouvrir l'interface web. Chaque jeton
porte un rôle, qui détermine les endpoints accessibles :

| Rôle | Usage (écran **Jetons**) | `/mcp` | API REST (lecture) | Changement de statut |
|---|---|---|---|---|
| `mcp` (défaut) | MCP | ✅ | — | — |
| `reader` | API REST — lecture seule | — | ✅ | — |
| `triager` | API REST — lecture et triage | — | ✅ | ✅ |
| `admin` | CLI uniquement | ✅ | ✅ | ✅ |

Un jeton `mcp`, `reader` ou `triager` restreint avec `--project` ne voit et ne trie que les
projets autorisés ; l'option peut être répétée (voir
[jetons restreints à un projet](../getting-started/http.md#jetons-restreints-a-un-projet)).

Les personnes se connectent avec un [compte utilisateur](#comptes-utilisateurs) : local
(identifiant et mot de passe) ou [SSO](#connexion-sso-openid-connect). Les comptes portent les
rôles `reader`, `triager` ou `admin`, jamais `mcp`, et n'ouvrent jamais `/mcp`. Un jeton créé
sans rôle reste `mcp` : il sert aux agents et à la CI, pas à l'interface web. Le rôle `triager`
ajoute uniquement le triage des findings. Un jeton `reader`, `triager` ou `admin` appelle l'API
REST, par exemple depuis un script, mais **n'ouvre pas l'interface** (la page de connexion ne
propose que les comptes) :

```bash
security-review-controller token create --label triage-bot --role triager
# {"id": "…", "label": "triage-bot", "role": "triager", "project": null, "created_at": "…", "token": "UJB7…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/projects
```

Révoquez-le avec `security-review-controller token revoke triage-bot`. Chaque changement de
statut est journalisé avec le label du jeton ou du compte :

```
INFO security_review_mcp.web: Finding 42 set to accepted by triage-bot
```

!!! warning "Authentification requise pour la Web UI"
    L'API de l'interface refuse les requêtes avec le statut `503` tant qu'aucun utilisateur ni
    jeton n'existe ; la mire de connexion reste affichée et indique que l'authentification doit
    être configurée. Activez `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` (c'est le cas dans l'image Docker),
    ou créez un compte avec `security-review-controller user create`. Cette restriction concerne
    la Web UI ; l'authentification MCP reste indépendante (un compte utilisateur n'ouvre jamais
    `/mcp`). Avec la [connexion SSO](#connexion-sso-openid-connect), l'API demande une connexion
    (`401`) même sans utilisateur ni jeton en base.

## Comptes utilisateurs

Un compte associe un **identifiant** (lettres, chiffres et `. _ @ -`, 64 caractères au plus), un
**type** et un rôle web : `reader`, `triager` ou `admin`. Un compte `reader` ou `triager` peut
être limité à une liste de projets ; un compte `admin` voit tous les projets.

| Type (`auth_source`) | Connexion | Création |
|---|---|---|
| **Local** (`local`) | Identifiant et mot de passe | Par un administrateur, ou le compte `admin` initial |
| **SSO** (`oidc`) | [Fournisseur d'identité](#connexion-sso-openid-connect), sans mot de passe | Par un administrateur, à l'approbation d'un enrôlement, ou à la première connexion si `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` |

Un compte SSO peut n'avoir **aucun rôle propre** : seul le rôle donné par ses groupes
s'applique (voir [comptes SSO](#comptes-sso)). Les comptes se gèrent dans l'écran
**Utilisateurs**, par l'API REST `/api/v1/users` (rôle `admin`) ou par la
[CLI](../reference/cli.md#security-review-controller) :

```bash
security-review-controller user create alice --role triager --project shop-api
# {"id": 2, "username": "alice", "auth_source": "local", "role": "triager", "projects": ["shop-api"], …, "password": "q3V…"}
printf '%s\n' "$PASSWORD" | security-review-controller user create bob --password-stdin
security-review-controller user create carol@example.com --sso --role none   # rôle des groupes
security-review-controller user create dave --sso --role reader --project billing
security-review-controller user list
security-review-controller user set-role alice --role reader
security-review-controller user reset-password alice   # compte local : nouveau mot de passe, sessions fermées
security-review-controller user delete alice
```

Par l'API, un compte SSO se crée avec `"auth_source": "oidc"`, sans `password` ; `"role": null`
le laisse sans rôle propre :

```bash
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "carol@example.com", "auth_source": "oidc", "role": null}'
```

Pour un compte local, sans `--password-stdin` (ou sans mot de passe dans l'interface), un mot de
passe aléatoire de 24 caractères est généré et affiché **une seule fois**. Un mot de passe choisi
compte 12 à 256 caractères. Un compte SSO n'a jamais de mot de passe : la connexion par
identifiant et mot de passe, la réinitialisation et **Mon compte** le refusent.

### Premier administrateur

Avec `SECREVIEW_AUTH_BOOTSTRAP_ADMIN=true` (c'est le cas dans l'image Docker), le contrôleur crée
au premier démarrage l'utilisateur **`admin`**, de rôle `admin`, tant qu'aucun compte n'existe.
Son mot de passe est affiché une seule fois dans les journaux du contrôleur :

```
WARNING security_review_mcp.controller: Initial Web UI administrator created: user 'admin', password (shown once): …
```

Traitez ce mot de passe comme un secret : restreignez l'accès aux journaux, connectez-vous avec
`admin` et changez-le depuis **Mon compte**. S'il est perdu, générez-en un nouveau (l'ancien est
aussitôt invalidé) : `security-review-controller user reset-password admin`.

!!! note "Mise à jour depuis le jeton `bootstrap-admin`"
    Les versions précédentes créaient un **jeton** `bootstrap-admin` à la place du compte. Sur une
    base existante, ce jeton reste valable ; le compte `admin` est créé au démarrage suivant s'il
    n'existe aucun compte. Une fois connecté avec le compte, révoquez l'ancien jeton :
    `security-review-controller token revoke bootstrap-admin`.

### Connexion et sessions

La page de connexion propose l'identifiant et le mot de passe d'un compte local et, avec la
[connexion SSO](#connexion-sso-openid-connect), le bouton du fournisseur d'identité ; elle
n'accepte pas de jeton. `POST /api/v1/auth/login` vérifie le mot de passe d'un compte local et
renvoie un **jeton de session** signé, valable `SECREVIEW_SESSION_HOURS` heures (8 par défaut),
que l'onglet utilise comme un jeton Bearer :

```bash
curl -s -X POST https://secreview.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username": "alice", "password": "…"}'
# {"session": "eyJ…", "expires_in": 28800, "username": "alice", "role": "triager"}
```

Chaque session désigne un compte (local ou SSO) ; à chaque requête, le contrôleur le relit en
base :

- un changement de **rôle ou de projets** s'applique immédiatement aux sessions ouvertes ;
- une **suppression** ou un **nouveau mot de passe** (changé par l'utilisateur ou réinitialisé
  par un administrateur) ferme toutes les sessions du compte ; `PUT /api/v1/me/password` remet une
  nouvelle session à l'onglet qui a changé le mot de passe.

Les sessions sont signées avec `SECREVIEW_SESSION_SECRET` (32 caractères au moins), partagé par
toutes les répliques du contrôleur ; sans lui, un secret aléatoire est tiré à chaque démarrage et
les sessions se terminent au redémarrage (un avertissement est journalisé).

Les échecs de connexion sont limités : après **5 échecs en 15 minutes** pour un identifiant
depuis une même adresse, ou **20 échecs** depuis une adresse tous identifiants confondus, la
connexion est refusée (`429`, en-tête `Retry-After`), même avec le bon mot de passe. Le compteur
est tenu en mémoire par chaque réplique. Derrière un reverse proxy, l'adresse vue est celle du
proxy : la limite s'applique alors à tous les clients du proxy. Chaque connexion et chaque échec
sont journalisés, sans le mot de passe :

```
INFO security_review_mcp.web: Web login of alice (role triager) from 10.0.0.12
WARNING security_review_mcp.web: Failed web login of alice from 10.0.0.12
```

## Connexion SSO (OpenID Connect)

Le contrôleur peut déléguer la connexion à l'interface à un fournisseur d'identité OpenID
Connect (Keycloak, Microsoft Entra ID, Okta, Authentik, Dex...). La page de connexion affiche
alors un bouton **Se connecter avec SSO** au-dessus du formulaire des comptes locaux, qui reste
disponible (compte `admin` initial, comptes de secours).

Le flux utilisé est le *authorization code* avec PKCE (`S256`), state et nonce :

1. `GET /api/v1/auth/oidc/login` redirige le navigateur vers le fournisseur ;
2. le fournisseur renvoie sur `GET /api/v1/auth/oidc/callback` ; le contrôleur échange le code
   (appel serveur à serveur), vérifie l'ID token (signature par les clés JWKS du fournisseur,
   émetteur, audience, expiration, nonce), retrouve le [compte SSO](#comptes-sso) de
   l'utilisateur (ou le crée) et enregistre le rôle donné par ses groupes ;
3. il remet à l'interface un **jeton de session** signé, valable
   `SECREVIEW_SESSION_HOURS` heures, que l'onglet utilise comme un jeton Bearer.

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
SECREVIEW_OIDC_AUTO_CREATE_USERS=true       # sinon, créez chaque compte SSO dans Utilisateurs
SECREVIEW_SESSION_SECRET=$(openssl rand -base64 48)
SECREVIEW_OIDC_DISPLAY_NAME=Keycloak
```

L'émetteur doit être en HTTPS (HTTP n'est accepté que sur `localhost`, pour le développement) ;
son document `/.well-known/openid-configuration` doit annoncer le même `issuer`. Si le
fournisseur utilise une CA interne, indiquez-la avec `SECREVIEW_OIDC_CAFILE`. Le contrôleur joint
le fournisseur par son proxy sortant (`SECREVIEW_PROXY` / `SECREVIEW_NO_PROXY`, ou l'écran
**Paramètres**), sinon par `HTTPS_PROXY` / `NO_PROXY`.

### Configurer le SSO dans l'interface

Les mêmes réglages se modifient dans la section **Configuration SSO** de l'écran **Rôles SSO**
(rôle `admin`), sans redémarrer le contrôleur. Comme pour l'écran **Paramètres**, une valeur
enregistrée en base **remplace sa variable** `SECREVIEW_OIDC_*`, champ par champ ; un champ jamais
modifié suit sa variable :

- chaque champ porte le badge **Variable** (la variable s'applique, sa valeur est rappelée sous le
  champ) ou **Interface web** (valeur enregistrée) ; le lien **Variable** d'un champ enregistré
  supprime la valeur stockée et applique de nouveau la variable ;
- le **secret client** n'est jamais réaffiché : laissé vide, le secret actuel est conservé ;
  **Supprimer** enregistre un secret vide (client public, PKCE seul) ;
- **Tester la connexion** contacte le fournisseur avec les valeurs du formulaire, sans les
  enregistrer : lecture du document `/.well-known/openid-configuration` (même `issuer`, points
  de terminaison en HTTPS), puis des clés de signature (JWKS) ;
- **Enregistrer** refuse (`422`) une configuration qui activerait une connexion invalide (émetteur
  manquant ou non HTTPS, scopes sans `openid`, rôle par défaut inconnu...) : rien n'est alors
  enregistré. Une configuration incomplète peut être préparée tant que le SSO reste désactivé.

Le changement s'applique à la connexion suivante, sur toutes les répliques (le contrôleur relit
la configuration à chaque connexion et reconstruit le flux OIDC quand elle change). Les sessions
déjà ouvertes restent valides jusqu'à leur expiration. Restent des variables uniquement :
`SECREVIEW_OIDC_CAFILE` (un fichier du déploiement) et les réglages de session
(`SECREVIEW_SESSION_SECRET`, `SECREVIEW_SESSION_HOURS`). Si une variable modifiée après coup rend
invalide la combinaison avec les valeurs enregistrées, le contrôleur démarre quand même : la
connexion SSO est désactivée et l'erreur journalisée, à corriger dans l'écran.

Par l'API (`/api/v1/oidc/settings`, rôle `admin`) : `GET` décrit chaque réglage (`value`
enregistrée ou `null`, `env`, `effective` ; un secret défini vaut `***`), `PUT` modifie les champs
envoyés (`null` applique de nouveau la variable, un champ absent est inchangé) et
`POST /api/v1/oidc/settings/test` teste le fournisseur sans rien enregistrer :

```bash
curl -X PUT https://secreview.example.com/api/v1/oidc/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled": true, "issuer": "https://sso.example.com/realms/acme",
       "client_id": "security-review", "client_secret": "...",
       "redirect_uri": "https://secreview.example.com/api/v1/auth/oidc/callback",
       "display_name": null}'
```

### Comptes SSO

Chaque utilisateur SSO est un compte de l'écran **Utilisateurs** (badge **SSO**), nommé par la
valeur du claim `SECREVIEW_OIDC_USERNAME_CLAIM` (`preferred_username` par défaut), comparée
exactement, casse comprise. Il n'y a pas de repli sur `email` ou `sub`, et une valeur qui n'est
pas un identifiant valide (caractère de contrôle ou invisible, espace, plus de 64 caractères) est
refusée.

À la connexion, le contrôleur cherche ce compte :

| Situation | Résultat |
|---|---|
| Compte SSO existant | Connexion, avec le rôle effectif ci-dessous |
| Aucun compte, `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` | Le compte est **créé** (`created_by` : `oidc`) si ses groupes ou le rôle par défaut lui donnent un rôle ; sinon refus, sans création |
| Aucun compte, `SECREVIEW_OIDC_AUTO_CREATE_USERS=false` (défaut) | **Refus** : un administrateur doit d'abord créer le compte SSO |
| Compte **local** du même nom | **Refus** : une connexion SSO n'ouvre jamais un compte local |
| Compte SSO lié à un autre `sub` | **Refus** (voir ci-dessous) |
| Compte SSO supprimé par un administrateur | **Refus**, même avec la création automatique (voir ci-dessous) |

À la première connexion, le compte est **lié** au claim `sub` du fournisseur ; une connexion
ultérieure avec le même identifiant mais un autre `sub` (compte du fournisseur supprimé puis
recréé, renommé...) est refusée. Pour réattribuer l'identifiant, supprimez puis recréez le
compte.

Le **rôle effectif** combine le rôle attribué au compte (écran **Utilisateurs**, ou approbation
d'un enrôlement) et celui de ses groupes ([role mapping](#role-mapping)), enregistré à chaque
connexion : le plus élevé l'emporte, et ses projets sont l'union de ceux des deux accès de ce
rôle. Un compte sans rôle propre ni rôle de groupe est refusé et ses sessions ouvertes se
ferment. Le rôle attribué s'applique aussitôt ; celui des groupes, à la prochaine connexion.

**Supprimer un compte SSO** (écran **Utilisateurs**, `DELETE /api/v1/users/{id}` ou
`security-review-controller user delete NOM`) ferme aussitôt ses sessions et **révoque** son
identifiant : une connexion SSO ne le recrée plus, même avec la création automatique et des
groupes qui lui donnent un rôle (message « compte supprimé » sur la page de connexion). Pour lui
rendre l'accès, un administrateur recrée le compte (à la main ou à l'approbation d'un enrôlement),
ou lève la révocation (**Autoriser à nouveau**, `DELETE /api/v1/users/revoked/{identifiant}`) :
le compte est alors recréé à sa prochaine connexion. `GET /api/v1/users/revoked` liste les
comptes révoqués, avec l'auteur et la date de la suppression.

Le **dernier administrateur** ne peut être ni supprimé ni rétrogradé. Est administrateur un
compte local ou SSO dont le rôle attribué est `admin`, ou un compte SSO auquel ses groupes ont
donné `admin` à sa dernière connexion. Gardez de préférence un administrateur local : si le
fournisseur d'identité devient injoignable, il reste le seul accès, en plus de la CLI.

```
INFO security_review_mcp.web: SSO web user alice created at its first login
INFO security_review_mcp.web: OIDC login of oidc:alice with role reader on every project
WARNING security_review_mcp.web: OIDC login of oidc:bob refused: no web user bob
INFO security_review_mcp.web: Web user carol (oidc) deleted by admin
WARNING security_review_mcp.web: OIDC login of oidc:carol refused: web user carol was deleted
```

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
   `triager`, tous les projets) ; vide (défaut), les groupes ne donnent aucun rôle et seul le
   rôle attribué au [compte SSO](#comptes-sso) permet encore la connexion, sinon elle est
   **refusée**. Le rôle `admin` ne peut pas être attribué par défaut.

Ce rôle de groupe est ensuite combiné avec le rôle attribué au compte (voir
[comptes SSO](#comptes-sso)).

Une session restreinte se comporte comme un
[jeton restreint à un projet](../getting-started/http.md#jetons-restreints-a-un-projet) : les autres
projets, leurs rapports et leurs findings sont traités comme inexistants. Un projet peut être
cité avant d'exister (l'écran propose les projets connus). Un changement d'association
s'applique à la **prochaine connexion** de l'utilisateur ; d'ici là, ses sessions ouvertes gardent
le rôle de groupe enregistré (voir [Sessions](#sessions)). Chaque création, modification ou
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

Le label d'une session SSO est `oidc:<identifiant>` : c'est lui qui apparaît dans les journaux et
l'historique du triage.

### Lecture du projet à l'enrôlement

À l'approbation d'une demande d'[enrôlement](../getting-started/http.md#enrolement-un-projet-demande-son-jeton),
l'administrateur peut aussi donner au développeur la lecture du projet dans le portail, sur son
**compte utilisateur** : le développeur qui a demandé un jeton MCP pour un projet en consulte
alors les rapports.

- Dans l'écran **Jetons de projet**, la colonne **Lecture dans le portail** est préremplie avec le
  demandeur (`requested_by`) quand il est renseigné, et cochée quand le SSO est activé. Ce champ
  est déclaré par le client et **n'est pas vérifié** : contrôlez-le ou corrigez-le avant
  d'approuver, ou décochez la case.
- Le nom désigne un compte de l'écran **Utilisateurs**, local ou SSO. Avec le SSO activé, un nom
  inconnu devient un **compte SSO** (`reader` sur le projet), prêt pour sa première connexion ;
  sans SSO, le compte doit exister.
- Un compte sans rôle propre devient `reader` sur le projet ; un compte `reader` ou `triager`
  restreint reçoit un projet de plus ; un compte qui voit déjà tous les projets est inchangé. Une
  demande complémentaire approuvée pour le même utilisateur ajoute le projet de la même façon.

L'accès figure ensuite sur le compte, où il se modifie comme les autres. Il est indépendant du
jeton MCP : révoquer le jeton ne le supprime pas.

```bash
# Approuver une demande en donnant la lecture du projet à l'utilisateur « alice »
curl -X POST https://secreview.example.com/api/v1/enrollments/$REQUEST_ID/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"portal_user": "alice"}'
```

La réponse contient alors `portal_user`, le compte mis à jour. Un identifiant invalide, un compte
inconnu sans SSO ou une limite atteinte sont refusés (`422`) avant l'approbation : la demande reste
en attente. Le journal du contrôleur trace l'accès :

```
INFO security_review_mcp.web: Web access to shop-api given to web user alice by admin
```

!!! note "Mise à jour depuis les accès nominatifs"
    Les versions précédentes enregistraient ces accès à part (« accès nominatifs », API
    `/api/v1/oidc/user-grants`). La migration de schéma `0006` les transforme en comptes SSO
    `reader` sur les mêmes projets, puis supprime la table. Un accès dont le nom n'est pas un
    identifiant valide ou qui porte le nom d'un compte local est abandonné, avec un avertissement
    dans le journal de la migration.

### Sessions

- Le jeton de session est signé (HMAC-SHA256) avec une clé dérivée de `SECREVIEW_SESSION_SECRET`
  (32 caractères au moins), comme celui des [comptes locaux](#connexion-et-sessions), et désigne
  le compte SSO, relu à chaque requête : supprimer le compte ou changer son rôle attribué
  s'applique aussitôt. Toutes les répliques du contrôleur doivent partager ce secret ; sans lui,
  un secret aléatoire est tiré à chaque démarrage et les sessions se terminent au redémarrage (un
  avertissement est journalisé).
- Un changement de groupe chez le fournisseur ne s'applique qu'à la connexion suivante. Pour
  couper toutes les sessions avant leur expiration, supprimez le compte, ou changez
  `SECREVIEW_SESSION_SECRET` et redémarrez le contrôleur (toutes les sessions sont coupées).
- **Se déconnecter** efface la session de l'onglet, pas celle du fournisseur d'identité.

En cas d'échec, la page de connexion indique la cause (accès refusé chez le fournisseur, aucun
rôle, compte SSO pas encore créé ou supprimé, identifiant pris par un compte local ou lié à un autre compte,
identifiant manquant, état expiré, jeton invalide, fournisseur injoignable) ; le détail est
journalisé par le contrôleur, sans code ni jeton.

## Sécurité

- Les fichiers statiques de `/ui/` sont publics (ils ne contiennent aucune donnée) ; l'API
  `/api/v1/` exige une session ou un jeton `reader`, `triager` ou `admin`. Seules les routes de
  connexion (`/api/v1/auth/…`) sont publiques.
- Les mots de passe des comptes ne sont jamais stockés : seule une empreinte **scrypt** salée
  (N=2¹⁴, r=8, p=5) est enregistrée et aucune réponse de l'API ne la renvoie. La vérification
  prend le même temps que l'identifiant existe ou non, et la réponse d'échec est identique. La documentation Swagger (`/api/docs`)
  et son schéma (`/api/openapi.json`) sont publics et ne donnent accès à aucune donnée.
  Dans Swagger, le cadenas d'une route indique qu'elle exige un jeton : il reste **ouvert**
  tant que vous n'avez pas saisi de jeton avec **Authorize**, et ne veut pas dire que la route
  est accessible sans jeton.
- Le contrôleur n'expose aucune route d'écriture sans jeton. Les demandes
  d'[enrôlement](../getting-started/http.md#enrolement-un-projet-demande-son-jeton) sont déposées sur
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
- Servez l'interface en HTTPS ([TLS intégré ou reverse proxy](../getting-started/http.md#tls)) dès
  qu'elle n'écoute plus sur localhost : le jeton circule à chaque requête.

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_WEB_UI` | `true` | Sert l'interface sur `/ui` ; à `false`, le contrôleur ne sert que l'API REST |
| `SECREVIEW_WEB_UI_DIR` | — | Dossier d'une autre build de l'application (défaut : celle du paquet) |
| `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` | `false` | Crée le compte `admin` au premier démarrage du contrôleur, tant qu'aucun compte n'existe ; `true` dans Docker |
| `SECREVIEW_SESSION_SECRET` | — | Secret de signature des sessions (32 caractères au moins), identique sur toutes les répliques |
| `SECREVIEW_SESSION_HOURS` | `8` | Durée d'une session (1 à 24 heures), connexion par compte local ou SSO |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Crée le [compte SSO](#comptes-sso) à la première connexion ; sinon un administrateur le crée |
| `SECREVIEW_ENROLLMENT` | `true` | Demandes de jetons par les projets (sur le serveur MCP), validées dans l'écran **Jetons** |
| `SECREVIEW_OIDC_*` | — | [Connexion SSO](#connexion-sso-openid-connect), voir la [référence](../reference/configuration.md) |

Le paquet publié et l'image Docker contiennent l'application déjà compilée. Si vous installez
depuis les sources sans la compiler, le contrôleur ne sert que l'API REST et un avertissement est
journalisé. Voir [Contribuer](../contributing.md#interface-web) pour la compiler.
