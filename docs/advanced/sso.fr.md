# Connexion OIDC (OpenID Connect)

Cette page est facultative : les [comptes locaux](../usage/web-interface.md#comptes-utilisateurs)
suffisent pour démarrer. Elle sert à connecter les personnes à l'interface web avec votre
fournisseur d'identité.

Le contrôleur peut déléguer la connexion à l'interface à un fournisseur d'identité OpenID
Connect (Keycloak, Microsoft Entra ID, Okta, Authentik, Dex...). La page de connexion affiche
alors un bouton **Se connecter avec OIDC** au-dessus du formulaire des comptes locaux, qui reste
disponible (compte `admin` initial, comptes de secours).

Le flux utilisé est le *authorization code* avec PKCE (`S256`), state et nonce :

1. `GET /api/v1/auth/oidc/login` redirige le navigateur vers le fournisseur ;
2. le fournisseur renvoie sur `GET /api/v1/auth/oidc/callback` ; le contrôleur échange le code
   (appel serveur à serveur), vérifie l'ID token (signature par les clés JWKS du fournisseur,
   émetteur, audience, expiration, nonce), retrouve le [compte OIDC](#comptes-oidc) de
   l'utilisateur (ou le crée) et enregistre les groupes nommés par son claim des groupes ;
3. il remet à l'interface un **jeton de session** signé, valable
   `SECREVIEW_SESSION_HOURS` heures, que l'onglet utilise comme un jeton Bearer.

## Déclarer le client chez le fournisseur

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
SECREVIEW_OIDC_ADMIN_GROUPS=secreview-admins   # créé avec le rôle admin (premier administrateur)
SECREVIEW_OIDC_AUTO_CREATE_USERS=true       # sinon, créez chaque compte OIDC dans Utilisateurs
SECREVIEW_SECRET_KEY=$(openssl rand -base64 48)
SECREVIEW_OIDC_DISPLAY_NAME=Keycloak
```

L'émetteur doit être en HTTPS (HTTP n'est accepté que sur `localhost`, pour le développement) ;
son document `/.well-known/openid-configuration` doit annoncer le même `issuer`. Si le
fournisseur utilise une CA interne, indiquez-la avec `SECREVIEW_OIDC_CAFILE`. Le contrôleur joint
le fournisseur par son proxy sortant (`HTTPS_PROXY` / `NO_PROXY`, ou l'écran **Proxy sortant**).

## Configurer le OIDC dans l'interface

Les mêmes réglages se modifient dans l'écran **OIDC** (permission `users.manage` : la
configuration OIDC décide qui rejoint quel groupe), sans redémarrer le contrôleur. Comme pour
l'écran **Proxy sortant**, **une variable `SECREVIEW_OIDC_*` définie est toujours
prioritaire**, champ par champ ; une valeur enregistrée en base ne s'applique qu'aux champs dont
la variable n'est pas définie :

- un champ dont la variable est définie porte le badge **Variable** (avec un cadenas) : il
  affiche la variable et ne se modifie pas ; une valeur enregistrée avant que la variable soit
  définie est signalée *valeur définie ici ignorée*, avec un lien **Supprimer** ;
- sinon le champ porte le badge **Interface web** (valeur enregistrée ; **Réinitialiser** la
  supprime et la valeur par défaut s'applique de nouveau) ou **Par défaut** ;
- le **secret client** n'est jamais réaffiché : laissé vide, le secret actuel est conservé ;
  **Supprimer** enregistre un secret vide (client public, PKCE seul) ;
- **Tester la connexion** contacte le fournisseur avec les valeurs du formulaire, sans les
  enregistrer : lecture du document `/.well-known/openid-configuration` (même `issuer`, points
  de terminaison en HTTPS), puis des clés de signature (JWKS) ;
- **Enregistrer** refuse (`422`) une configuration qui activerait une connexion invalide (émetteur
  manquant ou non HTTPS, scopes sans `openid`...) : rien n'est alors
  enregistré. Une configuration incomplète peut être préparée tant que le OIDC reste désactivé.

Le changement s'applique à la connexion suivante, sur toutes les répliques (le contrôleur relit
la configuration à chaque connexion et reconstruit le flux OIDC quand elle change). Les sessions
déjà ouvertes restent valides jusqu'à leur expiration. Restent des variables uniquement :
`SECREVIEW_OIDC_CAFILE` (un fichier du déploiement) et les réglages de session
(`SECREVIEW_SECRET_KEY`, `SECREVIEW_SESSION_HOURS`). Si une variable modifiée après coup rend
invalide la combinaison avec les valeurs enregistrées, le contrôleur démarre quand même : la
connexion OIDC est désactivée et l'erreur journalisée, à corriger dans l'écran ou dans les
variables.

Par l'API (`/api/v1/oidc/settings`, permission `users.manage`) : `GET` décrit chaque réglage (`value`
enregistrée ou `null`, `env`, `env_set` : la variable est définie et prioritaire, `effective` ;
un secret défini vaut `***`), `PUT` modifie les champs envoyés (`null` supprime la valeur
enregistrée, un champ absent est inchangé, un champ dont la variable est définie est refusé
avec `422`) et
`POST /api/v1/oidc/settings/test` teste le fournisseur sans rien enregistrer :

```bash
curl -X PUT https://secreview.example.com/api/v1/oidc/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled": true, "issuer": "https://sso.example.com/realms/acme",
       "client_id": "security-review", "client_secret": "...",
       "redirect_uri": "https://secreview.example.com/api/v1/auth/oidc/callback",
       "display_name": null}'
```

## Comptes OIDC

Chaque utilisateur OIDC est un compte de l'écran **Utilisateurs** (badge **OIDC**), nommé par la
valeur du claim `SECREVIEW_OIDC_USERNAME_CLAIM` (`preferred_username` par défaut), comparée
exactement, casse comprise. Il n'y a pas de repli sur `email` ou `sub`, et une valeur qui n'est
pas un identifiant valide (caractère de contrôle ou invisible, espace, plus de 64 caractères) est
refusée.

À la connexion, le contrôleur cherche ce compte :

| Situation | Résultat |
|---|---|
| Compte OIDC existant | Connexion, avec les permissions de ses groupes (ci-dessous) |
| Aucun compte, `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` | Le compte est **créé** (`created_by` : `oidc`) si ses groupes lui donnent une permission ; sinon refus, sans création |
| Aucun compte, `SECREVIEW_OIDC_AUTO_CREATE_USERS=false` (défaut) | **Refus** : un administrateur doit d'abord créer le compte OIDC |
| Compte **local** du même nom | **Refus** : une connexion OIDC n'ouvre jamais un compte local |
| Compte OIDC lié à un autre `sub` ou à un autre émetteur | **Refus** (voir ci-dessous) |
| Compte OIDC supprimé par un administrateur | **Refus**, même avec la création automatique (voir ci-dessous) |

À la première connexion, le compte est **lié** à l'émetteur (issuer) et au claim `sub` du
fournisseur : le compte est identifié par les deux. Une connexion ultérieure avec le même
identifiant mais un autre `sub` (compte du fournisseur supprimé puis recréé, renommé...) ou
venant d'un autre émetteur (un autre fournisseur d'identité, qui pourrait réutiliser le même
`sub`) est refusée. Un compte lié quand seul le `sub` était enregistré reçoit l'émetteur de sa
connexion suivante. Pour réattribuer l'identifiant, supprimez puis recréez le
compte.

Ce qu'un compte OIDC peut faire vient de ses [groupes](access-control.md) : ceux qu'un
administrateur lui a donnés (écran **Utilisateurs** ou **Groupes**, approbation d'un enrôlement)
et les groupes ouverts au OIDC nommés par son claim des groupes, enregistrés à chaque connexion
(voir [groupes du fournisseur d'identité](#groupes-du-fournisseur-didentite)). Un compte sans
aucune permission est refusé et ses sessions ouvertes se ferment. Un changement de ses groupes
donnés s'applique aussitôt ; un changement de ses groupes chez le fournisseur, à la prochaine
connexion.

**Supprimer un compte OIDC** (écran **Utilisateurs**, `DELETE /api/v1/users/{id}` ou
`security-review-controller user delete NOM`) ferme aussitôt ses sessions et **révoque** son
identifiant : une connexion OIDC ne le recrée plus, même avec la création automatique et des
groupes qui lui donnent une permission (message « compte supprimé » sur la page de connexion). Pour lui
rendre l'accès, un administrateur recrée le compte (à la main ou à l'approbation d'un enrôlement),
ou lève la révocation (**Autoriser à nouveau**, `DELETE /api/v1/users/revoked/{identifiant}`) :
le compte est alors recréé à sa prochaine connexion. `GET /api/v1/users/revoked` liste les
comptes révoqués, avec l'auteur et la date de la suppression.

Le [dernier détenteur](access-control.md#le-dernier-administrateur) de la permission
`users.manage` ne peut être ni supprimé ni la perdre. Gardez de préférence un administrateur
local : si le fournisseur d'identité devient injoignable, il reste le seul accès, en plus de la
CLI.

```
INFO security_review_mcp.web: OIDC web user alice created at its first login
INFO security_review_mcp.web: OIDC login of oidc:alice with role reader through 1 OIDC group(s)
WARNING security_review_mcp.web: OIDC login of oidc:bob refused: no web user bob
INFO security_review_mcp.web: Web user carol (oidc) deleted by admin
WARNING security_review_mcp.web: OIDC login of oidc:carol refused: web user carol was deleted
```

## Groupes du fournisseur d'identité

Les valeurs du claim `SECREVIEW_OIDC_ROLES_CLAIM` (liste ou chaîne, chemin pointé accepté) sont
comparées aux **noms des groupes** de l'écran **Groupes** : à chaque connexion, l'utilisateur
rejoint chaque groupe **ouvert au OIDC** dont le nom est **exactement** l'une de ces valeurs (casse
comprise), et quitte les groupes OIDC qu'il n'a plus. Les autres valeurs sont ignorées : créez un
groupe du même nom pour en utiliser une. Les rôles du groupe, et leurs projets, s'appliquent alors
(voir [Rôles, groupes et permissions](access-control.md)).

| Réglage | Effet |
|---|---|
| `SECREVIEW_OIDC_ADMIN_GROUPS` | Groupes séparés par des virgules qui ont le rôle `admin` : un tel groupe, absent à la connexion de l'un de ses membres, est créé ouvert au OIDC avec le rôle `admin`. Un groupe existant reste tel que les administrateurs l'ont modifié. Sert à nommer le premier administrateur |
| `SECREVIEW_OIDC_DEFAULT_GROUP` | Nom d'un groupe que tout utilisateur OIDC rejoint à chaque connexion, quel que soit son claim (vide par défaut : aucun). Un groupe absent ne donne rien |

Un groupe **non ouvert au OIDC** (par exemple `administrators`) n'est jamais rejoint par le claim, même quand une valeur porte son nom. Une session
restreinte se comporte comme un [jeton restreint à un projet](http.md#jetons-restreints-a-un-projet) :
les autres projets, leurs rapports et leurs findings sont traités comme inexistants.

Exemple : avec le claim `["payments-team", "staff"]`, un groupe `payments-team` ouvert au OIDC avec
le rôle `triager` sur `billing`, et aucun groupe `staff`, l'utilisateur ne trie que `billing`.

Le label d'une session OIDC est `oidc:<identifiant>` : c'est lui qui apparaît dans les journaux et
l'historique du triage.

## Lecture du projet à l'enrôlement

À l'approbation d'une demande d'[enrôlement](http.md#enrolement-un-projet-demande-son-jeton),
l'administrateur peut aussi donner au développeur la lecture du projet dans le portail, sur son
**compte utilisateur** : le développeur qui a demandé un jeton MCP pour un projet en consulte
alors les rapports.

- Dans l'écran **Jetons de projet**, la colonne **Lecture dans le portail** est préremplie avec le
  demandeur (`requested_by`) quand il est renseigné, et cochée quand le OIDC est activé. Ce champ
  est déclaré par le client et **n'est pas vérifié** : contrôlez-le ou corrigez-le avant
  d'approuver, ou décochez la case.
- Le nom désigne un compte de l'écran **Utilisateurs**, local ou OIDC. Avec le OIDC activé, un nom
  inconnu devient un **compte OIDC**, prêt pour sa première connexion ; sans OIDC, le compte doit
  exister. Donner cet accès demande la permission `users.manage`.
- Un compte qui lit déjà ce projet est inchangé. Sinon il rejoint, comme membre local, le
  [groupe de projet](access-control.md#groupes-de-projet) `project:<projet>` (`reader` sur ce seul
  projet, créé s'il manque), partagé par tous les développeurs enrôlés sur le projet. Une demande
  complémentaire approuvée pour le même utilisateur ajoute le projet de la même façon.

L'accès figure ensuite dans les groupes du compte, où il se modifie comme les autres. Il est indépendant du
jeton MCP : révoquer le jeton ne le supprime pas.

```bash
# Approuver une demande en donnant la lecture du projet à l'utilisateur « alice »
curl -X POST https://secreview.example.com/api/v1/enrollments/$REQUEST_ID/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"portal_user": "alice"}'
```

La réponse contient alors `portal_user`, le compte mis à jour. Un identifiant invalide, un compte
inconnu sans OIDC ou une limite atteinte sont refusés (`422`) avant l'approbation : la demande reste
en attente. Le journal du contrôleur trace l'accès :

```
INFO security_review_mcp.web: Web access to shop-api given to web user alice by admin
```

!!! note "Mise à jour depuis les accès nominatifs"
    Les versions précédentes enregistraient ces accès à part (« accès nominatifs », API
    `/api/v1/oidc/user-grants`). La migration de schéma `0006` les transforme en comptes OIDC
    `reader` sur les mêmes projets, puis supprime la table. Un accès dont le nom n'est pas un
    identifiant valide ou qui porte le nom d'un compte local est abandonné, avec un avertissement
    dans le journal de la migration.

## OIDC seul

Avec `SECREVIEW_OIDC_ONLY=true`, le fournisseur d'identité devient la seule porte d'entrée : la
page de connexion ne propose que son bouton, et `POST /api/v1/auth/login` refuse l'identifiant et
le mot de passe des comptes locaux (`403`, journalisé). Les sessions déjà ouvertes restent
valables jusqu'à leur expiration.

```bash
SECREVIEW_OIDC_ENABLED=true
SECREVIEW_OIDC_ONLY=true
```

Il ne s'applique que tant que le OIDC fonctionne : OIDC désactivé, ou réglages refusés à leur
vérification, les comptes locaux se connectent de nouveau, pour que personne ne reste bloqué.
`SECREVIEW_OIDC_ONLY` est une variable uniquement, jamais modifiée dans l'interface : si le
fournisseur est indisponible, retirez-la et redémarrez le contrôleur, puis connectez-vous avec un
compte local (son mot de passe peut être défini avec
`security-review-controller user reset-password`).

## Sessions

- Le jeton de session est signé (HMAC-SHA256) avec une clé dérivée de `SECREVIEW_SECRET_KEY`
  (32 caractères au moins), comme celui des [comptes locaux](../usage/web-interface.md#connexion-et-sessions), et désigne
  le compte OIDC, relu à chaque requête : supprimer le compte ou changer ses groupes ou leurs
  rôles s'applique aussitôt. Toutes les répliques du contrôleur doivent partager ce secret ; sans lui,
  le secret de `SECREVIEW_SECRET_KEY_FILE` est utilisé, généré au premier démarrage.
- Un changement de groupe chez le fournisseur ne s'applique qu'à la connexion suivante. Pour
  couper toutes les sessions avant leur expiration, supprimez le compte, ou changez
  `SECREVIEW_SECRET_KEY` et redémarrez le contrôleur (toutes les sessions sont coupées).
- **Se déconnecter** efface la session de l'onglet, pas celle du fournisseur d'identité.

En cas d'échec, la page de connexion indique la cause (accès refusé chez le fournisseur, aucune
permission, compte OIDC pas encore créé ou supprimé, identifiant pris par un compte local ou lié à un autre compte,
identifiant manquant, état expiré, jeton invalide, fournisseur injoignable) ; le détail est
journalisé par le contrôleur, sans code ni jeton.
