# Connexion OIDC en détail

La page [connexion OIDC](../usage/sso.md) décrit la mise en place dans l'interface web. Cette
page donne le flux, les variables, l'API et les règles détaillées.

Le serveur Controller peut déléguer la connexion à l'interface à un fournisseur d'identité OpenID
Connect (Keycloak, Microsoft Entra ID, Okta, Authentik, Dex...). La page de connexion affiche
alors un bouton **Se connecter avec OIDC** au-dessus du formulaire des comptes locaux, qui reste
disponible (compte `admin` initial, comptes de secours).

Le flux utilisé est le *authorization code* avec PKCE (`S256`), state et nonce :

1. `GET /api/v1/auth/oidc/login` redirige le navigateur vers le fournisseur ;
2. le fournisseur renvoie sur `GET /api/v1/auth/oidc/callback` ; le serveur Controller échange le code
   (appel serveur à serveur), vérifie l'ID token (signature par les clés JWKS du fournisseur,
   émetteur, audience, expiration, nonce), retrouve le [compte OIDC](#comptes-oidc) de
   l'utilisateur (ou le crée) et garde les valeurs de son claim des rôles qu'une
   [correspondance OIDC](#correspondances-oidc) nomme ;
3. il remet à l'interface un **jeton de session** signé, valable
   `SECREVIEW_SESSION_HOURS` heures, que l'onglet utilise comme un jeton Bearer.

## Déclarer le client chez le fournisseur

Créez un client OIDC *confidentiel* (ou public, sans secret : PKCE suffit) avec :

- **URL de redirection** : `https://<contrôleur>/api/v1/auth/oidc/callback`, l'URL publique
  exacte vue par le navigateur (derrière un reverse proxy, celle du proxy) ;
- un claim contenant les groupes ou rôles de l'utilisateur dans l'ID token (ou, à défaut, dans
  la réponse *userinfo*, que le serveur Controller consulte quand l'ID token ne le contient pas).

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
fournisseur utilise une CA interne, indiquez-la avec `SECREVIEW_OIDC_CAFILE`. Le serveur Controller joint
le fournisseur par son proxy sortant (`HTTPS_PROXY` / `NO_PROXY`, ou la page **Général**).

## Configurer le OIDC dans l'interface

Les mêmes réglages se modifient dans la page **Connexions** (permission `users.manage` : la
configuration OIDC décide qui reçoit quel rôle), sans redémarrer le serveur Controller. Comme pour
le proxy de la page **Général**, **une variable `SECREVIEW_OIDC_*` définie est toujours
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

Le changement s'applique à la connexion suivante, sur toutes les répliques (le serveur Controller relit
la configuration à chaque connexion et reconstruit le flux OIDC quand elle change). Les sessions
déjà ouvertes restent valides jusqu'à leur expiration. Restent des variables uniquement :
`SECREVIEW_OIDC_CAFILE` (un fichier du déploiement) et les réglages de session
(`SECREVIEW_SECRET_KEY`, `SECREVIEW_SESSION_HOURS`). Si une variable modifiée après coup rend
invalide la combinaison avec les valeurs enregistrées, le serveur Controller démarre quand même : la
connexion OIDC est désactivée et l'erreur journalisée, à corriger dans la page ou dans les
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

Chaque utilisateur OIDC est un compte de la page **Utilisateurs** (badge **OIDC**), **identifié par
l'émetteur et le claim `sub`** liés à sa première connexion, jamais par un nom. Il est nommé à sa
création par la valeur du claim `SECREVIEW_OIDC_USERNAME_CLAIM` (`preferred_username` par défaut), comparée
exactement, casse comprise. Il n'y a pas de repli sur `email` ou `sub`, et une valeur qui n'est
pas un identifiant valide (caractère de contrôle ou invisible, espace, plus de 64 caractères) est
refusée.

À la connexion, le serveur Controller cherche d'abord le compte lié à l'émetteur et au `sub` de la
connexion : il s'ouvre, quoi que dise maintenant le claim d'identifiant (un nom changé chez le
fournisseur garde le compte et son identifiant). Seule une identité liée à aucun compte est
cherchée par son identifiant :

| Situation | Résultat |
|---|---|
| Compte lié à cet émetteur et à ce `sub` | Connexion, avec les permissions de ses rôles (ci-dessous), même si le claim d'identifiant a changé |
| Compte OIDC de ce nom, pas encore lié (créé par un administrateur) | Le compte est **lié** à l'émetteur et au `sub`, puis connexion |
| Aucun compte, `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` | Le compte est **créé** (`created_by` : `oidc`) si ses correspondances lui donnent une permission ; sinon refus, sans création |
| Aucun compte, `SECREVIEW_OIDC_AUTO_CREATE_USERS=false` (défaut) | **Refus** : un administrateur doit d'abord créer le compte OIDC |
| Compte **local** du même nom | **Refus** : une connexion OIDC n'ouvre jamais un compte local |
| Compte OIDC lié à un autre `sub` ou à un autre émetteur | **Refus** (voir ci-dessous) |
| Compte OIDC supprimé par un administrateur | **Refus**, même avec la création automatique (voir ci-dessous) |

À la première connexion, le compte est **lié** à l'émetteur (issuer) et au claim `sub` du
fournisseur : le compte est identifié par les deux, et deux comptes ne peuvent pas les partager.
Une connexion ultérieure avec le même identifiant mais un autre `sub` (compte du fournisseur
supprimé puis recréé...) ou venant d'un autre émetteur (un autre fournisseur d'identité, qui
pourrait réutiliser le même `sub`) est refusée. Un compte lié quand seul le `sub` était
enregistré reçoit l'émetteur de sa connexion suivante. Pour réattribuer l'identifiant, supprimez
puis recréez le compte.

Ce qu'un compte OIDC peut faire vient de ses [rôles et projets](../usage/access-control.md) : ceux
qu'un administrateur lui a donnés (page **Utilisateurs** ou membres d'un projet) et ceux des
correspondances OIDC des valeurs de son claim des rôles, enregistrées à chaque connexion (voir
[correspondances OIDC](#correspondances-oidc)). Un compte sans aucune permission est refusé et ses
sessions ouvertes se ferment. Un changement de ses rôles, de ses projets ou des correspondances
s'applique aussitôt ; un changement de ses groupes chez le fournisseur, à la prochaine
connexion.

**Supprimer un compte OIDC** (page **Utilisateurs**, `DELETE /api/v1/users/{id}` ou
`security-review-controller user delete NOM`) ferme aussitôt ses sessions et **révoque** son
identifiant et son identité (émetteur et `sub`) : une connexion OIDC ne le recrée plus, sous ce
nom ni sous un autre (nom changé chez le fournisseur), même avec la création automatique et des
correspondances qui lui donnent une permission (message « compte supprimé » sur la page de connexion). Pour lui
rendre l'accès, un administrateur recrée le compte,
ou lève la révocation (**Autoriser à nouveau**, `DELETE /api/v1/users/revoked/{identifiant}`) :
le compte est alors recréé à sa prochaine connexion. `GET /api/v1/users/revoked` liste les
comptes révoqués, avec l'auteur et la date de la suppression.

Le [dernier détenteur](../usage/access-control.md#le-dernier-administrateur) de la permission
`users.manage` ne peut être ni supprimé ni la perdre. Gardez de préférence un administrateur
local : si le fournisseur d'identité devient injoignable, il reste le seul accès, en plus de la
CLI.

```
INFO security_review_mcp.web: OIDC web user alice created at its first login
INFO security_review_mcp.web: OIDC login of oidc:alice through 1 mapped claim(s)
WARNING security_review_mcp.web: OIDC login of oidc:bob refused: no web user bob
INFO security_review_mcp.web: Web user carol (oidc) deleted by admin
WARNING security_review_mcp.web: OIDC login of oidc:carol refused: web user carol was deleted
```

## Correspondances OIDC

Les valeurs du claim `SECREVIEW_OIDC_ROLES_CLAIM` (liste ou chaîne, chemin pointé accepté) sont
comparées aux **correspondances OIDC** de la page **Connexions**. Une correspondance, une par
valeur, donne des **rôles** (droits sur tout le serveur Controller), des droits par projet sur
tous les projets et des **projets** avec leurs droits par projet aux utilisateurs dont le claim
contient **exactement** sa valeur (casse comprise). À chaque connexion, les valeurs du claim
nommées par une correspondance sont gardées pour le compte ; les autres valeurs sont ignorées. Ils
s'ajoutent aux rôles et projets donnés au compte (voir
[Rôles et permissions](../usage/access-control.md)).

- Un changement des correspondances s'applique aussitôt, à chaque compte OIDC, par les valeurs de
  sa dernière connexion ; une valeur qu'aucune correspondance ne nomme plus est oubliée.
- Un projet pas encore créé est ignoré jusqu'à sa création, jamais créé par le fournisseur
  d'identité. Un projet supprimé est retiré des correspondances ; une correspondance qui ne donne
  plus rien est supprimée.
- Une connexion ne retire jamais le dernier détenteur de `users.manage` : les valeurs du claim qui
  la lui donnaient sont gardées, avec un avertissement dans les journaux et un événement
  `user.roles_changed`. Supprimer une telle correspondance dans l'interface est refusé.

| Réglage | Effet |
|---|---|
| `SECREVIEW_OIDC_ADMIN_GROUPS` | Valeurs du claim, séparées par des virgules, qui ont le rôle `admin` : une telle valeur, sans aucune correspondance à la connexion d'un utilisateur qui la porte, reçoit une correspondance vers `admin` avec la lecture et le triage de tous les projets. Une correspondance qui la nomme déjà reste telle que les administrateurs l'ont modifiée. Sert à nommer le premier administrateur |

```bash
# Toutes les correspondances OIDC, remplacées d'un bloc
curl -X PUT https://secreview.example.com/api/v1/oidc/mappings \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"mappings": [{"claim": "secreview-admins", "role_ids": [1], "all_projects_permissions": ["reports.read", "findings.triage"]},
                    {"claim": "payments-team", "projects": [{"project": "billing", "permissions": ["reports.read", "findings.triage"]}]}]}'
```

Une session restreinte se comporte comme un
[jeton restreint à un projet](bearer-tokens.md#jetons-restreints-a-un-projet) : les autres
projets, leurs rapports et leurs findings sont traités comme inexistants.

Exemple : avec le claim `["payments-team", "staff"]`, une correspondance de `payments-team` vers
le projet `billing` avec la lecture et le triage, et aucune correspondance de `staff`,
l'utilisateur lit et trie `billing` (et garde les projets donnés à son compte).

Le label d'une session OIDC est `oidc:<identifiant>` : c'est lui qui apparaît dans les journaux et
l'historique du triage.

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
fournisseur est indisponible, retirez-la et redémarrez le serveur Controller, puis connectez-vous avec un
compte local (son mot de passe peut être défini avec
`security-review-controller user reset-password`).

## Sessions

- Le jeton de session est signé (HMAC-SHA256) avec une clé dérivée de `SECREVIEW_SECRET_KEY`
  (32 caractères au moins), comme celui des [comptes locaux](architecture/controller.md#connexion-et-sessions), et désigne
  le compte OIDC, relu à chaque requête : supprimer le compte ou changer ses rôles ou les
  correspondances OIDC s'applique aussitôt. Toutes les répliques du serveur Controller doivent partager ce secret ; sans lui,
  un secret aléatoire est tiré à chaque démarrage et les sessions se terminent au redémarrage.
- Un changement de groupe chez le fournisseur ne s'applique qu'à la connexion suivante. Pour
  couper toutes les sessions avant leur expiration, supprimez le compte, ou changez
  `SECREVIEW_SECRET_KEY` et redémarrez le serveur Controller (toutes les sessions sont coupées).
- **Se déconnecter** efface la session de l'onglet, pas celle du fournisseur d'identité.

En cas d'échec, la page de connexion indique la cause (accès refusé chez le fournisseur, aucune
permission, compte OIDC pas encore créé ou supprimé, identifiant pris par un compte local ou lié à un autre compte,
identifiant manquant, état expiré, jeton invalide, fournisseur injoignable) ; le détail est
journalisé par le serveur Controller, sans code ni jeton.
