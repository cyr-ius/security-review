# Interface web

L'interface web permet aux équipes sécurité de consulter les rapports enregistrés par les agents
et de **trier les findings** (corrigé, risque accepté, faux positif) sans passer par un client
MCP. Elle est servie par le **contrôleur**, un processus distinct du serveur MCP qui partage sa
base de données (voir [Architecture et déploiement](../advanced/architecture.md)) :

| Chemin | Contenu |
|---|---|
| `/ui/` | Application web (Angular) |
| `/api/v1/…` | API REST utilisée par l'application |
| `/api/docs` | Documentation OpenAPI de l'API REST (publique, sans données), avec `SECREVIEW_SWAGGER_ENABLED=true` |
| `/api/favicon.svg` | Icône de l'interface web et de la documentation Swagger (publique) |
| `/healthz` | Sonde de vie (publique) |

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# interface : http://127.0.0.1:8080/ui/
```

## Écrans

Les écrans sont accessibles depuis la barre latérale : **Supervision** (projets, rapports) pour
tous les comptes, puis **Référentiel** (règles, checklists, normes) et **Administration**
(utilisateurs, groupes, rôles, jetons, journal d'audit, SSO, langue des rapports, proxy sortant,
base OSV), chaque écran n'étant affiché qu'aux comptes qui ont sa
[permission](../advanced/access-control.md#permissions). Le bas de la barre affiche le client connecté, son rôle et la
version, avec les boutons **Mon compte** et de déconnexion ; sur petit écran, la barre s'ouvre avec le bouton de menu. Le thème clair ou sombre se choisit en haut
à droite, y compris sur la page de connexion, et reste mémorisé dans le navigateur.

L'interface est proposée en **anglais**, **français** et **espagnol**. La langue se choisit dans
le sélecteur en haut à droite, y compris sur la page de connexion. Le changement est immédiat et
reste mémorisé dans le navigateur ; à la première visite, l'interface suit la langue du
navigateur, ou l'anglais si elle n'en propose aucune. Ce choix ne concerne que l'interface : la
langue des rapports de revue se règle dans **Langue des rapports**, et les messages d'erreur détaillés
renvoyés par l'API restent en anglais.

- **Projets** : tous les projets avec leurs findings ouverts par sévérité, triés par risque,
  activité ou nom.
- **Projet** : findings ouverts, tendance sur 30 jours à 1 an (graphique et tableau), délai
  moyen de correction, plus ancien finding ouvert, CWE les plus fréquentes, derniers rapports et
  export SARIF. Le bouton **Revoir les findings ouverts** ouvre l'écran suivant.
- **Findings à revoir** : tous les findings ouverts du projet, sur l'ensemble de ses rapports,
  du plus grave au moins grave puis du rapport le plus récent au plus ancien, pour une revue par
  un expert en cybersécurité. Chaque finding affiche sa description, son extrait de code et sa
  recommandation, et un lien vers son rapport (date, type de revue, branche, commit). Filtres
  par statut (pour revoir les risques acceptés ou les faux positifs), par sévérité et par type
  de revue (**Revue de sécurité**, **Revue de sécurité d'API**, **Revue du code complet**... :
  voir [type de revue](prompts-tools.md#type-de-revue)) ; **Afficher plus** affiche les findings
  suivants. Les utilisateurs qui ont la permission `findings.triage` changent le statut de chaque
  finding depuis cet écran et appliquent ou rejettent les statuts proposés par les agents (voir
  [triage des findings](#triage-des-findings)) ; un finding trié reste affiché jusqu'au
  rechargement.
- **Rapports** : liste filtrable par projet et niveau de risque (les filtres sont dans l'URL, on
  peut donc partager un lien), avec le **Type** et l'**Auteur** de chaque revue.
- **Rapport** : résumé, contexte (dépôt, branche, commit, type de revue, **Auteur** et
  **Envoyé par (jeton)**, voir [auteur d'un rapport](prompts-tools.md#auteur-dun-rapport)), findings avec
  emplacement, CWE, extrait de code et recommandation ; téléchargement Markdown et SARIF. Les
  utilisateurs qui ont la permission `findings.triage` changent le statut d'un finding directement
  depuis cet écran.
- **Normes** : les [normes de développement](../advanced/standards.md) transmises aux assistants IA par le
  prompt `development-standards`. Les administrateurs les recherchent, les lisent, les créent,
  les modifient (technologies, motifs de fichiers, contenu Markdown), les désactivent ou les
  suppriment. Un changement s'applique immédiatement. **Exporter** et **Importer** les copient
  sous forme de [fichier TOML](../advanced/standards.md#import-et-export).
- **Checklists** : les administrateurs consultent les items de contrôle par domaine, filtrent la
  liste et créent, modifient ou suppriment les items personnalisés. Les items par défaut peuvent
  être modifiés, mais pas supprimés. Toute modification est rechargée immédiatement par le serveur
  et intégrée aux prompts de revue. **Exporter** et **Importer** échangent des
  [packs TOML](../advanced/rules.md#import-et-export-dans-linterface-web).
- **Règles** : les administrateurs consultent toutes les [règles](../advanced/rules.md) stockées en base,
  filtrables par origine (par défaut ou personnalisée). Ils créent, modifient (dans une fenêtre
  modale, sans quitter la position dans la liste), activent ou désactivent les règles, et
  suppriment les règles personnalisées. Une règle par défaut peut être
  modifiée (badge « Par défaut, modifiée ») ou désactivée, mais pas supprimée. Le bouton
  **Recharger** applique immédiatement un changement fait avec la CLI
  `security-review-controller rules`. **Exporter** et **Importer** échangent des
  [packs TOML](../advanced/rules.md#import-et-export-dans-linterface-web).
- **Utilisateurs** : les administrateurs gèrent les [comptes](#comptes-utilisateurs), seuls
  à ouvrir l'interface. Chaque compte est **Local** (identifiant et mot de passe, saisi ou généré
  et affiché une seule fois) ou **SSO** (connexion par le fournisseur d'identité, sans mot de
  passe), avec un badge dans la liste. L'administrateur choisit ses **Groupes** et ses **Rôles et
  projets directs** (un rôle sur tous les projets ou sur les projets cochés, pour ce seul compte) ;
  la colonne **Groupes** montre les groupes, avec un bouclier pour les groupes SSO trouvés à la
  dernière connexion, la colonne **Rôles et projets directs** les rôles directs, et **Accès**
  résume ce qu'ils donnent. L'administrateur change les groupes et les rôles directs d'un compte,
  réinitialise le mot de passe d'un compte local ou supprime un compte. Un compte SSO supprimé
  n'est plus recréé à sa connexion : la section **Comptes SSO supprimés** les liste, avec le
  bouton **Autoriser à nouveau**. Le dernier détenteur de `users.manage` ne peut être ni supprimé
  ni la perdre.
- **Groupes** : les administrateurs créent les groupes, leur donnent des rôles (sur tous les
  projets ou sur certains), ajoutent des membres et choisissent si le groupe est **Ouvert au SSO**
  (voir [Rôles, groupes et permissions](../advanced/access-control.md#groupes)).
- **Rôles** : les administrateurs créent des rôles à partir des permissions ; les rôles système
  `reader`, `triager` et `admin` sont affichés en lecture seule.
- **Mon compte** : affiche le type du compte. Un utilisateur local y change son mot de passe (ses
  autres sessions sont fermées) ; celui d'un utilisateur SSO est géré par le fournisseur
  d'identité.
- **Jetons** : les administrateurs créent et révoquent des jetons pour un ou plusieurs
  projets, ou pour **Tous les projets** (jamais pour un jeton CI/CD). Le champ **Usage** choisit **MCP** (rôle `mcp`), **API REST** ou **Pipeline CI/CD**
  (rôle `ci`, pour [`security-review-ci`](gate.md#client-de-pipeline-security-review-ci)) ;
  pour l'API REST, **Droits API** choisit **Lecture seule** (`reader`) ou **Lecture et triage**
  (`triager`). Sous **Projets autorisés**, **Tous les projets** donne tous les projets, y
  compris ceux revus plus tard, et **Projets sélectionnés** affiche les cases des projets que voit
  le jeton ;
  **Validité** fixe sa durée de vie (30 jours à 1 an, ou le défaut du serveur,
  `SECREVIEW_TOKEN_MAX_DAYS`). La liste affiche l'usage de chaque jeton `mcp`, `reader`,
  `triager` et `ci`, ses projets et sa date d'expiration (**Expiré** une fois passée).
  **Projets** change les projets d'un jeton existant, ou lui donne **Tous les projets** après
  confirmation, sans changer son secret : le changement s'applique dès la requête suivante ; une
  demande en attente pour un projet désormais accordé est approuvée avec lui. **Renouveler** remplace le secret d'un jeton et affiche le
  nouveau une fois ; l'ancien reste valable pendant le délai de grâce choisi au-dessus de la
  liste (aucun, 1 h, 24 h ou 7 jours, voir
  [expiration et renouvellement](../advanced/http.md#expiration-et-renouvellement-des-jetons)). Un jeton n'ouvre jamais l'interface web. Les jetons `admin` et `metrics` restent non
  restreints et se gèrent uniquement par la CLI. Le secret n'est montré qu'une fois ; seule son empreinte est enregistrée, dans la base de
  données. Une révocation prend effet à la requête suivante. La section
  **Demandes en attente** distingue les nouveaux jetons des demandes d'accès à un projet
  supplémentaire ([enrôlement](../advanced/http.md#enrolement-un-projet-demande-son-jeton)) :
  **Approuver** active le nouveau jeton ou ajoute le projet au jeton existant ; **Refuser** ne
  supprime que la demande. Les projets autorisés et les ajouts encore en attente sont affichés
  pour chaque jeton. La colonne **Lecture dans le portail** permet de donner en même temps au
  développeur la lecture du projet dans l'interface web, sur son compte utilisateur (voir
  [lecture du projet à l'enrôlement](../advanced/sso.md#lecture-du-projet-a-lenrolement)).
- **Journal d'audit** : les administrateurs consultent le [journal d'audit](../advanced/audit-metrics.md#journal-daudit) :
  décisions de triage, propositions des agents, jetons et demandes d'enrôlement, du plus récent
  au plus ancien, avec leur auteur ; filtres par événement et par projet, **Afficher plus** pour
  les événements plus anciens.
- **SSO** : les administrateurs [configurent la connexion SSO](../advanced/sso.md#configurer-le-sso-dans-linterface)
  (chaque valeur enregistrée remplace sa variable `SECREVIEW_OIDC_*`, avec un test de connexion
  au fournisseur). Ce que peuvent faire les utilisateurs SSO vient des groupes ouverts au SSO
  nommés par leur claim des groupes (voir
  [groupes du fournisseur d'identité](../advanced/sso.md#groupes-du-fournisseur-didentite)).
Les trois écrans suivants portent des réglages enregistrés en base, prioritaires sur les
variables d'environnement et partagés par le serveur MCP et le contrôleur (permission
`settings.manage` ; l'ancienne adresse `/ui/settings` ouvre **Langue des rapports**).

- **Langue des rapports** : variable `SECREVIEW_REPORT_LANGUAGE`, choix laissé à l'agent ou
  langue définie ici (`French`, `fr`, `pt-BR`…). Elle s'applique aux prochains prompts de
  revue ; l'argument `report_language` d'un prompt reste prioritaire
  ([langue des rapports](prompts-tools.md#langue-des-rapports)).
- **Proxy sortant** : proxy des connexions sortantes du contrôleur, utilisé par le
  téléchargement OSV **et** par la
  [connexion SSO](../advanced/sso.md). Comme pour la configuration SSO, chaque
  valeur définie ici remplace sa variable (badges **Variable** / **Interface web**) :
  l'URL suit `SECREVIEW_PROXY` (sinon `HTTPS_PROXY` / `NO_PROXY`), est définie ici, ou force
  la connexion directe ; les **hôtes sans proxy** suivent `SECREVIEW_NO_PROXY` ou sont
  définis ici (voir [hôtes sans proxy](../advanced/dependencies.md#hotes-sans-proxy) : domaines, adresses
  IP, plages CIDR, `*`). Le changement s'applique au prochain
  téléchargement et à la prochaine connexion SSO, sans redémarrage. Le proxy appliqué, son
  origine et les variables de l'environnement sont affichés ; les mots de passe ne sont
  jamais réaffichés (`***`) : renvoyer `***` conserve celui enregistré. Par l'API :
  `PUT /api/v1/settings/proxy` avec `url` et `no_proxy` (`null` applique de nouveau la
  variable, `"url": ""` force la connexion directe, un champ absent est inchangé).
- **Base OSV** : état de la base de vulnérabilités OSV : nombre d'avis par écosystème, date et âge du dernier
  import, configuration du téléchargement, historique des 50 dernières mises à jour
  (planifiée, CLI ou interface web, avec statut, durée et résultat par écosystème) et bouton
  **Mettre à jour maintenant**, disponible seulement si `SECREVIEW_OSV_AUTO_UPDATE=true`
  ([mise à jour par le contrôleur](../advanced/dependencies.md#mise-a-jour-automatique-par-le-controleur)).

## Triage des findings

Le statut d'un finding est décidé par une **personne** ; un agent ne fait que le proposer (outil
MCP `propose_finding_status`, voir [statut d'un finding](prompts-tools.md#statut-dun-finding)).

- **Proposition d'un agent** : affichée sur le finding dans un encadré distinct, avec son auteur
  (label du jeton), sa date et son motif. Le motif peut venir du code relu : vérifiez-le.
  **Appliquer** enregistre `fixed` immédiatement, ou ouvre le formulaire ci-dessous pour
  `accepted` et `false_positive` ; **Rejeter** supprime la proposition. Aucun des deux ne change
  le statut à lui seul.
- **Risque accepté** et **Faux positif** : la liste des statuts ouvre un formulaire qui demande
  un **Motif** (10 à 1000 caractères) et une **Date d'expiration** (90 jours par défaut, au plus
  `SECREVIEW_MAX_DISMISSAL_DAYS`). L'utilisateur connecté est enregistré comme approbateur ; la
  carte affiche l'approbateur, le motif et la fin de validité. À partir de la date d'expiration,
  le finding est de nouveau compté comme ouvert (filtre de statut, posture,
  [gate](gate.md), SARIF, tendance) et la carte indique que la décision a expiré.
- **Ouvert** et **Corrigé** sont enregistrés immédiatement (motif facultatif par l'API). Toute
  décision supprime la proposition en attente.

Seule une session (compte local ou SSO) peut accepter un risque ou marquer un faux positif : un
jeton Bearer, même `triager` ou `admin`, reçoit `403`. Par l'API REST :

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42 \
  -d '{"status": "accepted", "reason": "Internal tool, not exposed to the Internet", "expires_on": "2027-01-31"}'
# {"id": 42, "status": "accepted", "status_approver": "alice", "status_expires_at": "2027-01-31T00:00:00Z", …}
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/findings/42/proposal    # rejette la proposition de l'agent
```

Un motif absent ou trop court, une date d'expiration passée ou trop lointaine, ou une date
d'expiration pour `open` / `fixed` reçoit `422`. Les décisions **Risque accepté** et **Faux
positif** prises avant cette fonctionnalité n'avaient ni motif ni approbateur : la mise à jour de
la base leur donne une date d'expiration 30 jours plus tard, avec un motif qui demande de les
confirmer. Revoyez-les avec les filtres de statut avant cette date, sinon elles bloquent de
nouveau la gate.

## Rôles

Les **jetons** donnent accès au serveur MCP et à l'API REST (agents, CI, scripts) ; les
**utilisateurs** (comptes locaux ou SSO) sont les seuls à ouvrir l'interface web. Chaque jeton
porte un rôle, qui détermine les endpoints accessibles :

| Rôle | Usage (écran **Jetons**) | `/mcp` | API REST (lecture) | Changement de statut |
|---|---|---|---|---|
| `mcp` (défaut) | MCP | ✅ | — | — |
| `reader` | API REST — lecture seule | — | ✅ | — |
| `triager` | API REST — lecture et triage | — | ✅ | `open`, `fixed` ¹ |
| `admin` | CLI uniquement | ✅ | ✅ | `open`, `fixed` ¹ |
| `ci` | Pipeline CI/CD — gate, SARIF et tendance | — | routes de pipeline seulement (`/api/v1/ci/`) | — |
| `metrics` | CLI seulement | — | `/metrics` seulement ([Prometheus](../advanced/audit-metrics.md#metriques-prometheus)) | — |

¹ Avec un jeton. `accepted` et `false_positive` exigent une personne connectée à l'interface
avec la permission `findings.triage` ([triage des findings](#triage-des-findings)). Sur `/mcp`,
aucun rôle ne change un statut : les agents ne font que le proposer.

Un jeton `mcp`, `reader` ou `triager` restreint avec `--project` ne voit et ne trie que les
projets autorisés ; un jeton `ci` est toujours restreint à ses projets (voir
[jeton `ci`](gate.md#jeton-ci-et-projets-visibles)) ; l'option peut être répétée (voir
[jetons restreints à un projet](../advanced/http.md#jetons-restreints-a-un-projet)).

Les personnes se connectent avec un [compte utilisateur](#comptes-utilisateurs) : local
(identifiant et mot de passe) ou [SSO](../advanced/sso.md). Ce qu'un compte peut faire vient
des rôles de ses groupes (voir [Rôles, groupes et permissions](../advanced/access-control.md)) ;
un compte n'ouvre jamais `/mcp`. Un jeton créé sans rôle reste `mcp` : il sert aux agents et à la
CI, pas à l'interface web. Un jeton `reader`, `triager` ou `admin` appelle l'API
REST, par exemple depuis un script, mais **n'ouvre pas l'interface** (la page de connexion ne
propose que les comptes) :

```bash
security-review-controller token create --label triage-bot --role triager
# {"id": "…", "label": "triage-bot", "role": "triager", "project": null, "created_at": "…", "token": "UJB7…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/projects
```

Le même jeton liste les findings d'un projet sur l'ensemble de ses rapports, ouverts par défaut,
du plus grave au moins grave (filtres `status`, `severity` et `review_type`, `limit` plafonné par
`SECREVIEW_MAX_LIST_LIMIT`, `total` donne le nombre de findings correspondants pour paginer) :

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/findings?project=shop-api&status=open&limit=50"
# {"project": "shop-api", "total": 12, "findings": [{"id": 42, "severity": "critical", "report_id": 7, "branch": "main", "commit_sha": "abc123", "review_type": "codebase-review", "report_created_at": "…", …}, …]}
```

`GET /api/v1/reports` liste les rapports (filtres `project`, `risk_level`, `review_type` et
`author`), chacun avec son `author` et son `submitted_by` :

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/reports?project=shop-api&author=alice@example.com"
```

Révoquez-le avec `security-review-controller token revoke triage-bot`. Chaque changement de
statut est journalisé avec le label du jeton ou du compte :

```
INFO security_review_mcp.web: Finding 42 set to fixed by triage-bot
```

et écrit dans le [journal d'audit](../advanced/audit-metrics.md#journal-daudit) (`GET /api/v1/audit`, permission
`audit.read`), avec l'acteur `token:triage-bot` ou `user:<nom>`.

!!! warning "Authentification requise pour la Web UI"
    L'API de l'interface refuse les requêtes avec le statut `503` tant qu'aucun utilisateur ni
    jeton n'existe ; la mire de connexion reste affichée et indique que l'authentification doit
    être configurée. Activez `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` (c'est le cas dans l'image Docker),
    ou créez un compte avec `security-review-controller user create`. Cette restriction concerne
    la Web UI ; l'authentification MCP reste indépendante (un compte utilisateur n'ouvre jamais
    `/mcp`). Avec la [connexion SSO](../advanced/sso.md), l'API demande une connexion
    (`401`) même sans utilisateur ni jeton en base.

## Comptes utilisateurs

Un compte associe un **identifiant** (lettres, chiffres et `. _ @ -`, 64 caractères au plus), un
**type**, des **groupes** et des **rôles directs** (un rôle sur tous les projets ou sur certains,
donné à ce seul compte) : leurs rôles donnent ses [permissions](../advanced/access-control.md#roles-et-projets-directs-dun-compte).

| Type (`auth_source`) | Connexion | Création |
|---|---|---|
| **Local** (`local`) | Identifiant et mot de passe | Par un administrateur, ou le compte `admin` initial |
| **SSO** (`oidc`) | [Fournisseur d'identité](../advanced/sso.md), sans mot de passe | Par un administrateur, à l'approbation d'un enrôlement, ou à la première connexion si `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` |

Un compte SSO rejoint aussi, à chaque connexion, les groupes ouverts au SSO nommés par son claim
des groupes (voir [comptes SSO](../advanced/sso.md#comptes-sso)). Les comptes se gèrent dans
l'écran **Utilisateurs**, par l'API REST `/api/v1/users` (permission `users.manage`) ou par la
[CLI](../reference/cli.md#security-review-controller) :

```bash
security-review-controller user create alice --group shop-triagers
# {"id": 2, "username": "alice", "auth_source": "local", "groups": [{"group_id": 3, "name": "shop-triagers", "source": "local"}], "permissions": {…}, "effective_role": "triager", …, "password": "q3V…"}
printf '%s\n' "$PASSWORD" | security-review-controller user create bob --password-stdin
security-review-controller user create carol@example.com --sso   # groupes SSO seulement
security-review-controller user list
security-review-controller user set-groups alice --group readers --group auditors
security-review-controller user set-groups alice --group administrators   # créé s'il manque
security-review-controller user set-roles alice --role triager:shop,billing   # rôles directs
security-review-controller user reset-password alice   # compte local : nouveau mot de passe, sessions fermées
security-review-controller user delete alice
security-review-controller group list    # groupes, leurs rôles et leurs membres
```

Par l'API, un compte SSO se crée avec `"auth_source": "oidc"`, sans `password` ; `group_ids`
liste ses groupes et `roles` ses rôles directs (`projects` vide : tous les projets) :

```bash
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "carol@example.com", "auth_source": "oidc", "group_ids": [4], "roles": [{"role_id": 3, "projects": ["crm"]}]}'
```

Un compte sans aucun groupe ni rôle direct n'a aucune permission et ne peut pas se connecter.

Pour un compte local, sans `--password-stdin` (ou sans mot de passe dans l'interface), un mot de
passe aléatoire de 24 caractères est généré et affiché **une seule fois**. Un mot de passe choisi
respecte la **politique de mot de passe** : 12 à 256 caractères, avec au moins une minuscule, une
majuscule, un chiffre et un caractère qui n'est ni une lettre ni un chiffre. Les écrans affichent
ces règles sous le champ et cochent chacune pendant la saisie, et **Mon compte** indique aussitôt
si la confirmation correspond. La politique s'applique aux nouveaux mots de passe : un mot de passe
défini avant reste valable jusqu'à son changement. Un compte SSO n'a jamais de mot de passe : la connexion par
identifiant et mot de passe, la réinitialisation et **Mon compte** le refusent.

### Premier administrateur

Avec `SECREVIEW_AUTH_BOOTSTRAP_ADMIN=true` (c'est le cas dans l'image Docker), le contrôleur crée
au premier démarrage l'utilisateur **`admin`**, membre du groupe `administrators` (rôle `admin`),
tant qu'aucun compte n'existe.
Son mot de passe est affiché une seule fois dans les journaux du contrôleur :

```
WARNING security_review_mcp.controller: Initial Web UI administrator created: user 'admin', password (shown once): …
```

Traitez ce mot de passe comme un secret : restreignez l'accès aux journaux et connectez-vous avec
`admin`. L'interface **exige alors un nouveau mot de passe** avant toute autre chose : elle ouvre
**Mon compte**, et l'API refuse toutes les autres routes (`403`) tant que le mot de passe n'est pas
changé. S'il est perdu, générez-en un nouveau (l'ancien est aussitôt invalidé) :
`security-review-controller user reset-password admin`.

Il en va de même de tout mot de passe défini par quelqu'un d'autre : un compte local créé ou
réinitialisé par un administrateur (écran ou CLI) change son mot de passe à sa première connexion.
L'écran **Utilisateurs** affiche **mot de passe à changer** jusque-là.

!!! note "Mise à jour depuis le jeton `bootstrap-admin`"
    Les versions précédentes créaient un **jeton** `bootstrap-admin` à la place du compte. Sur une
    base existante, ce jeton reste valable ; le compte `admin` est créé au démarrage suivant s'il
    n'existe aucun compte. Une fois connecté avec le compte, révoquez l'ancien jeton :
    `security-review-controller token revoke bootstrap-admin`.

### Connexion et sessions

La page de connexion propose l'identifiant et le mot de passe d'un compte local et, avec la
[connexion SSO](../advanced/sso.md), le bouton du fournisseur d'identité ; elle
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

- un changement de ses **groupes**, de leurs rôles ou d'un rôle s'applique immédiatement aux
  sessions ouvertes ;
- une **suppression** ou un **nouveau mot de passe** (changé par l'utilisateur ou réinitialisé
  par un administrateur) ferme toutes les sessions du compte ; `PUT /api/v1/me/password` remet une
  nouvelle session à l'onglet qui a changé le mot de passe.

Les sessions sont signées avec `SECREVIEW_SESSION_SECRET` (32 caractères au moins), partagé par
toutes les répliques du contrôleur. Sans lui, le secret est lu dans
`SECREVIEW_SESSION_SECRET_FILE` (`session-secret` dans le répertoire de travail, `/var/lib/secreview` en
Docker), où il est généré au premier démarrage avec les droits `0600` : les sessions survivent à
un redémarrage, et les répliques qui partagent le volume partagent le secret. Des répliques sans
volume partagé doivent partager `SECREVIEW_SESSION_SECRET`.

Les échecs de connexion sont limités : après **5 échecs en 15 minutes** pour un identifiant
depuis une même adresse, ou **20 échecs** depuis une adresse tous identifiants confondus, la
connexion est refusée (`429`, en-tête `Retry-After`), même avec le bon mot de passe. Les
compteurs sont tenus en base : tous les workers et réplicas du contrôleur les partagent. Chaque
adresse est aussi limitée sur toute l'API REST (par défaut 600 requêtes par minute, 30 sur les
routes de connexion, voir [`SECREVIEW_RATE_LIMIT_*`](../reference/configuration.md)). Derrière un reverse proxy, l'adresse vue est celle du
proxy, et la limite s'appliquerait alors à tous les clients du proxy : déclarez le proxy dans
[`SECREVIEW_FORWARDED_ALLOW_IPS`](../reference/configuration.md) pour que l'adresse du client
soit lue dans `X-Forwarded-For`. Chaque connexion et chaque échec
sont journalisés, sans le mot de passe :

```
INFO security_review_mcp.web: Web login of alice (role triager) from 10.0.0.12
WARNING security_review_mcp.web: Failed web login of alice from 10.0.0.12
```

## Sécurité

- Les fichiers statiques de `/ui/` sont publics (ils ne contiennent aucune donnée) ; l'API
  `/api/v1/` exige une session ou un jeton `reader`, `triager` ou `admin`. Seules les routes de
  connexion (`/api/v1/auth/…`) sont publiques.
- Les mots de passe des comptes ne sont jamais stockés : seule une empreinte **scrypt** salée
  (N=2¹⁴, r=8, p=5) est enregistrée et aucune réponse de l'API ne la renvoie. La vérification
  prend le même temps que l'identifiant existe ou non, et la réponse d'échec est identique. La documentation Swagger (`/api/docs`)
  et son schéma (`/api/openapi.json`) sont **désactivés par défaut**
  (`SECREVIEW_SWAGGER_ENABLED=true` les sert) ; une fois activés, ils sont publics et ne donnent
  accès à aucune donnée. Leurs fichiers sont fournis avec la build de l'interface web : rien
  n'est chargé depuis Internet, et Swagger n'envoie jamais le schéma au validateur en ligne.
  Dans Swagger, le cadenas d'une route indique qu'elle exige un jeton : il reste **ouvert**
  tant que vous n'avez pas saisi de jeton avec **Authorize**, et ne veut pas dire que la route
  est accessible sans jeton.
- Le contrôleur n'expose aucune route d'écriture sans jeton. Les demandes
  d'[enrôlement](../advanced/http.md#enrolement-un-projet-demande-son-jeton) sont déposées sur
  le **serveur MCP** (`POST /api/v1/enroll`, public) ; le contrôleur les liste et les traite
  (`GET /api/v1/enrollments`, `POST /api/v1/enrollments/{id}/approve`,
  `DELETE /api/v1/enrollments/{id}`, permission `tokens.manage`). Il peut donc rester sur un réseau interne.
- Le jeton est envoyé dans l'en-tête `Authorization` : pas de cookie, donc pas de CSRF.
  Seule la [connexion SSO](../advanced/sso.md) pose un cookie, `HttpOnly`,
  `SameSite=Lax`, `Secure` en HTTPS, limité à l'URL de retour et valable 10 minutes : il lie le
  retour du fournisseur au navigateur qui a lancé la connexion (protection contre le *login
  CSRF*). Le jeton de session est remis dans le fragment d'URL (`#session=...`), jamais envoyé à
  un serveur, et l'interface l'efface aussitôt de la barre d'adresse et de l'historique.
- Il est conservé dans le `sessionStorage` de l'onglet et disparaît à sa fermeture.
- Les pages sont servies avec une CSP stricte (`script-src 'self'`, aucune ressource externe),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` et `Referrer-Policy: no-referrer`.
- Servez l'interface en HTTPS ([TLS intégré ou reverse proxy](../advanced/http.md#tls)) dès
  qu'elle n'écoute plus sur localhost : le jeton circule à chaque requête.

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_WEB_UI` | `true` | Sert l'interface sur `/ui` ; à `false`, le contrôleur ne sert que l'API REST |
| `SECREVIEW_WEB_UI_DIR` | — | Dossier d'une autre build de l'application (défaut : celle du paquet) |
| `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` | `false` | Crée le compte `admin` au premier démarrage du contrôleur, tant qu'aucun compte n'existe ; `true` dans Docker |
| `SECREVIEW_SESSION_SECRET` | — | Secret de signature des sessions (32 caractères au moins), identique sur toutes les répliques |
| `SECREVIEW_SESSION_SECRET_FILE` | `session-secret` | Fichier du secret quand `SECREVIEW_SESSION_SECRET` n'est pas défini, généré au premier démarrage |
| `SECREVIEW_SESSION_HOURS` | `8` | Durée d'une session (1 à 24 heures), connexion par compte local ou SSO |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Crée le [compte SSO](../advanced/sso.md#comptes-sso) à la première connexion ; sinon un administrateur le crée |
| `SECREVIEW_ENROLLMENT` | `true` | Demandes de jetons par les projets (sur le serveur MCP), validées dans l'écran **Jetons** |
| `SECREVIEW_OIDC_*` | — | [Connexion SSO](../advanced/sso.md), voir la [référence](../reference/configuration.md) |

Le paquet publié et l'image Docker contiennent l'application déjà compilée. Si vous installez
depuis les sources sans la compiler, le contrôleur ne sert que l'API REST et un avertissement est
journalisé. Voir [Contribuer](../contributing.md#interface-web) pour la compiler.
