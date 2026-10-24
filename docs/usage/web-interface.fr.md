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
| `/api/health` | Disponibilité de l'API, vérifiée par l'application au chargement (publique, ne révèle ni la version ni les réglages) |
| `/healthz` | Sonde de vie (publique) |

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# interface : http://127.0.0.1:8080/ui/
```

## Écrans

Les écrans sont accessibles depuis la barre latérale : **Supervision** (projets, rapports) pour
tous les comptes, puis **Référentiel** (règles, checklists, normes) et **Administration**
(utilisateurs, groupes, rôles, jetons, journal d'audit, OIDC, langue des rapports, proxy sortant,
base OSV, connecteurs), chaque écran n'étant affiché qu'aux comptes qui ont sa
[permission](../advanced/access-control.md#permissions). Le bas de la barre affiche le client connecté (ses permissions au survol) et la
version (un lien vers **À propos**), avec les boutons **Mon compte** et de déconnexion.
Sur petit écran, la barre est réduite à ses icônes (chacune nomme son écran au survol) et le
bouton en haut à gauche l'ouvre en entier ; sur grand écran, le même bouton la réduit à ses icônes
ou la déplie, un choix mémorisé par le navigateur.

Le bouton de thème en haut à droite, y compris sur la page de connexion, passe d'**automatique**
(le thème du système, suivi en direct) à **clair** puis **sombre**. Le choix d'un utilisateur
connecté est conservé dans son compte (`GET` et `PUT /api/v1/me/preferences`), pour tous les
navigateurs qu'il utilise ; le navigateur retient le dernier pour la page de connexion.

L'interface est proposée en **anglais**, **français** et **espagnol**. La langue se choisit dans
le sélecteur en haut à droite, y compris sur la page de connexion. Le changement est immédiat et
reste mémorisé dans le navigateur ; à la première visite, l'interface suit la langue du
navigateur, ou l'anglais si elle n'en propose aucune. Ce choix ne concerne que l'interface : la
langue des rapports de revue se règle dans **Langue des rapports**, et les messages d'erreur détaillés
renvoyés par l'API restent en anglais.

La page **À propos** donne la version du contrôleur, si une **Nouvelle version** est disponible
sur GitHub (seulement avec `SECREVIEW_UPDATE_CHECK_ENABLED=true`, voir les
[connexions sortantes](../reference/security.md#securite-du-serveur-lui-meme)), les liens de la
documentation, du code source et pour signaler un problème, le lien de la documentation Swagger quand elle est activée,
et l'état du backend (`/api/health`, vérifié à nouveau avec **Vérifier à nouveau**). Au
chargement, l'application interroge d'abord `/api/health` : si le contrôleur ne répond pas (ou
cesse de répondre ensuite), la page **Backend indisponible** s'ouvre, et son bouton **Réessayer**
revient à la page demandée dès que le contrôleur répond de nouveau.

Les tableaux se trient en cliquant sur l'en-tête d'une colonne : une petite flèche indique la
colonne triée et le sens du tri, un second clic l'inverse. Chaque tableau s'ouvre trié sur sa
colonne par défaut (flèche affichée), et le navigateur mémorise le tri choisi pour les visites
suivantes.

- **Projets** : tous les projets avec leurs findings ouverts par sévérité. Rechercher par nom,
  trier par nom, pire finding ouvert ou dernier rapport, et filtrer par sévérité maximale. Le bouton
  **Revoir les findings ouverts** ouvre les findings à revoir de tous
  les projets que vous pouvez voir (**Findings à revoir : tous les projets**), chacun avec un
  lien vers son projet. Le bouton **Acceptations de risque** liste les risques acceptés de tous
  les projets que vous pouvez voir. Avec la permission `projects.create`, **Nouveau projet** (à gauche
  d'**Actualiser**) ouvre une fenêtre modale qui crée un projet que vous lisez ensuite (voir
  [Création d'un projet](../advanced/access-control.md#creation-dun-projet)), et la section
  **Projets en attente** liste les projets demandés par un
  [enrôlement](../advanced/http.md#enrolement-demander-le-projet) (demandeur, adresse, dates de
  demande et d'expiration) : **Valider** crée le projet sans aucun membre, **Refuser** supprime
  la demande ; une demande non validée avant son expiration est supprimée. Avec
  `projects.delete`, le bouton corbeille d'une ligne supprime le projet et tout ce qui s'y
  rapporte (voir [Suppression d'un projet](../advanced/access-control.md#suppression-dun-projet)).
- **Projet** : findings ouverts, tendance sur 30 jours à 1 an (graphique et tableau), délai
  moyen de correction, plus ancien finding ouvert, CWE les plus fréquentes, les 20 findings ouverts
  les plus graves (sévérité, règle, emplacement, rapport) et export SARIF ; **Tous les rapports**
  liste ses rapports. Le bouton **Revoir les findings ouverts** ouvre l'écran suivant ;
  **Acceptations de risque** liste les risques acceptés du projet ; **Actualiser** recharge la
  tendance et les findings ouverts.
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
  rechargement (bouton **Actualiser**).
- **Acceptations de risque** : les risques acceptés du projet (ou de tous les projets), y compris
  expirés, de l'expiration la plus proche à la plus lointaine. Recherche, tri et filtres par état
  (**Active**, **Expirée**) et par sévérité ; **Actualiser** recharge la liste. Un clic sur un
  finding ouvre ses détails : ses commentaires (le premier est le motif de l'acceptation) et,
  avec la permission `findings.triage`, les formulaires pour ajouter un commentaire, changer la
  date d'expiration et supprimer l'acceptation (voir [acceptations de risque](#acceptations-de-risque)).
- **Rapports** : liste filtrable par projet et niveau de risque, avec recherche dans les
  métadonnées et le résumé, tri par date, projet, risque, type, branche, jeton ou résumé. La
  colonne **Jeton** affiche le libellé du jeton qui a envoyé le rapport ; le survoler montre
  l'auteur déclaré à qui détient `users.manage` ou `tokens.manage`. La
  recherche et les filtres restent dans l'URL, pour partager la vue ; le tri est mémorisé par le
  navigateur.
- **Rapport** : résumé, contexte (dépôt, branche, commit, type de revue, **Auteur** (pour qui
  détient `users.manage` ou `tokens.manage`) et
  **Envoyé par (jeton)**, voir [auteur d'un rapport](prompts-tools.md#auteur-dun-rapport)),
  **Couverture de la revue** (points de checklist par résultat et règles qui ont remonté des
  pistes, celles citées par aucun finding marquées **écartée**, voir
  [couverture de la revue](prompts-tools.md#couverture-de-la-revue)), findings avec
  emplacement, CWE, extrait de code et recommandation ; téléchargement Markdown et SARIF. Les
  utilisateurs qui ont la permission `findings.triage` changent le statut d'un finding directement
  depuis cet écran, et relèvent sa criticité avec une justification (voir
  [criticité d'un finding](#criticite-dun-finding)).
- **Normes** : les [normes de développement](standards.md) transmises aux assistants IA par le
  prompt `development-standards`. Rechercher et trier par titre, technologie ou motif
  de fichier, filtrer par état activé. Les administrateurs les lisent, les créent,
  les modifient (technologies, motifs de fichiers, contenu Markdown), les désactivent ou les
  suppriment. Un changement s'applique immédiatement. **Exporter** et **Importer** les copient
  sous forme de [fichier TOML](standards.md#import-et-export).
- **Checklists** : les [checklists](checklists.md) des revues. Les administrateurs recherchent et trient les items de contrôle, filtrent par
  domaine et origine, et créent, modifient ou suppriment les items personnalisés. Les items par défaut peuvent
  être modifiés, mais pas supprimés. Toute modification est rechargée immédiatement par le serveur
  et intégrée aux prompts de revue. **Exporter** et **Importer** échangent des
  [packs TOML](rules.md#import-et-export-dans-linterface-web).
- **Règles** : les administrateurs recherchent et trient toutes les [règles](rules.md) stockées en base,
  filtrables par origine (par défaut ou personnalisée) et sévérité. Ils créent, modifient (dans une fenêtre
  modale, sans quitter la position dans la liste), activent ou désactivent les règles, et
  suppriment les règles personnalisées. Une règle par défaut peut être
  modifiée (badge « Par défaut, modifiée ») ou désactivée, mais pas supprimée. Le bouton
  **Recharger** applique immédiatement un changement fait avec la CLI
  `security-review-controller rules`. **Exporter** et **Importer** échangent des
  [packs TOML](rules.md#import-et-export-dans-linterface-web).
- **Utilisateurs** : les administrateurs gèrent les [comptes](#comptes-utilisateurs), seuls
  à ouvrir l'interface. Chaque compte est **Local** (identifiant et mot de passe, saisi ou généré
  et affiché une seule fois) ou **OIDC** (connexion par le fournisseur d'identité, sans mot de
  passe), avec un badge dans la liste. La liste est recherchable, triable et filtrable par type.
  Les comptes OIDC supprimés sont recherchables, triables et filtrables par administrateur de
  révocation. L'administrateur choisit ses **Groupes**, seule source de
  ses permissions ; la colonne **Groupes** montre les groupes, avec un bouclier pour les groupes
  OIDC trouvés à la dernière connexion, et **Accès** liste les permissions qu'ils donnent, avec leurs projets. L'administrateur
  change les groupes d'un compte, réinitialise le mot de passe d'un compte local ou supprime un compte. Un compte OIDC supprimé
  n'est plus recréé à sa connexion : la section **Comptes OIDC supprimés** les liste, avec le
  bouton **Autoriser à nouveau**. Le dernier détenteur de `users.manage` ne peut être ni supprimé
  ni la perdre.
- **Groupes** : les administrateurs recherchent et trient les groupes, et filtrent les groupes
  locaux de ceux ouverts au OIDC. Ils créent les groupes, leur donnent des rôles (sur tous les
  projets ou sur certains), ajoutent des membres et choisissent si le groupe est **Ouvert au OIDC**
  (voir [Rôles, groupes et permissions](../advanced/access-control.md#groupes)).
- **Rôles** : les administrateurs recherchent et trient les rôles, et filtrent les rôles intégrés
  des rôles personnalisés. Ils créent des rôles à partir des permissions ; les rôles intégrés
  `reader` et `admin` sont affichés en lecture seule. `triager` (lecture et triage) et `mcp-user`
  (jeton MCP personnel), créés avec la base, sont des rôles ordinaires : ils peuvent être modifiés
  ou supprimés.
- **Mon compte** : affiche le type du compte et **Mes permissions**. Un utilisateur local y change son mot de passe (ses
  autres sessions sont fermées) ; celui d'un utilisateur OIDC est géré par le fournisseur
  d'identité. **Jetons personnels** crée et révoque les jetons personnels du compte : des
  jetons [API REST](#jetons-api) (Swagger, scripts), qui portent ses droits, et des jetons
  [MCP](#jetons-mcp-et-ci-personnels) pour son agent, qui atteignent les projets qu'il peut lire.
- **Jetons** : les jetons sont recherchables, triables et filtrables par usage. Les administrateurs créent et révoquent des jetons pour un ou plusieurs
  projets, ou pour **Tous les projets** (jamais pour un jeton CI/CD). Le champ **Usage** choisit
  **MCP** (rôle `mcp`), **Pipeline CI/CD** (rôle `ci`, pour
  [`security-review-ci`](gate.md#client-de-pipeline-security-review-ci)) ou **API REST** (rôle
  `api`, avec le **Rôle** qu'il porte, voir [jetons API](#jetons-api)) : les jetons sont destinés
  aux machines, une personne lit et trie avec un [compte utilisateur](#comptes-utilisateurs).
  Sous **Projets autorisés**, **Tous les projets** donne tous les projets, y
  compris ceux revus plus tard, et **Projets sélectionnés** affiche les cases des projets que voit
  le jeton ;
  **Validité** fixe sa durée de vie (30 jours à 1 an, ou le défaut du serveur,
  `SECREVIEW_TOKEN_MAX_DAYS`). La liste affiche l'usage de chaque jeton `mcp` et `ci`, ses
  projets et sa date d'expiration (**Expiré** une fois passée).
  **Projets** change les projets d'un jeton existant, ou lui donne **Tous les projets** après
  confirmation, sans changer son secret : le changement s'applique dès la requête suivante. **Renouveler** remplace le secret d'un jeton et affiche le
  nouveau une fois ; l'ancien reste valable pendant le délai de grâce choisi au-dessus de la
  liste (aucun, 1 h, 24 h ou 7 jours, voir
  [expiration et renouvellement](../advanced/http.md#expiration-et-renouvellement-des-jetons)). Un jeton n'ouvre jamais l'interface web. Les jetons `admin` et `metrics` restent non
  restreints et se gèrent uniquement par la CLI. Le secret n'est montré qu'une fois ; seule son empreinte est enregistrée, dans la base de
  données. Une révocation prend effet à la requête suivante.
  L'[enrôlement](../advanced/http.md#enrolement-demander-le-projet) ne crée aucun jeton : un
  projet qu'il demande attend dans **Projets**, et une fois validé un administrateur en donne
  l'accès à un développeur en l'ajoutant à son groupe `project:<projet>` (écran **Groupes**).
- **Journal d'audit** : les administrateurs consultent le [journal d'audit](../advanced/audit-metrics.md#journal-daudit) :
  décisions de triage, propositions des agents, jetons et enrôlements, du plus récent
  au plus ancien, avec leur auteur ; filtres par événement et projet, recherche dans les détails,
  tri par date/action/auteur/cible/projet et **Afficher plus** pour les événements plus anciens.
  Les détenteurs de `settings.manage` y règlent aussi le
  [serveur syslog](../advanced/audit-metrics.md#envoi-vers-syslog) qui reçoit les événements
  (bouton **Syslog**, à côté de **Actualiser**).
- **OIDC** : les administrateurs [configurent la connexion OIDC](../advanced/sso.md#configurer-le-oidc-dans-linterface)
  (une valeur enregistrée s'applique quand sa variable `SECREVIEW_OIDC_*` n'est pas définie,
  avec un test de connexion au fournisseur). Ce que peuvent faire les utilisateurs OIDC vient des groupes ouverts au OIDC
  nommés par leur claim des groupes (voir
  [groupes du fournisseur d'identité](../advanced/sso.md#groupes-du-fournisseur-didentite)).
Les trois écrans suivants portent des réglages enregistrés en base et partagés par le serveur
MCP et le contrôleur (permission `settings.manage` ; l'ancienne adresse `/ui/settings` ouvre
**Langue des rapports**). **Une variable d'environnement définie (environnement ou fichier
`.env`) est toujours prioritaire** sur la valeur saisie dans l'interface : son champ est alors
verrouillé et affiche la variable, et une valeur enregistrée avant que la variable soit définie
est signalée comme ignorée, avec un bouton **Supprimer**.

- **Langue des rapports** : choix laissé à l'agent ou langue définie ici (`French`, `fr`,
  `pt-BR`…), quand `SECREVIEW_REPORT_LANGUAGE` n'est pas définie. Elle s'applique aux
  prochains prompts de revue ; l'argument `report_language` d'un prompt reste prioritaire
  ([langue des rapports](prompts-tools.md#langue-des-rapports)).
- **Proxy sortant** : proxy des connexions sortantes du contrôleur, utilisé par le
  téléchargement OSV **et** par la
  [connexion OIDC](../advanced/sso.md). Quand `HTTPS_PROXY` (sinon `HTTP_PROXY`) n'est pas
  définie, le proxy est défini ici (ou **Aucun proxy (connexion directe)**) ; quand
  `NO_PROXY` n'est pas définie, les **hôtes sans proxy** sont définis ici (voir
  [hôtes sans proxy](../advanced/dependencies.md#hotes-sans-proxy) : domaines, adresses IP,
  `*`, pas de plages CIDR). Une variable vide compte comme non définie. Le changement s'applique au prochain
  téléchargement et à la prochaine connexion OIDC, sans redémarrage. Le proxy appliqué, son
  origine et les variables sont affichés ; les mots de passe ne sont
  jamais réaffichés (`***`) : renvoyer `***` conserve celui enregistré. Par l'API :
  `PUT /api/v1/settings/proxy` avec `url` et `no_proxy` (`null` supprime la valeur
  enregistrée, `"url": ""` force la connexion directe, un champ absent est inchangé ; une
  valeur dont la variable est définie est refusée avec `422`). `GET /api/v1/settings` donne,
  pour chaque réglage, la valeur enregistrée `value`, la variable `env`, `env_set` (la variable
  est définie et prioritaire) et la valeur effective.
- **Base OSV** : état de la base de vulnérabilités OSV : nombre d'avis par écosystème, date et âge du dernier
  import, configuration du téléchargement, historique des 50 dernières mises à jour
  (planifiée, CLI ou interface web, avec statut, durée et résultat par écosystème), recherchable,
  triable et filtrable par statut/déclencheur, et bouton
  **Mettre à jour maintenant**, disponible seulement si `SECREVIEW_OSV_AUTO_UPDATE=true`
  ([mise à jour par le contrôleur](../advanced/dependencies.md#mise-a-jour-automatique-par-le-controleur)).
- **Connecteurs** : une carte par connecteur (Jira, ServiceNow, tiers) avec son interrupteur et
  une roue crantée pour ses paramètres : connexion (avec **Tester la connexion**) et destination
  de chaque projet, avec son envoi automatique facultatif ([ticketing](../advanced/ticketing.md)).

## Triage des findings

Le statut d'un finding est décidé par une **personne** ; un agent ne fait que le proposer (outil
MCP `propose_finding_status`, voir [statut d'un finding](prompts-tools.md#statut-dun-finding)).
Un trieur peut aussi envoyer un finding vers Jira ou ServiceNow (**Envoyer vers Jira**), quand
son projet a une destination : voir [ticketing](../advanced/ticketing.md#envoi-dun-finding).

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
  [gate](gate.md), SARIF, tendance) et la carte indique que la décision a expiré. Pour
  **Risque accepté**, la case **Sans expiration** supprime la date : le risque reste accepté
  jusqu'à ce que quelqu'un rouvre le finding (désactivée par
  `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false`). Un faux positif exige toujours une date.
- **Risque accepté** sous `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY` (`medium` par défaut, donc
  un finding `low` ou `info`) : une simple validation, enregistrée immédiatement sans motif ni
  date d'expiration. Variable vide : toute acceptation passe par le formulaire ci-dessus.
- **Ouvert** et **Corrigé** sont enregistrés immédiatement (motif facultatif par l'API). Toute
  décision supprime la proposition en attente.

Seule une session (compte local ou OIDC) peut accepter un risque ou marquer un faux positif : un
jeton Bearer, même `admin`, reçoit `403`. Par l'API REST :

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42 \
  -d '{"status": "accepted", "reason": "Internal tool, not exposed to the Internet", "expires_on": "2027-01-31"}'
# {"id": 42, "status": "accepted", "status_approver": "alice", "status_expires_at": "2027-01-31T00:00:00Z", …}
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/findings/42/proposal    # rejette la proposition de l'agent
```

Un motif absent ou trop court, une date d'expiration passée ou trop lointaine, ou une date
d'expiration pour `open` / `fixed` reçoit `422`. Sans `expires_on`, une acceptation n'expire
jamais, sauf si `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false` (`422`) ; `GET /api/v1/me` renvoie
`permanent_acceptance` pour indiquer si l'appelant peut le faire. Sous
`SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY`, `reason` et `expires_on` sont facultatifs pour
`accepted` (`{"status": "accepted"}` suffit) ; `GET /api/v1/me` renvoie ce seuil dans
`risk_acceptance_min_severity` (`null` : toute acceptation les exige).

### Criticité d'un finding

Un analyste de sécurité (une personne qui a la permission `findings.triage`) peut **relever** la
criticité donnée par un rapport, par exemple quand le code est exposé à Internet ou que les
données sont sensibles. **Relever la criticité**, en haut de la carte, ouvre un formulaire qui
demande la **Nouvelle criticité** et une **Justification** (10 à 1000 caractères). La carte
affiche ensuite la criticité du rapport, l'analyste, la date et la justification ; l'export
Markdown et `get_security_report` les affichent aussi, et le changement est inscrit au journal
d'audit (`finding.severity_changed`).

La criticité relevée compte partout (filtres, posture, [gate](gate.md), SARIF, tendance), et le
niveau de risque du rapport monte avec elle. Une criticité ne descend jamais sous celle du
rapport : un analyste peut seulement y revenir, avec une justification, pour annuler la hausse.
Pour clore un finding jugé moins grave, acceptez le risque. Seule une session peut le faire : un
jeton Bearer, même `admin`, reçoit `403` ; une criticité plus basse ou inchangée, ou une
justification absente, reçoit `422`.

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42/severity \
  -d '{"severity": "critical", "reason": "Endpoint reachable without authentication"}'
# {"id": 42, "severity": "critical", "original_severity": "medium", "severity_changed_by": "alice", …}
```

### Acceptations de risque

L'écran **Acceptations de risque** (`/ui/risk-acceptances`, ou par projet depuis les écrans
**Projets** et **Projet**) liste les risques acceptés, y compris expirés, pour les renouveler
avant ou après leur fin de validité. Dans les détails d'une acceptation :

- **Commentaires** : tous les commentaires, du plus ancien au plus récent, avec leur auteur et
  leur date. Le motif de l'acceptation est le premier : accepter un risque, ou l'accepter de
  nouveau avec un autre motif, l'ajoute aux commentaires. Toute personne qui lit le projet les
  voit. Un commentaire **ne peut être ni modifié
  ni supprimé** : aucune route de l'API ne le fait. Ils restent attachés au finding quand son
  acceptation est supprimée.
- **Ajouter un commentaire** (2000 caractères au plus, secrets masqués) enregistre l'utilisateur
  connecté comme auteur, également dans le journal d'audit (`finding.commented`).
- **Changer la date d'expiration** enregistre de nouveau l'acceptation avec le même motif et la
  nouvelle date (mêmes limites que ci-dessus, **Sans expiration** compris), sans ajouter de
  commentaire : l'utilisateur connecté en devient l'approbateur.
- **Supprimer l'acceptation** rouvre le finding, après confirmation.

Comme une acceptation, un commentaire demande une session avec la permission `findings.triage` :
un jeton Bearer reçoit `403`. Par l'API REST :

```bash
curl -H "Authorization: Bearer $SESSION" \
  "https://secreview.example.com/api/v1/risk-acceptances?project=shop-api"
# {"project": "shop-api", "total": 1, "acceptances": [{"id": 42, "status": "accepted", "expired": false, "comments_total": 1, …}]}
curl -H "Authorization: Bearer $SESSION" https://secreview.example.com/api/v1/findings/42/comments
# [{"id": 7, "finding_id": 42, "author": "alice", "body": "Renew it after the audit", "created_at": "…"}]
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42/comments -d '{"body": "Renew it after the audit"}'
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42 -d '{"status": "open"}'    # supprimer l'acceptation
```

`GET /api/v1/risk-acceptances` accepte `limit` (plafonné par `SECREVIEW_MAX_LIST_LIMIT`) et
`offset` ; sans `project`, il liste tous les projets que l'appelant peut lire.

## Rôles

Les **jetons** sont destinés aux machines (agents MCP, pipelines CI/CD, Prometheus, scripts
d'administration) ; les **utilisateurs** (comptes locaux ou OIDC) sont les personnes : eux seuls
ouvrent l'interface web, et leurs droits viennent des rôles de leurs groupes. Chaque jeton porte
un rôle, qui détermine les endpoints accessibles :

| Rôle | Usage (écran **Jetons**) | `/mcp` | API REST (lecture) | Changement de statut |
|---|---|---|---|---|
| `mcp` (défaut) | MCP | ✅ | — | — |
| `admin` | CLI uniquement | ✅ | ✅ | `open`, `fixed` ¹ |
| `api` | API REST — Swagger et scripts ([jetons API](#jetons-api)) | — | ✅ avec les permissions de son rôle ou de son utilisateur | `open`, `fixed` ¹ avec `findings.triage` |
| `ci` | Pipeline CI/CD — gate, SARIF, tendance et scans | — | routes de pipeline seulement (`/api/v1/ci/`), dont les scans qui enregistrent des rapports | — |
| `metrics` | CLI seulement | — | `/metrics` seulement ([Prometheus](../advanced/audit-metrics.md#metriques-prometheus)) | — |

¹ Avec un jeton. `accepted` et `false_positive` exigent une personne connectée à l'interface
avec la permission `findings.triage` ([triage des findings](#triage-des-findings)). Sur `/mcp`,
aucun rôle ne change un statut : les agents ne font que le proposer.

Un jeton `mcp` restreint avec `--project` ne voit que les projets autorisés ; un jeton `ci` est toujours restreint à ses projets (voir
[jeton `ci`](gate.md#jeton-ci-et-projets-visibles)) ; l'option peut être répétée (voir
[jetons restreints à un projet](../advanced/http.md#jetons-restreints-a-un-projet)).

Les personnes se connectent avec un [compte utilisateur](#comptes-utilisateurs) : local
(identifiant et mot de passe) ou [OIDC](../advanced/sso.md). Ce qu'un compte peut faire vient
des rôles de ses groupes (voir [Rôles, groupes et permissions](../advanced/access-control.md)) ;
un compte n'ouvre jamais `/mcp`. Un jeton créé sans rôle reste `mcp` : il sert aux agents, pas à
l'interface web. Il n'existe pas de jeton de lecture ou de triage : pour donner à une personne la
lecture ou le triage, ajoutez son compte à un groupe qui a le rôle `reader` ou `triager` (sur
certains projets ou sur tous). Un jeton `admin` appelle toute l'API REST, par exemple depuis un
script d'administration, mais **n'ouvre pas l'interface** (la page de connexion ne propose que
les comptes) :

```bash
security-review-controller token create --label ops-script --role admin
# {"id": "…", "label": "ops-script", "role": "admin", "project": null, "created_at": "…", "token": "UJB7…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/projects
```

L'API REST liste les findings d'un projet sur l'ensemble de ses rapports, ouverts par défaut,
du plus grave au moins grave (filtres `status`, `severity` et `review_type`, `limit` plafonné par
`SECREVIEW_MAX_LIST_LIMIT`, `total` donne le nombre de findings correspondants pour paginer).
Sans `project`, elle liste les findings de tous les projets que lit l'appelant
(`"project": null`) :

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/findings?project=shop-api&status=open&limit=50"
# {"project": "shop-api", "total": 12, "findings": [{"id": 42, "severity": "critical", "report_id": 7, "project": "shop-api", "branch": "main", "commit_sha": "abc123", "review_type": "codebase-review", "report_created_at": "…", …}, …]}
```

`GET /api/v1/reports` liste les rapports (filtres `project`, `risk_level`, `review_type` et
`author`), chacun avec son `author` et son `submitted_by`. L'`author` n'est renvoyé, filtré,
recherché et trié que pour un appelant qui détient `users.manage` ou `tokens.manage` : pour les
autres, il vaut `null` (dans le rapport et son export Markdown aussi) et le filtre `author` est
ignoré :

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/reports?project=shop-api&author=alice@example.com"
```

Révoquez-le avec `security-review-controller token revoke ops-script`. Chaque changement de
statut est journalisé avec le label du jeton ou du compte :

```
INFO security_review_mcp.web: Finding 42 set to fixed by ops-script
```

et écrit dans le [journal d'audit](../advanced/audit-metrics.md#journal-daudit) (`GET /api/v1/audit`, permission
`audit.read`), avec l'acteur `token:ops-script` ou `user:<nom>`.

!!! warning "Authentification requise pour la Web UI"
    L'API de l'interface refuse les requêtes avec le statut `503` tant qu'aucun utilisateur ni
    jeton n'existe ; la mire de connexion reste affichée et indique que l'authentification doit
    être configurée. `security-review-controller serve` crée le
    [premier administrateur](#premier-administrateur) à son premier démarrage : cela n'arrive donc
    qu'avant ; un compte peut aussi être créé avec `security-review-controller user create`. Cette restriction concerne
    la Web UI ; l'authentification MCP reste indépendante (un compte utilisateur n'ouvre jamais
    `/mcp`). Avec la [connexion OIDC](../advanced/sso.md), l'API demande une connexion
    (`401`) même sans utilisateur ni jeton en base.

### Jetons API

Un jeton `api` appelle l'API REST, depuis un script ou depuis la documentation Swagger
(`/api/docs`, bouton **Authorize**), avec les droits du contrôle d'accès, lus à chaque requête.
Il n'atteint jamais `/mcp`, n'ouvre jamais l'interface et, comme tout jeton, n'accepte jamais un
risque et ne marque jamais un faux positif. Il en existe deux sortes :

- **Jeton personnel** : un utilisateur le crée pour lui-même dans **Mon compte** > **Jetons
  personnels** avec l'**Usage** **API REST — Swagger et scripts** (un au plus par défaut,
  `SECREVIEW_PERSONAL_TOKENS_PER_USER` : révoquez-le pour en créer un autre ; label `<utilisateur>:<label>`, avec un `:` qu'aucun autre label de jeton ne peut contenir, validité bornée par `SECREVIEW_TOKEN_MAX_DAYS`). Il
  porte les droits actuels du compte, qui viennent de ses groupes : il n'atteint plus rien dès que
  le compte les perd, et il est supprimé avec le compte. Personne ne peut le renouveler ni changer
  ses projets ; un administrateur peut le révoquer depuis l'écran **Jetons**.
- **Jeton de rôle** : un administrateur (`tokens.manage`) le crée dans l'écran **Jetons** avec
  l'**Usage** **API REST** et un **Rôle**. Il porte les permissions de ce rôle sur ses projets
  (tous les projets, ou une liste quand le rôle ne détient que des permissions par projet). Son
  créateur doit détenir chacune de ces permissions sur ces projets ; un rôle utilisé par un jeton
  ne peut pas être supprimé.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "swagger", "expires_in_days": 30}'
# {"id": "…", "label": "alice:swagger", "role": "api", "personal": true, "access_role_id": null, …, "token": "Zq3…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/me
# {"client": "alice:swagger", "role": "api", "permissions": {"reports.read": ["shop-api"]}, …}
```

### Jetons MCP et CI personnels

Un utilisateur connecte son propre agent MCP avec un jeton `mcp` personnel, créé dans **Mon
compte** > **Jetons personnels** avec l'**Usage** **MCP**, proposé seulement quand ses groupes
portent la permission `mcp_tokens.create` (rôle `mcp-user`, voir
[Rôles](../advanced/access-control.md#roles) ; 403 sans elle). Un au plus par défaut
(`SECREVIEW_PERSONAL_TOKENS_PER_USER`), en plus du jeton API REST. Il atteint les projets que le
compte peut lire (`reports.read` de ses groupes), lus à chaque requête : un projet donné au compte
ou retiré s'applique aussitôt, tous les projets quand l'un de ses groupes lit tous les projets,
aucun projet quand il n'en a pas. La colonne **Projets** les affiche, de même que l'écran
**Jetons** pour les administrateurs.

Un jeton déjà créé continue de fonctionner quand le compte perd `mcp_tokens.create` : un
administrateur le révoque au besoin. Comme un jeton API REST personnel, il s'arrête tant que le compte doit changer un mot de passe
défini par un administrateur, il est supprimé avec le compte, personne ne peut le renouveler
ni changer ses projets, et un administrateur peut le révoquer. Pour un projet qu'il n'atteint
pas, un administrateur donne au compte l'accès au projet (un groupe qui le lit), ou
l'utilisateur le crée depuis **Projets** s'il est nouveau et qu'il porte `projects.create` (voir
[Création d'un projet](../advanced/access-control.md#creation-dun-projet)) ; un projet demandé par
un [enrôlement](../advanced/http.md#enrolement-demander-le-projet) attend sa validation. Quand le serveur refuse le jeton (inconnu, révoqué ou expiré), l'agent reçoit
un `401` qui invite l'utilisateur à se reconnecter pour en créer un nouveau. Il n'atteint jamais
l'API REST, mais il vaut aussi jeton `ci` personnel (ci-dessous) sur les routes de pipeline : un
seul `SECREVIEW_TOKEN` sur le poste sert à la fois à l'agent MCP et à `security-review-ci`. Un
jeton `mcp` créé par un administrateur sur l'écran **Jetons** reste un jeton d'agent MCP seulement.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "mcp"}'
# {"id": "…", "label": "alice:laptop", "role": "mcp", "personal": true, …, "token": "Zq3…"}
```

Un jeton `ci` personnel (**Usage** **Pipeline CI/CD**, même permission `mcp_tokens.create`, un au
plus par défaut) permet à [`security-review-ci`](gate.md#client-de-pipeline-security-review-ci)
de lancer les scans de code et de dépendances, la gate, l'export SARIF et la tendance depuis le
poste de l'utilisateur, sur les mêmes projets qu'un jeton `mcp` personnel et avec les mêmes
règles (un jeton `mcp` personnel en fait autant : celui-ci ne sert qu'à séparer les deux usages). Il n'atteint que les routes de pipeline (`/api/v1/ci/`), jamais `/mcp` ni le reste de
l'API REST. Un rapport qu'il enregistre est soumis par le jeton (`alice:laptop`). Voir
[scan depuis un poste de travail](../advanced/dependencies.md#scan-depuis-un-poste-de-travail-hook-de-commit).

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "ci"}'
# {"id": "…", "label": "alice:laptop", "role": "ci", "personal": true, …, "token": "Zq3…"}
```

## Comptes utilisateurs

Un compte associe un **identifiant** (lettres, chiffres et `. _ @ -`, 64 caractères au plus), un
**type** et des **groupes** : les rôles de ses groupes donnent ses
[permissions](../advanced/access-control.md#ce-quun-utilisateur-peut-faire). Un compte n'a ni rôle
ni projet propre.

| Type (`auth_source`) | Connexion | Création |
|---|---|---|
| **Local** (`local`) | Identifiant et mot de passe | Par un administrateur, ou le compte `admin` initial |
| **OIDC** (`oidc`) | [Fournisseur d'identité](../advanced/sso.md), sans mot de passe | Par un administrateur, ou à la première connexion si `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` |

Un compte OIDC rejoint aussi, à chaque connexion, les groupes ouverts au OIDC nommés par son claim
des groupes (voir [comptes OIDC](../advanced/sso.md#comptes-oidc)). Les comptes se gèrent dans
l'écran **Utilisateurs**, par l'API REST `/api/v1/users` (permission `users.manage`) ou par la
[CLI](../reference/cli.md#security-review-controller) :

```bash
security-review-controller user create alice --group shop-triagers
# {"id": 2, "username": "alice", "auth_source": "local", "groups": [{"group_id": 3, "name": "shop-triagers", "source": "local"}], "permissions": {…}, …, "password": "q3V…"}
printf '%s\n' "$PASSWORD" | security-review-controller user create bob --password-stdin
security-review-controller user create carol@example.com --sso   # groupes OIDC seulement
security-review-controller user list
security-review-controller user set-groups alice --group readers --group auditors
security-review-controller user set-groups alice --group administrators   # créé s'il manque
security-review-controller user reset-password alice   # compte local : nouveau mot de passe, sessions fermées
security-review-controller user delete alice
security-review-controller group list    # groupes, leurs rôles et leurs membres
```

Par l'API, un compte OIDC se crée avec `"auth_source": "oidc"`, sans `password` ; `group_ids`
liste ses groupes :

```bash
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "carol@example.com", "auth_source": "oidc", "group_ids": [4]}'
```

Un compte sans aucun groupe n'a aucune permission et ne peut pas se connecter.

Pour un compte local, sans `--password-stdin` (ou sans mot de passe dans l'interface), un mot de
passe aléatoire de 24 caractères est généré et affiché **une seule fois**. Un mot de passe choisi
respecte la **politique de mot de passe** : 12 à 256 caractères, avec au moins une minuscule, une
majuscule, un chiffre et un caractère qui n'est ni une lettre ni un chiffre. Les écrans affichent
ces règles sous le champ et cochent chacune pendant la saisie, et **Mon compte** indique aussitôt
si la confirmation correspond. La politique s'applique aux nouveaux mots de passe : un mot de passe
défini avant reste valable jusqu'à son changement. Un compte OIDC n'a jamais de mot de passe : la connexion par
identifiant et mot de passe, la réinitialisation et **Mon compte** le refusent.

### Premier administrateur

À son premier démarrage, tant qu'aucun compte n'existe, le contrôleur crée le compte local
**`admin`** (`SECREVIEW_ADMIN_USERNAME`), membre du groupe `administrators` (rôle `admin`),
avec un mot de passe aléatoire que personne ne connaît et qui n'est jamais écrit dans les
journaux. Le seul moyen d'obtenir un mot de passe est la CLI, qui en définit un nouveau et
l'affiche une fois :

```bash
security-review-controller user reset-password admin
# {"id": 1, "username": "admin", …, "must_change_password": true, "password": "q3V…"}
```

```
WARNING security_review_mcp.controller: Initial Web UI administrator 'admin' created: set its password with `security-review-controller user reset-password admin`
```

Traitez ce mot de passe comme un secret et connectez-vous avec `admin`. L'interface **exige alors
un nouveau mot de passe** avant toute autre chose : elle ouvre **Mon compte**, et l'API refuse
toutes les autres routes (`403`) tant que le mot de passe n'est pas changé. S'il est perdu,
voir [mot de passe perdu](#mot-de-passe-perdu).

Il en va de même de tout mot de passe défini par quelqu'un d'autre : un compte local créé ou
réinitialisé par un administrateur (écran ou CLI) change son mot de passe à sa première connexion.
L'écran **Utilisateurs** affiche **mot de passe à changer** jusque-là.

#### Mot de passe perdu

Le mot de passe est stocké sous forme d'empreinte scrypt : il est impossible de le relire.
Remplacez-le avec la CLI du contrôleur, sur la même base :

```bash
security-review-controller user reset-password admin
```

La commande affiche le compte en JSON, avec un mot de passe généré dans le champ `password`
(`| jq -r .password` pour ne garder que lui). L'ancien mot de passe est aussitôt invalidé, les
sessions ouvertes du compte prennent fin et le nouveau mot de passe doit être changé à la
prochaine connexion. Pour le choisir, donnez-le sur la première ligne de l'entrée standard (il
n'apparaît alors ni dans l'historique du shell ni dans la liste des processus, et le JSON n'a pas
de champ `password`) :

```bash
printf '%s\n' "$NEW_PASSWORD" | security-review-controller user reset-password admin --password-stdin
```

Lancez-la là où tourne le contrôleur :

```bash
# Docker Compose
docker compose exec controller security-review-controller user reset-password admin
# Kubernetes
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller user reset-password admin
```

Un compte OIDC n'a pas de mot de passe (code de sortie `2`). S'il ne reste aucun administrateur,
créez-en un avec `security-review-controller user create NAME --group administrators` (mot de
passe généré, affiché de la même façon) : le compte `admin` n'est créé au démarrage que tant
qu'aucun compte n'existe.

### Connexion et sessions

Quand le contrôleur n'accepte plus la session pendant la navigation (session expirée, mot de passe
changé dans un autre onglet, compte supprimé), une fenêtre **Session expirée** s'ouvre :
**Se reconnecter** ouvre la page de connexion puis revient à la même page.

La page de connexion propose l'identifiant et le mot de passe d'un compte local et, avec la
[connexion OIDC](../advanced/sso.md), le bouton du fournisseur d'identité ; elle
n'accepte pas de jeton. `POST /api/v1/auth/login` vérifie le mot de passe d'un compte local et
renvoie un **jeton de session** signé, valable `SECREVIEW_SESSION_HOURS` heures (8 par défaut),
que l'onglet utilise comme un jeton Bearer :

```bash
curl -s -X POST https://secreview.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username": "alice", "password": "…"}'
# {"session": "eyJ…", "expires_in": 28800, "username": "alice"}
```

Chaque session désigne un compte (local ou OIDC) ; à chaque requête, le contrôleur le relit en
base :

- un changement de ses **groupes**, de leurs rôles ou d'un rôle s'applique immédiatement aux
  sessions ouvertes ;
- une **suppression** ou un **nouveau mot de passe** (changé par l'utilisateur ou réinitialisé
  par un administrateur) ferme toutes les sessions du compte ; `PUT /api/v1/me/password` remet une
  nouvelle session à l'onglet qui a changé le mot de passe.

Les sessions sont signées avec `SECREVIEW_SECRET_KEY` (32 caractères au moins), partagé par
toutes les répliques du contrôleur. Sans lui, un secret aléatoire est tiré à chaque démarrage
(un avertissement est journalisé) : les sessions se terminent au redémarrage du contrôleur et ne
sont pas partagées entre répliques. Définissez-le en production (en Kubernetes, depuis un
`Secret` : voir [Kubernetes](../advanced/architecture.md#kubernetes)).

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
  `/api/v1/` exige une session ou un jeton `admin` ou `api`. Seules les routes de
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
  est accessible sans jeton. Saisissez-y un [jeton API](#jetons-api).
- Le contrôleur n'expose aucune route d'écriture sans jeton.
  L'[enrôlement](../advanced/http.md#enrolement-demander-le-projet) est servi par le **serveur
  MCP** (`POST /api/v1/enroll`, public) : il demande un projet, jamais un jeton ; le
  contrôleur liste et traite les demandes (`GET /api/v1/projects/pending`,
  `POST /api/v1/projects/pending/{id}/approve`, `DELETE /api/v1/projects/pending/{id}`,
  permission `projects.create`). Le contrôleur
  peut donc rester sur un réseau interne.
- Le jeton est envoyé dans l'en-tête `Authorization` : pas de cookie, donc pas de CSRF.
  Seule la [connexion OIDC](../advanced/sso.md) pose un cookie, `HttpOnly`,
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
| `SECREVIEW_ADMIN_USERNAME` | `admin` | Nom du [premier administrateur](#premier-administrateur), créé au premier démarrage du contrôleur tant qu'aucun compte n'existe ; son mot de passe se définit avec `user reset-password` |
| `SECREVIEW_OIDC_ONLY` | `false` | Avec le OIDC activé, refuse la connexion par mot de passe des comptes locaux ([OIDC seul](../advanced/sso.md#oidc-seul)) |
| `SECREVIEW_SECRET_KEY` | — | Secret de signature des sessions (32 caractères au moins), identique sur toutes les répliques ; non défini : aléatoire à chaque démarrage |
| `SECREVIEW_SESSION_HOURS` | `8` | Durée d'une session (1 à 24 heures), connexion par compte local ou OIDC |
| `SECREVIEW_OIDC_AUTO_CREATE_USERS` | `false` | Crée le [compte OIDC](../advanced/sso.md#comptes-oidc) à la première connexion ; sinon un administrateur le crée |
| `SECREVIEW_ENROLLMENT` | `true` | Demandes de projet par les clients MCP sans jeton (sur le serveur MCP), validées dans l'écran **Projets** ; aucun jeton n'est créé |
| `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` | `7` | Jours pendant lesquels un projet demandé attend sa validation avant d'être supprimé |
| `SECREVIEW_WEB_URL` | — | URL publique de l'interface web, donnée par le serveur MCP aux clients sans jeton valide |
| `SECREVIEW_OIDC_*` | — | [Connexion OIDC](../advanced/sso.md), voir la [référence](../reference/configuration.md) |

Le paquet publié et l'image Docker contiennent l'application déjà compilée. Si vous installez
depuis les sources sans la compiler, le contrôleur ne sert que l'API REST et un avertissement est
journalisé. Voir [Contribuer](../contributing.md#interface-web) pour la compiler.
