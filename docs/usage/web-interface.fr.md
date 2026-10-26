# Interface web

L'interface web permet aux équipes sécurité de consulter les rapports enregistrés par les agents
et de **trier les findings** (corrigé, risque accepté, faux positif) sans passer par un client
MCP. Elle est servie par le **contrôleur**, un processus distinct du serveur MCP qui partage sa
base de données (voir [Architecture](../advanced/architecture.md)) :

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
(utilisateurs, groupes, rôles, jetons, journal d'audit, OIDC, paramètres généraux, proxy sortant,
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
langue des rapports de revue se règle dans **Général**, et les messages d'erreur détaillés
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
  **Projets en attente** liste les projets demandés par les agents MCP des utilisateurs
  ([enrôlement](../advanced/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet) : demandeur, adresse, dates de
  demande et d'expiration), chacun marqué **Nouveau projet** ou **Demande d'accès** (un projet
  qui existe déjà) : **Valider** donne l'accès au projet au demandeur, en le créant s'il est nouveau (une demande d'accès demande aussi `users.manage`), **Refuser** supprime
  la demande ; une demande non validée avant son expiration est supprimée. Avec
  `projects.delete`, le bouton corbeille d'une ligne supprime le projet et tout ce qui s'y
  rapporte (voir [Suppression d'un projet](../advanced/access-control.md#suppression-dun-projet)).
- **Projet** : findings ouverts, tendance sur 30 jours à 1 an (graphique et tableau), délai
  moyen de correction, plus ancien finding ouvert, CWE les plus fréquentes, les 20 findings ouverts
  les plus graves (numéro, sévérité, règle, emplacement, rapport : le numéro ouvre le rapport sur
  ce finding) et export SARIF ; **Tous les rapports**
  liste ses rapports. Dans la colonne **Proposition**, une icône de robot clignotante signale un
  finding dont un agent a proposé le statut : survolez-la pour lire le statut proposé, cliquez
  dessus pour ouvrir le finding et appliquer ou rejeter la proposition ([triage](triage.md)). Le bouton **Revoir les findings ouverts** ouvre l'écran suivant ;
  **Acceptations de risque** liste les risques acceptés du projet ; **Actualiser** recharge la
  tendance et les findings ouverts.
- **Findings à revoir** : tous les findings ouverts du projet, sur l'ensemble de ses rapports,
  chaque problème une seule fois ([signalé de nouveau](triage.md#finding-signale-de-nouveau)),
  du plus grave au moins grave puis du rapport le plus récent au plus ancien, pour une revue par
  un expert en cybersécurité. Chaque finding affiche sa description, son extrait de code et sa
  recommandation, et un lien vers son rapport (date, type de revue, branche, commit). Filtres
  par statut (pour revoir les risques acceptés ou les faux positifs), par sévérité et par type
  de revue (**Revue de sécurité**, **Revue de sécurité d'API**, **Revue du code complet**... :
  voir [type de revue](prompts-tools.md#type-de-revue)) ; **Afficher plus** affiche les findings
  suivants. Les utilisateurs qui ont la permission `findings.triage` changent le statut de chaque
  finding depuis cet écran et appliquent ou rejettent les statuts proposés par les agents (voir
  [triage des findings](triage.md)) ; un finding trié reste affiché jusqu'au
  rechargement (bouton **Actualiser**).
- **Acceptations de risque** : les risques acceptés du projet (ou de tous les projets), y compris
  expirés, de l'expiration la plus proche à la plus lointaine. Recherche, tri et filtres par état
  (**Active**, **Expirée**) et par sévérité ; **Actualiser** recharge la liste. Un clic sur un
  finding ouvre ses détails : ses commentaires (le premier est le motif de l'acceptation) et,
  avec la permission `findings.triage`, les formulaires pour ajouter un commentaire, changer la
  date d'expiration et supprimer l'acceptation (voir [acceptations de risque](triage.md#acceptations-de-risque)).
- **Rapports** : liste filtrable par projet et niveau de risque, avec recherche dans les
  métadonnées et le résumé, tri par date, projet, risque, type, branche, jeton ou résumé. La
  colonne **Jeton** affiche le libellé du jeton qui a envoyé le rapport ; le survoler montre
  l'auteur à qui détient `users.manage` ou `tokens.manage`. La
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
  [criticité d'un finding](triage.md#criticite-dun-finding)).
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
- **Utilisateurs** : les administrateurs gèrent les [comptes](user-accounts.md), seuls
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
  jetons [API REST](tokens.md#jetons-api) (Swagger, scripts), qui portent ses droits, et des jetons
  [MCP / CI](tokens.md#jetons-mcp-et-ci-personnels) pour son agent et `security-review-ci`, qui atteignent les projets qu'il peut lire.
- **Jetons** : les jetons sont recherchables, triables et filtrables par usage. Les administrateurs créent et révoquent des jetons pour un ou plusieurs
  projets, ou pour **Tous les projets** (jamais pour un jeton CI/CD). Le champ **Usage** choisit
  **MCP** (rôle `mcp`), **Pipeline CI/CD** (rôle `ci`, pour
  [`security-review-ci`](../advanced/ci.md)) ou **API REST** (rôle
  `api`, avec le **Rôle** qu'il porte, voir [jetons API](tokens.md#jetons-api)) : les jetons sont destinés
  aux machines, une personne lit et trie avec un [compte utilisateur](user-accounts.md).
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
  [expiration et renouvellement](../advanced/bearer-tokens.md#expiration-et-renouvellement-des-jetons)). Un jeton n'ouvre jamais l'interface web. Les jetons `admin` et `metrics` restent non
  restreints et se gèrent uniquement par la CLI. Le secret n'est montré qu'une fois ; seule son empreinte est enregistrée, dans la base de
  données. Une révocation prend effet à la requête suivante.
  L'[enrôlement](../advanced/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet) ne crée aucun jeton : un
  projet demandé par un agent, nouveau ou existant, attend dans **Projets**, et sa validation en
  donne l'accès au demandeur ; un administrateur peut aussi en donner l'accès à un développeur
  en l'ajoutant à son groupe `project:<projet>` (écran **Groupes**).
- **Journal d'audit** : les administrateurs consultent le [journal d'audit](../advanced/audit-metrics.md) :
  décisions de triage, propositions des agents, jetons et demandes de projet, du plus récent
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
MCP et le contrôleur (permission `settings.manage` ; les anciennes adresses `/ui/settings` et
`/ui/settings/language` ouvrent **Général**). **Une variable d'environnement définie (environnement ou fichier
`.env`) est toujours prioritaire** sur la valeur saisie dans l'interface : son champ est alors
verrouillé et affiche la variable, et une valeur enregistrée avant que la variable soit définie
est signalée comme ignorée, avec un bouton **Supprimer**.

- **Général**, avec deux cartes :
  - **Langue des rapports** : choix laissé à l'agent ou langue définie ici (`French`, `fr`,
    `pt-BR`…), quand `SECREVIEW_REPORT_LANGUAGE` n'est pas définie. Elle s'applique aux
    prochains prompts de revue ; l'argument `report_language` d'un prompt reste prioritaire
    ([langue des rapports](prompts-tools.md#langue-des-rapports)).
  - **Adresse du contrôleur** : URL publique racine du contrôleur (`https://…`, sans `/ui`), dont
    le serveur MCP donne l'interface web (`/ui`) aux agents connectés sans jeton valide
    (enrôlement, `401`) et vers laquelle les connecteurs pointent dans leurs fiches.
    `SECREVIEW_CONTROLLER_URL` définie sur le contrôleur (la variable que lit aussi
    `security-review-ci`) est recopiée en base à chaque démarrage et verrouille le champ : le
    serveur MCP l'y lit, sans variable à lui. **Utiliser l'adresse actuelle** remplit l'adresse
    de ce contrôleur. Une modification atteint le
    serveur MCP en moins d'une minute, sans redémarrage, et est enregistrée dans le journal
    d'audit (`controller_url.changed`). Par l'API : `PUT /api/v1/settings/controller-url` avec `value` (`null`
    la supprime).
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
  de chaque projet, avec son envoi automatique facultatif ([connecteurs](../connectors/index.md)).

## Voir aussi

- [Triage des findings](triage.md) : décisions sur les findings, criticité, acceptations de risque ;
- [Jetons](tokens.md) : rôles des jetons, jetons API, jetons MCP et CI personnels ;
- [Comptes utilisateurs](user-accounts.md) : comptes locaux et OIDC, politique de mots de passe.
