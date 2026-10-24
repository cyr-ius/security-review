# Sécurité et limites

## Sécurité du serveur lui-même

- **Deux processus** : le serveur MCP (exposé aux agents) et le contrôleur (API REST, interface
  web, administration) tournent séparément et ne partagent que la base (voir
  [Architecture et déploiement](../advanced/architecture.md)). Le serveur MCP n'accepte que les
  jetons `mcp` et `admin`, le contrôleur que les sessions web et les jetons `admin` et `api`, plus `ci` sur ses
  routes de pipeline (`/api/v1/ci/` : gate, SARIF et tendance en lecture seule, scans qui
  enregistrent des rapports de ses projets) et nulle part ailleurs. Le contrôleur
  n'expose aucune route d'écriture sans jeton : il peut rester sur un réseau interne, et la
  compromission du serveur MCP exposé ne donne pas accès à l'interface d'administration.
- **Transport HTTP** : authentification MCP par jeton Bearer et TLS intégrés mais facultatifs (voir
  [Serveur HTTP, authentification et TLS](../advanced/http.md)). Les jetons sont stockés en
  base et seules leurs empreintes SHA-256 sont conservées. Chaque requête recherche l'empreinte
  du jeton présenté, ce qui ne révèle rien d'exploitable sans préimage, puis la vérifie en temps
  constant : une révocation est donc immédiate sur toutes les instances. Un jeton créé avec
  `--project` est limité à ce projet dans les outils MCP et les routes de pipeline : tout autre projet,
  rapport ou finding est traité comme inexistant (voir
  [jetons restreints à un projet](../advanced/http.md#jetons-restreints-a-un-projet)). Tant
  qu'aucun jeton n'existe, le serveur MCP reste fermé (seul l'enrôlement est accessible), sauf
  s'il écoute sur localhost ou avec `SECREVIEW_ALLOW_UNAUTHENTICATED=true`. Si l'écoute n'est pas sur
  localhost, un avertissement est journalisé quand l'authentification ou le TLS manque. Le
  serveur ne génère jamais de certificat TLS : le HTTPS utilise le certificat fourni par
  l'opérateur, signé par une
  [autorité de certification](../advanced/http.md#autorite-de-certification). Il n'y a
  pas de limitation de débit. Chaque jeton porte un [rôle](../usage/web-interface.md#roles)
  (`mcp`, `api`, `admin`, `ci`, `metrics`). Un jeton `api` ne porte que des droits du contrôle
  d'accès, lus à chaque requête : ceux de son utilisateur (jeton personnel, supprimé avec
  l'utilisateur, jamais renouvelé par un tiers, dont le nouveau secret porterait les droits de
  l'utilisateur) ou ceux de son rôle sur ses projets (jeton de rôle, dont le créateur doit détenir
  chaque permission). Un jeton ne crée jamais un autre jeton personnel. Un jeton `mcp` sans projet
  accède à tous les outils MCP et à tous les projets ; un jeton `mcp` personnel atteint les
  projets que son utilisateur peut lire à l'instant, aucun quand l'utilisateur n'en a pas (jamais
  tous les projets par défaut), et s'arrête quand l'utilisateur est supprimé ou doit changer un mot
  de passe défini par un administrateur. Un utilisateur web
  détient au plus `SECREVIEW_PERSONAL_TOKENS_PER_USER` jetons personnels de chaque rôle (1 par
  défaut).
- **Expiration et renouvellement des jetons** : un jeton expiré n'authentifie plus rien (`401`), et `SECREVIEW_TOKEN_MAX_DAYS` borne la validité de tout jeton créé ou renouvelé. Les jetons
  expirés comptent toujours comme configurés : un serveur dont tous les jetons ont expiré reste
  fermé. Un renouvellement n'enregistre que l'empreinte du nouveau secret ; l'empreinte
  précédente est conservée pendant le délai de grâce (168 heures au plus), comparée en temps
  constant comme l'actuelle, et l'ancien secret d'un jeton expiré ne revient jamais (voir
  [expiration et renouvellement](../advanced/http.md#expiration-et-renouvellement-des-jetons)).
- **Jetons refusés sur `/mcp`** : un jeton inconnu, révoqué ou expiré reçoit un `401` dont la
  description invite l'utilisateur à se connecter à l'interface web pour créer un nouveau jeton
  MCP personnel (voir [jeton refusé](../advanced/http.md#jeton-refuse-se-reconnecter)) ; il
  n'atteint jamais le serveur d'enrôlement. Chaque refus est aussi journalisé en avertissement
  par le serveur MCP (`Rejected unauthenticated request` / `Rejected expired token`, avec
  l'adresse du client) ; la [métrique](../advanced/audit-metrics.md)
  `secreview_auth_rejections_total` ne compte que les refus du contrôleur. `SECREVIEW_WEB_URL`,
  donnée dans cette description, est une URL publique : elle ne contient aucun identifiant
  (refusé au démarrage).
- **Journal d'audit** : les décisions de triage, les propositions des agents, les créations,
  renouvellements et révocations de jetons et les enrôlements sont écrits
  dans la même transaction que le changement, avec leur acteur (`user:`, `token:`, `cli`,
  `anonymous`). Les détails sont bornés et masqués, et ne contiennent jamais de jeton ni de mot
  de passe ; aucun outil ni aucune route ne modifie un événement, seule la purge de
  `SECREVIEW_AUDIT_RETENTION_DAYS` les supprime (voir
  [journal d'audit](../advanced/audit-metrics.md#journal-daudit)).
- **Métriques** : `/metrics` n'existe que sur le contrôleur (le serveur MCP garde `/mcp`,
  `/api/v1/enroll` et `/healthz`), derrière un jeton `metrics` ou `admin` ; un jeton `metrics`
  n'atteint rien d'autre. La réponse contient des nombres et des noms de projets, jamais un
  finding, un label de jeton ou un secret, et chaque valeur de label est échappée (voir
  [métriques Prometheus](../advanced/audit-metrics.md#metriques-prometheus)).
- **Jetons de pipeline** (`ci`) : toujours restreints à des projets (un jeton `ci` sans projet
  ne peut pas être créé, et un jeton trouvé sans projet n'en atteint aucun) ; un jeton `ci`
  personnel atteint les projets que son utilisateur peut lire à l'instant, comme un jeton `mcp`
  personnel, qui vaut aussi jeton `ci` sur les routes de pipeline (jamais un jeton `mcp` créé par
  un administrateur). Il ne lit que le
  gate, le journal SARIF et la tendance de ses projets ; les autres routes du contrôleur, `/mcp`
  et l'interface web répondent `403`, les autres projets `404`. Le client de pipeline
  ([`security-review-ci`](../usage/gate.md#client-de-pipeline-security-review-ci)) n'ouvre
  aucune base, ne lit le jeton que dans l'environnement ou sur stdin, refuse le HTTP en clair
  hors localhost, les identifiants dans l'URL et les redirections, et borne les réponses.
- **Enrôlement** (actif par défaut, `SECREVIEW_ENROLLMENT`) : un client sans jeton atteint un
  serveur MCP restreint qui ne permet que de demander son projet, et `POST /api/v1/enroll` est
  public sur le serveur MCP (corps limité à 4 Kio). L'enrôlement **ne crée jamais de jeton** et
  ne donne aucun accès : un projet demandé reste **en attente** jusqu'à ce qu'un utilisateur
  portant `projects.create` le valide sur le contrôleur, ce qui crée son groupe de projet sans
  aucun membre ; seul un administrateur y ajoute un utilisateur, et le développeur crée un jeton
  MCP personnel dans l'interface web, après s'être connecté. La réponse est la même que le
  projet existe ou non. Les enrôlements sont bornés (20 projets en attente, 5 par adresse
  cliente et par heure, `429` au-delà), une demande que personne n'a validée sous
  `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` est supprimée, et le texte libre du demandeur est
  masqué et tronqué : vérifiez le demandeur et l'adresse avant de valider. Chaque enrôlement est audité. Voir
  [l'enrôlement](../advanced/http.md#enrolement-demander-le-projet).
- **Appels réseau sortants** : le serveur MCP n'en fait aucun, et ne charge même pas les
  modules du contrôleur qui en font (téléchargement des avis, OIDC, syslog, tickets, recherche
  de nouvelle version) : un test le vérifie. La commande
  `security-review-mcp enroll` contacte, à la demande de l'opérateur, l'URL qu'il indique ; elle
  refuse HTTP en clair hors localhost (sauf `--allow-http`), les identifiants dans l'URL et les
  redirections. Le contrôleur ne télécharge les avis OSV que si un administrateur l'active
  (`SECREVIEW_OSV_AUTO_UPDATE` ou `advisories update`) : uniquement depuis `SECREVIEW_OSV_URL`
  en HTTPS avec vérification du certificat, redirections limitées à HTTPS, taille bornée
  (`SECREVIEW_OSV_MAX_DOWNLOAD_MB`), proxy facultatif dont les identifiants ne sont jamais
  journalisés. Le bouton **Mettre à jour maintenant** de l'interface web (permission `settings.manage`) n'est
  accepté que si `SECREVIEW_OSV_AUTO_UPDATE=true`. Le proxy sortant (`HTTPS_PROXY` / `NO_PROXY`, ou
  l'écran **Proxy sortant**) sert au téléchargement OSV et au fournisseur OIDC ; seul le nom des
  réglages modifiés est journalisé. Un proxy défini dans l'interface web est
  enregistré en base **avec ses identifiants, en clair** : l'API ne les renvoie jamais (mot de
  passe remplacé par `***`) et les messages d'erreur de l'historique en sont expurgés, mais
  préférez `HTTPS_PROXY` (secret Kubernetes) si la base n'est pas protégée comme un
  secret. Voir la
  [mise à jour automatique](../advanced/dependencies.md#mise-a-jour-automatique-par-le-controleur).
  Avec la [connexion OIDC](../advanced/sso.md)
  (`SECREVIEW_OIDC_ENABLED`, désactivée par défaut), le contrôleur contacte aussi le fournisseur
  d'identité configuré : HTTPS uniquement (HTTP seulement sur localhost), redirections limitées
  à HTTPS, réponses bornées à 1 Mio, délai de 10 secondes. Cette configuration peut aussi être
  [modifiée dans l'interface](../advanced/sso.md#configurer-le-oidc-dans-linterface)
  par un administrateur, avec les mêmes contrôles (refus d'une configuration invalide) ; le
  bouton **Tester la connexion** contacte l'émetteur saisi, sous les mêmes conditions. Le
  **secret client** saisi dans l'interface est enregistré en base **en clair** : l'API ne le
  renvoie jamais (`***`) et les journaux ne citent que le nom des réglages modifiés ; préférez
  `SECREVIEW_OIDC_CLIENT_SECRET` (secret Kubernetes) si la base n'est pas protégée comme un
  secret. Avec `SECREVIEW_UPDATE_CHECK_ENABLED=true` (désactivé par défaut), la page **À
  propos** demande à `api.github.com` la dernière version publiée du dépôt : HTTPS uniquement,
  par le proxy sortant, redirections limitées au HTTPS, réponse bornée à 512 Kio, délai de
  10 secondes, au plus une requête par processus du contrôleur toutes les 6 heures (15 minutes
  après un échec) ; seuls la version et le lien de la version sont conservés (un lien hors des
  versions du dépôt est remplacé), et la page ne reçoit qu'un code d'erreur court. Une fois
  un connecteur activé dans l'écran **Connecteurs** (tous désactivés par défaut, tous verrouillés
  par `SECREVIEW_TICKETING_ENABLED=false`), le contrôleur crée des tickets dans les Jira et
  ServiceNow configurés : HTTPS uniquement, par le proxy sortant, **aucune
  redirection**, réponse bornée à 1 Mio, délai de 15 secondes ; les textes envoyés sont de
  nouveau masqués et, dans Jira, jamais interprétés comme balisage wiki ; les secrets saisis
  dans l'écran **Connecteurs** sont stockés en clair, jamais renvoyés (`***`) et liés à l'hôte de
  leur URL ; un connecteur tiers n'est chargé que si `SECREVIEW_TICKETING_PLUGINS` le nomme et
  ne joint que son URL configurée par le client du contrôleur, voir
  [ticketing](../advanced/ticketing.md#securite). Avec
  `SECREVIEW_AUDIT_SYSLOG_ADDRESS` ou un serveur défini sur la page **Journal d'audit**
  (désactivé par défaut ; permission `settings.manage`, `udp://`, `tcp://` ou `tls://`
  uniquement, modification inscrite au journal d'audit), le contrôleur envoie les
  [événements d'audit](../advanced/audit-metrics.md#envoi-vers-syslog) à ce serveur syslog (UDP
  ou TCP en clair, TLS avec vérification du certificat et du nom d'hôte du serveur, ou socket
  Unix ; pas de proxy) ; les événements ne contiennent aucun secret (détails masqués), et le
  serveur MCP ne se connecte toujours nulle part.
- **Administrateur initial** : créé par le contrôleur à son premier démarrage avec un mot de
  passe aléatoire que personne ne connaît, jamais journalisé ni passé par une variable ; le seul
  moyen d'obtenir un mot de passe est `security-review-controller user reset-password`, lancé par
  un opérateur, qui l'affiche une fois. Avec `SECREVIEW_OIDC_ONLY=true` et le OIDC activé, la connexion par mot
  de passe des comptes locaux est refusée (`403`) ; une configuration OIDC désactivée ou invalide
  ne bloque jamais les comptes locaux.
- **Interface web** (contrôleur) : l'API REST exige toujours une session ou un jeton `admin` ou
  `api` ;
  sans utilisateur ni jeton, elle répond `503` au lieu d'accorder les droits anonymes. Seuls une
  session ou un jeton `api` qui ont la permission `findings.triage`, ou un jeton `admin`, changent le statut d'un
  finding (action journalisée avec l'utilisateur ou le label du jeton), et seule une personne
  connectée à l'interface (session) accepte un risque ou marque un faux positif : un jeton Bearer
  est refusé (`403`), même `admin`. Ces deux décisions exigent un motif et une date d'expiration
  (au plus `SECREVIEW_MAX_DISMISSAL_DAYS` jours) ; l'approbateur est l'utilisateur connecté, et le
  finding est de nouveau compté comme ouvert une fois la date passée. Seule une acceptation peut
  être sans date d'expiration, sauf si `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false` : réglez-le
  ainsi pour imposer une revue périodique de chaque risque accepté. Un risque moins grave que
  `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY` (`medium` par défaut) est accepté sans motif ni date,
  toujours par une personne connectée, enregistrée comme approbateur ; laissez la variable vide
  pour les exiger à chaque acceptation. Les commentaires d'un finding
  suivent la même règle (session avec `findings.triage`) et sont en ajout seul : aucune route ne
  les modifie ni ne les supprime. De même pour relever la criticité d'un finding : avec une
  justification, journalisé, jamais sous la criticité du rapport (baisser un finding passe par
  une acceptation de risque).
- **Les agents ne ferment jamais un finding** : le serveur MCP n'offre que
  `propose_finding_status`, qui enregistre une proposition (motif masqué et borné, auteur tiré du
  jeton) sans changer le statut ni la gate. Le code relu est non fiable : une injection de prompt
  ne peut pas neutraliser un finding. Pages servies avec une CSP
  stricte et les en-têtes anti-clickjacking, et chaque réponse du contrôleur (API, refus
  compris) porte `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, une CSP fermée quand la route n'en définit pas et, en HTTPS (TLS du
  contrôleur, ou `X-Forwarded-Proto` d'un proxy listé dans `SECREVIEW_FORWARDED_ALLOW_IPS`),
  `Strict-Transport-Security: max-age=31536000` ; jeton gardé dans le `sessionStorage` de l'onglet.
  La documentation Swagger et son schéma OpenAPI sont désactivés par défaut
  (`SECREVIEW_SWAGGER_ENABLED`) ; une fois activés, ils sont publics, servis depuis des fichiers
  locaux uniquement avec une CSP stricte, et les routes de données
  restent protégées. Le contrôle est fait deux fois : par le middleware Bearer, puis par
  chaque route de l'API, qui refuse (`401`) toute requête sans identité authentifiée. Ainsi,
  l'API ne donne jamais de droits par défaut, même si elle est servie sans le middleware.
  Chaque réponse JSON passe par son modèle de réponse déclaré : un champ qu'un service ajouterait
  par erreur (une empreinte, un secret) est retiré au lieu d'être renvoyé. Les réponses qui
  contiennent un secret (session, jeton créé ou renouvelé, mot de passe généré) sont envoyées
  avec `Cache-Control: no-store`.
- **Injection de prompt par le code relu** : le contenu que le serveur renvoie à un modèle est
  balisé comme une donnée. Le code des prompts et les preuves enregistrées d'un finding sont
  entourés d'une clôture de code plus longue que toute suite d'accents graves qu'ils contiennent :
  ils ne peuvent pas fermer leur bloc. Les caractères invisibles (largeur nulle, contrôles
  bidirectionnels, Unicode tags et sélecteurs de variante supplémentaires) sont remplacés par un
  marqueur visible `<U+XXXX>` dans ces blocs, dans les extraits de `scan_code` et dans le
  résumé, la description, la preuve et la recommandation enregistrés dans un rapport (puis coupés
  de nouveau à `SECREVIEW_MAX_CONTENT_CHARS`) : rien n'est supprimé, le texte caché devient
  lisible. Les
  [règles `AI-*`](../usage/rules.md#regles-par-defaut-par-plateforme) signalent les caractères
  cachés et le texte adressé à un assistant IA, pour que la gate puisse les bloquer. Le serveur
  ne voit que ce que l'agent lui envoie : il ne peut pas filtrer les fichiers que l'hôte lit avec
  ses propres outils ; la [garde de lecture](../advanced/read-guard.md), un hook côté hôte, les
  vérifie avant que l'assistant ne les lise.
- **Comptes utilisateurs** ([identifiant et mot de passe](../usage/web-interface.md#comptes-utilisateurs)) :
  seule une empreinte **scrypt** salée (N=2¹⁴, r=8, p=5, sel aléatoire de 16 octets) est
  stockée ; une empreinte stockée aux paramètres hors bornes est refusée au lieu d'épuiser la
  mémoire. Mots de passe de 12 à 256 caractères, avec une
  minuscule, une majuscule, un chiffre et un caractère qui n'est ni l'un ni l'autre (contrôlés par
  le contrôleur, mots de passe générés compris) ; un mot de passe défini par quelqu'un d'autre
  (premier administrateur, création ou réinitialisation par un administrateur) doit être changé
  à la première connexion : jusque-là, la session n'atteint que **Mon compte** (`403` ailleurs), identifiants limités à `[A-Za-z0-9._@-]`. La
  vérification coûte le même temps que l'identifiant existe ou non (empreinte factice), et
  l'échec renvoie toujours le même `401`. Les échecs sont limités en base, partagés par toutes
  les réplicas (5 par identifiant et adresse, 20 par adresse, sur 15 minutes, puis `429`), comme
  les requêtes d'une adresse vers l'API REST (`SECREVIEW_RATE_LIMIT_*`, comptées avant le
  contrôle du jeton, pour limiter aussi les essais de jetons ; les compteurs enregistrent des
  empreintes SHA-256, jamais les adresses) ; derrière un reverse proxy,
  l'adresse du client n'est lue dans `X-Forwarded-For` que pour les proxies listés dans
  `SECREVIEW_FORWARDED_ALLOW_IPS` (`*` laisse tout client choisir son adresse et contourner les
  limites). Seuls les identifiants valides sont
  journalisés, jamais les mots de passe. La session est un jeton signé avec
  `SECREVIEW_SECRET_KEY`, comme celle du OIDC, mais le compte est **relu en base à chaque
  requête** : suppression, nouveau rôle ou nouveaux projets s'appliquent immédiatement, et un
  changement de mot de passe tire une nouvelle version de session aléatoire qui invalide toutes
  les sessions précédentes. La session doit aussi porter l'identifiant du compte : elle n'ouvre
  jamais un compte recréé sous le même numéro interne. Le dernier administrateur, local ou OIDC (par son rôle ou celui de ses groupes), ne peut être ni supprimé ni rétrogradé. Le mot de passe
  du compte `admin` initial apparaît une fois dans les journaux du contrôleur : protégez-les et
  changez-le dès la première connexion.
- **Connexion OIDC (OpenID Connect)**, facultative : flux *authorization code* avec PKCE `S256`,
  state lié au navigateur par un cookie signé `HttpOnly` / `SameSite=Lax` de 10 minutes, nonce,
  ID token vérifié (signature par les clés JWKS du fournisseur, algorithmes asymétriques
  uniquement, jamais `none` ni HMAC ; émetteur, audience, `azp`, expiration). Les permissions
  viennent des [groupes](../advanced/access-control.md) du compte : ceux donnés par un
  administrateur et les groupes ouverts au OIDC dont le nom est exactement une valeur du claim des
  groupes (les autres valeurs sont ignorées, un groupe non ouvert au OIDC n'est jamais rejoint par
  le claim) ; une session OIDC n'ouvre jamais `/mcp`. Le compte est identifié par l'émetteur et le `sub` de
  sa première connexion (uniques en base), jamais par un nom : un nom changé chez le fournisseur
  garde le compte. Il est nommé à sa création par l'identifiant exact du claim
  `SECREVIEW_OIDC_USERNAME_CLAIM` (sans repli sur `email` ou `sub`, valeur refusée si ce n'est pas
  un identifiant valide), qui lie aussi un compte créé à l'avance par un administrateur :
  choisissez un claim que l'utilisateur ne peut pas modifier chez le fournisseur. Par défaut (`SECREVIEW_OIDC_AUTO_CREATE_USERS=false`), seul un compte OIDC créé par
  un administrateur peut se connecter. Une connexion OIDC n'ouvre jamais un compte local du même
  nom, et le compte est lié à l'émetteur et au `sub` de sa première connexion : un autre `sub`
  ou un autre émetteur est refusé. Un
  compte OIDC supprimé est révoqué, par son nom et par son émetteur et son `sub` : la création automatique ne le recrée pas, tant qu'un
  administrateur ne l'a pas recréé ou autorisé à nouveau.
  Vérifiez le demandeur d'un enrôlement (texte libre, non vérifié) avant de lui donner la lecture
  du projet. Une session restreinte à des projets l'est comme un jeton `--project`. La session est
  un jeton signé (HMAC-SHA256, clé dérivée de `SECREVIEW_SECRET_KEY`) qui désigne le compte,
  relu à chaque requête : la suppression du compte la coupe aussitôt. Elle est acceptée par le
  contrôleur seulement, jamais par le serveur MCP. L'URL de retour après connexion est limitée aux chemins locaux. Codes,
  jetons et secrets ne sont jamais journalisés par le contrôleur ; le code d'autorisation
  apparaît toutefois dans les journaux d'accès d'un reverse proxy ou d'uvicorn, ce qui est
  sans danger : il est à usage unique et inutilisable sans le vérificateur PKCE du cookie. Les
  réglages secrets (`SECREVIEW_SECRET_KEY`, `SECREVIEW_OIDC_CLIENT_SECRET`,
  `SECREVIEW_TLS_KEYFILE_PASSWORD`, `SECREVIEW_DATABASE_URL`) sont typés comme secrets : ils
  n'apparaissent jamais dans un affichage des réglages. Sans `SECREVIEW_SECRET_KEY`, le
  contrôleur tire un secret de session aléatoire à chaque démarrage, gardé en mémoire
  seulement (un avertissement est journalisé) : les sessions se terminent au redémarrage.
- **Pas d'accès disque côté MCP** : `scan_code` travaille uniquement sur le contenu fourni ; le
  serveur ne lit aucun fichier du disque, ce qui évite les traversées de chemin. Pour le scan du
  dépôt complet, le client de pipeline (`security-review-ci scan-code`), lancé par l'opérateur
  sur un dossier qu'il choisit, lit les fichiers sans suivre les liens symboliques et envoie
  leur contenu au contrôleur, qui le scanne sans lire son propre disque.
- **Scans de pipeline** : `POST /api/v1/ci/scan/code` et `/scan/deps` demandent un jeton `ci` ou
  `admin` (une session web est refusée) et restent dans les
  projets du jeton ; ils n'enregistrent un rapport qu'avec `save`. Le corps de la requête est
  borné (`SECREVIEW_MAX_SCAN_REQUEST_MB`, `413` au-delà, lu après la vérification du jeton),
  comme le nombre de fichiers (`SECREVIEW_MAX_SCAN_FILES`) et leur taille ; les secrets sont
  masqués dans les extraits et dans le rapport enregistré.
- **Corps des requêtes du contrôleur** : chaque corps est borné avant d'être analysé, `413`
  au-delà : 512 Kio pour les routes JSON, publiques comprises (connexion, SSO), 8 Mio pour les
  imports de packs et `SECREVIEW_MAX_SCAN_REQUEST_MB` pour les scans de pipeline. Le
  `Content-Length` déclaré est vérifié d'abord, un corps fragmenté (chunked) au fil de la
  lecture.
- **Corps des requêtes du serveur MCP** : un corps sur `/mcp` n'est lu qu'après la
  vérification du jeton et il est borné (`413` au-delà) : `SECREVIEW_MAX_MCP_REQUEST_MB` pour un
  client authentifié, 64 Kio pour un client sans jeton servi par le serveur d'enrôlement. Un
  jeton refusé reçoit son `401` avant que son corps soit lu.
- **Base de données** : les requêtes SQL passent par l'ORM (paramètres liés) ; les tailles
  d'entrée, le nombre de findings et la pagination sont bornés. Chaque nom de projet est
  [normalisé](../usage/prompts-tools.md#nom-du-projet) avant usage : seuls des lettres, des
  chiffres et des tirets simples atteignent la base, les journaux, les libellés des métriques et
  les noms de fichiers. Le schéma est migré par
  Alembic ; le serveur MCP HTTP ne le modifie jamais et refuse de servir une base qui n'est pas
  à la révision attendue.
- **Règles de scan** : les règles par défaut (`default_rules.toml`) sont copiées en base au
  premier lancement. Si la base est inaccessible ou n'a jamais été initialisée, le serveur
  applique directement ce fichier : le scan ne tourne jamais sans règles. Une règle par défaut
  peut être modifiée ou désactivée par un administrateur, mais pas supprimée
  (voir [Règles](../usage/rules.md#regles-par-defaut)).
- **Normes de développement** : leur contenu est transmis tel quel à l'assistant IA comme
  consignes ; seuls les administrateurs du contrôleur les écrivent (champs validés et bornés,
  200 normes de 50 000 caractères au plus). Le serveur MCP les lit seulement, et la tâche
  fournie au prompt `development-standards` est encadrée pour ne pas pouvoir en sortir. Le prompt
  rappelle qu'une norme ne prime jamais sur la sécurité (voir
  [Normes de développement](../usage/standards.md)).
- **Journaux** sur stderr (stdout est réservé au protocole en stdio).

!!! warning "Protégez la base"
    Les rapports contiennent des informations sensibles sur vos vulnérabilités : protégez la base
    (droits fichier, compte PostgreSQL dédié, sauvegardes chiffrées).

## Limites connues

- Le scan par motifs produit des pistes et des faux positifs ; il ne remplace ni un SAST, ni une
  analyse SCA complète (pas de résolution transitive des manifestes, base à tenir à jour), ni
  une relecture humaine.
- Les règles sont des motifs ligne par ligne : elles ne voient ni le flux de données ni les
  contrôles absents (autorisation manquante, par exemple). Ce travail reste celui de l'agent
  guidé par les checklists, et de vos outils SAST/SCA.
- Les quelques [analyses Tree-sitter](../usage/rules.md#regles-par-defaut) (`PY-026`, `JV-019`,
  `NG-021`, `GO-019`, `CS-021`, `RS-015`, `TS-016`) ne suivent que des flux simples dans un seul
  fichier. Elles sont bornées pour qu'un fichier piégé ne puisse pas bloquer un scan : chaque
  fonction est analysée une fois par état d'entrée, et le code trop imbriqué n'est contrôlé que
  par les motifs.
- La [couverture d'une revue](../usage/prompts-tools.md#couverture-de-la-revue) (résultats de
  checklist, règles des pistes du scan) est déclarée par l'agent : le serveur ne garde que les
  identifiants qu'il connaît et marque `not_covered` les points sautés, il ne peut pas vérifier
  que l'agent a réellement lu le code.
- L'`author` d'un rapport (nom d'utilisateur du développeur) est déclaré par le client :
  quiconque détient un jeton du projet peut nommer quelqu'un d'autre. Seul `submitted_by`, le
  libellé du jeton qui a enregistré le rapport, est fixé par le serveur (voir
  [auteur d'un rapport](../usage/prompts-tools.md#auteur-dun-rapport)). Un `author` est souvent
  une adresse e-mail, donc une donnée personnelle, conservée aussi longtemps que le rapport :
  dans l'interface web et l'API REST, seul qui détient `users.manage` ou `tokens.manage` la voit
  (les autres ne peuvent pas non plus la retrouver par le filtre, la recherche ou le tri) ; les
  outils MCP la renvoient toujours aux jetons qui atteignent le projet.
