# Sécurité et limites

## Sécurité du serveur lui-même

- **Deux processus** : le serveur MCP (exposé aux agents) et le contrôleur (API REST, interface
  web, administration) tournent séparément et ne partagent que la base (voir
  [Architecture et déploiement](../demarrage/kubernetes.md)). Le serveur MCP n'accepte que les
  rôles `mcp` et `admin`, le contrôleur que `reader`, `triager` et `admin`. Le contrôleur
  n'expose aucune route d'écriture sans jeton : il peut rester sur un réseau interne, et la
  compromission du serveur MCP exposé ne donne pas accès à l'interface d'administration.
- **Transport HTTP** : authentification MCP par jeton Bearer et TLS intégrés mais facultatifs (voir
  [Serveur HTTP, authentification et TLS](../demarrage/http.md)). Les jetons sont stockés en
  base et seules leurs empreintes SHA-256 sont conservées. Chaque requête recherche l'empreinte
  du jeton présenté, ce qui ne révèle rien d'exploitable sans préimage, puis la vérifie en temps
  constant : une révocation est donc immédiate sur toutes les instances. Un jeton créé avec
  `--project` est limité à ce projet dans les outils MCP et l'API web : tout autre projet,
  rapport ou finding est traité comme inexistant (voir
  [jetons restreints à un projet](../demarrage/http.md#jetons-restreints-a-un-projet)). Si l'écoute n'est pas sur
  localhost, un avertissement est journalisé quand l'authentification ou le TLS manque. Le
  [certificat auto-signé](../demarrage/http.md#certificat-auto-signe) facultatif est régénéré à
  chaque démarrage (clé privée en `0600` dans un dossier temporaire, jamais journalisée) et n'est
  pas reconnu par les clients sans ajout explicite. Il n'y a
  pas de limitation de débit. Chaque jeton porte un [rôle](../utilisation/interface-web.md#roles)
  (`mcp`, `reader`, `triager`, `admin`) ; un jeton `mcp` sans projet accède à tous les outils
  MCP et à tous les projets.
- **Enrôlement** (actif par défaut, `SECREVIEW_ENROLLMENT`) : un client sans jeton atteint un
  serveur MCP restreint qui ne permet que de déposer une demande, et `POST /api/v1/enroll` est
  public sur le serveur MCP (corps limité à 4 Kio). L'approbation se fait sur le contrôleur. Une demande est un jeton `mcp` restreint au projet, **en attente** : il ne donne accès
  à rien avant l'approbation d'un administrateur, et les demandes en attente n'activent jamais
  l'authentification d'un serveur ouvert. Le nombre de demandes en attente est borné (20) et
  une demande non traitée expire après 7 jours ; le texte libre du demandeur est masqué et
  tronqué. N'importe quel client qui atteint le serveur peut déposer une demande : vérifiez le
  demandeur et l'adresse affichés avant d'approuver, ou désactivez l'enrôlement. Voir
  [l'enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton).
- **Appels réseau sortants** : le serveur MCP n'en fait aucun. La commande
  `security-review-mcp enroll` contacte, à la demande de l'opérateur, l'URL qu'il indique ; elle
  refuse HTTP en clair hors localhost (sauf `--allow-http`), les identifiants dans l'URL et les
  redirections. Le contrôleur ne télécharge les avis OSV que si un administrateur l'active
  (`SECREVIEW_OSV_AUTO_UPDATE` ou `advisories update`) : uniquement depuis `SECREVIEW_OSV_URL`
  en HTTPS avec vérification du certificat, redirections limitées à HTTPS, taille bornée
  (`SECREVIEW_OSV_MAX_DOWNLOAD_MB`), proxy facultatif dont les identifiants ne sont jamais
  journalisés. Le bouton **Mettre à jour maintenant** de l'interface web (rôle `admin`) n'est
  accepté que si `SECREVIEW_OSV_AUTO_UPDATE=true`. Un proxy défini dans l'interface web est
  enregistré en base **avec ses identifiants, en clair** : l'API ne les renvoie jamais (mot de
  passe remplacé par `***`) et les messages d'erreur de l'historique en sont expurgés, mais
  préférez `SECREVIEW_OSV_PROXY` (secret Kubernetes) si la base n'est pas protégée comme un
  secret. Voir la
  [mise à jour automatique](../utilisation/dependances.md#mise-a-jour-automatique-par-le-controleur).
  Avec la [connexion SSO](../utilisation/interface-web.md#connexion-sso-openid-connect)
  (`SECREVIEW_OIDC_ENABLED`, désactivée par défaut), le contrôleur contacte aussi le fournisseur
  d'identité configuré : HTTPS uniquement (HTTP seulement sur localhost), redirections limitées
  à HTTPS, réponses bornées à 1 Mio, délai de 10 secondes.
- **Interface web** (contrôleur) : l'API REST exige toujours un jeton de rôle web ; sans configuration, elle
  répond `503` au lieu d'accorder les droits anonymes. Seuls `triager` et `admin` changent
  le statut d'un finding (action journalisée avec le label du jeton). Pages servies avec une CSP
  stricte et les en-têtes anti-clickjacking ; jeton gardé dans le `sessionStorage` de l'onglet.
  La documentation Swagger et son schéma OpenAPI sont publics, mais les routes de données
  restent protégées. Le contrôle est fait deux fois : par le middleware Bearer, puis par
  chaque route de l'API, qui refuse (`401`) toute requête sans identité authentifiée. Ainsi,
  l'API ne donne jamais de droits par défaut, même si elle est servie sans le middleware.
- **Connexion SSO (OpenID Connect)**, facultative : flux *authorization code* avec PKCE `S256`,
  state lié au navigateur par un cookie signé `HttpOnly` / `SameSite=Lax` de 10 minutes, nonce,
  ID token vérifié (signature par les clés JWKS du fournisseur, algorithmes asymétriques
  uniquement, jamais `none` ni HMAC ; émetteur, audience, `azp`, expiration). Le rôle vient des
  groupes de l'utilisateur ; sans groupe reconnu, la connexion est refusée par défaut, et ni le
  rôle `admin` par défaut ni le rôle `mcp` ne sont possibles. La session est un jeton signé
  (HMAC-SHA256, clé dérivée de `SECREVIEW_OIDC_SESSION_SECRET`), accepté par le contrôleur
  seulement, jamais par le serveur MCP, et révocable uniquement par son expiration ou un
  changement du secret. L'URL de retour après connexion est limitée aux chemins locaux. Codes,
  jetons et secrets ne sont jamais journalisés par le contrôleur ; le code d'autorisation
  apparaît toutefois dans les journaux d'accès d'un reverse proxy ou d'uvicorn, ce qui est
  sans danger : il est à usage unique et inutilisable sans le vérificateur PKCE du cookie.
- **Pas d'accès disque côté MCP** : `scan_code` travaille uniquement sur le contenu fourni ; le
  serveur ne lit aucun fichier du disque, ce qui évite les traversées de chemin. Le scan du dépôt
  complet est réservé à la CLI (`code scan`), lancée par l'opérateur sur un dossier qu'il
  choisit ; elle ne suit pas les liens symboliques.
- **Base de données** : les requêtes SQL passent par l'ORM (paramètres liés) ; les tailles
  d'entrée, le nombre de findings et la pagination sont bornés. Le schéma est migré par
  Alembic ; le serveur MCP HTTP ne le modifie jamais et refuse de servir une base qui n'est pas
  à la révision attendue.
- **Règles de scan** : les règles par défaut (`default_rules.toml`) sont copiées en base au
  premier lancement. Si la base est inaccessible ou n'a jamais été initialisée, le serveur
  applique directement ce fichier : le scan ne tourne jamais sans règles. Une règle par défaut
  peut être modifiée ou désactivée par un administrateur, mais pas supprimée
  (voir [Règles internes](../utilisation/regles.md#regles-par-defaut)).
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
