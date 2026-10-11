# Sécurité et limites

## Sécurité du serveur lui-même

- **Transport HTTP** : authentification MCP par jeton Bearer et TLS intégrés mais facultatifs (voir
  [Serveur HTTP, authentification et TLS](../demarrage/http.md)). Les jetons sont stockés en
  base et seules leurs empreintes SHA-256 sont conservées. Chaque requête recherche l'empreinte
  du jeton présenté, ce qui ne révèle rien d'exploitable sans préimage, puis la vérifie en temps
  constant : une révocation est donc immédiate sur toutes les instances. Un jeton créé avec
  `--project` est limité à ce projet dans les outils MCP et l'API web : tout autre projet,
  rapport ou finding est traité comme inexistant (voir
  [jetons restreints à un projet](../demarrage/http.md#jetons-restreints-a-un-projet)). Si l'écoute n'est pas sur
  localhost, un avertissement est journalisé quand l'authentification ou le TLS manque. Il n'y a
  pas de limitation de débit. Chaque jeton porte un [rôle](../utilisation/interface-web.md#roles)
  (`mcp`, `reader`, `triager`, `admin`) ; un jeton `mcp` sans projet accède à tous les outils
  MCP et à tous les projets.
- **Interface web** : l'API REST exige toujours un jeton de rôle web; sans configuration, elle
  répond `503` au lieu d'accorder les droits anonymes. Seuls `triager` et `admin` changent
  le statut d'un finding (action journalisée avec le label du jeton). Pages servies avec une CSP
  stricte et les en-têtes anti-clickjacking ; jeton gardé dans le `sessionStorage` de l'onglet.
  La documentation Swagger et son schéma OpenAPI sont publics, mais les routes de données
  restent protégées.
- **Pas d'accès disque côté MCP** : `scan_code` travaille uniquement sur le contenu fourni ; le
  serveur ne lit aucun fichier du disque, ce qui évite les traversées de chemin. Le scan du dépôt
  complet est réservé à la CLI (`code scan`), lancée par l'opérateur sur un dossier qu'il
  choisit ; elle ne suit pas les liens symboliques.
- **Base de données** : les requêtes SQL passent par l'ORM (paramètres liés) ; les tailles
  d'entrée, le nombre de findings et la pagination sont bornés.
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
