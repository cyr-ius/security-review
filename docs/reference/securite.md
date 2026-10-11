# Sécurité et limites

## Sécurité du serveur lui-même

- **Transport HTTP** : authentification par jeton Bearer et TLS intégrés mais facultatifs (voir
  [Serveur HTTP, authentification et TLS](../demarrage/http.md)). Seules les empreintes SHA-256
  des jetons sont gardées en mémoire, comparées en temps constant. Si l'écoute n'est pas sur
  localhost, un avertissement est journalisé quand l'authentification ou le TLS manque. Il n'y a
  ni limitation de débit ni gestion fine des droits : tout jeton valide accède à tous les outils.
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
