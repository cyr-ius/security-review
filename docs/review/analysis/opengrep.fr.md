# Moteur OpenGrep

Le serveur Controller lance OpenGrep comme second moteur d'analyse statique lors d'un scan de code complet
(`security-review-ci scan-code`). Le scanner intégré reste actif et inchangé. Les scans de fragments
(`scan_code`) du serveur MCP n'utilisent OpenGrep que lorsqu'ils sont
[délégués au serveur Controller](#scans-de-fragments-scan_code).

Les règles OpenGrep sont stockées en base, comme les règles internes : chaque réplica du
serveur Controller voit les mêmes règles, et aucune n'est perdue au redémarrage d'un conteneur.
OpenGrep ne lit que des fichiers : chaque processus qui le lance (le serveur Controller, un
[moteur de scan](../../advanced/architecture/scan-engine.md#regles)) copie donc les règles dans son
propre répertoire de travail, `SECREVIEW_OPENGREP_RULES_DIR`, et met cette copie à jour avant un
scan quand une règle a changé. Ce répertoire est un cache : il n'a besoin d'aucun volume
persistant ni partagé.

## Scans de fragments (`scan_code`)

Par défaut, l'outil `scan_code` scanne le fragment reçu avec les seules règles du serveur MCP, sans
lancer de processus externe. Quand la délégation est activée, il envoie le fragment
à `POST /api/v1/scan/content` du serveur Controller avec le jeton de l'agent : le serveur Controller
applique ses règles, puis ses règles OpenGrep quand le moteur est activé, et n'enregistre rien. La
réponse indique les moteurs utilisés (`engines` : `rules`, `opengrep`). Tant que la délégation est
désactivée, le serveur Controller répond `404` sur cette route : un jeton `mcp` ne peut pas lui
faire lancer OpenGrep pour une fonction qui n'est pas utilisée.

Le serveur Controller décide, et enregistre son choix en base, où le serveur MCP le lit à chaque
appel. `SECREVIEW_SCANCODE_DELEGATED`, défini sur le serveur Controller, vaut `true` (vers son URL
publique), l'URL racine du serveur Controller vue du serveur MCP (par exemple
`http://controller:8080` dans Compose : les fragments restent alors sur le réseau interne) ou
`false`. Sans la variable, un administrateur peut activer la délégation dans l'interface web : dans la page
**Activité**, l'interrupteur **Le serveur MCP délègue l'analyse du code au serveur Controller** (section **Délégation des scans de code**) envoie les fragments à l'adresse publique
définie dans la page **Général**, sous **Adresse du serveur Controller** (le serveur MCP doit la
joindre). Le même interrupteur donne son ticket de scan à
[`start_codebase_scan`](code-scan.md#scan-lance-par-lagent-start_codebase_scan) : tant qu'il est
désactivé, cet outil est refusé.
Il est désactivé par défaut, exige une adresse connue, s'applique au prochain appel de `scan_code`,
et se désactive quand l'adresse change (réactivez-le pour la nouvelle adresse : les jetons ne
suivent jamais une adresse modifiée). Chaque changement est enregistré dans le journal d'audit (`mcp_scan_delegation.changed`). Quand
la variable est définie, l'interrupteur est verrouillé. `SECREVIEW_MCP_SCAN_CONTROLLER_URL`, ancienne
variable du serveur MCP, est obsolète : encore lue avec un avertissement, elle est prioritaire.

- Le jeton de l'agent est relayé tel quel : un jeton `mcp` ou `admin` n'atteint que cette route, pas
  le reste de l'API REST.
- Sans jeton d'appelant (stdio, serveur ouvert), ou quand le serveur Controller ne répond pas
  (injoignable, OpenGrep occupé, `SECREVIEW_MCP_SCAN_TIMEOUT_SECONDS` dépassé), `scan_code` scanne avec
  les règles du serveur MCP et en donne la raison dans `controller_error`.
- L'appel ne va qu'à l'URL configurée, sans proxy ni redirection, avec une réponse bornée ; utilisez
  une URL `https://` quand le serveur Controller n'est pas sur le même réseau privé.
- Les fragments ont leurs propres créneaux OpenGrep (`SECREVIEW_OPENGREP_MAX_CONCURRENT_FRAGMENT_SCANS`) :
  des agents qui appellent souvent `scan_code` ne font jamais attendre les scans du dépôt des pipelines.
  Les deux réserves s'additionnent : dimensionnez l'hôte pour
  (`SECREVIEW_OPENGREP_MAX_CONCURRENT_SCANS` + `SECREVIEW_OPENGREP_MAX_CONCURRENT_FRAGMENT_SCANS`)
  scans simultanés, chacun avec `SECREVIEW_OPENGREP_JOBS` cœurs et `SECREVIEW_OPENGREP_MAX_MEMORY_MB`
  Mio (gardez une limite de mémoire).

## Image Docker

L'[image `-opengrep`](../../advanced/deployment/docker.md#images-publiees) (`latest-opengrep`,
`X.Y.Z-opengrep`) contient une version épinglée d'OpenGrep dans `/usr/local/bin/opengrep`, vérifiée par son
empreinte SHA-256 à la construction (cible `opengrep` du `Dockerfile`) et décompactée à ce moment, en
lecture seule, pour qu'un scan ne l'extraie jamais : utilisez-la pour le serveur Controller. Les
[règles par défaut](#regles-par-defaut) sont installées et tenues à jour à chaque démarrage. L'image `-opengrep` définit `SECREVIEW_OPENGREP_ENABLED=true` ; l'image par défaut ne contient pas OpenGrep. Avec une installation du paquet
PyPI, installez OpenGrep vous-même, définissez `SECREVIEW_OPENGREP_ENABLED=true` et `SECREVIEW_OPENGREP_BINARY` s'il n'est pas dans
`/usr/local/bin`.

## Configuration

Le moteur est désactivé par défaut et activé dans l'image `-opengrep` ; définissez
`SECREVIEW_OPENGREP_ENABLED=true` pour l'activer ailleurs. Une fois activé, il ne s'exécute qu'une fois au moins une règle YAML installée : sans
règle, `scan-code` n'exécute que le scanner intégré. Variables d'environnement du serveur Controller :

| Variable | Valeur par défaut | Description |
| --- | --- | --- |
| `SECREVIEW_OPENGREP_ENABLED` | `false` | Active OpenGrep pour les scans de code complet |
| `SECREVIEW_OPENGREP_BINARY` | `/usr/local/bin/opengrep` | Chemin de l'exécutable OpenGrep |
| `SECREVIEW_OPENGREP_RULES_DIR` | `/var/lib/secreview/rules/opengrep` | Répertoire de travail où le serveur Controller et les moteurs de scan copient pour OpenGrep les règles OpenGrep de la base (un cache : un `emptyDir` suffit, jamais partagé entre réplicas) ; les fichiers de règles laissés là par une version précédente sont importés une fois en base |
| `SECREVIEW_OPENGREP_TIMEOUT_SECONDS` | `600` | Durée maximale d'un scan OpenGrep |
| `SECREVIEW_OPENGREP_MAX_CONCURRENT_SCANS` | `1` | Scans OpenGrep simultanés dans un processus du serveur Controller ; un scan au-delà est refusé avec `503` et `Retry-After` |
| `SECREVIEW_OPENGREP_MAX_CONCURRENT_FRAGMENT_SCANS` | `1` | Fragments de [`scan_code`](#scans-de-fragments-scan_code) scannés par OpenGrep en même temps, dans leurs propres créneaux pour que les agents ne prennent jamais ceux des scans du dépôt (`503` au-delà : le serveur MCP scanne avec ses règles) ; `0` : les fragments ne sont scannés qu'avec les règles |
| `SECREVIEW_OPENGREP_JOBS` | `2` | Cœurs utilisés par un scan OpenGrep (`--jobs`) |
| `SECREVIEW_OPENGREP_MAX_MEMORY_MB` | `2048` | Mémoire en Mio d'un scan OpenGrep (`--max-memory`, `0` : sans limite) |
| `SECREVIEW_OPENGREP_TAINT_INTRAFILE` | `true` | Suit le flux de données à travers les fonctions d'un même fichier (`--taint-intrafile`, environ 10 à 30 % plus long) ; `false` pour un exécutable OpenGrep plus ancien qui ne connaît pas l'option |

Les [règles par défaut](#regles-par-defaut) sont installées en base au démarrage, ou par
`security-review-controller opengrep install` ; ajoutez vos propres règles dans la
[onglet **Règles OpenGrep**](#gestion-des-regles-depuis-linterface-web). Les règles ne sont jamais
téléchargées. `SECREVIEW_OPENGREP_RULES_DIR` ne contient que la copie écrite pour OpenGrep : un
fichier déposé là à la main n'est pas lu.

Lorsque le moteur est activé, le Controller écrit les sources déjà reçues du client CI dans un répertoire
temporaire privé, exécute OpenGrep sans shell, analyse sa sortie JSON puis supprime l'espace de travail.
Les résultats sont convertis au format de findings existant et intégrés au même rapport et au même export
SARIF que les résultats du scanner natif. Les identifiants des règles OpenGrep sont préfixés par
`OPENGREP:` (`OPENGREP:secreview.python.taint-sql`). OpenGrep ignore les chemins de sa liste
d'exclusion par défaut (répertoires de tests comme `tests/`, `node_modules/`...).

## Règles par défaut

Security Review fournit 147 règles OpenGrep écrites pour le projet (licence Apache-2.0, comme le
reste du code) : les packs communautaires ne sont pas redistribués, car leurs licences
(Semgrep Rules License, ou LGPL avec la Commons Clause pour le fork `opengrep-rules`) interdisent
leur usage dans un produit comme celui-ci. Elles complètent les [règles intégrées](../rules.md)
avec ce qu'un motif ligne par ligne ne voit pas :

- **analyse de propagation (taint)** : une valeur lue dans la requête (Flask, Django, FastAPI,
  aiohttp, Tornado, Bottle, Pyramid, Azure Functions, Spring, servlets, Express, NestJS,
  ASP.NET Core, `net/http`, Gin, Echo), sur une socket, une websocket ou dans un événement AWS
  Lambda est suivie à travers les variables et la construction de chaînes jusqu'à un appel
  dangereux (SQL, commande, chemin de fichier, URL sortante, redirection, template, HTML,
  désérialisation). Un assainissement en chemin (`int()`, `secure_filename`, `path.basename`,
  `html.EscapeString`...) l'arrête. Les données locales (arguments de la ligne de commande,
  entrée standard, variables d'environnement) ne sont pas des sources : un outil en ligne de
  commande qui agit sur ce que demande sa propre utilisatrice ne franchit aucune frontière de
  confiance. La valeur est suivie dans un fichier, d'une fonction à l'autre
  (`SECREVIEW_OPENGREP_TAINT_INTRAFILE`), mais pas d'un fichier à l'autre ([mesure de la détection](../../reference/detection-benchmark.md)) ;
- **structure** : une option absente (une fabrique XML sans `disallow-doctype-decl`, une archive
  extraite sans filtre, un serveur HTTP sans délais, un Dockerfile sans `USER`) ou une
  combinaison d'arguments (CORS avec toute origine *et* identifiants).

| Langage (répertoire) | Règles | Principaux contrôles |
| --- | --- | --- |
| Python (`python`) | 30 | Taint : SQL, NoSQL, commande, `eval`, SSRF, chemin, redirection, template, HTML (réponses Flask, Django et FastAPI), XPath, LDAP, session (trust boundary), désérialisation, mass assignment ; TLS, YAML, JWT, debug, CORS, archives, hachages, cookies, XXE, `random` pour un secret, TLS 1.0/1.1, `requests` sans timeout, `csrf_exempt`, secrets comparés avec `==` |
| Java, Spring (`java`) | 31 | Taint : SQL/JPQL, commande, `ScriptEngine`/Groovy, chemin, SSRF, redirection, XSS, XPath, session (trust boundary), SpEL/OGNL, Velocity/FreeMarker, JNDI/LDAP ; désérialisation, XXE (DOM, SAX, StAX), CSRF, TLS sans vérification, nom d'hôte, chiffrements, hachages, cookies, Jackson, SnakeYAML, zip slip, `Random` pour un secret, JWT non vérifié, TLS 1.0/1.1, `XMLDecoder`, XStream, CORS avec toute origine et identifiants, secrets comparés avec `equals` |
| JavaScript, TypeScript, Angular (`javascript`) | 24 | Taint : SQL, NoSQL, commande, désérialisation, mass assignment, `eval`/`vm`, chemin, SSRF, redirection, XSS, RegExp, templates, pollution de prototype, XSS DOM depuis l'URL ou la route ; données `message` lues sans vérifier leur origine, `bypassSecurityTrust*`, TLS, CORS, JWT, cookies, cryptographie, XXE (`noent`), `Math.random` pour un secret, `postMessage` vers toute origine |
| Go (`go`) | 17 | Taint : SQL, commande, chemin, SSRF, redirection, XSS, templates ; `InsecureSkipVerify`, zip slip, délais du serveur, cryptographie, `math/rand` pour un secret, JWT non vérifié, cookies, TLS 1.0/1.1, client HTTP sans timeout, secrets comparés avec `==` |
| C#, ASP.NET Core (`csharp`) | 20 | Taint : SQL (ADO.NET, EF Core, Dapper), processus, chemin, SSRF, redirection, XSS, XPath ; désérialiseurs, validation des certificats, JWT, cryptographie, DTD, encodage HTML, CORS, zip slip, `System.Random` pour un secret, cookies, TLS 1.0/1.1, antiforgery désactivé, secrets comparés avec `==` |
| Rust (`rust`) | 13 | Taint : SQL (sqlx, diesel, pilotes), commande, chemin, SSRF, redirection depuis les extracteurs axum et actix-web ; SQL construit avec `format!`, shell, TLS, cryptographie, JWT, CORS, cookies, HTML |
| Dockerfile (`dockerfile`) | 2 | Pas de `USER` avant `CMD`/`ENTRYPOINT`, dernier `USER` à root |
| GitHub Actions (`github-actions`) | 10 | Injection de script avec `${{ }}`, `pull_request_target` qui récupère le code de la pull request, action non épinglée sur un SHA, `write-all`, artefacts de `workflow_run`, runner auto-hébergé sur les pull requests, `secrets: inherit` vers un autre dépôt, pas de `permissions`, `issue_comment` qui récupère une pull request, cache dans `pull_request_target` |

Leurs identifiants suivent `secreview.<langage>.<contrôle>` (`secreview.go.zip-slip`) et leurs
métadonnées donnent la CWE et la catégorie OWASP, reprises dans les findings.

À chaque démarrage, le serveur Controller copie les règles par défaut en base, comme les règles
TOML par défaut, qu'OpenGrep tourne sur lui ou non (les moteurs de scan les y prennent) : une
nouvelle règle est installée, une règle restée telle qu'installée est remplacée par la nouvelle
version, une règle modifiée ou supprimée dans l'onglet **Règles OpenGrep** est laissée telle
quelle, et une règle par défaut qui n'est plus fournie est retirée, sauf si elle a été modifiée.
La commande installe les règles par défaut à la demande, sur le serveur Controller :

```bash
security-review-controller opengrep list                          # bundled rules by language
security-review-controller opengrep install                       # every language
security-review-controller opengrep install --language python --language javascript
security-review-controller opengrep install --overwrite           # after an upgrade
```

`install` écrit les règles en base et affiche les identifiants installés, remplacés et ignorés
(JSON). Une règle déjà présente est conservée, pour
qu'une modification faite dans l'onglet **Règles OpenGrep** survive ; `--overwrite` la remplace
par la version du paquet (après une mise à niveau, par exemple). Pour retirer une règle,
supprimez-la dans cette page. En conteneur, lancez la commande dans le conteneur du serveur
Controller (`docker compose exec controller security-review-controller opengrep install`).

!!! note "Mise à niveau depuis une version qui gardait les règles dans des fichiers"

    Auparavant, les règles étaient des fichiers de `SECREVIEW_OPENGREP_RULES_DIR`. À son premier
    démarrage après la mise à niveau (`db upgrade` crée la table), le serveur Controller importe
    une fois en base les fichiers de règles de ce répertoire (`<id>.yaml` ou `<id>.yml`, une règle
    chacun), avec les règles par défaut enregistrées dans son manifeste
    `.secreview-default-rules.json` : une règle par défaut modifiée le reste, une règle supprimée
    n'est pas réinstallée. Démarrez d'abord un seul réplica, avec le répertoire monté comme avant.
    Les fichiers ne sont plus lus ensuite et peuvent être supprimés.

## Sécurité opérationnelle

- Exécutez le Controller avec l'utilisateur non privilégié `secreview` déjà utilisé par l'image.
- Réservez la gestion des packs de règles aux administrateurs ; leur mise à jour est une opération sensible.
- Appliquez des limites CPU, mémoire et processus au conteneur. Le délai maximal, le nombre de scans
  simultanés, ainsi que les cœurs et la mémoire d'un scan sont appliqués par l'adaptateur (à l'expiration du
  délai, OpenGrep et ses processus de travail sont arrêtés), mais ne remplacent pas les limites de ressources
  du conteneur.
- Si OpenGrep est occupé par d'autres scans ou indisponible, `scan-code` reçoit une réponse `503` :
  relancez plus tard.
- Ne montez aucun secret applicatif ni chemin hôte sans rapport avec le scan dans l'espace de travail.
- Le Controller n'exécute pas les sources analysées. Il écrit toutefois les contenus reçus dans un répertoire
  temporaire afin qu'OpenGrep puisse les lire.
- Si des règles sont installées mais que le binaire OpenGrep est absent, ou si le scan échoue, le scan de code
  échoue explicitement au lieu de signaler silencieusement un succès limité au scanner natif.

## Gestion des règles depuis l’interface web

Le serveur Controller gère ces règles dans l'onglet **Règles OpenGrep** de la page **Règles**
(`/ui/rules/opengrep`, authentifiée). Les utilisateurs disposant de `rules.read` peuvent
consulter les règles YAML stockées en base. Ceux disposant de `rules.manage` peuvent les créer,
modifier, valider et supprimer. Chaque règle contient exactement une règle OpenGrep, dont
l'identifiant YAML doit correspondre à celui de la règle. Toute écriture est d'abord validée avec
`opengrep validate` : créer ou modifier une règle demande donc l'exécutable OpenGrep sur le
serveur Controller (image `-opengrep`) ; les règles par défaut, non. Le
serveur Controller ne télécharge aucun pack de règles et ne suit aucune source distante à la
place de l’administrateur.

Les règles sont listées dans un tableau : identifiant, message, CWE, langage, sévérité des
findings (`ERROR` donne **Haute**, `WARNING` **Moyenne**, `INFO` **Basse**) et date de la
dernière modification, lus dans le YAML de chaque fichier (un champ écrit autrement affiche
`—`). Le champ de recherche porte sur l'identifiant, le message et la CWE ; les filtres gardent
un ou plusieurs langages et sévérités, et chaque colonne sauf le message trie le tableau. Le
crayon (l'œil avec `rules.read` seulement) ouvre le YAML de la règle dans une boîte de dialogue,
avec **Valider**, **Enregistrer** et **Supprimer**.

## Règles proposées par les agents

Pendant une revue, quand un problème confirmé suit un motif vulnérable que le scan n'a pas
relevé et qui peut se répéter, l'agent peut proposer une règle OpenGrep avec l'outil MCP
`propose_opengrep_rule` ([outils](../../reference/prompts-tools.md#outils)) : la règle YAML, son motif et
du code de test (cas `ruleid:` et `ok:`). **La règle n'est pas installée** : le serveur MCP
enregistre seulement la proposition en base, et les prompts de revue demandent à l'agent de ne
proposer une règle qu'après avoir enregistré le rapport.

- Le fichier doit contenir exactement une règle dont l'`id` est l'identifiant proposé ; le
  préfixe `secreview.` est réservé aux règles par défaut. Une règle qui semble contenir un
  secret, ou des caractères invisibles, est refusée. Le motif est masqué et borné comme celui
  d'une proposition de statut.
- Le jeton doit atteindre le projet et y détenir `reports.write` (comme pour
  `save_security_report`). Une nouvelle proposition avec l'identifiant d'une proposition en
  attente du même projet la remplace (depuis un autre projet, elle est refusée) ; au plus `SECREVIEW_OPENGREP_MAX_PENDING_PROPOSALS` propositions
  attendent en même temps.
- Les doublons sont refusés : une règle dont l'identifiant est déjà installé, ou qui détecte le
  même code qu'une règle installée, qu'une règle par défaut ou qu'une autre proposition en
  attente. Deux règles détectent le même code quand elles ne diffèrent que par leur `id`,
  `message`, `metadata`, `severity` ou `fix`, leurs commentaires, leur indentation, leurs
  espaces ou les guillemets autour d'une valeur. Le refus nomme la règle existante, ou la
  proposition quand elle appartient au même projet ; pour corriger une proposition en attente,
  l'agent la propose de nouveau avec son identifiant.
- Les propositions en attente sont listées en haut de l'onglet **Règles OpenGrep** pour les
  utilisateurs disposant de `rules.manage` ; tant qu'il y en a, leur nombre s'affiche à côté de
  **Règles** dans le menu et sur l'onglet. **Examiner** en ouvre une dans l'éditeur avec son
  projet, son auteur, son motif et son code de test : l'approbateur peut corriger le YAML (pas
  son identifiant), le valider avec OpenGrep, puis l'**Approuver et installer** ou la
  **Rejeter** avec un motif facultatif.
- Seule une personne connectée à l'interface web décide : un jeton Bearer, qu'un agent peut
  détenir, reçoit `403`. Une approbation valide la règle avec `opengrep validate` et crée son
  fichier ; elle ne remplace jamais une règle installée (`409`). La proposition, l'approbation
  et le rejet sont inscrits au [journal d'audit](../../advanced/audit-log.md).

| Route | Permission | Rôle |
|---|---|---|
| `GET /api/v1/opengrep/proposals?status=pending` | `rules.manage` | Propositions d'un statut (`pending` par défaut, `approved`, `rejected`), les plus récentes d'abord, avec leur nombre `total` |
| `POST /api/v1/opengrep/proposals/{id}/approve` | `rules.manage`, session web | Corps `{"content": null}` (ou le YAML corrigé) : valide et installe la règle |
| `POST /api/v1/opengrep/proposals/{id}/reject` | `rules.manage`, session web | Corps `{"reason": null}` : la règle n'est pas installée |
