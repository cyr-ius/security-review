# Moteur OpenGrep

Le serveur Controller lance OpenGrep comme second moteur d'analyse statique lors d'un scan de code complet
(`security-review-ci scan-code`). Le scanner intégré reste actif et inchangé. Les scans de fragments
(`scan_code`) ne lancent aucun processus externe.

## Image Docker

L'[image `-opengrep`](../../advanced/deployment/docker.md#images-publiees) (`latest-opengrep`,
`X.Y.Z-opengrep`) contient une version épinglée d'OpenGrep dans `/usr/local/bin/opengrep`, vérifiée par son
empreinte SHA-256 à la construction (cible `opengrep` du `Dockerfile`) et décompactée à ce moment, en
lecture seule, pour qu'un scan ne l'extraie jamais : utilisez-la pour le serveur Controller. Les
[règles par défaut](#regles-par-defaut) sont installées et tenues à jour à chaque démarrage. L'image par défaut ne contient pas OpenGrep et définit `SECREVIEW_OPENGREP_ENABLED=false`. Avec une installation du paquet
PyPI, installez OpenGrep vous-même et définissez `SECREVIEW_OPENGREP_BINARY` s'il n'est pas dans
`/usr/local/bin`.

## Configuration

Le moteur est activé par défaut (sauf dans l'image Docker par défaut, sans OpenGrep), mais il ne s'exécute qu'une fois au moins une règle YAML installée : sans
règle, `scan-code` n'exécute que le scanner intégré. Définissez `SECREVIEW_OPENGREP_ENABLED=false` pour le
désactiver. Variables d'environnement du serveur Controller :

| Variable | Valeur par défaut | Description |
| --- | --- | --- |
| `SECREVIEW_OPENGREP_ENABLED` | `true` | Active OpenGrep pour les scans de code complet |
| `SECREVIEW_OPENGREP_BINARY` | `/usr/local/bin/opengrep` | Chemin de l'exécutable OpenGrep |
| `SECREVIEW_OPENGREP_RULES_DIR` | `/var/lib/secreview/rules/opengrep` | Répertoire des packs de règles YAML |
| `SECREVIEW_OPENGREP_TIMEOUT_SECONDS` | `600` | Durée maximale d'un scan OpenGrep |
| `SECREVIEW_OPENGREP_MAX_CONCURRENT_SCANS` | `1` | Scans OpenGrep simultanés dans un processus du serveur Controller ; un scan au-delà est refusé avec `503` et `Retry-After` |
| `SECREVIEW_OPENGREP_JOBS` | `2` | Cœurs utilisés par un scan OpenGrep (`--jobs`) |
| `SECREVIEW_OPENGREP_MAX_MEMORY_MB` | `2048` | Mémoire en Mio d'un scan OpenGrep (`--max-memory`, `0` : sans limite) |

Les [règles par défaut](#regles-par-defaut) sont installées au démarrage par l'image
`-opengrep`, ou par `security-review-controller opengrep install` ; ajoutez vos propres packs de
règles dans le répertoire configuré, par exemple en montant un répertoire administré sur
`/var/lib/secreview/rules/opengrep` (gardez-le sur un volume, pour que les modifications et
suppressions faites dans la page **Règles OpenGrep** survivent à un nouveau conteneur). Les règles
ne sont jamais téléchargées. Le répertoire doit contenir au moins un fichier `.yml` ou `.yaml`.

Lorsque le moteur est activé, le Controller écrit les sources déjà reçues du client CI dans un répertoire
temporaire privé, exécute OpenGrep sans shell, analyse sa sortie JSON puis supprime l'espace de travail.
Les résultats sont convertis au format de findings existant et intégrés au même rapport et au même export
SARIF que les résultats du scanner natif. Les identifiants des règles OpenGrep sont préfixés par
`OPENGREP:` (`OPENGREP:secreview.python.taint-sql`). OpenGrep ignore les chemins de sa liste
d'exclusion par défaut (répertoires de tests comme `tests/`, `node_modules/`...).

## Règles par défaut

Security Review fournit 90 règles OpenGrep écrites pour le projet (licence Apache-2.0, comme le
reste du code) : les packs communautaires ne sont pas redistribués, car leurs licences
(Semgrep Rules License, ou LGPL avec la Commons Clause pour le fork `opengrep-rules`) interdisent
leur usage dans un produit comme celui-ci. Elles complètent les [règles intégrées](../rules.md)
avec ce qu'un motif ligne par ligne ne voit pas :

- **analyse de propagation (taint)** : une valeur lue dans la requête (Flask, Django, FastAPI,
  Spring, servlets, Express, NestJS, ASP.NET Core, `net/http`, Gin, Echo) est suivie à travers
  les variables et la construction de chaînes jusqu'à un appel dangereux (SQL, commande, chemin
  de fichier, URL sortante, redirection, template, HTML, désérialisation). Un assainissement en
  chemin (`int()`, `secure_filename`, `path.basename`, `html.EscapeString`...) l'arrête ;
- **structure** : une option absente (une fabrique XML sans `disallow-doctype-decl`, une archive
  extraite sans filtre, un serveur HTTP sans délais, un Dockerfile sans `USER`) ou une
  combinaison d'arguments (CORS avec toute origine *et* identifiants).

| Langage (répertoire) | Règles | Principaux contrôles |
| --- | --- | --- |
| Python (`python`) | 18 | Taint : SQL, commande, `eval`, SSRF, chemin, redirection, template, HTML, désérialisation ; TLS, YAML, JWT, debug, CORS, archives, hachages, cookies |
| Java, Spring (`java`) | 18 | Taint : SQL/JPQL, commande, chemin, SSRF, redirection, XSS, SpEL/OGNL, JNDI/LDAP ; désérialisation, XXE (DOM, SAX, StAX), CSRF, TLS sans vérification, nom d'hôte, chiffrements, hachages, cookies, Jackson |
| JavaScript, TypeScript, Angular (`javascript`) | 16 | Taint : SQL, commande, `eval`/`vm`, chemin, SSRF, redirection, XSS, RegExp, XSS DOM depuis l'URL ou la route ; données `message` lues sans vérifier leur origine, `bypassSecurityTrust*`, TLS, CORS, JWT, cookies, cryptographie |
| Go (`go`) | 11 | Taint : SQL, commande, chemin, SSRF, redirection, XSS ; `InsecureSkipVerify`, zip slip, délais du serveur, cryptographie, `math/rand` pour un secret |
| C#, ASP.NET Core (`csharp`) | 12 | Taint : SQL (ADO.NET, EF Core, Dapper), processus, chemin, SSRF, redirection ; désérialiseurs, validation des certificats, JWT, cryptographie, DTD, encodage HTML, CORS |
| Rust (`rust`) | 9 | Taint : SQL (sqlx, diesel, pilotes) depuis les extracteurs axum et actix-web ; SQL construit avec `format!`, shell, TLS, cryptographie, JWT, CORS, cookies, HTML |
| Dockerfile (`dockerfile`) | 2 | Pas de `USER` avant `CMD`/`ENTRYPOINT`, dernier `USER` à root |
| GitHub Actions (`github-actions`) | 4 | Injection de script avec `${{ }}`, `pull_request_target` qui récupère le code de la pull request, action non épinglée sur un SHA, `write-all` |

Leurs identifiants suivent `secreview.<langage>.<contrôle>` (`secreview.go.zip-slip`) et leurs
métadonnées donnent la CWE et la catégorie OWASP, reprises dans les findings.

Tant que le moteur est activé (`SECREVIEW_OPENGREP_ENABLED`) et que l'exécutable OpenGrep est
présent (image `-opengrep`), le serveur Controller les met à jour à chaque démarrage, comme les règles TOML par défaut : une nouvelle règle
est installée, une règle restée telle qu'installée est remplacée par la nouvelle version, et une
règle modifiée ou supprimée dans la page **Règles OpenGrep** est laissée telle quelle. Les
empreintes des versions installées sont gardées dans `.secreview-default-rules.json` du
répertoire de règles ; supprimez-le pour repartir de zéro. La commande les installe à la
demande, sur le serveur Controller :

```bash
security-review-controller opengrep list                          # bundled rules by language
security-review-controller opengrep install                       # every language
security-review-controller opengrep install --language python --language javascript
security-review-controller opengrep install --overwrite           # after an upgrade
```

`install` copie un fichier par règle dans `SECREVIEW_OPENGREP_RULES_DIR` et affiche les
identifiants installés, remplacés et ignorés (JSON). Une règle déjà présente est conservée, pour
qu'une modification faite dans la page **Règles OpenGrep** survive ; `--overwrite` la remplace
par la version du paquet (après une mise à niveau, par exemple). Pour retirer une règle,
supprimez-la dans cette page. En conteneur, lancez la commande dans le conteneur du serveur
Controller (`docker compose exec controller security-review-controller opengrep install`).

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

Le Controller propose une page de gestion authentifiée à l’adresse `/ui/opengrep-rules`.
Les utilisateurs disposant de `rules.read` peuvent consulter les fichiers YAML du répertoire
`SECREVIEW_OPENGREP_RULES_DIR`. Ceux disposant de `rules.manage` peuvent créer, modifier,
valider et supprimer ces fichiers. Chaque fichier géré contient exactement une règle et son
identifiant YAML doit correspondre à celui du fichier. Toute écriture est validée avec
`opengrep validate <fichier>` avant un remplacement atomique. Le Controller ne télécharge
aucun pack de règles et ne suit aucune source distante à la place de l’administrateur.
