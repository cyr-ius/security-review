# Règles internes

Toutes les règles de scan et les checklists sont stockées dans la **base de données** : toutes
les instances du serveur qui partagent la base appliquent les mêmes règles. Vos équipes sécurité
peuvent ajouter des règles de scan et des items de checklist, modifier les règles par défaut et
activer ou désactiver n'importe quelle règle, **sans toucher au code**.

Les règles se gèrent avec la commande `security-review-controller rules` (import et export de packs
TOML, activation, désactivation, suppression) ou depuis l'écran **Règles** de
l'[interface web](../usage/web-interface.md). Les items de checklist se gèrent depuis l'écran
**Checklists** de cette interface, ou avec les packs TOML de la commande `rules`. Ces deux écrans
[importent et exportent aussi les packs TOML](#import-et-export-dans-linterface-web).

## Règles par défaut

Le serveur est livré avec un jeu de règles et de checklists par défaut, décrit dans le fichier
`default_rules.toml` du paquet (même format qu'un [pack](#format-dun-pack)).

- **Au premier lancement** (création de la base par le serveur ou par une commande CLI), ce
  contenu est copié en base.
- **À chaque démarrage**, les règles par défaut ajoutées par une nouvelle version du serveur
  sont ajoutées, et celles qu'elle a corrigées sont mises à jour, **sauf si un administrateur
  les a modifiées** : une règle modifiée n'est jamais écrasée.
- Une règle par défaut peut être **modifiée** (motif, sévérité, conseil...) ou **désactivée**,
  mais pas supprimée. `rules list` l'affiche alors avec l'origine `modified` (`modified: true`
  en JSON).
- Si la base est inaccessible ou n'a jamais été initialisée, le serveur applique directement
  les règles du fichier : le scan ne tourne jamais sans règles.
- Pour revenir aux règles par défaut, utilisez `rules import --replace` (voir plus bas).

Les scans Python incluent aussi `PY-026`, une analyse Tree-sitter bornée des flux locaux directs depuis
`input()` ou des champs de requête courants (`request.args`, `request.form` et équivalents) vers
du SQL construit dynamiquement et transmis à `execute`, `executemany` ou `text`. Cette analyse
reste volontairement ciblée et ne remplace pas un SAST complet. Elle suit les arguments et les
valeurs de retour lors d'appels directs à des fonctions locales du même fichier. Les paramètres SQL
liés ne sont pas signalés.

Les scans TypeScript, JavaScript et Angular incluent aussi `NG-021`, qui suit les flux locaux
simples des paramètres de requête ou de route vers les affectations à `innerHTML` ou les appels
Angular `bypassSecurityTrust*`. Elle reconnaît `DomSanitizer.sanitize(SecurityContext.HTML, value)`
comme barrière d'assainissement et ne signale pas les mises à jour du DOM en texte seul. Cette
analyse ciblée ne couvre pas les wrappers d'assainissement ni les appels indirects. Elle suit les
arguments contaminés et les valeurs de retour des fonctions déclarées et fléchées appelées
directement dans le même fichier.

Ces scans incluent aussi `NG-022` pour les écouteurs d'événements `message` qui lisent
`event.data` sans vérifier `event.origin`. L'analyse se limite aux callbacks transmis directement
à `addEventListener` ; elle ne déduit pas une validation déléguée à une autre fonction.

Les scans Java incluent aussi `JV-019`, une analyse Tree-sitter bornée qui traite les accesseurs
de requête Servlet et les paramètres annotés Spring `@RequestParam`, `@PathVariable`,
`@RequestBody` et `@RequestHeader` comme des sources non fiables. Elle suit les affectations
locales, la concaténation, `String.format`, `concat`, `StringBuilder.append` et `toString`, ainsi
que les arguments et valeurs de retour lors d'appels directs à des méthodes locales. Les méthodes
d'exécution SQL JDBC/JPA sont les puits. Les valeurs liées séparément avec `PreparedStatement` ou
JPA `setParameter` ne sont pas signalées. L'analyse ne résout ni les surcharges, ni les champs,
ni les wrappers de framework, ni les appels entre fichiers ; elle ne déduit pas non plus qu'une
validation ou un échappement arbitraire assainit la valeur.

D'autres ajouts ciblés comprennent `PY-027` pour la désactivation explicite de la vérification
de signature JWT, `JV-018` lorsqu'une valeur directe de requête est passée à JNDI `lookup`, et
`NG-023` pour les affectations qui modifient `__proto__` ou `constructor.prototype`. Ces règles
examinent les motifs sur une ligne et ne déduisent pas les flux indirects ; vérifiez le code
environnant avant de conclure qu'un finding est exploitable.

```bash
security-review-controller rules import examples/rules/company.toml   # importer un pack
security-review-controller rules list --custom                        # vérifier
```

## Commande `rules`

| Commande | Rôle |
|---|---|
| `rules list [--language L] [--custom] [--format text\|json]` | Liste toutes les règles avec leur origine (`builtin`, `modified`, `custom`) et leur état (`enabled` / `disabled`) |
| `rules import PATH… [--replace]` | Importe des packs TOML (fichiers, ou dossiers dont les `*.toml` sont lus par ordre alphabétique) |
| `rules export [-o FICHIER]` | Exporte en un pack TOML réimportable ce qui diffère des valeurs par défaut (règles personnalisées ou modifiées, règles désactivées) |
| `rules disable ID…` / `rules enable ID…` | Désactive ou réactive des règles **par défaut ou personnalisées** |
| `rules delete ID…` | Supprime des règles personnalisées ou des items de checklist personnalisés |

- L'import est **tout ou rien** : si une entrée est invalide, rien n'est importé et la commande
  liste les erreurs (code de sortie `2`).
- Sans `--replace`, l'import ajoute ou remplace les entrées par identifiant et ajoute les
  identifiants de `disabled_rules` aux règles déjà désactivées. Avec `--replace`, le contenu
  stocké est d'abord **remis aux valeurs par défaut** (règles et checklists personnalisées
  supprimées, modifications annulées, toutes les règles réactivées) : la base correspond alors
  aux règles par défaut plus les packs importés (pratique pour versionner les règles dans un
  dépôt revu et les déployer depuis la CI).
- `enable`, `disable` et `delete` refusent un identifiant inconnu sans rien modifier. Une règle
  ou un item de checklist par défaut ne peut pas être supprimé : désactivez ou modifiez-le.
- La commande ne suit pas les liens symboliques ; un pack est limité à 256 Kio.

```bash
security-review-controller rules disable PY-008            # règle par défaut trop bruyante
security-review-controller rules export -o rules.toml      # sauvegarde ou revue
security-review-controller rules import --replace rules.toml
```

## Import et export dans l'interface web

Les écrans **Règles** et **Checklists** ont des boutons **Exporter** et **Importer** (permission
`rules.manage`) :

- **Exporter** télécharge un pack TOML de ce qui diffère des valeurs par défaut, comme
  `rules export` : `security-review-rules.toml` (règles personnalisées ou modifiées, règles
  désactivées) depuis l'écran **Règles**, `security-review-checklists.toml` (items de checklist
  personnalisés ou modifiés) depuis l'écran **Checklists**.
- **Importer** lit un pack TOML choisi sur votre poste (256 Kio au plus), depuis l'un ou l'autre
  écran : les règles, items de checklist et `disabled_rules` qu'il contient sont importés,
  **tout ou rien**, comme `rules import` sans `--replace` (entrées ajoutées ou remplacées par
  identifiant, les autres entrées conservées). Le message donne le nombre d'entrées importées,
  ou les erreurs quand rien n'a été importé. Pour revenir aux valeurs par défaut, utilisez
  `rules import --replace` en CLI.

| Méthode | Route | Rôle |
|---|---|---|
| `GET` | `/api/v1/packs/rules[?sections=rules\|checklist]` | `rules.manage` : pack TOML (les deux sections par défaut) |
| `POST` | `/api/v1/packs/rules` | `rules.manage` : corps `{"name": "acme.toml", "content": "<TOML>"}` ; `422` avec les erreurs si le pack est invalide |

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" -o rules.toml \
  "https://secreview.example.com/api/v1/packs/rules?sections=rules"
```

## Format d'un pack

Un pack TOML est le format d'échange de `rules import` et `rules export` :

```toml
disabled_rules = ["PY-008"]                  # règles désactivées (par défaut ou personnalisées)

[[rules]]
id = "ACME-001"                              # identifiant unique, ex. ACME-001 (50 caractères max.)
title = "Connexion JDBC directe"
severity = "medium"                          # critical | high | medium | low | info
cwe = "CWE-400"                              # optionnel
languages = ["java"]                         # ou ["*"]
pattern = '''DriverManager\.getConnection\s*\('''
advice = "Utiliser la DataSource gérée."
ignore_case = true                           # optionnel (vrai par défaut)

[[checklist]]
domain = "company"                           # "company" est ajouté à TOUS les prompts de revue
id = "ACME-CL-01"
title = "Isolation des tenants"
what_to_look_for = "Chaque requête est filtrée par le tenant du jeton."
cwe = "CWE-639"
```

Un exemple complet est fourni dans `examples/rules/company.toml`.

## Comportement

- Un `id` identique à une règle par défaut la **modifie** (elle apparaît alors comme
  `modified` et n'est plus mise à jour par les nouvelles versions du serveur).
- Un nouveau `domain` est immédiatement utilisable avec `get_review_checklist`, et les prompts
  de revue le nomment pour que l'agent le récupère.
- Une modification (CLI, interface web) est prise en compte par chaque serveur en cours
  d'exécution **en quelques secondes**, sans redémarrage ; l'outil `reload_rules` et le bouton
  **Recharger** de l'écran Règles l'appliquent immédiatement. Les changements effectués dans
  l'écran Checklists rechargent immédiatement le registre.
- Une règle stockée qui ne passe plus la validation est **ignorée et signalée** (outil
  `list_rules`, champ `load_errors`) ; si la base est inaccessible, les règles par défaut du
  fichier `default_rules.toml` s'appliquent.
- Les motifs avec quantificateurs imbriqués (`(a+)+`), trop longs (500 caractères) ou qui
  matchent la chaîne vide sont refusés. Les lignes de plus de 2000 caractères sont tronquées
  avant analyse.
- `security-review-ci scan-code` applique les règles de la base du contrôleur.

!!! warning "Contenu de confiance"
    Les règles internes sont du contenu **de confiance** : seuls les opérateurs qui ont accès à
    la base (CLI) et le rôle `admin` de l'interface web peuvent les modifier. Versionnez les
    packs dans un dépôt revu et déployez-les avec `rules import --replace`.

## Règles par défaut par plateforme

| Famille | Couverture principale |
|---|---|
| `GEN-*` (tous langages) | Identifiants en dur, clés privées, clés cloud, jetons au format connu (GitHub, GitLab, Slack, Google, Stripe, npm), identifiants dans une URL, JWT en dur, SSL/TLS obsolète, secrets écrits dans les journaux, HTTP en clair, URL LDAP, FTP, AMQP, Redis, MQTT ou Telnet en clair, TLS désactivé dans un paramètre de connexion (`sslmode=disable`, `useSSL=false`, Kafka `PLAINTEXT`), certificat non vérifié hors HTTP (`TLS_REQCERT never`, `trustServerCertificate=true`) |
| `PY-*` (Python) | `eval`/`exec`, désérialisation (pickle, `torch.load`, `joblib`...), YAML, commandes shell, SQL formaté, TLS désactivé, crypto faible ou mode ECB, aléa non cryptographique, XXE (lxml), SSTI, `SECRET_KEY` en dur, `ALLOWED_HOSTS = ['*']`, CSRF désactivé, `mark_safe`, cookies sans `Secure`/`HttpOnly`, SSRF, comparaison de secrets non constante, fichiers temporaires, vérification de signature JWT désactivée |
| `JV-*` (Java) | Désérialisation (dont XStream, SnakeYAML), commandes OS, SQL et LDAP concaténés, flux requête vers SQL dynamique à travers des appels locaux (`JV-019`), XXE, CSRF, CORS, crypto faible, TLS « trust all », chemins et redirections construits depuis la requête, SSRF via une URL directement issue de la requête, JNDI `lookup` contrôlé par la requête, SpEL/EL, cookies, `Random`, `printStackTrace` |
| `NG-*` (Angular, JavaScript, TypeScript) | Contournement du sanitizer, `innerHTML` et autres puits HTML, flux URL-vers-DOM, origine `message` non vérifiée, mutation de la chaîne de prototypes, `eval`, `setTimeout` avec chaîne, jetons en web storage, `postMessage('*')`, XSRF désactivé, redirections ouvertes ; côté Node.js : commandes shell, SQL interpolé, `$where`, chemins de fichiers, CORS ouvert, TLS désactivé, `jwt.decode`, crypto faible |
| `TS-*` (backend TypeScript et JavaScript : Express, NestJS, Fastify, Prisma, TypeORM, Sequelize) | SQL brut non sûr (`$queryRawUnsafe`, `where` interpolé, `literal`), objet de requête utilisé comme filtre NoSQL, corps de requête lié à un modèle, `vm`/`vm2`, `unserialize`, secret JWT ou de cookie en dur, cookie de session sans `httpOnly`/`secure`, SSRF, `RegExp` construite depuis la requête, réponse réfléchie, `ValidationPipe` sans whitelist, limite de corps énorme, `trust proxy` à `true`, fichiers cachés servis, comparaison de secrets non constante |
| `GO-*` (Go) | SQL construit avec `fmt.Sprintf`, `sh -c`, `InsecureSkipVerify`, MD5/SHA-1/DES/RC4, `math/rand`, conversions `template.HTML`, chemins, SSRF et redirections depuis la requête, serveur sans timeouts, zip slip, JWT `ParseUnverified` et `none`, CORS ouvert, cookies, `net/http/pprof`, TLS obsolète, modes accessibles en écriture à tous, lecture du corps sans limite |
| `CS-*` (C#, ASP.NET Core, Razor, Blazor) | SQL concaténé ou interpolé (ADO.NET, `FromSqlRaw`, Dapper), `BinaryFormatter` et `TypeNameHandling`, `cmd`/`powershell`, validation de certificat désactivée, crypto faible, `Random`, XXE, `Html.Raw`/`MarkupString`, antiforgery désactivé, CORS ouvert, page d'exception développeur, validation JWT affaiblie, cookies, chemins, redirections et SSRF depuis la requête, filtres LDAP, TLS obsolète, scripts XSLT |
| `RS-*` (Rust) | SQL construit avec `format!`, `sh -c`, `danger_accept_invalid_certs`, blocs `unsafe` et primitives mémoire non sûres (`transmute`, `from_raw_parts`), crypto faible, générateur aléatoire initialisé ou non cryptographique, chemins depuis la requête, CORS permissif, validation JWT désactivée, cookies, HTML construit avec `format!` ou `PreEscaped`, `bincode` sans limite, TLS obsolète |
| `CFG-*` (Docker, Compose, Kubernetes, serveurs) | Conteneur privilégié ou root, socket Docker, namespaces de l'hôte, capacités dangereuses, élévation de privilèges, montages sensibles, ports de bases exposés, secrets dans `ENV`/`ARG`, `ADD` distant, mots de passe par défaut, services sans authentification, RBAC `*` ou `cluster-admin`, buckets publics, CORS `*`, listage de répertoires, SSH faible, `curl \| sh`, debug, WAF désactivé, en mode détection seule ou avec des exclusions trop larges (ModSecurity, Coraza, Ingress NGINX) |
| `GL-*` (GitLab CI) | `include` distant, secrets affichés, DinD sans TLS, `allow_failure`, jeton CI en ligne de commande, variables non fiables évaluées par un shell, `CI_DEBUG_TRACE`, artefacts publics, `GIT_SSL_NO_VERIFY` |
| `JK-*` (Jenkinsfile) | Injection dans `sh`, bibliothèque partagée non épinglée, `agent any`, sandbox désactivée, identifiant interpolé dans une chaîne Groovy, API interne `Jenkins.instance` |
| `CI-*` (CI/CD commun) | Vérification TLS ou de signature désactivée, traçage shell, installation sans lockfile |
| `SP-*` (Spring) | Actuator exposé ou non protégé, console H2, TLS désactivé, logs SQL, `permitAll`, entités liées au corps de requête, détails d'erreur renvoyés, mot de passe dans la configuration, `web.ignoring()`, en-têtes de sécurité désactivés |
| `FA-*` (FastAPI) | CORS `*` ou regex `.*`, signature JWT non vérifiée, mode `reload` |
| `AI-*` (tous langages, instructions d'assistants IA) | Texte caché à une personne mais lu par un assistant IA : Unicode tags et sélecteurs de variante supplémentaires (`AI-001`), contrôles bidirectionnels de Trojan Source (`AI-002`), caractères de largeur nulle (`AI-003`) ; texte adressé à l'assistant (remplacement de ses instructions, jetons de modèle de conversation comme `<\|im_start\|>`, `AI-004`) ou demandant d'écarter un finding (`AI-005`) |

Les checklists par défaut couvrent les domaines `python`, `java`, `angular`, `node` (backend
TypeScript et JavaScript), `go`, `csharp`, `rust`, `api`, `config`, `cicd` et `dependencies` (par exemple : validation des jetons OAuth/OIDC, webhooks, flux métier
sensibles, désynchronisation HTTP, injection CRLF, validation avant normalisation, upload de
fichiers, durcissement Kubernetes, RBAC, en-têtes du proxy, WAF, connexions chiffrées vers les
services (LDAPS par exemple), instructions des assistants IA, intégrité des lockfiles).
`get_review_checklist` et l'écran **Checklists** de l'interface web les affichent en entier.

Langages acceptés par `scan_code` : `python`, `java`, `typescript`, `javascript`, `angular`,
`go`, `csharp`, `rust`, `config`, `yaml`, `docker`, `gitlab-ci`, `jenkins`, `agent-instructions` (fichiers qui pilotent
un assistant IA : `AGENTS.md`, `CLAUDE.md`, `.cursorrules`... ; seules les règles de tous les
langages s'y appliquent) (alias : `golang`, `c#`, `cs`, `dotnet`, `rs`, `jenkinsfile`, `groovy`, `gitlab`, `yml`...).

### Checklists des prompts de revue

| Prompt | Checklists intégrées |
|---|---|
| `security-review` | Celles de `language` (`python`, `java`, `go`, `csharp`, `rust`, `angular` et `node` pour `typescript` et `javascript`, `config` et `cicd` pour les pipelines), puis `api` |
| `codebase-review` | Celles de `languages`, puis `api`, `config` et `cicd` |
| `api-security-review` | `api` |
| `configuration-review` | `config`, plus `cicd` quand les fichiers ressemblent à un pipeline |
| `dependency-review` | `dependencies` |

La checklist `company` est ajoutée à chaque prompt. Les autres domaines, internes compris, sont
nommés à la fin des checklists : l'agent récupère avec `get_review_checklist` ceux qui
s'appliquent au code qu'il relit. Il déclare ensuite le résultat de chaque point parcouru dans
`save_security_report` ([couverture de la revue](../usage/prompts-tools.md#couverture-de-la-revue)).

## Supprimer un faux positif

Ajoutez un commentaire sur la ligne concernée :

```python
subprocess.run(cmd, shell=True)  # secreview:ignore PY-004 commande figée, aucune entrée utilisateur
```

Sans identifiant, toutes les règles de la ligne sont ignorées.

Les suppressions ne sont **pas cachées** : `scan_code` les renvoie dans `suppressed`, et les
prompts demandent à l'agent de signaler toute suppression injustifiée (un auteur de MR pourrait
sinon masquer une faille).
