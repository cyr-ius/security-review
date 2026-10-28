# Consignes pour les agents IA

Ce fichier est la **référence unique** pour tout agent (Claude, Copilot, Codex, Cursor...)
qui modifie ce dépôt. `CLAUDE.md` et `.github/copilot-instructions.md` ne font qu'y renvoyer :
modifiez les règles ici, pas là-bas.

`security-review-mcp` est un serveur MCP de revue de code orientée sécurité : prompts,
checklists, scan par motifs, analyse de dépendances, rapports persistés (SQLModel, migrations
Alembic), CLI pour la CI/CD (gate, SARIF, tendances) et transport HTTP avec jetons Bearer / TLS.

Deux processus partagent la base et ne s'appellent jamais : le **serveur MCP**
(`security-review-mcp`, endpoint `/mcp`, avec un serveur d'enrôlement sans outil pour un client sans jeton) et le **contrôleur**
(`security-review-controller` : API REST, interface web, migrations, administration).

## Une tâche n'est terminée que si

1. **Le comportement ajouté ou corrigé est vérifié par un test pertinent**, existant ou nouveau
   (voir [Tests](#tests)).
2. **Les vérifications qui correspondent aux fichiers modifiés passent**, et seulement
   celles-là (voir [Vérifications selon les fichiers modifiés](#vérifications-selon-les-fichiers-modifiés)).
3. **La documentation `docs/` est à jour, en anglais et en français**
   (voir [Documentation](#documentation)).
4. **Les `README.md` (anglais) et `README.fr.md` (français) sont à jour, en restant
   synthétiques** (voir [README](#readme)).
5. `.env.example` est à jour si un paramètre `SECREVIEW_*` a été ajouté ou modifié.
6. **Une revue de sécurité des changements a été faite avec le serveur MCP `security-review`**
   s'il est opérationnel (voir [Revue de sécurité](#revue-de-sécurité)).

Si l'une de ces étapes est volontairement omise (ex. refactorisation interne sans effet visible
sur la doc), dites-le explicitement dans votre réponse ou dans la description de PR, avec la
raison. Ne déclarez jamais une tâche terminée sans avoir lancé les vérifications qui
correspondent aux fichiers modifiés.

### Vérifications selon les fichiers modifiés

Lancez uniquement les vérifications des zones touchées par le changement (`git diff --stat`) :
**ne lancez pas `pytest` ni `ruff` pour un changement qui ne touche que l'interface Angular ou
la documentation**, ni le build Angular pour un changement Python. La CI relance tout de toute
façon.
Ne pas hésiter à lancer les tests en arrière plan si cela permet d'avancer su le reste.

| Fichiers modifiés | Vérifications |
|---|---|
| Python (`src/**/*.py`, `tests/`, `migrations/`), `default_rules.toml`, `pyproject.toml`, `uv.lock` | `uv run ruff check . && uv run ruff format --check .` puis `uv run pytest` |
| Angular (`web/`) | `npm --prefix web run build` (et `npm --prefix web exec --no -- prettier --check` sur les fichiers modifiés) ; plus `uv run pytest tests/test_audit.py` si un catalogue `web/src/app/core/i18n/messages/audit.ts` change |
| Documentation (`docs/`, `mkdocs.yml`) | `uv run mkdocs build --strict` |
| `README.md`, `README.fr.md`, `AGENTS.md`, `.env.example` | aucune (relecture seulement) |
| Workflows, `docker-compose.yml`, YAML / JSON | `npm --prefix web exec --no -- prettier --check` sur les fichiers modifiés |

Un changement qui touche plusieurs zones cumule leurs vérifications. Pendant le développement,
ciblez d'abord les tests du module modifié (`uv run pytest tests/test_<module>.py`), puis lancez
`uv run pytest` complet une fois, à la fin, si du Python a changé.

## Commandes

```bash
uv sync --extra dev --extra docs   # environnement complet
uv run pytest                      # tests (aucun accès réseau, base SQLite en mémoire)
uv run pytest tests/test_scanner.py -k python   # cibler un test
uv run ruff check --fix . && uv run ruff format .
uv run mkdocs build --strict       # ce que fait la CI : un lien cassé fait échouer le build
```

La CI (`.github/workflows/`) lance ruff et pytest sur Python 3.14 et 3.15 avec
`uv sync --locked` (d'où `uv lock` après un changement de dépendances). Les actions des workflows sont épinglées sur le SHA complet d'un commit,
avec la version en commentaire (`@<sha> # vX.Y.Z`) : faites de même pour toute nouvelle action.

## Branches et versions

| Branche | Rôle |
|---|---|
| `dev` | Branche de développement : **on y code par défaut** |
| `feat/<sujet>` | Uniquement pour une **grosse rupture** (refonte, changement d'API ou de schéma, travail sur plusieurs jours), créée depuis `dev` et fusionnée dans `dev` par PR |
| `master` | Branche de production : ne reçoit que des fusions de `dev`, jamais de commit direct |

- Travaillez sur `dev`, sauf rupture importante. Dans ce cas, créez `feat/<sujet>` depuis `dev`.
  En cas de doute, demandez.
- Ne commitez jamais directement sur `master`.
- **Une version = un tag `vX.Y.Z` sur `master`, créé par Release Please**
  (`release-please.yml`, `release-please-config.json`). Ne changez pas la version à la main
  (`uv version`) : Release Please la calcule. Procédure :
  1. fusionner `dev` dans `master` ;
  2. Release Please ouvre (ou met à jour) la PR de release : `CHANGELOG.md` et la version dans
     `pyproject.toml`, `uv.lock`, `web/package.json` et `web/package-lock.json` ;
  3. la fusion de cette PR crée le tag et une release GitHub en brouillon, puis lance
     `publish.yml` sur le tag (`workflow_dispatch` : un tag créé avec le jeton du workflow ne
     déclenche aucun workflow) : lint et tests, vérification que le tag correspond à `version`
     dans `pyproject.toml`, publication sur PyPI (`security-review` et le client seul
     `security-review-ci`) et des images Docker (GHCR et Docker Hub, `docker.yml`), puis ajout
     des distributions à la release, qui n'est publiée qu'à ce moment.
  Un tag poussé à la main déclenche toujours `publish.yml`.
- Versionnement sémantique, déduit des Conventional Commits : `X` pour une rupture de
  compatibilité (outil, prompt, option CLI ou paramètre retiré ou renommé), à signaler par `!`
  (`feat!:`) ou un pied `BREAKING CHANGE:` ; `Y` pour une fonctionnalité (`feat:`) ; `Z` pour une
  correction (`fix:`). Un type mal choisi donne une mauvaise version.
- **Un agent ne crée et ne pousse jamais un tag, ne fusionne jamais dans `master` et ne
  fusionne jamais la PR de Release Please, sans demande explicite** : publier une version est
  irréversible (PyPI refuse de republier une version).

### Opérations GitHub

La CLI `gh` **n'est pas installée** dans l'environnement de développement : n'essayez pas de
l'utiliser.

- **git (push, fetch, pull)** : passez par **SSH**. Le remote `origin` est en HTTPS, sans
  identifiants : utilisez l'URL SSH, par ex.
  `git push git@github.com:cyr-ius/security-review.git dev`
  (ou `git remote set-url --push origin git@github.com:cyr-ius/security-review.git`).
- **API GitHub (pull requests, issues, revues, commentaires, releases)** : passez par le
  **connecteur GitHub MCP**.
- Si SSH est indisponible, le connecteur peut aussi pousser des fichiers (`push_files`). Il crée
  alors un autre commit : vérifiez avec `git fetch` puis `git diff HEAD origin/<branche>` que le
  contenu est identique, puis réalignez la branche locale sur `origin/<branche>`.
- Si git n'a pas d'identité configurée, reprenez celle des commits précédents pour ce commit
  seulement (`git -c user.name=... -c user.email=... commit`), sans modifier la configuration.

## Carte du code

| Zone | Fichiers |
|---|---|
| Prompts, outils, ressources MCP, point d'entrée du serveur MCP | `server.py`, `prompts.py` |
| Point d'entrée du contrôleur (`serve`, `db`, commandes d'administration) ; recherche de nouvelle version (page À propos) ; `HEALTHCHECK` de l'image Docker | `controller.py` ; `update_check.py` ; `healthcheck.py` |
| Moteur de scan, masquage des secrets | `rules/scanner.py` |
| Règles et checklists par défaut (copiées en base au premier lancement) | `rules/default_rules.toml` |
| Règles en base (amorçage, packs TOML), registre actif | `rules/rules_loader.py`, `rules/rule_store.py`, `rules/registry.py`, `rules/checklists.py` |
| CLI : `CONTROLLER_COMMANDS` (`db`, `advisories`, `rules`, `token`, `user`, `group`, `project`, `audit`) ; client de pipeline `security-review-ci`, seul à exécuter `gate`, `sarif`, `trend`, `scan-code` et `scan-deps` (jeton `ci`, bibliothèque standard uniquement, aussi publié seul sur PyPI par `scripts/build_ci_client.py` : n'importe rien du paquet, lit ses variables dans l'environnement ; il liste les fichiers, le contrôleur les scanne : `rules/codescan.py`, `deps/depscan.py`, `web_api/ci_routes.py`) ; sa commande `agent-review`, hook post-commit du poste de travail, lance l'agent de code du développeur (`claude`, `copilot` ou `codex`) limité aux outils de revue du serveur MCP, sans shell ni appel au contrôleur ; sa commande `guard`, hook de l'agent avant un appel d'outil, analyse hors ligne les fichiers lus avec une copie des règles `AI-*` (gardée identique par un test) | `cli.py` (`CONTROLLER_COMMANDS`), `rules/codescan.py`, `ci_client.py` ; téléchargement public du client par le contrôleur pour `uv --find-links` (`/api/ci-client/`, activé par défaut) : `clients/ci_wheel.py`, `web_api/ci_client_routes.py` |
| Dépendances et avis OSV (téléchargement facultatif par le contrôleur : `deps/advisory_sync.py`) ; proxy sortant du contrôleur (OSV et OIDC) | `deps/dependencies.py`, `deps/depscan.py`, `deps/advisories.py`, `deps/advisory_sync.py`, `deps/versions.py` ; `proxy.py` |
| Normalisation des noms de projet (minuscules, nom du dépôt, `-` seul séparateur), appliquée à toute entrée | `storage/project_names.py` |
| Persistance, schéma (purge des rapports sans findings et de l'audit : `storage/retention.py` ; couverture déclarée d'une revue, contrôlée avec le registre : `reports/coverage.py`) | `storage/models.py`, `reports/services.py`, `reports/coverage.py`, `storage/retention.py`, `storage/database.py`, `storage/migrations/` (Alembic) |
| Journal d'audit (écrit par `services`, `token_store` et `access_control` dans la transaction du changement ; envoi syslog facultatif par le contrôleur) ; métriques Prometheus du contrôleur (`/metrics`, rôle `metrics`) | `observability/audit.py`, `observability/audit_syslog.py` ; `observability/metrics.py` |
| Export et tendances | `reports/sarif.py`, `reports/trends.py` |
| Connecteurs : envoi des findings vers des systèmes externes (tickets, registre de vulnérabilités...), manuel et automatique par le contrôleur : API publique des connecteurs (contrat des connecteurs tiers, versionné), registre (intégrés + plugins autorisés par `SECREVIEW_CONNECTORS_PLUGINS`), connexions, client HTTP imposé, Jira et ServiceNow | paquet `connectors/` (`api.py`, `registry.py`, `connections.py`, `transport.py`, `core.py`, `jira.py`, `servicenow.py`), `web_api/connector_routes.py`, exemple `examples/connector/` |
| HTTP des deux processus, auth (jetons et rôles), TLS, `/healthz` | `http_server.py` ; stockage des jetons en base : `auth/token_store.py` ; comptes web locaux et OIDC, seuls à ouvrir l'interface (mot de passe, création OIDC à la volée, sessions, admin initial) : `auth/web_users.py` ; protocole OIDC du contrôleur : `auth/oidc.py` ; connexion OAuth des clients MCP (serveur d'autorisation du contrôleur, routes du SDK MCP, écran de consentement : `web_api/oauth_routes.py`) : `auth/oauth_server.py`, jetons vérifiés par `auth/token_store.py` ; permissions, rôles, groupes et membres (groupes OIDC par le claim), demandes de projet (`request_project`) : `auth/access_control.py` |
| Contrôleur : API REST `/api/v1` et fichiers de `/ui` | paquet `web_api/` (`__init__.py` : `create_app` ; `schemas.py` : modèles de requête et de réponse ; `deps.py` : identité et permissions ; un `*_routes.py` par domaine) ; application Angular dans `web/` |
| Normes de développement par technologie (prompt `development-standards`, écran « Normes ») | `standards.py` |
| Paramètres `SECREVIEW_*` ; réglages modifiables dans l'interface web (langue, proxy sortant, configuration OIDC) | `config.py` ; `app_settings.py` |

Tous les modules sont dans `src/security_review_mcp/` : à la racine, les points d'entrée et
les briques communes (`config`, `http_server`, `proxy`...) ; ailleurs, un sous-paquet par
domaine (`storage/`, `reports/`, `rules/`, `deps/`, `auth/`, `observability/`, `clients/`,
`connectors/`, `web_api/`). Un nouveau module va dans le sous-paquet de son domaine, pas à la
racine. L'application Angular (`web/`) est compilée par `npm run build` dans
`src/security_review_mcp/webui/` (ignoré par git). La logique métier va dans les modules
(`reports/services.py`, `rules/scanner.py`...) ; `server.py` et `cli.py` restent des couches
minces qui valident les entrées et appellent ces modules.

## Conventions de code

**Les normes et conventions de développement par technologie (Python, Angular...) sont
disponibles via le serveur MCP `security-review`.** S'il est connecté, consultez-les avant
d'écrire du code : prompt `development-standards`, outils `list_development_standards` et
`get_development_standards` (par technologie ou par fichier), ressources `standards://catalog`
et `standard://{slug}`. Les règles génériques qu'elles contiennent ne sont pas répétées ici :
`conventions` (ruff, `uv lock`, Conventional Commits), `fastapi` (Python 3.14, annotations,
docstrings, code et logs en anglais, `get_settings()`, ORM, Alembic, jetons hachés), `angular`
et `tests-python` (méthode de test). Ce fichier ne garde que ce qui est propre à ce dépôt ; en
cas de conflit, il prévaut.

- La documentation utilisateur (`docs/`, README) est **bilingue, anglais et français** (voir
  [Documentation](#documentation)).
- Imitez le code voisin : mêmes noms, même densité de commentaires, pas de nouvelle dépendance
  sans nécessité (le serveur doit rester installable hors ligne).

### Outils et prompts MCP

- Chaque outil porte `annotations=READ_ONLY` ou `WRITE` et le décorateur `@_tool_errors`, qui
  transforme `ValueError` / `services.NotFoundError` en `ToolError` visible par le modèle.
  Levez ces exceptions pour les erreurs attendues ; ne renvoyez pas de dictionnaire d'erreur.
- Décrivez les paramètres avec `Annotated[..., Field(description=...)]` : c'est ce que lit le
  modèle hôte.
- Un nouvel outil ou prompt doit être cité dans `INSTRUCTIONS` (`server.py`) s'il change le
  déroulé d'une revue.
- Les prompts de revue se terminent par l'appel unique à `save_security_report` ; le contenu
  fourni par l'utilisateur est encadré avec `prompts.fenced`.

### API REST et interface web

- Chaque route JSON du contrôleur déclare son modèle de réponse dans `web_api/schemas.py` (jamais
  `-> dict`) : il documente l'API et filtre les champs non déclarés. Un test le vérifie sur le
  schéma OpenAPI.
- Angular, en plus du standard `angular` : formulaires de saisie en Signal Forms (obligatoire),
  aucun `.subscribe()` dans les composants (`rxResource` ou `firstValueFrom`), couleurs par
  variables Bootstrap ou jetons de `styles.css`. Le détail est dans `docs/contributing/web-ui`.

### Invariants de sécurité (ne jamais régresser)

C'est un outil de sécurité : un écart ici est un bug bloquant.

- **stdout est réservé au protocole MCP** en stdio : aucun `print` dans le serveur, journaux sur
  stderr via `logging.getLogger("security_review_mcp")`. Seule la CLI écrit sur stdout.
- **Les outils MCP ne lisent jamais le disque** à partir d'un chemin fourni par le client : ils
  travaillent sur le contenu transmis. L'accès fichiers est réservé à la CLI (opérateur), qui ne
  suit pas les liens symboliques.
- **Toute entrée est bornée** par un paramètre de `Settings` (`max_content_chars`,
  `max_findings_per_report`, `max_list_limit`...). Un nouvel outil qui accepte du texte ou une
  liste doit appliquer une limite.
- **Les secrets sont masqués** (`scanner.redact_secrets`) avant stockage et dans les extraits
  renvoyés. Ne journalisez jamais un jeton, un mot de passe ou une URL de base avec identifiants.
- **SQL uniquement via l'ORM** (SQLModel, paramètres liés), jamais de SQL construit par chaîne.
- **Schéma via Alembic uniquement** : toute modification d'un modèle de table s'accompagne d'une
  nouvelle révision dans `migrations/versions/` (jamais de modification d'une révision publiée) ;
  `tests/test_database.py` vérifie que les migrations produisent exactement les modèles. Le
  serveur MCP HTTP ne migre jamais le schéma.
- **Séparation MCP / contrôleur** : le serveur MCP n'expose que `/mcp` (serveur d'enrôlement
  sans outil pour un client sans jeton), `/healthz` et, avec la connexion OAuth des clients MCP
  (`SECREVIEW_MCP_OAUTH_ENABLED`, désactivée par défaut), le document statique en lecture seule
  `/.well-known/oauth-protected-resource/...` ; le serveur d'autorisation OAuth est le
  contrôleur, le serveur MCP ne fait que vérifier les jetons en base ; aucun des deux processus n'expose de
  route d'écriture sans jeton. N'ajoutez pas de route
  web au serveur MCP ni d'endpoint MCP au contrôleur.
- **Le serveur MCP ne charge aucun module du contrôleur** qui sort sur le réseau ou sert ses
  routes (`controller`, `advisory_sync`, `oidc`, `oauth_server`, `audit_syslog`, `connectors`,
  `update_check`, `web_api`), même indirectement ; `tests/test_server.py` le vérifie. Un module partagé par les
  deux processus (comme `app_settings`) les importe dans la fonction qui s'en sert.
- **Aucun appel réseau sortant** du serveur MCP : la base de vulnérabilités est importée par la
  CLI. Exceptions : `security-review-ci`, qui contacte l'URL donnée par l'opérateur, et le téléchargement OSV du contrôleur (`advisory_sync`), **désactivé par défaut**, en HTTPS
  uniquement, taille bornée, proxy facultatif (`proxy`, partagé avec le OIDC) jamais journalisé
  avec ses identifiants, et la
  connexion OIDC du contrôleur (`oidc`), **désactivée par défaut**, qui ne contacte que le
  fournisseur d'identité configuré, en HTTPS, réponses bornées, la recherche de nouvelle version
  du contrôleur (`update_check`, **désactivée par défaut**, HTTPS vers l'API GitHub, par le
  proxy, réponse bornée et mise en cache), l'envoi syslog du journal d'audit par le contrôleur
  (`audit_syslog`, **désactivé par défaut**, qui lit les événements en base : le serveur MCP n'y
  participe pas) et l'envoi des findings par les connecteurs du contrôleur (`connectors`, **chaque connecteur
  désactivé par défaut**, activé dans l'interface par un administrateur, tous verrouillés par
  `SECREVIEW_CONNECTORS_ENABLED=false`) : un connecteur (Jira, ServiceNow ou tiers) ne sort que par `connectors.transport`
  (HTTPS, URL configurée uniquement, par le proxy, sans suivre de redirection, réponse bornée,
  secrets jamais journalisés ni renvoyés, secret lié à l'hôte de son URL) ; un connecteur tiers
  n'est chargé que s'il est listé dans `SECREVIEW_CONNECTORS_PLUGINS` ; à sens unique : un
  envoi ne change jamais le statut d'un finding. Ne cassez pas `connectors/api.py` sans
  incrémenter `API_VERSION` : c'est le contrat des connecteurs tiers.
- Les regex de règles doivent éviter le backtracking catastrophique (pas de quantificateurs
  imbriqués) ; `rules_loader` les valide pour les règles internes.
- Jetons Bearer : seules les empreintes SHA-256 sont conservées, comparaison en temps constant.
- **Un agent ne ferme jamais un finding** : aucun outil MCP ne change un statut
  (`propose_finding_status` enregistre seulement une proposition). `accepted` et
  `false_positive` sont décidés par une personne connectée à l'interface (session, jamais un
  jeton Bearer), qui est enregistrée comme approbateur ; une acceptation exige aussi un motif et
  une date d'expiration (elle peut en être dépourvue tant que
  `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED` est actif ; un faux positif n'exige ni motif ni date ;
  sous
  `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY`, une acceptation n'exige ni motif ni date) ; une décision expirée
  compte comme ouverte (gate, posture, SARIF, tendances).

### Paramètres

Un nouveau paramètre s'ajoute dans `config.Settings` (préfixe `SECREVIEW_` automatique), avec
un commentaire, puis dans `.env.example` et `docs/reference/configuration.md` (et `.fr.md`).

### Règles de scan

Identifiants `PRÉFIXE-NNN` par famille : `PY`, `JV`, `NG` (Angular), `CFG`, `GEN`, `GL`
(GitLab CI), `JK` (Jenkins), `CI`, `SP` (Spring), `FA` (FastAPI), `GO` (Go), `CS` (C#), `RS` (Rust), `TS` (backend
TypeScript / Node.js), `DEP` (hygiène des
dépendances), `AI` (texte caché ou instructions adressées à un assistant IA). Ne réutilisez et ne renumérotez jamais un identifiant existant : les utilisateurs
les citent dans `secreview:ignore` et `disabled_rules`. Indiquez la CWE quand elle existe.

Les règles et checklists par défaut sont dans `src/security_review_mcp/rules/default_rules.toml`,
jamais dans le code Python. Elles sont copiées en base au premier lancement
(`rule_store.seed_defaults`, appelé par `init_db`). Une règle ajoutée ou corrigée dans ce
fichier atteint les bases existantes au démarrage suivant, sauf si un administrateur l'a modifiée.

### CLI

Codes de sortie identiques partout : `0` succès, `1` bloqué (gate / findings au-dessus du
seuil), `2` erreur d'usage ou de données (`_fail` écrit l'erreur en JSON sur stderr).

## Tests

La méthode (un test protège un **contrat** ou un **invariant**, pas une ligne de code ; quoi
tester et quoi ne pas tester ; étendre un test existant plutôt qu'en créer un ; **1 à 3 tests**
par changement ; **un** test de régression qui échoue avant la correction ; un invariant de
sécurité testé une fois, au plus près du module qui le garantit) est dans le standard
`tests-python` du serveur MCP. Les tests d'un changement sont dans le même commit que lui.

**Conventions**

- Un fichier par module : `tests/test_<module>.py`. Ajoutez au fichier existant plutôt que d'en
  créer un nouveau.
- `tests/conftest.py` ignore le `.env` du développeur et les variables `SECREVIEW_*` du shell :
  un test qui a besoin d'un réglage le définit lui-même (`monkeypatch.setenv`, `Settings(...)`).
- `tests/conftest.py` fournit automatiquement une base SQLite en mémoire et un registre de
  règles vide par test : n'utilisez pas la base réelle. Utilisez la fixture `import_pack` pour
  charger des règles internes (pack TOML importé en base), `tmp_path` pour les fichiers.
- Outils, prompts et ressources MCP : test de bout en bout avec `mcp.client.Client(mcp)` (voir
  `tests/test_server.py`, `pytestmark = pytest.mark.anyio`), avec un cas d'erreur
  représentatif (`ToolError` attendu).
- Règle de scan : au moins un cas **positif** (le motif vulnérable est détecté) et un cas
  **négatif** (le code sûr équivalent ne l'est pas), pour limiter les faux positifs.
- CLI : appelez `server.main([...])` ou les fonctions de `cli.py`, vérifiez le **code de sortie**
  et la sortie (`capsys`).
- Pas de réseau, pas de `sleep`, pas de dépendance à l'ordre des tests. Les clés et jetons de
  test sont factices.

## Revue de sécurité

Ce projet utilise son propre serveur MCP pour se relire. **Si le serveur MCP `security-review`
est connecté et répond** (ses prompts et outils apparaissent dans votre session), une revue de
sécurité des changements est **systématique** avant de déclarer une tâche terminée ou d'ouvrir
une PR, quelle que soit la taille du changement :

1. Lancez le prompt `security-review` (ou `api-security-review` pour l'API REST,
   `configuration-review` pour Dockerfile / workflows / YAML, `dependency-review` si
   `pyproject.toml`, `uv.lock` ou `package.json` changent) sur les fichiers modifiés, avec le
   diff comme contexte. Pour un changement très étendu, utilisez `codebase-review`.
2. Appuyez-vous sur `scan_code` et `get_review_checklist` pendant la revue.
3. Enregistrez le résultat **une seule fois** avec `save_security_report` (`project` :
   `security-review-mcp`, plus `branch` et `commit_sha` quand ils sont connus).
4. Corrigez les findings `critical` et `high` avant de terminer, avec un test qui couvre la
   correction. Pour les autres, corrigez-les ou justifiez-les, et proposez leur statut avec
   `propose_finding_status` (`fixed`, `accepted`, `false_positive`, avec le motif) : un agent ne
   change jamais un statut, c'est une personne qui valide la proposition dans l'interface web.
5. Résumez la revue (identifiant du rapport, findings et suite donnée) dans votre réponse et dans
   la description de PR.
6. Quand vous commitez le changement relu, ajoutez le trailer `Security-Review: <identifiant du
   rapport>` au message de commit : le hook post-commit `agent-review` ne relance pas de revue
   pour un commit qui le porte. Sans revue faite, n'ajoutez pas ce trailer.

Si le serveur n'est pas connecté ou ne répond pas, dites-le explicitement : ne prétendez pas
avoir fait la revue. Lancez au minimum le scan en CLI sur le dépôt
(`uv run security-review-ci scan-code . --project security-review-mcp --exclude tests/`, avec
`SECREVIEW_CONTROLLER_URL` et un jeton `ci` dans `SECREVIEW_CI_TOKEN`) et signalez ses résultats ;
si aucun contrôleur n'est joignable, dites-le aussi.

## Documentation

`docs/` (MkDocs Material) est la **source de vérité complète** pour les utilisateurs, en
**deux langues** : chaque page existe en anglais (`page.md`, langue par défaut, servie à la
racine du site) et en français (`page.fr.md`, à côté, servie sous `/fr/`), avec le plugin
`mkdocs-static-i18n`. Mettez-la à jour dans le même changement que le code, **dans les deux
langues** :

La doc est organisée en parcours de mise en œuvre : **Démarrage** (`getting-started/` :
mise en service du serveur en mode partagé, mode local avec l'installation du paquet PyPI,
connexion de l'hôte, normes centralisées, hooks de commit), **Revue de sécurité** (`review/` : fonctionnement, prompts et outils, règles,
checklists, normes, gate) et **Application** (`usage/` : interface web, triage, jetons, comptes,
projets, rôles, groupes et permissions, connexion OIDC, journal d'audit) ne
contiennent que l'essentiel pour travailler ; **Connecteurs** (`usage/connectors/`, sous-menu d'**Application**) décrit l'envoi des
findings vers d'autres outils, une page par connecteur intégré et une pour les connecteurs tiers ;
**Avancé** (`advanced/`) regroupe les détails et les fonctions facultatives. Une nouvelle
explication détaillée va dans `advanced/`, avec au plus une ligne et un lien depuis les pages
essentielles.

| Si vous modifiez... | Mettez à jour (`.md` et `.fr.md`) |
|---|---|
| Un prompt ou un outil MCP (nom, argument, comportement) | `docs/review/prompts-tools` |
| Une règle de scan ou une checklist par défaut (`default_rules.toml`) | `docs/review/rules` ou `docs/review/checklists` (et `review/analysis/code-scan` si le scan du dépôt change) |
| Le format des packs TOML internes | `docs/review/rules` (et `review/checklists` pour `[[checklist]]`), `examples/rules/company.toml` |
| L'analyse de dépendances, les formats de manifeste, l'import OSV | `docs/review/analysis/dependencies` |
| Une commande ou option CLI, un code de sortie | `docs/reference/cli` + la page d'usage concernée (`review/gate`, `advanced/architecture/ci`, `review/analysis/code-scan`, `advanced/reports/sarif`...) |
| Un paramètre `SECREVIEW_*` | `docs/reference/configuration`, `.env.example` |
| Transport HTTP, authentification, TLS, enrôlement, connexion OAuth des clients MCP | `docs/advanced/bearer-tokens`, `docs/advanced/mcp-oauth`, `docs/advanced/tls`, `docs/advanced/architecture/mcp-server` (enrôlement), `docs/reference/security` (+ `getting-started/deploy` et `getting-started/host` si le parcours de base change) |
| Séparation MCP / contrôleur, Compose, Kubernetes, reverse proxy | `docs/advanced/architecture/index`, `docs/getting-started/deploy`, `docs/advanced/reverse-proxy`, `docker-compose.yml`, `examples/kubernetes/` |
| La base de données (SQLite / PostgreSQL, migrations, conservation, sauvegarde, mise à niveau) | `docs/advanced/database` |
| Le serveur MCP (routes, transports, démarrage, réponse selon le jeton, enrôlement, garanties, exposition, réplicas) | `docs/advanced/architecture/mcp-server` |
| Le client de pipeline `security-review-ci` (installation, jeton `ci`, commandes, exemples par plateforme CI/CD, tendance) | `docs/advanced/architecture/ci` (+ `review/gate`) |
| Le contrôleur (routes, démarrage, tâches de fond, connexions sortantes, exposition, réplicas, premier administrateur, sessions, sécurité de l'interface) | `docs/advanced/architecture/controller` |
| Les normes de développement (prompt, outils, ressources, écran) | `docs/review/standards` (+ `review/prompts-tools`, `getting-started/stored-standards`) |
| L'interface web, l'API REST ou les rôles | `docs/usage/index` (écrans), `docs/usage/triage` (triage, criticité, acceptations), `docs/usage/tokens` (jetons), `docs/usage/user-accounts` (comptes), `docs/usage/access-control` (rôles, groupes, permissions), `docs/usage/projects` (projets) ; connexion OIDC : `docs/usage/sso` ; détails et API : `docs/advanced/reports/triage-api`, `docs/advanced/access-control-api`, `docs/advanced/oidc` |
| Les connecteurs (contrat `connectors/api.py`, Jira, ServiceNow, écran **Connecteurs**, routes) | `docs/usage/connectors/` (`index`, `jira`, `servicenow`, `third-party`), `docs/advanced/connectors`, `docs/contributing/connectors` (contrat `connectors/api.py`), `examples/connector/` |
| Installation, image Docker | `docs/getting-started/deploy` (conteneurs), `docs/getting-started/stdio` (paquet PyPI), `docs/advanced/deployment/installation`, `docs/advanced/deployment/manual-install`, `docs/advanced/deployment/docker` |
| Une garantie ou limite de sécurité | `docs/reference/security` |
| Le journal d'audit (événements, conservation, syslog) ou les métriques Prometheus | `docs/usage/audit-metrics`, `docs/advanced/audit-log`, `docs/reference/metrics` |
| La structure du code, l'environnement de dev (devcontainer, VS Code), l'image | `docs/contributing/index` |
| Une convention de développement propre au serveur MCP, au contrôleur ou à l'interface Angular | `docs/contributing/mcp-server`, `docs/contributing/controller` ou `docs/contributing/web-ui` |
| La méthode ou les conventions de test, les fixtures de `tests/conftest.py` | `docs/contributing/tests` |
| Les règles de rédaction ou la construction de la doc, les règles du README | `docs/contributing/documentation` |
| Les linters, formateurs, hooks `prek`, workflows de CI, la procédure de revue, les branches ou la publication d'une version | `docs/contributing/checks-and-releases` |

- Les deux versions d'une page disent la même chose : pas de section qui n'existe que dans une
  langue. Les exemples (commandes, sorties, JSON) sont identiques ; seuls le texte et les
  commentaires sont traduits.
- Dans la doc, les README et les textes de l'interface web, le contrôleur s'appelle toujours
  **serveur Controller** en français, **Controller server** en anglais et **servidor
  Controller** en espagnol (« Controller » en anglais, avec sa majuscule, jamais seul) ; les
  commandes, identifiants et clés (`security-review-controller`, `SECREVIEW_CONTROLLER_URL`,
  `settings.controllerUrlTitle`...) ne changent pas, ni les noms des configurations de
  `.vscode/launch.json`.
- L'interface web est traduite (anglais, français, espagnol) : chaque version de la doc cite les
  libellés de l'interface dans sa langue, tels qu'ils s'affichent (**Tokens** / **Jetons**).
- Tout texte affiché par l'interface passe par les catalogues de `web/src/app/core/i18n/messages/`,
  dans les trois langues (voir `docs/contributing/web-ui`) : pas de texte en dur dans un template.
- Nouvelle page : créez `page.md` et `page.fr.md` dans `docs/`, déclarez `page.md` dans `nav`
  de `mkdocs.yml` et traduisez son titre dans `nav_translations` (langue `fr` du plugin `i18n`).
- Liens relatifs entre pages, toujours vers le fichier anglais (`../reference/cli.md`) : le
  plugin les fait pointer vers la page française depuis une page française. Les ancres suivent
  les titres de chaque langue (`#report-language` / `#langue-des-rapports`). Vérifiez avec
  `mkdocs build --strict` : une ancre inconnue fait échouer le build.
- Exemples copiables et exacts : options, noms de variables et sorties doivent correspondre au
  code actuel.

## README

Le `README.md` (anglais, celui de PyPI et de GitHub) et le `README.fr.md` (français) sont des
**vitrines synthétiques**, pas une seconde documentation. Ils ont le même contenu, traduit, se
lient l'un à l'autre en tête, restent nettement plus courts que `docs/` et ne contiennent que :

1. une description en quelques lignes et le lien vers la documentation complète ;
2. les capacités principales sous forme de liste ou de tableau court (noms des prompts, outils
   et commandes CLI, une ligne chacun, sans détail des arguments) ;
3. une installation et un lancement minimaux (quelques commandes) ;
4. un exemple de configuration d'hôte ;
5. des liens vers les pages de `docs/` pour tout le reste.

Règles :

- Tout ce qui figure dans le README doit aussi figurer dans `docs/` ; l'inverse n'est pas vrai.
- Pas de tableau exhaustif des variables, d'options CLI détaillées, de cas limites ni de
  procédures longues : mettez-les dans `docs/` et ajoutez un lien.
- Quand vous ajoutez une capacité visible (outil, prompt, commande, transport), ajoutez **une
  ligne** au README avec un lien vers la page de doc ; quand vous en retirez ou renommez une,
  corrigez le README.
- Modifiez toujours les deux fichiers ensemble.
- Les liens vers la doc pointent sur le site publié : `https://cyr-ius.github.io/security-review/...`
  depuis `README.md`, `https://cyr-ius.github.io/security-review/fr/...` (ancres
  françaises) depuis `README.fr.md`.
