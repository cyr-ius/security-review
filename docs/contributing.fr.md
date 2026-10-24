# Contribuer

## Environnement de développement

```bash
uv sync --extra dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
pre-commit install          # facultatif : mêmes contrôles avant chaque commit, et le scan des
                            # dépendances si SECREVIEW_MCP_URL est défini
```

Le hook `prettier` formate les fichiers YAML et JSON et les sources de `web/src/` avec la
version de Prettier verrouillée par `web/package-lock.json` (celle de la CI) : lancez `npm ci`
dans `web/` avant le premier commit. La CI vérifie les mêmes fichiers (`lint.yml`, job **web**).
`.prettierrc` fixe la largeur à 100 colonnes, comme ruff ; les fichiers de verrouillage sont
listés dans `.prettierignore`.

### Revue de sécurité de chaque commit

Le hook facultatif `agent-review` (`scripts/agent-review.sh`) demande à Claude Code de relire
chacun de vos commits sous l'angle de la sécurité, en arrière-plan, avec le serveur MCP
`security-review` de votre `.mcp.json`. La revue suit la procédure de revue de sécurité de
`AGENTS.md` et enregistre un rapport, que vous lisez dans l'interface web. Activez-le une fois :

```bash
prek install --hook-type post-commit
SKIP=agent-review git commit ...      # la sauter pour un commit
```

- Le commit n'est jamais bloqué : la revue s'exécute après lui, et son journal est dans
  `.git/agent-review/<commit>.log`.
- L'agent reçoit le commit dans son prompt et peut seulement lire le dépôt et appeler les outils
  de revue du serveur (`--restricted`, `--permission-mode dontAsk`) : il ne modifie aucun
  fichier, ne lance aucune commande, ne propose aucun statut de finding et ne peut lire ni
  `.env`, ni `.mcp.json`, ni aucun fichier hors du dépôt.
- Le hook ne fait rien pour un commit fait par Claude Code (déjà relu dans sa session), pendant
  un rebase ou un cherry-pick, ou si le CLI `claude` ou `.mcp.json` manque.
- Chaque revue consomme de l'usage du modèle sur votre compte Claude.

Dans VS Code (`.vscode/`) :

| Configuration de `launch.json` | Rôle |
|---|---|
| **MCP server + controller** | Lance la tâche **Database upgrade**, puis les deux processus sur la même base |
| **MCP server (HTTP, port 8000)** | Serveur MCP seul ; la base doit déjà être migrée |
| **Controller (web UI and API, port 8080)** | Contrôleur seul ; migre la base et affiche le mot de passe du compte `admin` initial au premier démarrage |
| **Controller CLI (prompt for arguments)** | Une commande du contrôleur (`db status`, `token list`…) sous le débogueur |
| **Controller + web UI (Angular, port 4200)** | Contrôleur et application Angular sous le débogueur, rechargement à chaud |
| **Web UI + API (Angular dev server, port 4200)** | Lance la tâche **Web UI + API: dev servers** (contrôleur sur 8080 et `ng serve`), attend qu'ils soient prêts, puis ouvre Chrome sur `http://localhost:4200/ui/` avec les points d'arrêt TypeScript |
| **Pytest (current file)** | Tests du fichier ouvert |

| Tâche de `tasks.json` | Commande |
|---|---|
| **Build security_review_mcp** | `uv sync --extra dev --extra docs --extra postgres` |
| **Database upgrade** | `uv run security-review-controller db upgrade` (après **Build**) |
| **Tests** / **Lint** | `pytest`, puis ruff et `mkdocs build --strict` |
| **Web UI: build** / **Web UI: dev server (port 4200)** | Build Angular servie par le contrôleur, ou `ng serve` avec `/api` redirigé vers le port 8080 |
| **API: controller (port 8080)** / **Web UI + API: dev servers** | Contrôleur seul hors débogueur (`security-review-controller serve`), ou contrôleur et `ng serve` en parallèle |
| **Docs: serve (port 8001)** | `mkdocs serve` |
| **Docker: compose up** / **down** | Pile `docker-compose.yml` de l'image, avec sa propre base PostgreSQL (mêmes ports 8000 et 8080 : arrêtez les configurations de debug avant) |

### Devcontainer

Le dépôt fournit un devcontainer (`.devcontainer/`) avec Python, uv, Node.js, un démon Docker
dédié (feature *docker-in-docker*) et une base **PostgreSQL 17**. `compose.yaml` décrit deux
services : `app`, le conteneur de développement, et `db`, la base, joignable depuis `app` sous
le nom `db` et conservée dans le volume `secreview-dev-pg` entre deux reconstructions.
`SECREVIEW_DATABASE_URL` y pointe par défaut : le serveur MCP, le contrôleur et la CLI utilisent
PostgreSQL. Les tests, eux, utilisent toujours une base SQLite en mémoire et ignorent votre
fichier `.env` et les variables `SECREVIEW_*` du shell.

À sa création, le devcontainer installe le client `psql`, les hooks `prek` et l'environnement
complet (`uv sync --extra dev --extra docs --extra postgres`), puis migre la base. Il redirige les
ports 8000 (serveur MCP), 8080 (contrôleur), 4200 (serveur de dev Angular), 8001 (doc) et 5432
(PostgreSQL, identifiants de développement `secreview` / `secreview`).

```bash
psql -h db -U secreview secreview                     # mot de passe : secreview
SECREVIEW_DATABASE_URL=sqlite:///./dev.db security-review-mcp serve   # revenir ponctuellement à SQLite
```

Le démon Docker permet de construire et de lancer l'image du
[Dockerfile](advanced/docker.md) sans quitter le conteneur :

```bash
docker build -t security-review-mcp .
docker run --rm -p 8080:8000 -v secreview-data:/var/lib/secreview \
    --entrypoint security-review-controller security-review-mcp serve --host 0.0.0.0
docker run --rm -p 8000:8000 -v secreview-data:/var/lib/secreview security-review-mcp \
    serve --transport streamable-http --host 0.0.0.0 --port 8000
```

Les ports sont redirigés vers le poste : l'interface web est sur `http://localhost:8080/ui/`,
l'API REST sur `/api/v1` et l'endpoint MCP sur `http://localhost:8000/mcp`. Images et volumes sont conservés dans des volumes propres au
devcontainer : ils ne se mélangent pas avec ceux de l'hôte.

!!! note "Pourquoi pas le socket Docker de l'hôte ?"
    Monter `/var/run/docker.sock` donnerait à tout outil du devcontainer, agents IA compris, un
    accès équivalent à root sur l'hôte. Le démon dédié exige un conteneur `privileged`, mais
    reste isolé du démon de l'hôte. Après l'ajout de la feature, reconstruisez le conteneur
    (*Dev Containers: Rebuild Container*).

## Définition de « terminé »

Une contribution, humaine ou produite par un agent IA, n'est terminée que si le comportement
qu'elle ajoute ou corrige est vérifié par un test pertinent, nouveau ou existant, que la documentation `docs/` est à jour dans les deux langues et que les `README.md`, qui
restent des résumés, le sont aussi. Quand le serveur MCP `security-review` est opérationnel, les changements sont en outre
relus avec lui (le projet se relit lui-même) et le rapport est enregistré. Les règles détaillées
(conventions, invariants de sécurité, correspondance code → pages de doc) sont dans `AGENTS.md`
à la racine du dépôt ; `CLAUDE.md` et `.github/copilot-instructions.md` y renvoient.

Un test protège un contrat ou un invariant, pas une ligne de code, et il n'y a pas d'objectif de
couverture. Testez d'abord les invariants de sécurité, les contrats publics (outils et prompts
MCP, codes de sortie CLI, schéma REST, migrations) et chaque bug corrigé (un test de régression).
Ne testez pas ce que garantit déjà une bibliothèque, le détail d'implémentation ni le texte exact
d'un message. Avant d'ajouter un test, étendez celui qui couvre déjà le comportement (assertion
supplémentaire, ligne de `parametrize`) : un changement ajoute en général un à trois tests.

## Structure du code

```
src/security_review_mcp/
├── server.py      # prompts, outils, ressources, point d'entrée du serveur MCP
├── prompts.py     # construction des prompts
├── standards.py   # normes de développement : stockage, recherche par technologie / fichier, rendu
├── controller.py  # point d'entrée du contrôleur (serve, db et commandes d'administration)
├── ci_client.py   # `security-review-ci` : client de pipeline du contrôleur, liste des fichiers (bibliothèque standard uniquement)
├── cli.py         # commandes du contrôleur : db, advisories, rules, token, user, group, project, audit
├── http_server.py # HTTP des deux processus : jetons Bearer et rôles, TLS, /healthz, uvicorn
├── healthcheck.py # HEALTHCHECK de l'image Docker (/healthz des processus HTTP)
├── config.py      # paramètres (SECREVIEW_*)
├── app_settings.py # réglages modifiables dans l'interface (langue, proxy sortant, OIDC), en base
├── proxy.py       # proxy sortant du contrôleur (OSV, OIDC) : URL, no_proxy, handler urllib
├── update_check.py # recherche d'une nouvelle version sur GitHub (page À propos, facultatif)
├── storage/       # persistance
│   ├── database.py        # moteur, sessions et migrations (Alembic)
│   ├── models.py          # modèles SQLModel (tables + schémas)
│   ├── migrations/        # environnement Alembic et révisions du schéma (versions/)
│   ├── retention.py       # purge quotidienne des rapports sans findings et des anciens événements d'audit
│   └── project_names.py   # normalisation des noms de projet (toute entrée)
├── reports/       # rapports de sécurité
│   ├── services.py        # logique de persistance des rapports
│   ├── coverage.py        # contrôle les résultats de checklist et règles déclarés avec un rapport
│   ├── sarif.py           # export SARIF 2.1.0
│   └── trends.py          # rapport de tendance
├── rules/         # règles de scan et checklists
│   ├── scanner.py         # moteur de scan, suppression inline, masquage des secrets
│   ├── syntax_analysis.py # analyses structurelles Tree-sitter, séparées des règles ligne par ligne
│   ├── codescan.py        # scan du code complet des fichiers envoyés par security-review-ci (findings)
│   ├── default_rules.toml # règles et checklists par défaut, copiées en base au premier lancement
│   ├── rules_loader.py    # validation des règles, lecture des packs TOML et du fichier par défaut
│   ├── rule_store.py      # règles en base : amorçage, import/export, activation, suppression
│   ├── registry.py        # règles/checklists actives (lues en base), rechargement
│   └── checklists.py      # structure d'un item de checklist
├── deps/          # analyse des dépendances
│   ├── dependencies.py    # analyseurs de manifestes / lockfiles, hygiène
│   ├── depscan.py         # scan de dépendances et conversion en findings
│   ├── advisories.py      # import OSV, correspondance des versions
│   ├── advisory_sync.py   # téléchargement OSV par le contrôleur (proxy, mise à jour quotidienne, historique)
│   └── versions.py        # comparaison de versions
├── auth/          # identité et accès
│   ├── access_control.py  # permissions, rôles, groupes et membres des comptes web, enrôlement des projets
│   ├── token_store.py     # jetons Bearer en base : création, expiration, renouvellement, révocation
│   ├── web_users.py       # comptes de l'interface web, locaux (scrypt) ou OIDC (création à la volée), sessions, admin initial
│   ├── oidc.py            # connexion OIDC OpenID Connect à l'interface web (contrôleur)
│   ├── rate_limit.py      # limites de débit de l'API REST et des connexions (fenêtre glissante en base)
│   └── enrollment_api.py  # endpoint public POST /api/v1/enroll du serveur MCP
├── observability/ # journal d'audit et métriques
│   ├── audit.py           # journal d'audit : événements des décisions de triage, propositions, jetons et enrôlements
│   ├── audit_syslog.py    # envoi des événements d'audit vers syslog par le contrôleur (facultatif)
│   └── metrics.py         # métriques Prometheus du contrôleur (/metrics)
├── clients/       # clients CLI qui contactent l'URL donnée par l'opérateur
│   ├── commands.py        # commandes `enroll` et `scan-deps` de security-review-mcp
│   ├── enrollment.py      # client de `enroll` : enrôlement d'un projet sur un serveur partagé
│   └── remote_scan.py     # client de `scan-deps` : scan des dépendances par un serveur partagé
├── ticketing/     # tickets des findings : api (API des connecteurs), registry, connections,
│                  # transport (client HTTP), core (envoi), jira, servicenow
└── web_api/       # contrôleur : API REST /api/v1 et fichiers de l'application (/ui)
    ├── __init__.py    # create_app, fichiers statiques de /ui, assemblage des routeurs
    ├── schemas.py     # modèles de requête et de réponse de chaque route
    ├── deps.py        # identité de l'appelant, permissions, portée projet
    └── *_routes.py    # un routeur par domaine (auth, account, report, ci, rule, token, admin, access)
tests/             # pytest (scanner, services, client MCP de bout en bout)
web/               # application Angular (compilée dans src/security_review_mcp/webui/)
```

Le serveur MCP n'importe jamais les modules du contrôleur qui ouvrent des connexions sortantes
ou servent ses routes (`controller`, `deps/advisory_sync`, `auth/oidc`,
`observability/audit_syslog`, `ticketing`, `update_check`, `web_api`), même indirectement :
`tests/test_server.py` le vérifie. Un module partagé par les deux processus (comme
`app_settings`) les importe dans la fonction qui en a besoin, jamais en tête.

## Interface web

L'application Angular 22 (signaux, zoneless, Bootstrap 5) est dans `web/`. Sa build est écrite
dans `src/security_review_mcp/webui/`, d'où le contrôleur la sert sur `/ui/` et le wheel l'embarque.

```bash
cd web
npm ci
npm run build                 # build de production (à refaire avant uv build)
npm start                     # serveur de dev sur http://localhost:4200/ui/
npm run format                # Prettier
```

`npm start` redirige `/api` vers `http://127.0.0.1:8080` (`web/proxy.conf.json`) : lancez le
contrôleur en parallèle avec `security-review-controller serve --port 8080`, ou utilisez la
configuration VS Code **Web UI + API (Angular dev server, port 4200)**, qui démarre les deux
(**Controller + web UI (Angular, port 4200)** si vous voulez aussi déboguer le Python) : chaque enregistrement d'un
fichier de `web/src/` recharge la page (styles et templates sans rechargement complet), et les
points d'arrêt posés dans les fichiers `.ts` sont pris en compte. Dans le devcontainer, Chrome
est ouvert sur le poste local et le port 4200 est redirigé automatiquement.

### Conventions de code

- **API REST** : toute route qui répond en JSON déclare son modèle de réponse
  (`web_api/schemas.py`) : FastAPI le documente dans OpenAPI et retire tout champ non déclaré.
  `test_openapi_documents_the_response_of_every_json_route` échoue sur une route qui renvoie un
  `dict` brut.
- **Composants** : template et styles dans des fichiers séparés. Une fonctionnalité à plusieurs
  écrans a un dossier par composant (`features/access/role-list/`) ; ses fichiers partagés
  (styles, classe de base, messages d'erreur) restent à la racine de la fonctionnalité.
- **Formulaires** : les formulaires de saisie utilisent les Signal Forms (`form()`,
  `[formField]`, validateurs avec un message traduit) ; les filtres de liste et les listes
  dynamiques de cases à cocher restent de simples gestionnaires d'événements.
- **Appels HTTP** : par `rxResource` pour les données d'un écran, ou `await
  firstValueFrom(...)` pour une action ; pas de `.subscribe()` dans les composants.
- **État** : `signal()` et `computed()` ; une valeur dérivée d'une autre mais modifiable (un
  formulaire rempli avec les réglages chargés) est un `linkedSignal()`. `effect()` est réservé aux
  vrais effets de bord (attributs du document, stockage local, minuteries), jamais pour recopier
  un signal dans un autre. Un service expose ses signaux avec `asReadonly()` et les modifie par
  des méthodes nommées.
- **Dossiers** : `shared/` contient des composants réutilisables sans logique métier : ils
  reçoivent leurs données par des entrées et répondent par des sorties, jamais par un service
  métier de `core/` (la fiche d'un finding émet la décision, `TriageService` l'enregistre). La
  coquille de l'application est `layout/`.
- **Templates** : liaisons de l'hôte dans `host: {}` (pas de `@HostListener`) ; un message qui
  explique pourquoi un champ est invalide lui est relié par `aria-describedby`.
- **Tableaux** : `app-table-controls` porte la recherche et les filtres ; le tri se choisit sur les
  en-têtes de colonne (`<th [appSortHeader]="sort" sortKey="name">`), avec un `TableSort` nommé
  d'après le tableau (`shared/utils/table-sort.ts`) que le navigateur mémorise sous
  `secreview.sort.<nom>`.
- **Couleurs** : variables Bootstrap (`var(--bs-…)`) ou jetons de `styles.css` (`--app-…`),
  jamais une couleur écrite dans un composant, pour que les thèmes clair et sombre fonctionnent.

### Traductions de l'interface

L'interface est traduite en anglais, français et espagnol par un service maison
(`web/src/app/core/i18n/`), sans dépendance supplémentaire. Chaque écran a son catalogue dans
`core/i18n/messages/<écran>.ts`, déclaré dans `messages/index.ts`, avec ses messages dans les trois
langues :

```ts
export const tokens = defineMessages({
  en: { 'tokens.created': 'Token “{label}” created.' },
  fr: { 'tokens.created': 'Jeton « {label} » créé.' },
  es: { 'tokens.created': 'Token «{label}» creado.' },
});
```

- Dans un template : `{{ 'tokens.title' | t }}`, ou avec des paramètres
  `{{ 'tokens.created' | t: { label: name } }}`.
- Dans le code : `I18nService.translate(...)` (confirmations, messages des validateurs Signal
  Forms via `message: () => ...`). Un message affiché plus tard (succès, erreur) est gardé sous la
  forme `msg(clé, paramètres)` et traduit dans le template, pour suivre un changement de langue.
- Le titre des routes est une clé, traduite par `I18nTitleStrategy`.

Les clés sont typées : une clé inconnue, ou absente d'une des trois langues, fait échouer
`npm run build`.

## Migrations du schéma

Toute modification d'un modèle de table (`models.py`) s'accompagne d'une révision Alembic dans
`src/security_review_mcp/storage/migrations/versions/`. Le test
`test_upgrade_creates_the_schema_of_the_models` (`tests/test_database.py`) échoue tant que les
migrations ne produisent pas exactement le schéma des modèles. Pour générer un brouillon de
révision à relire :

```bash
uv run python - <<'PY'
from alembic import command
from security_review_mcp import database
with database.get_engine().begin() as connection:
    command.revision(
        database.alembic_config(connection), "describe the change", autogenerate=True, rev_id="0002"
    )
PY
```

Lancez-le avec `SECREVIEW_DATABASE_URL` pointant sur une base SQLite jetable déjà à jour
(`security-review-controller db upgrade`). Numérotez les révisions à la suite (`0002`, `0003`…),
relisez le fichier généré et ne modifiez jamais une révision déjà publiée.

## Documentation

La documentation est écrite en Markdown dans `docs/`, en **anglais et en français**, et
construite avec [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) et le plugin
[mkdocs-static-i18n](https://ultrabug.github.io/mkdocs-static-i18n/).

```bash
uv sync --extra docs
uv run mkdocs serve          # aperçu sur http://127.0.0.1:8000, rechargement à chaud
uv run mkdocs build --strict # ce que fait la CI : un lien cassé fait échouer le build
```

- Chaque page existe deux fois, côte à côte : `page.md` en anglais (langue par défaut, servie à
  la racine du site) et `page.fr.md` en français (servie sous `/fr/`). Modifiez les deux dans le
  même commit.
- Les liens entre pages visent le fichier anglais (`../reference/cli.md`) : depuis une page
  française, le plugin les fait pointer vers la page française. Les ancres suivent les titres de
  chaque langue (`#report-language` en anglais, `#langue-des-rapports` en français).
- Les pages suivent l'ordre d'une mise en œuvre : **Démarrage** (`getting-started/`) et
  **Utilisation** (`usage/`) ne contiennent que l'essentiel pour travailler ; **Avancé**
  (`advanced/`) regroupe les détails et les fonctions facultatives. Placez une explication
  détaillée dans `advanced/`, avec au plus une ligne et un lien depuis les pages essentielles.
- Pour ajouter une page, créez les deux fichiers dans `docs/`, déclarez le fichier anglais dans
  la section `nav` de `mkdocs.yml` et traduisez son titre dans `nav_translations` (langue `fr`
  du plugin `i18n`).

### Publication

Le workflow `.github/workflows/docs.yml` :

- sur une **pull request** qui touche `docs/` ou `mkdocs.yml` : construit le site en mode
  `--strict` (vérification seulement) ;
- sur un **push sur `master`** : construit le site et le publie sur GitHub Pages.

Activation unique dans le dépôt GitHub : **Settings → Pages → Build and deployment → Source :
GitHub Actions**.

## Branches

- **`dev`** : branche de développement, on y code par défaut.
- **`feat/<sujet>`** : seulement pour une grosse rupture (refonte, changement d'API ou de
  schéma), créée depuis `dev` et fusionnée dans `dev` par pull request.
- **`master`** : branche de production, alimentée uniquement par des fusions de `dev`.

## Publication d'une version

Une version correspond à un tag poussé sur `master` :

1. Sur `dev`, mettez à jour `version` dans `pyproject.toml` (par ex. `uv version 1.3.0`) et
   commitez.
2. Fusionnez `dev` dans `master`.
3. Sur `master`, poussez le tag correspondant : `git tag v1.3.0 && git push origin v1.3.0`.
4. Le push du tag déclenche `publish.yml` : lint et tests, vérification que le tag correspond à
   la version, publication sur PyPI et des images Docker (`docker.yml`), puis création de la
   release GitHub.

Le tag publie deux distributions PyPI à la même version : `security-review-mcp` et
`security-review-ci`, le client de pipeline seul (sans dépendance), dont le projet est écrit par
`scripts/build_ci_client.py` à partir de `ci_client.py`, avec le `requires-python` du serveur.
Le job **ci-client** de `tests.yml` le construit et lance le wheel seul, sans le serveur.

Le workflow `.github/workflows/docker.yml` construit l'image (`linux/amd64`, `linux/arm64`,
variantes par défaut et `-pg`) et vérifie que les deux points d'entrée démarrent. Sur chaque pull
request (la protection de `master` exige ces vérifications), il construit seulement ; sur un tag de
version, il pousse les images sur `ghcr.io/cyr-ius/security-review-mcp` et
`docker.io/cyrius44/security-review-mcp` (voir [images publiées](advanced/docker.md#images-publiees)).
Une exécution manuelle (**Actions → Docker image → Run workflow**, `push` coché) publie une
image de branche (`dev`, `dev-pg`).

Mise en place unique : un jeton d'accès Docker Hub (lecture et écriture) dans le secret du dépôt
`DOCKERHUB_TOKEN` ; GHCR utilise le jeton du workflow. Après la première publication, rendez le
paquet GHCR public (**Packages → security-review-mcp → Package settings**).

Chaque action des workflows est épinglée sur le SHA complet d'un commit, avec sa version en
commentaire (`uses: actions/checkout@<SHA de 40 caractères> # v7.0.1`) : un tag peut être
déplacé, pas un commit. Dependabot (`.github/dependabot.yml`) met à jour le SHA et le
commentaire ensemble. Épinglez de la même façon toute nouvelle action.
