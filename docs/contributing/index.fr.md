# Contribuer

## Environnement de développement

Il faut Python 3.14, [uv](https://docs.astral.sh/uv/) et Node.js 24 (le
[devcontainer](#devcontainer) les fournit et installe les dépendances à sa création) :

```bash
git clone https://github.com/cyr-ius/security-review-mcp.git
cd security-review-mcp
uv sync --extra dev --extra docs
npm --prefix web ci                                   # Angular, Prettier (Node.js 24)
npm --prefix web run build                            # interface servie par le contrôleur sur /ui/
uv run security-review-controller db upgrade
```

Sans la build Angular, le contrôleur ne sert que l'API REST (`/api/v1`). `prek install`
(facultatif), linters, formateurs et revues de sécurité : voir
[Vérifications, revues et publication](checks-and-releases.md).

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
dédié (feature *docker-in-docker*) et une base **PostgreSQL 18**. `compose.yaml` décrit deux
services : `app`, le conteneur de développement, et `db`, la base, joignable depuis `app` sous
le nom `db` et conservée dans le volume `secreview-dev-pg` entre deux reconstructions.
`SECREVIEW_DATABASE_URL` y pointe par défaut : le serveur MCP, le contrôleur et la CLI utilisent
PostgreSQL. Les tests, eux, utilisent toujours une base SQLite en mémoire et ignorent votre
fichier `.env` et les variables `SECREVIEW_*` du shell.

À sa création, le devcontainer installe le client `psql`, les hooks `prek` et l'environnement
complet (`uv sync --extra dev --extra docs --extra postgres`, `npm --prefix web ci`), puis migre la base. Il redirige les
ports 8000 (serveur MCP), 8080 (contrôleur), 4200 (serveur de dev Angular), 8001 (doc) et 5432
(PostgreSQL, identifiants de développement `secreview` / `secreview`).

```bash
psql -h db -U secreview secreview                     # mot de passe : secreview
SECREVIEW_DATABASE_URL=sqlite:///./dev.db security-review-mcp serve   # revenir ponctuellement à SQLite
```

Le démon Docker permet de construire et de lancer l'image du
[Dockerfile](../advanced/docker.md) sans quitter le conteneur.

## Construire l'image

```bash
docker build -t security-review-mcp .   # SQLite et PostgreSQL (pilote inclus)
```

Le build compile aussi l'[interface web](../usage/web-interface.md) (étape Node.js) ;
elle est servie sur `/ui/` par le contrôleur.

L'image tourne sous un utilisateur non root (uid `10001`), sans sources ni outils de build. Son
`HEALTHCHECK` (`python -m security_review_mcp.healthcheck`, toutes les 30 secondes) interroge
`/healthz` du serveur MCP HTTP ou du contrôleur sur l'interface de bouclage, en HTTPS quand le
TLS est activé (en ne faisant confiance qu'au certificat du conteneur) ; en stdio, rien n'écoute
et le conteneur reste sain, et avec le TLS mutuel (`SECREVIEW_TLS_CLIENT_CA`) il n'interroge
rien : appuyez-vous sur les sondes de l'orchestrateur. La
base SQLite est dans le volume `/var/lib/secreview`. Le fichier `.env` n'est **pas** copié dans l'image :
passez la configuration avec `-e` ou `--env-file`.

## Définition de « terminé »

Une contribution, humaine ou produite par un agent IA, n'est terminée que si le comportement
qu'elle ajoute ou corrige est vérifié par un test pertinent, nouveau ou existant, que la documentation `docs/` est à jour dans les deux langues et que les `README.md`, qui
restent des résumés, le sont aussi. Quand le serveur MCP `security-review` est opérationnel, les changements sont en outre
relus avec lui (le projet se relit lui-même) et le rapport est enregistré. Les règles détaillées
(conventions, invariants de sécurité, correspondance code → pages de doc) sont dans `AGENTS.md`
à la racine du dépôt ; `CLAUDE.md` et `.github/copilot-instructions.md` y renvoient.

La méthode de test est dans [Tests](tests.md) ; les vérifications à lancer et la procédure de
revue sont dans [Vérifications, revues et publication](checks-and-releases.md).

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
│   ├── commands.py        # commande `enroll` de security-review-mcp
│   └── enrollment.py      # client de `enroll` : enrôlement d'un projet sur un serveur en mode partagé
├── connectors/    # findings envoyés vers des systèmes externes : api (API des connecteurs),
│                  # registry, connections, transport (client HTTP), core (envoi), jira, servicenow
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
`observability/audit_syslog`, `connectors`, `update_check`, `web_api`), même indirectement :
`tests/test_server.py` le vérifie. Un module partagé par les deux processus (comme
`app_settings`) les importe dans la fonction qui en a besoin, jamais en tête.

## Développement par composant

Chaque partie du projet a sa page, avec ses conventions, ses invariants et la façon de la
tester :

| Page | Code | Contenu |
|---|---|---|
| [Serveur MCP](mcp-server.md) | `server.py`, `prompts.py`, `rules/` | Outils, prompts et ressources, règles de scan, invariants de sécurité du processus MCP |
| [Contrôleur (FastAPI)](controller.md) | `web_api/`, `cli.py`, `storage/` | Routes REST et leurs schémas, permissions, paramètres, CLI, migrations du schéma |
| [Interface web (Angular)](web-ui.md) | `web/` | Build et serveur de développement, conventions de code, traductions |
| [Documentation](documentation.md) | `docs/`, `mkdocs.yml`, `README.md` | Rédaction et construction de la documentation bilingue, README, publication |
| [Tests](tests.md) | `tests/`, `tests/conftest.py` | Quoi tester, conventions, fixtures, tests par type de code |
| [Vérifications, revues et publication](checks-and-releases.md) | `.pre-commit-config.yaml`, `.github/workflows/` | Linters, formateurs, tests, revue de sécurité, branches, versions |

Les normes génériques de chaque technologie (Python et FastAPI, Angular, tests) sont servies par
le projet lui-même : prompt `development-standards`, outil `get_development_standards` (voir
[normes de développement](../usage/standards.md)). Ces pages ne gardent que ce qui est propre à
ce dépôt ; en cas de conflit, elles prévalent.
