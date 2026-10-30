# Contribuer

## Environnement de développement

Il faut Python 3.14, [uv](https://docs.astral.sh/uv/) et Node.js 24 (le
[devcontainer](#devcontainer) les fournit et installe les dépendances à sa création) :

```bash
git clone https://github.com/cyr-ius/security-review.git
cd security-review
uv sync --extra dev --extra docs
npm --prefix web ci                                   # Angular, Prettier (Node.js 24)
npm --prefix web run build                            # interface servie par le serveur Controller sur /ui/
uv run security-review-controller db upgrade
```

Sans la build Angular, le serveur Controller ne sert que l'API REST (`/api/v1`). `prek install`
(facultatif), linters, formateurs et revues de sécurité : voir
[Vérifications, revues et publication](checks-and-releases.md).

Dans VS Code (`.vscode/`) :

| Configuration de `launch.json` | Rôle |
|---|---|
| **Controller (debug: FastAPI + Angular)** | Serveur Controller sur le port 8080 et `ng serve` sur le port 4200 sous le débogueur, puis Chrome sur `http://localhost:4200/ui/` avec les points d'arrêt TypeScript ; rechargement à chaud de la page, redémarrage du serveur Controller à chaque enregistrement dans `src/` (`scripts/dev_reload.py`), migre la base et affiche le mot de passe du compte `admin` initial au premier démarrage. Pour rester connecté entre les redémarrages, définissez `SECREVIEW_SECRET_KEY` dans votre `.env` (ignoré par git), par exemple avec la sortie de `openssl rand -hex 32` |
| **MCP server (debug, port 8000)** | Lance la tâche **Database upgrade**, puis le serveur MCP HTTP sous le débogueur |
| **Controller CLI (prompt for arguments)** | Une commande du serveur Controller (`db status`, `token list`…) sous le débogueur |
| **Docs: MkDocs (port 8001)** | `mkdocs serve` avec rechargement à chaud, ouvre le site dans le navigateur |

| Tâche de `tasks.json` | Commande |
|---|---|
| **Build security_review_mcp** | `uv sync --extra dev --extra docs --extra postgres` |
| **Database upgrade** | `uv run security-review-controller db upgrade` (après **Build**) |
| **Tests** / **Lint** | `pytest`, puis ruff et `mkdocs build --strict` |
| **Web UI: build** / **Web UI: dev server (port 4200)** | Build Angular servie par le serveur Controller, ou `ng serve` avec `/api` redirigé vers le port 8080 (arrêté avec le débogueur par **Web UI: stop dev server**) |
| **Docker: compose up** / **down** | Pile `docker-compose.yml` de l'image, avec sa propre base PostgreSQL (mêmes ports 8000 et 8080 : arrêtez les configurations de debug avant) |

### Devcontainer

Le dépôt fournit un devcontainer (`.devcontainer/`) avec Python, uv, Node.js, un démon Docker
dédié (feature *docker-in-docker*) et une base **PostgreSQL 18**. `compose.yaml` décrit deux
services : `app`, le conteneur de développement, et `db`, la base, joignable depuis `app` sous
le nom `db` et conservée dans le volume `secreview-dev-pg` entre deux reconstructions.
`SECREVIEW_DATABASE_URL` y pointe par défaut : le serveur MCP, le serveur Controller et la CLI utilisent
PostgreSQL. Les tests, eux, utilisent toujours une base SQLite en mémoire et ignorent votre
fichier `.env` et les variables `SECREVIEW_*` du shell.

À sa création, le devcontainer installe le client `psql`, les hooks `prek` et l'environnement
complet (`uv sync --extra dev --extra docs --extra postgres`, `npm --prefix web ci`), puis migre la base. Il redirige les
ports 8000 (serveur MCP), 8080 (serveur Controller), 4200 (serveur de dev Angular), 8001 (doc) et 5432
(PostgreSQL, identifiants de développement `secreview` / `secreview`).

```bash
psql -h db -U secreview secreview                     # mot de passe : secreview
SECREVIEW_DATABASE_URL=sqlite:///./dev.db security-review-mcp serve   # revenir ponctuellement à SQLite
```

Le démon Docker permet de construire et de lancer l'image du
[Dockerfile](../advanced/deployment/docker.md) sans quitter le conteneur.

## Construire l'image

```bash
docker build -t security-review-mcp .   # SQLite et PostgreSQL (pilote inclus)
```

Le build compile aussi l'[interface web](../usage/index.md) (étape Node.js) ;
elle est servie sur `/ui/` par le serveur Controller.

L'image tourne sous un utilisateur non root (uid `10001`), sans sources ni outils de build. Son
`HEALTHCHECK` (`python -m security_review_mcp.healthcheck`, toutes les 30 secondes) interroge
`/healthz` du serveur MCP HTTP ou du serveur Controller sur l'interface de bouclage, en HTTPS quand le
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
├── controller.py  # point d'entrée du serveur Controller (serve, db et commandes d'administration)
├── ci_client.py   # `security-review-ci` : client de pipeline du serveur Controller, liste des fichiers (bibliothèque standard uniquement)
├── cli.py         # commandes du serveur Controller : db, advisories, rules, token, user, role, project, audit
├── http_server.py # HTTP des deux processus : jetons Bearer et rôles, TLS, /healthz, uvicorn
├── healthcheck.py # HEALTHCHECK de l'image Docker (/healthz des processus HTTP)
├── config.py      # paramètres (SECREVIEW_*)
├── app_settings.py # réglages modifiables dans l'interface (langue, proxy sortant, OIDC), en base
├── proxy.py       # proxy sortant du serveur Controller (OSV, OIDC) : URL, no_proxy, handler urllib
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
│   ├── advisory_sync.py   # téléchargement OSV par le serveur Controller (proxy, mise à jour quotidienne, historique)
│   └── versions.py        # comparaison de versions
├── auth/          # identité et accès
│   ├── access_control.py  # permissions, rôles des comptes web, correspondances OIDC, demandes de projet
│   ├── token_store.py     # jetons Bearer en base : création, expiration, renouvellement, révocation
│   ├── web_users.py       # comptes de l'interface web, locaux (scrypt) ou OIDC (création à la volée), sessions, admin initial
│   ├── oidc.py            # connexion OIDC OpenID Connect à l'interface web (serveur Controller)
│   └── rate_limit.py      # limites de débit de l'API REST et des connexions (fenêtre glissante en base)
├── observability/ # journal d'audit et métriques
│   ├── audit.py           # journal d'audit : événements des décisions de triage, propositions, jetons et demandes de projet
│   ├── audit_syslog.py    # envoi des événements d'audit vers syslog par le serveur Controller (facultatif)
│   └── metrics.py         # métriques Prometheus du serveur Controller (/metrics)
├── clients/       # clients du serveur Controller
│   └── ci_wheel.py        # wheel de security-review-ci construite et servie par le serveur Controller (/api/ci-client/)
├── connectors/    # findings envoyés vers des systèmes externes : api (API des connecteurs),
│                  # registry, connections, transport (client HTTP), core (envoi), jira, servicenow
└── web_api/       # serveur Controller : API REST /api/v1 et fichiers de l'application (/ui)
    ├── __init__.py    # create_app, fichiers statiques de /ui, assemblage des routeurs
    ├── schemas.py     # modèles de requête et de réponse de chaque route
    ├── deps.py        # identité de l'appelant, permissions, portée projet
    └── *_routes.py    # un routeur par domaine (auth, account, report, ci, rule, token, admin, access)
tests/             # pytest (scanner, services, client MCP de bout en bout)
web/               # application Angular (compilée dans src/security_review_mcp/webui/)
```

Le serveur MCP n'importe jamais les modules du serveur Controller qui ouvrent des connexions sortantes
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
| [Serveur Controller (FastAPI)](controller.md) | `web_api/`, `cli.py`, `storage/` | Routes REST et leurs schémas, permissions, paramètres, CLI, migrations du schéma |
| [Interface web (Angular)](web-ui.md) | `web/` | Build et serveur de développement, conventions de code, traductions |
| [Écrire un connecteur](connectors.md) | `connectors/api.py`, `examples/connector/` | Connecteur tiers : classe `Connector`, point d'entrée, garanties du serveur Controller |
| [Documentation](documentation.md) | `docs/`, `mkdocs.yml`, `README.md` | Rédaction et construction de la documentation bilingue, README, publication |
| [Tests](tests.md) | `tests/`, `tests/conftest.py` | Quoi tester, conventions, fixtures, tests par type de code |
| [Vérifications, revues et publication](checks-and-releases.md) | `.pre-commit-config.yaml`, `.github/workflows/` | Linters, formateurs, tests, revue de sécurité, branches, versions |

Les normes génériques de chaque technologie (Python et FastAPI, Angular, tests) sont servies par
le projet lui-même : prompt `development-standards`, outil `get_development_standards` (voir
[normes de développement](../review/standards.md)). Ces pages ne gardent que ce qui est propre à
ce dépôt ; en cas de conflit, elles prévalent.
