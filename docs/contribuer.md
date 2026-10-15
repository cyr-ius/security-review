# Contribuer

## Environnement de développement

```bash
uv sync --extra dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
pre-commit install          # facultatif : mêmes contrôles avant chaque commit
```

Dans VS Code (`.vscode/`) :

| Configuration de `launch.json` | Rôle |
|---|---|
| **MCP server + controller** | Lance la tâche **Database upgrade**, puis les deux processus sur la même base |
| **MCP server (HTTP, port 8000)** | Serveur MCP seul ; la base doit déjà être migrée |
| **Controller (web UI and API, port 8080)** | Contrôleur seul ; migre la base et affiche le mot de passe du compte `admin` initial au premier démarrage |
| **Controller CLI (prompt for arguments)** | Une commande du contrôleur (`db status`, `token list --pending`…) sous le débogueur |
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
PostgreSQL. Les tests, eux, utilisent toujours une base SQLite en mémoire.

À sa création, le devcontainer installe le client `psql`, les hooks `prek` et l'environnement
complet (`uv sync --extra dev --extra docs --extra postgres`), puis migre la base. Il redirige les
ports 8000 (serveur MCP), 8080 (contrôleur), 4200 (serveur de dev Angular), 8001 (doc) et 5432
(PostgreSQL, identifiants de développement `secreview` / `secreview`).

```bash
psql -h db -U secreview secreview                     # mot de passe : secreview
SECREVIEW_DATABASE_URL=sqlite:///./dev.db security-review-mcp   # revenir ponctuellement à SQLite
``` Le démon Docker permet de construire et de lancer
l'image du [Dockerfile](demarrage/docker.md) sans quitter le conteneur :

```bash
docker build -t security-review-mcp .
docker run --rm -p 8080:8000 -v secreview-data:/data \
    --entrypoint security-review-controller security-review-mcp serve --host 0.0.0.0
docker run --rm -p 8000:8000 -v secreview-data:/data security-review-mcp \
    --transport streamable-http --host 0.0.0.0 --port 8000
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

Une contribution, humaine ou produite par un agent IA, n'est terminée que si elle comprend des
tests, que la documentation `docs/` est à jour et que le `README.md`, qui reste un résumé, l'est
aussi. Quand le serveur MCP `security-review` est opérationnel, les changements sont en outre
relus avec lui (le projet se relit lui-même) et le rapport est enregistré. Les règles détaillées
(conventions, invariants de sécurité, correspondance code → pages de doc) sont dans `AGENTS.md`
à la racine du dépôt ; `CLAUDE.md` et `.github/copilot-instructions.md` y renvoient.

## Structure du code

```
src/security_review_mcp/
├── server.py      # prompts, outils, ressources, point d'entrée du serveur MCP
├── controller.py  # point d'entrée du contrôleur (serve, db et commandes d'administration)
├── http_server.py # HTTP des deux processus : jetons Bearer et rôles, TLS, /healthz, uvicorn
├── oidc.py        # connexion SSO OpenID Connect à l'interface web (contrôleur)
├── role_mapping.py # role mapping OIDC : groupes du fournisseur → rôle web et projets
├── token_store.py # jetons Bearer en base : création, révocation, enrôlement
├── web_users.py   # comptes de l'interface web, locaux (scrypt) ou SSO (création à la volée), sessions, admin initial
├── enrollment.py  # client de `enroll` : demande de jeton à un serveur partagé
├── enrollment_api.py  # endpoint public POST /api/v1/enroll du serveur MCP
├── web_api.py     # contrôleur : API REST /api/v1 et fichiers de l'application (/ui)
├── prompts.py     # construction des prompts
├── standards.py   # normes de développement : stockage, recherche par technologie / fichier, rendu
├── default_rules.toml  # règles et checklists par défaut, copiées en base au premier lancement
├── checklists.py  # structure d'un item de checklist
├── scanner.py     # moteur de scan, suppression inline, masquage des secrets
├── rules_loader.py    # validation des règles, lecture des packs TOML et du fichier par défaut
├── rule_store.py  # règles en base : amorçage, import/export, activation, suppression
├── registry.py    # règles/checklists actives (lues en base), rechargement
├── cli.py         # commandes db, gate, sarif, trend, advisories, deps, code, rules, token, enroll
├── codescan.py    # scan du code complet (liste des fichiers, langage, findings)
├── sarif.py       # export SARIF 2.1.0
├── trends.py      # rapport de tendance
├── versions.py    # comparaison de versions
├── advisories.py  # import OSV, correspondance des versions
├── advisory_sync.py  # téléchargement OSV par le contrôleur (proxy, mise à jour quotidienne, historique)
├── app_settings.py    # réglages de l'écran Paramètres (langue des rapports, proxy OSV), en base
├── dependencies.py    # analyseurs de manifestes / lockfiles, hygiène
├── depscan.py     # scan de dépendances et conversion en findings
├── services.py    # logique de persistance des rapports
├── models.py      # modèles SQLModel (tables + schémas)
├── database.py    # moteur, sessions et migrations (Alembic)
├── migrations/    # environnement Alembic et révisions du schéma (versions/)
└── config.py      # paramètres (SECREVIEW_*)
tests/             # pytest (scanner, services, client MCP de bout en bout)
web/               # application Angular (compilée dans src/security_review_mcp/webui/)
```

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

## Migrations du schéma

Toute modification d'un modèle de table (`models.py`) s'accompagne d'une révision Alembic dans
`src/security_review_mcp/migrations/versions/`. Le test
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

La documentation est écrite en Markdown dans `docs/` et construite avec
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/).

```bash
uv sync --extra docs
uv run mkdocs serve          # aperçu sur http://127.0.0.1:8000, rechargement à chaud
uv run mkdocs build --strict # ce que fait la CI : un lien cassé fait échouer le build
```

Pour ajouter une page, créez le fichier dans `docs/` et déclarez-le dans la section `nav` de
`mkdocs.yml`.

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
   la version, publication sur PyPI puis création de la release GitHub.
