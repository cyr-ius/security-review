# Contribuer

## Environnement de développement

```bash
uv sync --extra dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
pre-commit install          # facultatif : mêmes contrôles avant chaque commit
```

Dans VS Code, la configuration **MCP server (streamable-http)** de `launch.json` lance au
préalable la tâche **Build security_review_mcp**, qui synchronise l'environnement avec
`uv sync --extra dev --extra docs`.

### Devcontainer

Le dépôt fournit un devcontainer (`.devcontainer/`) avec Python, uv, Node.js et un démon Docker
dédié (feature *docker-in-docker*). À sa création, il installe les hooks `prek` et l'environnement
complet (`uv sync --extra dev --extra docs`). Le démon Docker permet de construire et de lancer
l'image du [Dockerfile](demarrage/docker.md) sans quitter le conteneur :

```bash
docker build -t security-review-mcp .
docker run --rm -p 8000:8000 -v secreview-data:/data security-review-mcp \
    --transport streamable-http --host 0.0.0.0 --port 8000
```

Le port 8000 est redirigé vers le poste : l'interface web est sur `http://localhost:8000/ui/`
et l'API REST sur `/api/v1`. Images et volumes sont conservés dans des volumes propres au
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
├── server.py      # prompts, outils, ressources, point d'entrée
├── http_server.py # transport HTTP : jetons Bearer et rôles, TLS, lancement d'uvicorn
├── token_store.py # jetons Bearer en base : création, révocation, enrôlement, admin initial
├── enrollment.py  # client de `enroll` : demande de jeton à un serveur partagé
├── web_api.py     # interface web : API REST /api/v1 et fichiers de l'application (/ui)
├── prompts.py     # construction des prompts
├── default_rules.toml  # règles et checklists par défaut, copiées en base au premier lancement
├── checklists.py  # structure d'un item de checklist
├── scanner.py     # moteur de scan, suppression inline, masquage des secrets
├── rules_loader.py    # validation des règles, lecture des packs TOML et du fichier par défaut
├── rule_store.py  # règles en base : amorçage, import/export, activation, suppression
├── registry.py    # règles/checklists actives (lues en base), rechargement
├── cli.py         # commandes gate, sarif, trend, advisories, deps, code, rules, token
├── codescan.py    # scan du code complet (liste des fichiers, langage, findings)
├── sarif.py       # export SARIF 2.1.0
├── trends.py      # rapport de tendance
├── versions.py    # comparaison de versions
├── advisories.py  # import OSV, correspondance des versions
├── dependencies.py    # analyseurs de manifestes / lockfiles, hygiène
├── depscan.py     # scan de dépendances et conversion en findings
├── services.py    # logique de persistance des rapports
├── models.py      # modèles SQLModel (tables + schémas)
├── database.py    # moteur et sessions
└── config.py      # paramètres (SECREVIEW_*)
tests/             # pytest (scanner, services, client MCP de bout en bout)
web/               # application Angular (compilée dans src/security_review_mcp/webui/)
```

## Interface web

L'application Angular 21 (signaux, zoneless, Bootstrap 5) est dans `web/`. Sa build est écrite
dans `src/security_review_mcp/webui/`, d'où le serveur la sert sur `/ui/` et le wheel l'embarque.

```bash
cd web
npm ci
npm run build                 # build de production (à refaire avant uv build)
npm start                     # serveur de dev sur http://localhost:4200/ui/
npm run format                # Prettier
```

`npm start` redirige `/api` vers `http://127.0.0.1:8000` (`web/proxy.conf.json`) : lancez le
serveur en parallèle avec `security-review-mcp --transport streamable-http`.

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
