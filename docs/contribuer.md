# Contribuer

## Environnement de développement

```bash
uv sync --extra dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
pre-commit install          # facultatif : mêmes contrôles avant chaque commit
```

## Structure du code

```
src/security_review_mcp/
├── server.py      # prompts, outils, ressources, point d'entrée
├── http_server.py # transport HTTP : jetons Bearer, TLS, lancement d'uvicorn
├── prompts.py     # construction des prompts
├── checklists.py  # checklists intégrées par domaine
├── scanner.py     # règles de scan, suppression inline, masquage des secrets
├── rules_platform.py  # règles GitLab CI, Jenkins, Spring, FastAPI
├── rules_loader.py    # chargement et validation des packs TOML internes
├── registry.py    # règles/checklists actives (intégrées + internes), rechargement
├── cli.py         # commandes gate, sarif, trend, advisories, deps, code, token
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
```

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

## Publication d'une version

1. Mettez à jour `version` dans `pyproject.toml` (par ex. `uv version 1.3.0`).
2. Poussez un tag correspondant : `git tag v1.3.0 && git push origin v1.3.0`.
3. Le workflow `publish.yml` lance lint et tests, vérifie que le tag correspond à la version,
   publie sur PyPI puis crée la release GitHub.
