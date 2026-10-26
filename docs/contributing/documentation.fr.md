# Documentation

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
- Les pages suivent l'ordre d'une mise en œuvre : **Démarrage** (`getting-started/`),
  **Revue de sécurité** (fonctionnement, prompts et outils, règles, checklists, normes, gate) et **Application** (interface web, triage, jetons, comptes, rôles, groupes et permissions, connexion OIDC, journal d'audit) (toutes deux dans `usage/`) ne contiennent que l'essentiel pour travailler ; **Connecteurs**
  (`connectors/`, sous-menu d'**Application**) a une page par connecteur intégré ; **Avancé** (`advanced/`) regroupe les
  détails et les fonctions facultatives. Placez une explication
  détaillée dans `advanced/`, avec au plus une ligne et un lien depuis les pages essentielles.
- Pour ajouter une page, créez les deux fichiers dans `docs/`, déclarez le fichier anglais dans
  la section `nav` de `mkdocs.yml` et traduisez son titre dans `nav_translations` (langue `fr`
  du plugin `i18n`).
- Pour montrer un fichier de `examples/`, incluez-le plutôt que de le copier :
  `--8<-- "kubernetes/postgres.yaml"` (`pymdownx.snippets`, chemins relatifs à `examples/` ; un
  fichier absent fait échouer le build). Dans un lien vers un fichier du dépôt, écrivez
  `\{{ release_tag }}` au lieu de `master` : le hook `scripts/mkdocs_hooks.py` le remplace par le
  tag de la version de `pyproject.toml` (`v3.0.0`), pour que les commandes copiées récupèrent les
  fichiers de la version documentée.

## Règles de rédaction

- Les deux versions d'une page disent la même chose : pas de section qui n'existe que dans une
  langue. Les exemples (commandes, sorties, JSON) sont identiques ; seuls le texte et les
  commentaires sont traduits.
- L'interface web est traduite (anglais, français, espagnol) : chaque version cite les libellés
  de l'interface dans sa langue, tels qu'ils s'affichent (**Tokens** en anglais, **Jetons** en
  français).
- Les exemples sont copiables tels quels : options, noms de variables et sorties correspondent au
  code actuel.
- Un changement du code met à jour sa documentation dans le même commit. Le tableau « Si vous
  modifiez... » d'`AGENTS.md` donne les pages à mettre à jour pour chaque type de changement
  (outil MCP, règle de scan, option CLI, paramètre `SECREVIEW_*`, API REST…).

## README

`README.md` (anglais, affiché sur PyPI et GitHub) et `README.fr.md` (français) sont des vitrines
synthétiques, pas une seconde documentation. Ils ont le même contenu, traduit, et ne contiennent
qu'une courte description, les capacités principales (une ligne chacune), une installation
minimale, un exemple de configuration d'hôte et des liens vers la documentation.

- Tout ce qui figure dans le README figure aussi dans `docs/` ; l'inverse n'est pas vrai.
- Une capacité visible ajoutée (outil, prompt, commande, transport) reçoit **une ligne** dans le
  README, avec un lien vers sa page ; une capacité retirée ou renommée y est corrigée.
- Modifiez les deux fichiers ensemble. Les liens visent le site publié :
  `https://cyr-ius.github.io/security-review/...` depuis `README.md`,
  `https://cyr-ius.github.io/security-review/fr/...` (ancres françaises) depuis
  `README.fr.md`.

## Publication

Le workflow `.github/workflows/docs.yml` :

- sur une **pull request** qui touche `docs/`, `mkdocs.yml`, `examples/`, `pyproject.toml`
  (version des liens) ou le hook `scripts/mkdocs_hooks.py` : construit le site en mode
  `--strict` (vérification seulement) ;
- sur un **push sur `master`** : construit le site et le publie sur GitHub Pages.

Activation unique dans le dépôt GitHub : **Settings → Pages → Build and deployment → Source :
GitHub Actions**.
