# Instructions pour GitHub Copilot

Suivez les consignes de [`AGENTS.md`](../AGENTS.md) à la racine du dépôt : c'est la référence
unique pour tous les agents. En résumé, un changement n'est terminé que si :

- le comportement ajouté ou corrigé est vérifié par un **test pertinent**, existant ou nouveau
  (contrat ou invariant, pas une ligne de code ; étendre un test existant plutôt qu'en créer un,
  1 à 3 tests par changement, voir `AGENTS.md`) ;
- `uv run pytest`, `uv run ruff check .` et `uv run ruff format --check .` passent ;
- la **documentation** `docs/` (français) est à jour et `uv run mkdocs build --strict` passe ;
- le **README** est à jour mais reste **synthétique** : une ligne par capacité et un lien vers
  la doc, jamais de détail qui n'existe pas déjà dans `docs/` ;
- les invariants de sécurité sont respectés (rien sur stdout côté serveur, pas de lecture disque
  depuis un outil MCP, entrées bornées, secrets masqués, SQL via l'ORM, aucun appel réseau) ;
- si le serveur MCP `security-review` est opérationnel, une **revue de sécurité** des
  changements a été faite avec lui et enregistrée (`save_security_report`), findings
  `critical` / `high` corrigés.

Branches : on code sur `dev` (branche `feat/<sujet>` depuis `dev` seulement pour une grosse
rupture) ; `master` est la production. Une version se publie en fusionnant la PR de Release
Please, qui crée le tag `vX.Y.Z` sur `master` : ne le faites jamais sans demande explicite.

Code, docstrings et commentaires en anglais ; documentation utilisateur en français.
