## Description

<!-- Quoi et pourquoi. Lien vers l'issue le cas échéant (« Closes #123 »). -->

## Type de changement

<!-- Cochez ce qui s'applique. Il détermine la prochaine version (voir AGENTS.md). -->

- [ ] Correction (`fix:`, version `Z`)
- [ ] Fonctionnalité (`feat:`, version `Y`)
- [ ] Rupture de compatibilité (version `X`) : outil, prompt, option CLI, paramètre ou schéma
      retiré ou renommé
- [ ] Documentation, tests, CI ou outillage uniquement (`docs:`, `test:`, `ci:`, `chore:`)
- [ ] Release (`dev` → `master`)

## Compatibilité

<!-- Rupture : qu'est-ce qui change pour l'utilisateur, et comment migrer ?
     Identifiants de règles, paramètres SECREVIEW_*, schéma de base, codes de sortie CLI...
     Sinon, écrivez « Aucun impact ». -->

## Tests

<!-- Tests ajoutés ou modifiés, et vérifications faites à la main (CLI, interface web, Docker...). -->

## Revue de sécurité

<!-- Revue faite avec le serveur MCP `security-review` (voir AGENTS.md).
     Si le serveur n'était pas disponible, dites-le et collez le résultat de :
     uv run security-review-ci scan-code . --project security-review-mcp --exclude tests/ -->

- Rapport n° : …
- Prompt utilisé : `security-review` / `api-security-review` / `configuration-review` /
  `dependency-review` / `codebase-review`

| Finding | Sévérité | Suite donnée |
|---|---|---|
| | | `fixed` / `accepted` / `false_positive` (justification) |

## Checklist

- [ ] Tests ajoutés ou mis à jour (`uv run pytest` passe)
- [ ] `uv run ruff check .` et `uv run ruff format --check .` passent
- [ ] Documentation `docs/` mise à jour (`uv run mkdocs build --strict` passe)
- [ ] `README.md` mis à jour si une capacité visible change (rester synthétique, lien vers la doc)
- [ ] `.env.example` mis à jour si un paramètre `SECREVIEW_*` change
- [ ] `uv.lock` régénéré (`uv lock`) si les dépendances de `pyproject.toml` changent
- [ ] Invariants de sécurité de `AGENTS.md` respectés
- [ ] Findings `critical` / `high` de la revue de sécurité corrigés, avec un test

<!-- Si une case est volontairement non cochée, expliquez pourquoi. -->
