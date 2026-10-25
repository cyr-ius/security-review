# Vérifications, revues et publication

Ce qui tourne avant qu'un changement soit fusionné, et comment une version est publiée. La CI
relance toutes les vérifications (`lint.yml`, `tests.yml`, `docs.yml`, `docker.yml`).

## Linters et formateurs

```bash
uv run ruff check --fix . && uv run ruff format .           # Python
npm --prefix web exec --no -- prettier --check <files>      # web/src/, YAML et JSON
prek install          # facultatif : mêmes contrôles avant chaque commit, et le scan des
                      # dépendances si SECREVIEW_CONTROLLER_URL est défini
```

Le hook `prettier` formate les fichiers YAML et JSON et les sources de `web/src/` avec la
version de Prettier verrouillée par `web/package-lock.json` (celle de la CI) : lancez `npm ci`
dans `web/` avant le premier commit. La CI vérifie les mêmes fichiers (`lint.yml`, job **web**).
`.prettierrc` fixe la largeur à 100 colonnes, comme ruff ; les fichiers de verrouillage sont
listés dans `.prettierignore`.

### Vérifications selon les fichiers modifiés

Lancez uniquement les vérifications des zones touchées par le changement (`git diff --stat`) ;
la CI les relance toutes de toute façon.

| Fichiers modifiés | Vérifications |
|---|---|
| Python (`src/**/*.py`, `tests/`, migrations), `default_rules.toml`, `pyproject.toml`, `uv.lock` | `uv run ruff check . && uv run ruff format --check .`, puis `uv run pytest` |
| Angular (`web/`) | `npm --prefix web run build` et Prettier sur les fichiers modifiés ; plus `uv run pytest tests/test_audit.py` si le catalogue `web/src/app/core/i18n/messages/audit.ts` change |
| Documentation (`docs/`, `mkdocs.yml`) | `uv run mkdocs build --strict` |
| Workflows, `docker-compose.yml`, YAML / JSON | Prettier sur les fichiers modifiés |

En CI, `lint.yml` lance ruff (job **ruff**) et, dans le job **web**, Prettier et la build
Angular ; `tests.yml` lance pytest sur Python 3.14 et 3.15 avec `uv sync --locked` (lancez
`uv lock` après un changement de dépendances), et construit le client `security-review-ci` seul
(job **ci-client**).

## Tests

La méthode, les conventions et les fixtures sont dans [Tests](tests.md).

## Revue de sécurité

Le projet se relit avec son propre serveur MCP. Quand le serveur `security-review` est
connecté, chaque changement est relu avant d'être déclaré terminé ou d'ouvrir une pull request :
prompt `security-review` (ou `api-security-review`, `configuration-review`,
`dependency-review` selon les fichiers), aidé de `scan_code` et `get_review_checklist`, puis un
rapport enregistré avec `save_security_report` (projet `security-review-mcp`). Les findings
`critical` et `high` sont corrigés, avec un test ; les autres sont corrigés ou justifiés par
`propose_finding_status`, qu'une personne valide dans l'interface web. La procédure complète
est dans `AGENTS.md`.

Quand `SECREVIEW_CONTROLLER_URL` et un jeton `ci` personnel (`SECREVIEW_TOKEN`) sont définis, le
hook `scan-deps` analyse aussi les dépendances quand `uv.lock`, `pyproject.toml` ou
`web/package*.json` changent.

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

Le tag publie deux distributions PyPI à la même version : `security-review` et
`security-review-ci`, le client de pipeline seul (sans dépendance), dont le projet est écrit par
`scripts/build_ci_client.py` à partir de `ci_client.py`, avec le `requires-python` du serveur.
Le job **ci-client** de `tests.yml` le construit et lance le wheel seul, sans le serveur.

Le workflow `.github/workflows/docker.yml` construit l'image (`linux/amd64`, `linux/arm64`,
avec le pilote PostgreSQL) et vérifie que les deux points d'entrée démarrent. Sur chaque pull
request (la protection de `master` exige ces vérifications), il construit seulement ; sur un tag de
version, il pousse les images sur `ghcr.io/cyr-ius/security-review` et
`docker.io/cyrius44/security-review` (voir [images publiées](../advanced/docker.md#images-publiees)).
Une exécution manuelle (**Actions → Docker image → Run workflow**, `push` coché) publie une
image de branche (`dev`). Chaque tag est aussi publié avec le suffixe `-pg` (`X.Y.Z-pg`,
`latest-pg`, `dev-pg`) : alias déprécié de la même image, conservé pour l'ancienne variante
PostgreSQL jusqu'à la prochaine version majeure.

Mise en place unique : un jeton d'accès Docker Hub (lecture et écriture) dans le secret du dépôt
`DOCKERHUB_TOKEN` ; GHCR utilise le jeton du workflow. Après la première publication, rendez le
paquet GHCR public (**Packages → security-review → Package settings**).

Chaque action des workflows est épinglée sur le SHA complet d'un commit, avec sa version en
commentaire (`uses: actions/checkout@<SHA de 40 caractères> # v7.0.1`) : un tag peut être
déplacé, pas un commit. Dependabot (`.github/dependabot.yml`) met à jour le SHA et le
commentaire ensemble. Épinglez de la même façon toute nouvelle action.
