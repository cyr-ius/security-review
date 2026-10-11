# Consignes pour les agents IA

Ce fichier est la **référence unique** pour tout agent (Claude, Copilot, Codex, Cursor...)
qui modifie ce dépôt. `CLAUDE.md` et `.github/copilot-instructions.md` ne font qu'y renvoyer :
modifiez les règles ici, pas là-bas.

`security-review-mcp` est un serveur MCP de revue de code orientée sécurité : prompts,
checklists, scan par motifs, analyse de dépendances, rapports persistés (SQLModel), CLI pour la
CI/CD (gate, SARIF, tendances) et transport HTTP avec jetons Bearer / TLS.

## Une tâche n'est terminée que si

1. **Des tests couvrent le changement** (voir [Tests](#tests)) et `uv run pytest` passe.
2. `uv run ruff check . && uv run ruff format --check .` passe.
3. **La documentation `docs/` est à jour** et `uv run mkdocs build --strict` passe
   (voir [Documentation](#documentation)).
4. **Le `README.md` est à jour, en restant synthétique** (voir [README](#readme)).
5. `.env.example` est à jour si un paramètre `SECREVIEW_*` a été ajouté ou modifié.
6. **Une revue de sécurité des changements a été faite avec le serveur MCP `security-review`**
   s'il est opérationnel (voir [Revue de sécurité](#revue-de-sécurité)).

Si l'une de ces étapes est volontairement omise (ex. refactorisation interne sans effet visible
sur la doc), dites-le explicitement dans votre réponse ou dans la description de PR, avec la
raison. Ne déclarez jamais une tâche terminée sans avoir lancé les tests.

## Commandes

```bash
uv sync --extra dev --extra docs   # environnement complet
uv run pytest                      # tests (aucun accès réseau, base SQLite en mémoire)
uv run pytest tests/test_scanner.py -k python   # cibler un test
uv run ruff check --fix . && uv run ruff format .
uv run mkdocs build --strict       # ce que fait la CI : un lien cassé fait échouer le build
```

La CI (`.github/workflows/`) lance ruff et pytest sur Python 3.11, 3.12 et 3.13 avec
`uv sync --locked` : après un changement de dépendances dans `pyproject.toml`, lancez `uv lock`
et commitez `uv.lock`.

## Branches et versions

| Branche | Rôle |
|---|---|
| `dev` | Branche de développement : **on y code par défaut** |
| `feat/<sujet>` | Uniquement pour une **grosse rupture** (refonte, changement d'API ou de schéma, travail sur plusieurs jours), créée depuis `dev` et fusionnée dans `dev` par PR |
| `master` | Branche de production : ne reçoit que des fusions de `dev`, jamais de commit direct |

- Travaillez sur `dev`, sauf rupture importante. Dans ce cas, créez `feat/<sujet>` depuis `dev`.
  En cas de doute, demandez.
- Ne commitez jamais directement sur `master`.
- **Une version = un tag sur `master`.** Pousser un tag `vX.Y.Z` déclenche `publish.yml` :
  lint et tests, vérification que le tag correspond à `version` dans `pyproject.toml`, puis
  publication sur PyPI et création de la release GitHub. Procédure :
  1. sur `dev`, mettre à jour la version (`uv version X.Y.Z`) et commiter ;
  2. fusionner `dev` dans `master` ;
  3. sur `master` : `git tag vX.Y.Z && git push origin vX.Y.Z`.
- Versionnement sémantique : `X` pour une rupture de compatibilité (outil, prompt, option CLI
  ou paramètre retiré ou renommé), `Y` pour une fonctionnalité, `Z` pour une correction.
- **Un agent ne crée et ne pousse jamais un tag, et ne fusionne jamais dans `master`, sans
  demande explicite** : publier une version est irréversible (PyPI refuse de republier une
  version).

### Opérations GitHub

La CLI `gh` **n'est pas installée** dans l'environnement de développement : n'essayez pas de
l'utiliser.

- **git (push, fetch, pull)** : passez par **SSH**. Le remote `origin` est en HTTPS, sans
  identifiants : utilisez l'URL SSH, par ex.
  `git push git@github.com:cyr-ius/security-review-mcp.git dev`
  (ou `git remote set-url --push origin git@github.com:cyr-ius/security-review-mcp.git`).
- **API GitHub (pull requests, issues, revues, commentaires, releases)** : passez par le
  **connecteur GitHub MCP**.
- Si SSH est indisponible, le connecteur peut aussi pousser des fichiers (`push_files`). Il crée
  alors un autre commit : vérifiez avec `git fetch` puis `git diff HEAD origin/<branche>` que le
  contenu est identique, puis réalignez la branche locale sur `origin/<branche>`.
- Si git n'a pas d'identité configurée, reprenez celle des commits précédents pour ce commit
  seulement (`git -c user.name=... -c user.email=... commit`), sans modifier la configuration.

## Carte du code

| Zone | Fichiers |
|---|---|
| Prompts, outils, ressources MCP, point d'entrée | `server.py`, `prompts.py` |
| Règles de scan, masquage des secrets | `scanner.py`, `rules_platform.py` |
| Règles internes TOML, registre actif | `rules_loader.py`, `registry.py`, `checklists.py` |
| CLI (`gate`, `sarif`, `trend`, `advisories`, `deps`, `code`, `token`) | `cli.py`, `codescan.py` |
| Dépendances et avis OSV | `dependencies.py`, `depscan.py`, `advisories.py`, `versions.py` |
| Persistance | `models.py`, `services.py`, `database.py` |
| Export et tendances | `sarif.py`, `trends.py` |
| Transport HTTP, auth (jetons et rôles), TLS | `http_server.py` |
| Interface web : API REST `/api/v1` et fichiers de `/ui` | `web_api.py` ; application Angular dans `web/` |
| Paramètres `SECREVIEW_*` | `config.py` |

Tous les modules sont dans `src/security_review_mcp/`. L'application Angular (`web/`) est
compilée par `npm run build` dans `src/security_review_mcp/webui/` (ignoré par git). La logique métier va dans les modules
(`services.py`, `scanner.py`...) ; `server.py` et `cli.py` restent des couches minces qui
valident les entrées et appellent ces modules.

## Conventions de code

- Python ≥ 3.11, annotations de type partout, ruff (longueur 100, règles `E F W I B C4 UP`).
- **Code, docstrings, commentaires, messages d'erreur et logs en anglais.** Chaque module et
  chaque fonction a une docstring. La documentation utilisateur (`docs/`, README) est en
  **français**.
- Imitez le code voisin : mêmes noms, même densité de commentaires, pas de nouvelle dépendance
  sans nécessité (le serveur doit rester installable hors ligne).
- Messages de commit : Conventional Commits en anglais (`feat:`, `fix:`, `docs:`, `test:`,
  `chore:`, `ci:`).

### Outils et prompts MCP

- Chaque outil porte `annotations=READ_ONLY` ou `WRITE` et le décorateur `@_tool_errors`, qui
  transforme `ValueError` / `services.NotFoundError` en `ToolError` visible par le modèle.
  Levez ces exceptions pour les erreurs attendues ; ne renvoyez pas de dictionnaire d'erreur.
- Décrivez les paramètres avec `Annotated[..., Field(description=...)]` : c'est ce que lit le
  modèle hôte.
- Un nouvel outil ou prompt doit être cité dans `INSTRUCTIONS` (`server.py`) s'il change le
  déroulé d'une revue.
- Les prompts de revue se terminent par l'appel unique à `save_security_report` ; le contenu
  fourni par l'utilisateur est encadré avec `prompts.fenced`.

### Invariants de sécurité (ne jamais régresser)

C'est un outil de sécurité : un écart ici est un bug bloquant.

- **stdout est réservé au protocole MCP** en stdio : aucun `print` dans le serveur, journaux sur
  stderr via `logging.getLogger("security_review_mcp")`. Seule la CLI écrit sur stdout.
- **Les outils MCP ne lisent jamais le disque** à partir d'un chemin fourni par le client : ils
  travaillent sur le contenu transmis. L'accès fichiers est réservé à la CLI (opérateur), qui ne
  suit pas les liens symboliques.
- **Toute entrée est bornée** par un paramètre de `Settings` (`max_content_chars`,
  `max_findings_per_report`, `max_list_limit`...). Un nouvel outil qui accepte du texte ou une
  liste doit appliquer une limite.
- **Les secrets sont masqués** (`scanner.redact_secrets`) avant stockage et dans les extraits
  renvoyés. Ne journalisez jamais un jeton, un mot de passe ou une URL de base avec identifiants.
- **SQL uniquement via l'ORM** (SQLModel, paramètres liés), jamais de SQL construit par chaîne.
- **Aucun appel réseau sortant** : la base de vulnérabilités est importée hors ligne par la CLI.
- Les regex de règles doivent éviter le backtracking catastrophique (pas de quantificateurs
  imbriqués) ; `rules_loader` les valide pour les packs internes.
- Jetons Bearer : seules les empreintes SHA-256 sont conservées, comparaison en temps constant.

### Paramètres

Un nouveau paramètre s'ajoute dans `config.Settings` (préfixe `SECREVIEW_` automatique), avec
un commentaire, puis dans `.env.example` et `docs/reference/configuration.md`. Lisez-le via
`get_settings()`, jamais avec `os.environ`.

### Règles de scan

Identifiants `PRÉFIXE-NNN` par famille : `PY`, `JV`, `NG` (Angular), `CFG`, `GEN`, `GL`
(GitLab CI), `JK` (Jenkins), `CI`, `SP` (Spring), `FA` (FastAPI), `DEP` (hygiène des
dépendances). Ne réutilisez et ne renumérotez jamais un identifiant existant : les utilisateurs
les citent dans `secreview:ignore` et `disabled_rules`. Indiquez la CWE quand elle existe.

### CLI

Codes de sortie identiques partout : `0` succès, `1` bloqué (gate / findings au-dessus du
seuil), `2` erreur d'usage ou de données (`_fail` écrit l'erreur en JSON sur stderr).

## Tests

**Tout changement de comportement s'accompagne de tests dans le même commit.** Une
fonctionnalité sans test n'est pas terminée ; une correction de bug commence par un test qui
échoue et reproduit le bug.

- Un fichier par module : `tests/test_<module>.py`. Ajoutez au fichier existant plutôt que d'en
  créer un nouveau.
- `tests/conftest.py` fournit automatiquement une base SQLite en mémoire et un registre de
  règles vide par test : n'utilisez pas la base réelle ni `SECREVIEW_RULES_DIR` de la machine.
  Utilisez la fixture `rules_dir` pour tester des packs TOML, `tmp_path` pour les fichiers.
- Outils, prompts et ressources MCP : test de bout en bout avec `mcp.client.Client(mcp)` (voir
  `tests/test_server.py`, `pytestmark = pytest.mark.anyio`), y compris le cas d'erreur
  (`ToolError` attendu).
- Règle de scan : au moins un cas **positif** (le motif vulnérable est détecté) et un cas
  **négatif** (le code sûr équivalent ne l'est pas), pour limiter les faux positifs.
- CLI : appelez `server.main([...])` ou les fonctions de `cli.py`, vérifiez le **code de sortie**
  et la sortie (`capsys`).
- Sécurité : testez explicitement les invariants touchés (secret masqué, limite dépassée
  refusée, 401 sans jeton...).
- Pas de réseau, pas de `sleep`, pas de dépendance à l'ordre des tests. Les clés et jetons de
  test sont factices.

## Revue de sécurité

Ce projet utilise son propre serveur MCP pour se relire. **Si le serveur MCP `security-review`
est connecté et répond** (ses prompts et outils apparaissent dans votre session), une revue de
sécurité des changements est **systématique** avant de déclarer une tâche terminée ou d'ouvrir
une PR, quelle que soit la taille du changement :

1. Lancez le prompt `security-review` (ou `api-security-review` pour l'API REST,
   `configuration-review` pour Dockerfile / workflows / YAML, `dependency-review` si
   `pyproject.toml`, `uv.lock` ou `package.json` changent) sur les fichiers modifiés, avec le
   diff comme contexte. Pour un changement très étendu, utilisez `codebase-review`.
2. Appuyez-vous sur `scan_code` et `get_review_checklist` pendant la revue.
3. Enregistrez le résultat **une seule fois** avec `save_security_report` (`project` :
   `security-review-mcp`, plus `branch` et `commit_sha` quand ils sont connus).
4. Corrigez les findings `critical` et `high` avant de terminer, avec un test qui couvre la
   correction. Pour les autres, corrigez-les ou justifiez-les, et mettez leur statut à jour avec
   `update_finding_status` (`fixed`, `accepted`, `false_positive`).
5. Résumez la revue (identifiant du rapport, findings et suite donnée) dans votre réponse et dans
   la description de PR.

Si le serveur n'est pas connecté ou ne répond pas, dites-le explicitement : ne prétendez pas
avoir fait la revue. Lancez au minimum le scan en CLI sur le dépôt
(`uv run security-review-mcp code scan . --exclude tests/`) et signalez ses résultats.

## Documentation

`docs/` (MkDocs Material, en français) est la **source de vérité complète** pour les
utilisateurs. Mettez-la à jour dans le même changement que le code :

| Si vous modifiez... | Mettez à jour |
|---|---|
| Un prompt ou un outil MCP (nom, argument, comportement) | `docs/utilisation/prompts-outils.md` |
| Une règle de scan ou une checklist intégrée | `docs/utilisation/regles.md` (et `code-scan.md` si le scan du dépôt change) |
| Le format des packs TOML internes | `docs/utilisation/regles.md`, `examples/rules/company.toml` |
| L'analyse de dépendances, les formats de manifeste, l'import OSV | `docs/utilisation/dependances.md` |
| Une commande ou option CLI, un code de sortie | `docs/reference/cli.md` + la page d'usage concernée (`ci-cd/*.md`, `code-scan.md`...) |
| Un paramètre `SECREVIEW_*` | `docs/reference/configuration.md`, `.env.example` |
| Transport HTTP, authentification, TLS | `docs/demarrage/http.md`, `docs/reference/securite.md` |
| L'interface web, l'API REST ou les rôles | `docs/utilisation/interface-web.md` |
| Installation, image Docker | `docs/demarrage/installation.md`, `docs/demarrage/docker.md` |
| Une garantie ou limite de sécurité | `docs/reference/securite.md` |
| La structure du code, l'outillage de dev | `docs/contribuer.md` |

- Nouvelle page : créez-la dans `docs/` **et** déclarez-la dans `nav` de `mkdocs.yml`.
- Liens relatifs entre pages (`../reference/cli.md`) ; vérifiez avec `mkdocs build --strict`.
- Exemples copiables et exacts : options, noms de variables et sorties doivent correspondre au
  code actuel.

## README

Le `README.md` est une **vitrine synthétique**, pas une seconde documentation. Il doit rester
nettement plus court que `docs/` et ne contenir que :

1. une description en quelques lignes et le lien vers la documentation complète ;
2. les capacités principales sous forme de liste ou de tableau court (noms des prompts, outils
   et commandes CLI, une ligne chacun, sans détail des arguments) ;
3. une installation et un lancement minimaux (quelques commandes) ;
4. un exemple de configuration d'hôte ;
5. des liens vers les pages de `docs/` pour tout le reste.

Règles :

- Tout ce qui figure dans le README doit aussi figurer dans `docs/` ; l'inverse n'est pas vrai.
- Pas de tableau exhaustif des variables, d'options CLI détaillées, de cas limites ni de
  procédures longues : mettez-les dans `docs/` et ajoutez un lien.
- Quand vous ajoutez une capacité visible (outil, prompt, commande, transport), ajoutez **une
  ligne** au README avec un lien vers la page de doc ; quand vous en retirez ou renommez une,
  corrigez le README.
- Les liens vers la doc pointent sur le site publié
  `https://cyr-ius.github.io/security-review-mcp/...`.
