# Consignes pour les agents IA

Ce fichier est la **référence unique** pour tout agent (Claude, Copilot, Codex, Cursor...)
qui modifie ce dépôt. `CLAUDE.md` et `.github/copilot-instructions.md` ne font qu'y renvoyer :
modifiez les règles ici, pas là-bas.

`security-review-mcp` est un serveur MCP de revue de code orientée sécurité : prompts,
checklists, scan par motifs, analyse de dépendances, rapports persistés (SQLModel, migrations
Alembic), CLI pour la CI/CD (gate, SARIF, tendances) et transport HTTP avec jetons Bearer / TLS.

Deux processus partagent la base et ne s'appellent jamais : le **serveur MCP**
(`security-review-mcp`, endpoint `/mcp` et enrôlement public) et le **contrôleur**
(`security-review-controller` : API REST, interface web, migrations, administration).

## Une tâche n'est terminée que si

1. **Des tests couvrent le changement** (voir [Tests](#tests)) et `uv run pytest` passe.
2. `uv run ruff check . && uv run ruff format --check .` passe.
3. **La documentation `docs/` est à jour, en anglais et en français**, et
   `uv run mkdocs build --strict` passe
   (voir [Documentation](#documentation)).
4. **Les `README.md` (anglais) et `README.fr.md` (français) sont à jour, en restant
   synthétiques** (voir [README](#readme)).
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

La CI (`.github/workflows/`) lance ruff et pytest sur Python 3.14 et 3.15 avec
`uv sync --locked` : après un changement de dépendances dans `pyproject.toml`, lancez `uv lock`
et commitez `uv.lock`. Les actions des workflows sont épinglées sur le SHA complet d'un commit,
avec la version en commentaire (`@<sha> # vX.Y.Z`) : faites de même pour toute nouvelle action.

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
  publication sur PyPI et des images Docker (GHCR et Docker Hub, `docker.yml`), et création de
  la release GitHub. Procédure :
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
| Prompts, outils, ressources MCP, point d'entrée du serveur MCP | `server.py`, `prompts.py` |
| Point d'entrée du contrôleur (`serve`, `db`, commandes d'administration) ; recherche de nouvelle version (page À propos) ; `HEALTHCHECK` de l'image Docker | `controller.py` ; `update_check.py` ; `healthcheck.py` |
| Moteur de scan, masquage des secrets | `scanner.py` |
| Règles et checklists par défaut (copiées en base au premier lancement) | `default_rules.toml` |
| Règles en base (amorçage, packs TOML), registre actif | `rules_loader.py`, `rule_store.py`, `registry.py`, `checklists.py` |
| CLI : `CONTROLLER_COMMANDS` (`db`, `advisories`, `deps`, `code`, `rules`, `token`, `user`, `group`, `audit`) et `MCP_COMMANDS` (`enroll`, `scan-deps`) ; client de pipeline `security-review-ci`, seul à exécuter `gate`, `sarif` et `trend` (jeton `ci`, bibliothèque standard uniquement : n'importe rien du paquet, lit ses variables dans l'environnement) | `cli.py`, `codescan.py`, `enrollment.py` (client de `enroll`), `remote_scan.py` (client de `scan-deps`), `ci_client.py` |
| Dépendances et avis OSV (téléchargement facultatif par le contrôleur : `advisory_sync.py`) ; proxy sortant du contrôleur (OSV et OIDC) | `dependencies.py`, `depscan.py`, `advisories.py`, `advisory_sync.py`, `versions.py` ; `proxy.py` |
| Persistance, schéma (purge des rapports sans findings et de l'audit : `retention.py`) | `models.py`, `services.py`, `retention.py`, `database.py`, `migrations/` (Alembic) |
| Journal d'audit (écrit par `services`, `token_store` et `access_control` dans la transaction du changement ; envoi syslog facultatif par le contrôleur) ; métriques Prometheus du contrôleur (`/metrics`, rôle `metrics`) | `audit.py`, `audit_syslog.py` ; `metrics.py` |
| Export et tendances | `sarif.py`, `trends.py` |
| HTTP des deux processus, auth (jetons et rôles), TLS, `/healthz` | `http_server.py` ; stockage des jetons et enrôlement en base : `token_store.py` ; comptes web locaux et OIDC, seuls à ouvrir l'interface (mot de passe, création OIDC à la volée, sessions, admin initial) : `web_users.py` ; protocole OIDC du contrôleur : `oidc.py` ; permissions, rôles, groupes et membres (groupes OIDC par le claim) : `access_control.py` |
| Enrôlement public `POST /api/v1/enroll` (servi par le serveur MCP) | `enrollment_api.py` |
| Contrôleur : API REST `/api/v1` et fichiers de `/ui` | paquet `web_api/` (`__init__.py` : `create_app` ; `schemas.py` : modèles de requête et de réponse ; `deps.py` : identité et permissions ; un `*_routes.py` par domaine) ; application Angular dans `web/` |
| Normes de développement par technologie (prompt `development-standards`, écran « Normes ») | `standards.py` |
| Paramètres `SECREVIEW_*` ; réglages modifiables dans l'interface web (langue, proxy sortant, configuration OIDC) | `config.py` ; `app_settings.py` |

Tous les modules sont dans `src/security_review_mcp/`. L'application Angular (`web/`) est
compilée par `npm run build` dans `src/security_review_mcp/webui/` (ignoré par git). La logique métier va dans les modules
(`services.py`, `scanner.py`...) ; `server.py` et `cli.py` restent des couches minces qui
valident les entrées et appellent ces modules.

## Conventions de code

- Python ≥ 3.14, annotations de type partout, ruff (longueur 100, règles `E F W I B C4 UP`).
- **Code, docstrings, commentaires, messages d'erreur et logs en anglais.** Chaque module et
  chaque fonction a une docstring. La documentation utilisateur (`docs/`, README) est
  **bilingue, anglais et français** (voir [Documentation](#documentation)).
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

### API REST et interface web

- Chaque route JSON du contrôleur déclare son modèle de réponse dans `web_api/schemas.py` (jamais
  `-> dict`) : il documente l'API et filtre les champs non déclarés. Un test le vérifie sur le
  schéma OpenAPI.
- Angular : formulaires de saisie en Signal Forms, pas de `.subscribe()` dans les composants
  (`rxResource` ou `firstValueFrom`), un dossier par composant quand une fonctionnalité en a
  plusieurs, `linkedSignal` plutôt qu'un `effect()` qui recopie un signal, signaux des services en
  `asReadonly()`, `shared/` sans service métier, couleurs par variables Bootstrap ou jetons de
  `styles.css`. Le détail est dans `docs/contributing`.

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
- **Schéma via Alembic uniquement** : toute modification d'un modèle de table s'accompagne d'une
  nouvelle révision dans `migrations/versions/` (jamais de modification d'une révision publiée) ;
  `tests/test_database.py` vérifie que les migrations produisent exactement les modèles. Le
  serveur MCP HTTP ne migre jamais le schéma.
- **Séparation MCP / contrôleur** : le serveur MCP n'expose que `/mcp`, l'enrôlement public et
  `/healthz` ; le contrôleur n'expose aucune route d'écriture sans jeton. N'ajoutez pas de route
  web au serveur MCP ni d'endpoint MCP au contrôleur.
- **Aucun appel réseau sortant** du serveur MCP : la base de vulnérabilités est importée par la
  CLI. Exceptions : les commandes CLI `enroll`, `scan-deps` et `security-review-ci`, qui contactent l'URL donnée par
  l'opérateur, et le téléchargement OSV du contrôleur (`advisory_sync`), **désactivé par défaut**, en HTTPS
  uniquement, taille bornée, proxy facultatif (`proxy`, partagé avec le OIDC) jamais journalisé
  avec ses identifiants, et la
  connexion OIDC du contrôleur (`oidc`), **désactivée par défaut**, qui ne contacte que le
  fournisseur d'identité configuré, en HTTPS, réponses bornées, la recherche de nouvelle version
  du contrôleur (`update_check`, **désactivée par défaut**, HTTPS vers l'API GitHub, par le
  proxy, réponse bornée et mise en cache) et l'envoi syslog du journal d'audit par le contrôleur
  (`audit_syslog`, **désactivé par défaut**, qui lit les événements en base : le serveur MCP n'y
  participe pas).
- Les regex de règles doivent éviter le backtracking catastrophique (pas de quantificateurs
  imbriqués) ; `rules_loader` les valide pour les règles internes.
- Jetons Bearer : seules les empreintes SHA-256 sont conservées, comparaison en temps constant.
- **Un agent ne ferme jamais un finding** : aucun outil MCP ne change un statut
  (`propose_finding_status` enregistre seulement une proposition). `accepted` et
  `false_positive` sont décidés par une personne connectée à l'interface (session, jamais un
  jeton Bearer), avec motif, approbateur et date d'expiration ; une décision expirée compte comme
  ouverte (gate, posture, SARIF, tendances).

### Paramètres

Un nouveau paramètre s'ajoute dans `config.Settings` (préfixe `SECREVIEW_` automatique), avec
un commentaire, puis dans `.env.example` et `docs/reference/configuration.md` (et `.fr.md`). Lisez-le via
`get_settings()`, jamais avec `os.environ`.

### Règles de scan

Identifiants `PRÉFIXE-NNN` par famille : `PY`, `JV`, `NG` (Angular), `CFG`, `GEN`, `GL`
(GitLab CI), `JK` (Jenkins), `CI`, `SP` (Spring), `FA` (FastAPI), `DEP` (hygiène des
dépendances). Ne réutilisez et ne renumérotez jamais un identifiant existant : les utilisateurs
les citent dans `secreview:ignore` et `disabled_rules`. Indiquez la CWE quand elle existe.

Les règles et checklists par défaut sont dans `src/security_review_mcp/default_rules.toml`,
jamais dans le code Python. Elles sont copiées en base au premier lancement
(`rule_store.seed_defaults`, appelé par `init_db`). Une règle ajoutée ou corrigée dans ce
fichier atteint les bases existantes au démarrage suivant, sauf si un administrateur l'a modifiée.

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
  règles vide par test : n'utilisez pas la base réelle. Utilisez la fixture `import_pack` pour
  charger des règles internes (pack TOML importé en base), `tmp_path` pour les fichiers.
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
   correction. Pour les autres, corrigez-les ou justifiez-les, et proposez leur statut avec
   `propose_finding_status` (`fixed`, `accepted`, `false_positive`, avec le motif) : un agent ne
   change jamais un statut, c'est une personne qui valide la proposition dans l'interface web.
5. Résumez la revue (identifiant du rapport, findings et suite donnée) dans votre réponse et dans
   la description de PR.

Si le serveur n'est pas connecté ou ne répond pas, dites-le explicitement : ne prétendez pas
avoir fait la revue. Lancez au minimum le scan en CLI sur le dépôt
(`uv run security-review-controller code scan . --exclude tests/`) et signalez ses résultats.

## Documentation

`docs/` (MkDocs Material) est la **source de vérité complète** pour les utilisateurs, en
**deux langues** : chaque page existe en anglais (`page.md`, langue par défaut, servie à la
racine du site) et en français (`page.fr.md`, à côté, servie sous `/fr/`), avec le plugin
`mkdocs-static-i18n`. Mettez-la à jour dans le même changement que le code, **dans les deux
langues** :

La doc est organisée en parcours de mise en œuvre : **Démarrage** (`getting-started/` :
installation, mise en service du serveur, connexion de l'hôte) et **Utilisation** (`usage/` :
prompts et outils, interface web, gate) ne contiennent que l'essentiel pour travailler ;
**Avancé** (`advanced/`) regroupe les détails et les fonctions facultatives. Une nouvelle
explication détaillée va dans `advanced/`, avec au plus une ligne et un lien depuis les pages
essentielles.

| Si vous modifiez... | Mettez à jour (`.md` et `.fr.md`) |
|---|---|
| Un prompt ou un outil MCP (nom, argument, comportement) | `docs/usage/prompts-tools` |
| Une règle de scan ou une checklist par défaut (`default_rules.toml`) | `docs/advanced/rules` (et `code-scan` si le scan du dépôt change) |
| Le format des packs TOML internes | `docs/advanced/rules`, `examples/rules/company.toml` |
| L'analyse de dépendances, les formats de manifeste, l'import OSV | `docs/advanced/dependencies` |
| Une commande ou option CLI, un code de sortie | `docs/reference/cli` + la page d'usage concernée (`usage/gate`, `advanced/code-scan`, `advanced/sarif`...) |
| Un paramètre `SECREVIEW_*` | `docs/reference/configuration`, `.env.example` |
| Transport HTTP, authentification, TLS, enrôlement | `docs/advanced/http`, `docs/reference/security` (+ `getting-started/deploy` et `getting-started/host` si le parcours de base change) |
| Séparation MCP / contrôleur, migrations, Compose, Kubernetes | `docs/advanced/architecture`, `docs/getting-started/deploy`, `docker-compose.yml`, `examples/kubernetes/` |
| Les normes de développement (prompt, outils, ressources, écran) | `docs/advanced/standards` (+ `usage/prompts-tools`) |
| L'interface web, l'API REST ou les rôles | `docs/usage/web-interface` (connexion OIDC : `docs/advanced/sso`) |
| Installation, image Docker | `docs/getting-started/installation`, `docs/advanced/installation`, `docs/advanced/docker` |
| Une garantie ou limite de sécurité | `docs/reference/security` |
| La structure du code, l'outillage de dev | `docs/contributing` |

- Les deux versions d'une page disent la même chose : pas de section qui n'existe que dans une
  langue. Les exemples (commandes, sorties, JSON) sont identiques ; seuls le texte et les
  commentaires sont traduits.
- L'interface web est traduite (anglais, français, espagnol) : chaque version de la doc cite les
  libellés de l'interface dans sa langue, tels qu'ils s'affichent (**Tokens** / **Jetons**).
- Tout texte affiché par l'interface passe par les catalogues de `web/src/app/core/i18n/messages/`,
  dans les trois langues (voir `docs/contributing`) : pas de texte en dur dans un template.
- Nouvelle page : créez `page.md` et `page.fr.md` dans `docs/`, déclarez `page.md` dans `nav`
  de `mkdocs.yml` et traduisez son titre dans `nav_translations` (langue `fr` du plugin `i18n`).
- Liens relatifs entre pages, toujours vers le fichier anglais (`../reference/cli.md`) : le
  plugin les fait pointer vers la page française depuis une page française. Les ancres suivent
  les titres de chaque langue (`#report-language` / `#langue-des-rapports`). Vérifiez avec
  `mkdocs build --strict` : une ancre inconnue fait échouer le build.
- Exemples copiables et exacts : options, noms de variables et sorties doivent correspondre au
  code actuel.

## README

Le `README.md` (anglais, celui de PyPI et de GitHub) et le `README.fr.md` (français) sont des
**vitrines synthétiques**, pas une seconde documentation. Ils ont le même contenu, traduit, se
lient l'un à l'autre en tête, restent nettement plus courts que `docs/` et ne contiennent que :

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
- Modifiez toujours les deux fichiers ensemble.
- Les liens vers la doc pointent sur le site publié : `https://cyr-ius.github.io/security-review-mcp/...`
  depuis `README.md`, `https://cyr-ius.github.io/security-review-mcp/fr/...` (ancres
  françaises) depuis `README.fr.md`.
