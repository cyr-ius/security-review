# security-review-mcp

Serveur MCP pour la **revue de code orientée sécurité** (failles et mauvaises configurations).
Il fournit à l'hôte (VS Code, Copilot, Claude, agent CI/CD) :

- des **prompts** structurés pour lancer une revue ;
- des **outils** : checklists, scan rapide par motifs, enregistrement et consultation de rapports ;
- une **base de données** (SQLite par défaut, PostgreSQL possible) qui stocke les rapports et leurs findings.

## Prompts

| Prompt | Usage | Arguments |
|---|---|---|
| `security-review` | Revue générale Python / Java / Angular | `language`, `code`, `context`, `focus` |
| `api-security-review` | API REST (OWASP API Top 10) | `framework`, `code`, `context`, `focus` |
| `configuration-review` | Dockerfile, CI/CD, Spring, YAML, properties | `config_type`, `content`, `context`, `focus` |
| `codebase-review` | Revue du **dépôt complet** (pas seulement un diff) | `languages`, `scan_results`, `context`, `focus` |
| `dependency-review` | Manifestes et lockfiles (supply chain) | `ecosystem`, `files`, `context` |
| `triage-report` | Re-qualifier les findings d'un rapport stocké | `report_id`, `context` |

Si `code` est vide, le prompt demande à l'agent de relire les fichiers de son espace de travail.
Chaque prompt se termine par l'instruction d'appeler `save_security_report` une seule fois.

## Outils

| Outil | Rôle |
|---|---|
| `list_checklists` / `get_review_checklist` | Checklists par domaine : `python`, `java`, `angular`, `api`, `config` |
| `scan_code` | Scan rapide par motifs (pistes à vérifier, **pas** un SAST). Extraits masqués |
| `save_security_report` | **Enregistre le rapport et ses findings en base** |
| `get_security_report` | Relit un rapport (Markdown par défaut, ou JSON) |
| `list_security_reports` | Liste filtrable par projet / niveau de risque, avec pagination |
| `update_finding_status` | `open`, `fixed`, `accepted`, `false_positive` |
| `get_project_security_posture` | Findings ouverts par sévérité (utile comme garde-fou CI) |
| `check_project_gate` | Gate CI : `passed` est faux tant qu'un finding **ouvert** atteint le seuil `fail_on` |
| `export_sarif` | Export SARIF 2.1.0 d'un rapport ou d'un projet |
| `get_trend_report` | Tendance d'un projet : nouveaux / corrigés, backlog, score de risque, MTTR |
| `scan_dependencies` | Analyse d'un manifeste / lockfile : versions vulnérables + hygiène |
| `get_advisory_status` | Taille et âge de la base de vulnérabilités |
| `list_rules` / `reload_rules` | Règles actives (intégrées + internes), erreurs de chargement, rechargement à chaud |

Ressources : `report://{report_id}` et `checklist://{domain}`.

### Rapport enregistré

`save_security_report` reçoit `project`, `summary` et une liste de `findings`
(`title`, `severity`, `description`, et optionnellement `cwe`, `owasp`, `file_path`,
`line_start`, `line_end`, `evidence`, `recommendation`, `category`) ainsi que
`repository`, `branch`, `commit_sha`, `reviewer`, `scope`.

- Le **niveau de risque** du rapport est calculé (sévérité maximale des findings). Le paramètre
  `risk_level` peut seulement le relever, jamais le baisser.
- Les **secrets** présents dans `summary`, `description`, `evidence` et `recommendation`
  (mots de passe, tokens, clés AWS, JWT, clés privées, identifiants dans les URL) sont masqués
  avant stockage. C'est un filet de sécurité : l'agent doit aussi éviter de les recopier.

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # ajouter ".[postgres]" pour PostgreSQL
cp .env.example .env
pytest && ruff check .
```

Python 3.11 ou plus. Le projet cible le SDK `mcp` **2.x** (`MCPServer`) ; avec un miroir
interne limité à `mcp` 1.x, l'import `mcp.server.mcpserver` ne fonctionnera pas.

### Installation hors ligne (environnement sans Internet)

Sur une machine connectée, avec **la même version de Python que la cible (3.12)** :

```bash
python3.12 -m pip wheel --no-deps -w wheels .
python3.12 -m pip download -d wheels "mcp>=2,<3" "sqlmodel>=0.0.22" "pydantic-settings>=2.2"
# PostgreSQL uniquement : python3.12 -m pip download -d wheels psycopg2-binary
```

Copiez ensuite le dossier `wheels/` sur la machine cible (même OS et architecture que la
machine connectée, sinon ajoutez `--platform` et `--only-binary=:all:` à `pip download`).

Puis, sur la machine cible, en ciblant explicitement Python 3.12 :

```bash
python3.12 -m venv /opt/security-review-mcp/venv
/opt/security-review-mcp/venv/bin/pip install --no-index --find-links wheels security-review-mcp
```

## Lancement

```bash
# stdio : l'hôte lance le processus lui-même (poste développeur)
security-review-mcp

# HTTP : serveur partagé (CI/CD)
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
# endpoint : http://127.0.0.1:8000/mcp
```

### Configuration de l'hôte

VS Code / GitHub Copilot (`.vscode/mcp.json`) :

```json
{
  "servers": {
    "security-review": {
      "type": "stdio",
      "command": "/opt/security-review-mcp/venv/bin/security-review-mcp",
      "env": { "SECREVIEW_DATABASE_URL": "sqlite:////data/security_reports.db" }
    }
  }
}
```

Claude (`.mcp.json`) :

```json
{
  "mcpServers": {
    "security-review": {
      "command": "/opt/security-review-mcp/venv/bin/security-review-mcp",
      "env": { "SECREVIEW_DATABASE_URL": "sqlite:////data/security_reports.db" }
    }
  }
}
```

## Docker

```bash
docker build -t security-review-mcp .
docker build -t security-review-mcp:pg --build-arg EXTRAS=postgres .   # pilote PostgreSQL
```

L'image tourne sous un utilisateur non root, sans sources ni outils de build. La base SQLite est
dans le volume `/data`. Le fichier `.env` n'est **pas** copié dans l'image : passez la
configuration avec `-e` ou `--env-file`.

Poste développeur (stdio, l'hôte lance le container) — `.vscode/mcp.json` :

```json
{
  "servers": {
    "security-review": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "--rm", "-v", "secreview-data:/data", "security-review-mcp"]
    }
  }
}
```

`-i` est indispensable (le protocole passe par stdin) ; ne mettez pas `-t`. Pour Claude
(`.mcp.json`), même `command` / `args` sous `mcpServers`.

Serveur partagé (HTTP), à placer derrière un reverse proxy TLS + authentification :

```bash
docker run -d --name security-review-mcp -p 127.0.0.1:8000:8000 \
    -e SECREVIEW_DATABASE_URL=postgresql+psycopg2://user:pass@db:5432/secreview \
    security-review-mcp:pg --transport streamable-http --host 0.0.0.0 --port 8000
```

Règles internes : `-v ./rules.d:/etc/security-review-mcp/rules.d:ro -e SECREVIEW_RULES_DIR=/etc/security-review-mcp/rules.d`.
Les commandes CLI passent aussi : `docker run --rm -v secreview-data:/data security-review-mcp gate --project portal --fail-on high`.

## Règles internes

Vos équipes sécurité peuvent ajouter des règles de scan et des items de checklist **sans toucher
au code**, avec des fichiers TOML (aucune dépendance supplémentaire) :

```bash
export SECREVIEW_RULES_DIR=/etc/security-review-mcp/rules.d
cp examples/rules/company.toml "$SECREVIEW_RULES_DIR/"
```

Chaque fichier `*.toml` du dossier est chargé (ordre alphabétique) :

```toml
disabled_rules = ["PY-008"]                  # désactiver une règle intégrée trop bruyante

[[rules]]
id = "ACME-001"                              # identifiant unique, ex. ACME-001
title = "Connexion JDBC directe"
severity = "medium"                          # critical | high | medium | low | info
cwe = "CWE-400"                              # optionnel
languages = ["java"]                         # ou ["*"]
pattern = '''DriverManager\.getConnection\s*\('''
advice = "Utiliser la DataSource gérée."

[[checklist]]
domain = "company"                           # "company" est ajouté à TOUS les prompts de revue
id = "ACME-CL-01"
title = "Isolation des tenants"
what_to_look_for = "Chaque requête est filtrée par le tenant du jeton."
cwe = "CWE-639"
```

- Un `id` identique à une règle intégrée la **remplace**.
- Un nouveau `domain` est immédiatement utilisable avec `get_review_checklist`.
- Une entrée invalide est **ignorée et signalée** (outil `list_rules`, champ `load_errors`) :
  un fichier cassé n'empêche jamais le démarrage.
- Après modification, appelez `reload_rules` : pas de redémarrage nécessaire.
- Les motifs avec quantificateurs imbriqués (`(a+)+`), trop longs ou qui matchent la chaîne vide
  sont refusés. Les lignes de plus de 2000 caractères sont tronquées avant analyse.
- Les fichiers de règles sont du contenu **de confiance** : réservez l'écriture du dossier aux
  administrateurs (et versionnez-le dans un dépôt revu).

### Règles intégrées par plateforme

En plus des règles Python, Java, Angular et configuration : **GitLab CI** (`GL-*`),
**Jenkinsfile** (`JK-*`), **CI/CD commun** (`CI-*`), **Spring** (`SP-*`) et **FastAPI** (`FA-*`).
Langages acceptés par `scan_code` : `python`, `java`, `typescript`, `javascript`, `angular`,
`config`, `yaml`, `docker`, `gitlab-ci`, `jenkins` (alias : `jenkinsfile`, `groovy`, `gitlab`, `yml`...).
Une checklist `cicd` est ajoutée automatiquement aux revues de pipelines.

### Supprimer un faux positif

Ajoutez un commentaire sur la ligne concernée :

```python
subprocess.run(cmd, shell=True)  # secreview:ignore PY-004 commande figée, aucune entrée utilisateur
```

Sans identifiant, toutes les règles de la ligne sont ignorées. Les suppressions ne sont **pas
cachées** : `scan_code` les renvoie dans `suppressed`, et les prompts demandent à l'agent de
signaler toute suppression injustifiée (un auteur de MR pourrait sinon masquer une faille).

## Scan du code complet

Les prompts de revue travaillent sur ce que l'agent leur donne, souvent le diff d'une MR, et
`scan_code` est limité à `SECREVIEW_MAX_CONTENT_CHARS` par appel. Pour couvrir **tout** le dépôt :

```bash
security-review-mcp code scan .                               # résumé texte, code de sortie 0/1/2
security-review-mcp code scan . --format json -o scan.json    # pour le prompt codebase-review
security-review-mcp code scan . --format sarif -o code.sarif  # GitHub code scanning, Jenkins...
security-review-mcp code scan . --save --project portal --commit "$CI_COMMIT_SHA"
```

- Les fichiers viennent de `git ls-files` (suivis + non suivis non ignorés : `.gitignore` est
  respecté). Hors dépôt git, ou avec `--no-git`, l'arborescence est parcourue en ignorant
  `node_modules`, `.venv`, `dist`, `build`, `target`, etc.
- Le langage est déduit du nom : `.py`, `.java`, `.ts`, `.js`, `.html` (templates Angular),
  `.yml`/`.yaml`, `.properties`, `.toml`, `.env*`, `Dockerfile*`, `Jenkinsfile`, `.gitlab-ci.yml`.
  Les lockfiles, `*.min.js` et `*.d.ts` sont ignorés.
- Fichiers ignorés et signalés : `--exclude GLOB` (répétable, ex. `--exclude tests/`), au-delà de
  `--max-file-bytes` (1 Mio par défaut), binaires, liens symboliques.
- `--fail-on` (défaut `high`) fixe le seuil de blocage ; les règles internes et les marqueurs
  `secreview:ignore` s'appliquent comme pour `scan_code`.
- `--save` enregistre les correspondances comme findings (au plus
  `SECREVIEW_MAX_FINDINGS_PER_REPORT`, les plus sévères d'abord) et la liste des fichiers non
  analysés dans `scope`. Ce sont des **pistes** : triez-les (`triage-report`) avant de faire
  dépendre une gate de ce rapport, sinon les faux positifs la bloqueront.

Ensuite, le prompt `codebase-review` (argument `scan_results` = le JSON, éventuellement filtré)
guide l'agent : inventaire, priorisation des points d'entrée, traçage des flux entre fichiers,
checklists, et une section **couverture** qui dit ce qui n'a pas été relu.

## Gate CI/CD

Sans agent ni client MCP, un job Jenkins ou GitLab peut bloquer un déploiement tant que des
findings critiques restent ouverts :

```bash
security-review-mcp gate --project portal --fail-on high
# code de sortie : 0 = passe, 1 = bloqué, 2 = erreur (projet/rapport introuvable)
# options : --report-id N pour ne juger qu'un rapport
```

```yaml
# .gitlab-ci.yml
security-gate:
  stage: test
  script:
    - security-review-mcp gate --project "$CI_PROJECT_PATH_SLUG" --fail-on high
  variables:
    SECREVIEW_DATABASE_URL: $SECREVIEW_DATABASE_URL   # variable masquée et protégée
```

Un finding sort du blocage quand il passe à `fixed`, `accepted` ou `false_positive`
(`update_finding_status`) : la décision reste tracée en base.

## Export SARIF

```bash
security-review-mcp sarif --project mon-projet -o results.sarif      # ou --report-id N
```

SARIF 2.1.0 (validé contre le schéma officiel). Seuls les findings **ouverts** sont exportés ;
`--include-resolved` ajoute les autres (`baselineState: absent` pour les corrigés, `suppressions`
pour les acceptés / faux positifs). Pour un projet, un finding signalé dans plusieurs rapports
n'apparaît qu'une fois. L'empreinte (`partialFingerprints`) ignore le numéro de ligne : elle reste
stable quand le code bouge. Sans chemin de fichier, le finding n'a qu'une localisation logique.

- **GitHub** : `github/codeql-action/upload-sarif` (code scanning).
- **GitLab** : n'ingère **pas** SARIF nativement (rapports `sast` au format GitLab) ; gardez le
  fichier comme artefact ou convertissez-le. **Jenkins** : plugin Warnings Next Generation.

## Rapport de tendance

```bash
security-review-mcp trend --project mon-projet --days 90 --granularity week --format markdown
```

Par période (jour, semaine, mois) : findings nouveaux et corrigés, backlog ouvert, score de risque
(critical 10, high 5, medium 2, low 1) et direction (marge de ±10 % sur les deux dernières
périodes), délai moyen de correction (MTTR) par sévérité, plus ancien finding ouvert, CWE les plus
fréquentes. Les corrections faites avant la v1.2 n'ont pas de date : elles sont signalées en note.

## Analyse des dépendances

Fichiers pris en charge : `requirements*.txt`, `pyproject.toml` (PEP 621/735, Poetry),
`poetry.lock`, `Pipfile.lock`, `package.json`, `package-lock.json` / `npm-shrinkwrap.json`,
`yarn.lock` (v1 et berry), `pom.xml`, `build.gradle(.kts)`.

**Base de vulnérabilités hors ligne (format OSV).** Le serveur n'appelle aucun service externe :
sur une machine connectée, téléchargez les exports d'osv.dev
(`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`, idem `npm` et `Maven`),
transférez-les, puis importez-les (opération réservée à la CLI, idempotente) :

```bash
security-review-mcp advisories import PyPI.zip      # .json, dossier ou .zip
security-review-mcp advisories import npm.zip
security-review-mcp advisories import Maven.zip --ecosystem Maven   # filtre facultatif
security-review-mcp advisories status
```

Scan en pipeline (pour les gros lockfiles, préférez la CLI à l'outil MCP, limité à
`SECREVIEW_MAX_DEPENDENCY_CHARS`) :

```bash
security-review-mcp deps scan package-lock.json requirements.txt \
    --fail-on high --require-database --project mon-projet --save
# code de sortie : 0 = ok, 1 = bloqué, 2 = erreur
```

Le champ `vulnerability_check` dit si la vérification a eu lieu : `performed`,
`skipped_no_advisory_database` ou `skipped_no_advisories_for_ecosystem`. Dans les deux derniers
cas, **une liste vide ne signifie pas que les dépendances sont sûres** (`--require-database` fait
échouer le pipeline). Une base de plus de 30 jours est signalée. Une sévérité absente de l'avis est
traitée comme `medium` (`severity_known: false`). Les versions en intervalle (`>=2`) ne sont pas
vérifiables : analysez le lockfile. Règles d'hygiène `DEP-001` à `DEP-009` (versions non épinglées,
URL / VCS, HTTP, index supplémentaire, `--trusted-host`, etc.).

## Configuration

Variables d'environnement préfixées `SECREVIEW_` (voir `.env.example`) :
`DATABASE_URL`, `TRANSPORT`, `HOST`, `PORT`, `LOG_LEVEL`, `RULES_DIR`, `MAX_CONTENT_CHARS`,
`MAX_FINDINGS_PER_REPORT`, `MAX_DEPENDENCY_CHARS`, `MAX_LIST_LIMIT`.

PostgreSQL : `SECREVIEW_DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/secreview`.
Les tables sont créées au démarrage (`create_all`) et les colonnes facultatives ajoutées par les
versions récentes sont ajoutées automatiquement aux bases existantes. Pour des migrations plus
complexes en production, ajouter Alembic.

## Sécurité du serveur lui-même

- **Pas d'authentification intégrée** sur le transport HTTP : ne l'exposez qu'en local ou
  derrière un reverse proxy qui impose TLS et authentification. Un avertissement est journalisé
  si l'écoute n'est pas sur localhost.
- `scan_code` travaille uniquement sur le **contenu fourni** : le serveur ne lit aucun fichier
  du disque, ce qui évite les traversées de chemin. Le scan du dépôt complet est réservé à la CLI
  (`code scan`), lancée par l'opérateur sur un dossier qu'il choisit ; elle ne suit pas les liens
  symboliques.
- Les requêtes SQL passent par l'ORM (paramètres liés) ; les tailles d'entrée, le nombre de
  findings et la pagination sont bornés.
- Les journaux vont sur **stderr** (stdout est réservé au protocole en stdio).
- Les rapports contiennent des informations sensibles sur vos vulnérabilités : protégez la base
  (droits fichier, compte PostgreSQL dédié, sauvegardes chiffrées).

## Structure

```
src/security_review_mcp/
├── server.py      # prompts, outils, ressources, point d'entrée
├── prompts.py     # construction des prompts
├── checklists.py  # checklists intégrées par domaine
├── scanner.py     # règles de scan, suppression inline, masquage des secrets
├── rules_platform.py  # règles GitLab CI, Jenkins, Spring, FastAPI
├── rules_loader.py    # chargement et validation des packs TOML internes
├── registry.py    # règles/checklists actives (intégrées + internes), rechargement
├── cli.py         # commandes gate, sarif, trend, advisories, deps, code
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

## Limites connues

- Le scan par motifs produit des pistes et des faux positifs ; il ne remplace ni un SAST, ni
  une analyse SCA complète (pas de résolution transitive des manifestes, base à tenir à jour), ni une relecture humaine.
- Les règles sont des motifs ligne par ligne : elles ne voient ni le flux de données ni les
  contrôles absents (autorisation manquante, par exemple). Ce travail reste celui de l'agent
  guidé par les checklists, et de vos outils SAST/SCA.
