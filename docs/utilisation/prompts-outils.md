# Prompts et outils

## Prompts

| Prompt | Usage | Arguments |
|---|---|---|
| `security-review` | Revue générale Python / Java / Angular | `language`, `code`, `context`, `focus`, `report_language` |
| `api-security-review` | API REST (OWASP API Top 10) | `framework`, `code`, `context`, `focus`, `report_language` |
| `configuration-review` | Dockerfile, CI/CD, Spring, YAML, properties | `config_type`, `content`, `context`, `focus`, `report_language` |
| `codebase-review` | Revue du **dépôt complet** (pas seulement un diff) | `languages`, `scan_results`, `context`, `focus`, `report_language` |
| `dependency-review` | Manifestes et lockfiles (supply chain) | `ecosystem`, `files`, `context`, `report_language` |
| `triage-report` | Re-qualifier les findings d'un rapport stocké | `report_id`, `context`, `report_language` |
| `development-standards` | Donne à l'assistant les [normes de développement](normes.md) de sa pile **avant d'écrire du code** | `technologies`, `files`, `task`, `context` |

Si `code` est vide, le prompt demande à l'agent de relire les fichiers de son espace de travail.
Chaque prompt de revue se termine par l'instruction d'appeler `save_security_report` une seule
fois ; `development-standards` n'enregistre rien.

### Langue des rapports

`report_language` fixe la langue de la réponse de l'agent et des champs rédigés du rapport
enregistré (résumé, périmètre, titres, descriptions, recommandations), par exemple `French`,
`fr` ou `pt-BR`. Sans cet argument, le prompt reprend la langue choisie par un administrateur
dans l'écran [**Paramètres**](interface-web.md#ecrans) de l'interface web, sinon
[`SECREVIEW_REPORT_LANGUAGE`](../reference/configuration.md) ; si aucune n'est définie, l'agent
choisit (en général la langue de la conversation). L'écran peut aussi imposer « l'agent
choisit » malgré la variable.

Le code, les extraits, les chemins, les identifiants de règles, les références CWE / OWASP et
les valeurs fixes attendues par les outils (sévérité, catégorie, statut) restent inchangés :
le gate, l'export SARIF et les tendances fonctionnent quelle que soit la langue.

La valeur n'accepte que des lettres, espaces, `-`, `_` et parenthèses (40 caractères au plus),
pour qu'elle ne puisse pas transporter d'instructions ; sinon le prompt est refusé.

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
| `request_enrollment` | Demande un jeton pour un premier projet ou l'ajout d'un projet au jeton présenté, après approbation par un administrateur ([enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton)) |
| `list_development_standards` / `get_development_standards` | [Normes de développement](normes.md) : catalogue, puis normes à appliquer pour des technologies ou des noms de fichiers |
| `list_rules` / `reload_rules` | Règles actives ([par défaut et personnalisées](regles.md), stockées en base), erreurs de chargement, rechargement immédiat |

Sur le transport HTTP, un jeton restreint ne peut utiliser les outils de rapports que sur ses
projets autorisés ; `reload_rules` lui est refusé (voir
[jetons restreints à un projet](../demarrage/http.md#jetons-restreints-a-un-projet)).
Un jeton associé à plusieurs projets peut utiliser les outils de rapports sur chacun d'eux ;
`request_enrollment` demande l'ajout au jeton courant sans créer ni révéler un nouveau secret.

### Serveur d'enrôlement

Sur le transport HTTP, un client qui se connecte **sans jeton** (ou avec un jeton dont
l'enrôlement n'est pas encore approuvé) atteint un serveur restreint, du même nom, qui
n'expose que :

| Élément | Rôle |
|---|---|
| `request_enrollment` | Dépose la demande pour un projet et renvoie le jeton (affiché une fois) |
| `get_enrollment_status` | `pending` si le jeton présenté attend l'approbation, `not_enrolled` sans jeton |
| Prompts `security-review`, `api-security-review`, `configuration-review`, `codebase-review`, `dependency-review` | Argument `project` facultatif ; expliquent à l'agent comment demander l'accès au lieu de lancer la revue |

Voir [l'enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton).

## Ressources

- `report://{report_id}` : un rapport enregistré ;
- `checklist://{domain}` : la checklist d'un domaine ;
- `standards://catalog` : le catalogue des [normes de développement](normes.md) ;
- `standard://{slug}` : une norme de développement.

## Rapport enregistré

`save_security_report` reçoit :

- `project`, `summary` ;
- une liste de `findings` : `title`, `severity`, `description`, et optionnellement `cwe`,
  `owasp`, `file_path`, `line_start`, `line_end`, `evidence`, `recommendation`, `category` ;
- `repository`, `branch`, `commit_sha`, `reviewer`, `scope`.

Le **niveau de risque** du rapport est calculé (sévérité maximale des findings). Le paramètre
`risk_level` peut seulement le relever, jamais le baisser.

!!! info "Masquage des secrets"
    Les secrets présents dans `summary`, `description`, `evidence` et `recommendation`
    (mots de passe, tokens, `SECRET_KEY`, clés AWS, jetons GitHub, GitLab, Slack, Google, Stripe
    et npm, JWT, clés privées, identifiants dans les URL) sont masqués
    avant stockage. C'est un filet de sécurité : l'agent doit aussi éviter de les recopier.
