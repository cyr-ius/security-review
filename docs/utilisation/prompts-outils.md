# Prompts et outils

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

Sur le transport HTTP, un jeton restreint à un projet ne peut utiliser les outils de rapports
que sur ce projet ; `reload_rules` lui est refusé (voir
[jetons restreints à un projet](../demarrage/http.md#jetons-restreints-a-un-projet)).

## Ressources

- `report://{report_id}` : un rapport enregistré ;
- `checklist://{domain}` : la checklist d'un domaine.

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
    (mots de passe, tokens, clés AWS, JWT, clés privées, identifiants dans les URL) sont masqués
    avant stockage. C'est un filet de sécurité : l'agent doit aussi éviter de les recopier.
