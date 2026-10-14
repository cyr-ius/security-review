# Security Review MCP

Serveur MCP pour la **revue de code orientée sécurité** (failles et mauvaises configurations),
utilisable depuis VS Code / Copilot, Claude ou un agent CI/CD. Il fournit des prompts de revue,
des checklists, un scan par motifs, une analyse de dépendances hors ligne et une base de
rapports (SQLite ou PostgreSQL) exploitable en pipeline.

📖 **Documentation complète : <https://cyr-ius.github.io/security-review-mcp/>**

## Capacités

| | |
|---|---|
| **Prompts** | `security-review`, `api-security-review`, `configuration-review`, `codebase-review`, `dependency-review`, `triage-report` |
| **Outils** | checklists, `scan_code`, `scan_dependencies`, enregistrement / lecture / triage des rapports, posture et gate projet, export SARIF, tendances, gestion des règles |
| **CLI** | `security-review-mcp` (serveur MCP, `enroll`) et `security-review-controller` (`serve`, `db`, `gate`, `sarif`, `trend`, `code scan`, `deps scan`, `advisories`, `rules`, `token`), codes de sortie 0 / 1 / 2 |
| **Règles** | Python, Java, Angular, configuration, GitLab CI, Jenkins, Spring, FastAPI, copiées en base au premier lancement, plus vos [règles internes](https://cyr-ius.github.io/security-review-mcp/utilisation/regles/) (import/export TOML) |
| **Transport** | stdio ou HTTP, avec jetons Bearer stockés en base (CLI `token`) et TLS (mutuel) facultatifs |
| **Déploiement** | serveur MCP et contrôleur (API REST, interface web) [séparés](https://cyr-ius.github.io/security-review-mcp/demarrage/kubernetes/) sur une base partagée, migrations Alembic, exemples Docker Compose et Kubernetes |
| **Enrôlement** | un projet [demande son jeton ou un accès supplémentaire](https://cyr-ius.github.io/security-review-mcp/demarrage/http/#enrolement-un-projet-demande-son-jeton) (outil MCP `request_enrollment` ou CLI `enroll`), un administrateur valide la demande |
| **Interface web** | tableau de bord, triage, gestion des [règles, checklists et jetons projet](https://cyr-ius.github.io/security-review-mcp/utilisation/interface-web/), mot de passe admin initial dans les logs Docker |

Détail : [prompts et outils](https://cyr-ius.github.io/security-review-mcp/utilisation/prompts-outils/),
[scan du code complet](https://cyr-ius.github.io/security-review-mcp/utilisation/code-scan/),
[dépendances](https://cyr-ius.github.io/security-review-mcp/utilisation/dependances/),
[gate](https://cyr-ius.github.io/security-review-mcp/ci-cd/gate/),
[SARIF](https://cyr-ius.github.io/security-review-mcp/ci-cd/sarif/),
[tendances](https://cyr-ius.github.io/security-review-mcp/ci-cd/tendances/).

## Démarrage rapide

```bash
pip install security-review-mcp        # Python ≥ 3.14 ; extra [postgres] pour PostgreSQL

security-review-mcp                    # stdio : lancé par l'hôte

# serveur partagé : deux processus sur la même base
security-review-controller db upgrade                              # schéma (Alembic)
security-review-controller serve --port 8080                       # interface /ui et API REST
security-review-mcp --transport streamable-http --port 8000        # endpoint /mcp

security-review-controller gate --project portal --fail-on high    # bloquer un pipeline
```

Configuration de l'hôte (VS Code, `.vscode/mcp.json`) :

```json
{
  "servers": {
    "security-review": {
      "type": "stdio",
      "command": "security-review-mcp",
      "env": { "SECREVIEW_DATABASE_URL": "sqlite:////data/security_reports.db" }
    }
  }
}
```

Autres cas : [installation hors ligne](https://cyr-ius.github.io/security-review-mcp/demarrage/installation/),
[Claude et autres hôtes](https://cyr-ius.github.io/security-review-mcp/demarrage/hote/),
[HTTP, authentification et TLS](https://cyr-ius.github.io/security-review-mcp/demarrage/http/),
[Docker et Docker Compose avec PostgreSQL](https://cyr-ius.github.io/security-review-mcp/demarrage/docker/),
[architecture et Kubernetes](https://cyr-ius.github.io/security-review-mcp/demarrage/kubernetes/),
[variables `SECREVIEW_*`](https://cyr-ius.github.io/security-review-mcp/reference/configuration/).

## Limites

Le scan par motifs produit des pistes, avec des faux positifs. Il ne remplace ni un SAST, ni une
analyse SCA complète, ni une relecture humaine. Voir
[sécurité et limites](https://cyr-ius.github.io/security-review-mcp/reference/securite/).

## Contribuer

```bash
uv sync --extra dev && uv run pytest && uv run ruff check .
```

Le développement se fait sur `dev`, et une version est publiée en poussant un tag `vX.Y.Z`
sur `master`. Voir le [guide de contribution](https://cyr-ius.github.io/security-review-mcp/contribuer/)
et [`AGENTS.md`](AGENTS.md) (consignes pour les agents IA).
