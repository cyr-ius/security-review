# Security Review MCP

Serveur MCP pour la **revue de code orientée sécurité** (failles et mauvaises configurations),
utilisable depuis VS Code / Copilot, Claude ou un agent CI/CD. Il fournit des prompts de revue,
des checklists, un scan par motifs, une analyse de dépendances hors ligne et une base de
rapports (SQLite ou PostgreSQL) exploitable en pipeline.

📖 **Documentation complète : <https://cyr-ius.github.io/security-review-mcp/fr/>**

🇬🇧 [English version](README.md)

## Capacités

| | |
|---|---|
| **Prompts** | `security-review`, `api-security-review`, `configuration-review`, `codebase-review`, `dependency-review`, `triage-report`, `development-standards` |
| **Outils** | checklists, `scan_code`, `scan_dependencies`, enregistrement / lecture / triage des rapports, posture et gate projet, export SARIF, tendances, gestion des règles |
| **CLI** | `security-review-mcp` (serveur MCP, `enroll`) et `security-review-controller` (`serve`, `db`, `gate`, `sarif`, `trend`, `code scan`, `deps scan`, `advisories`, `rules`, `token`, `user`), codes de sortie 0 / 1 / 2 |
| **Règles** | Plus de 120 règles et plus de 75 items de checklist : Python, Java, Angular / Node.js, Docker, Kubernetes, configuration, GitLab CI, Jenkins, Spring, FastAPI, copiés en base au premier lancement, plus vos [règles internes](https://cyr-ius.github.io/security-review-mcp/fr/usage/rules/) (import/export TOML) |
| **Normes de développement** | [conventions par technologie](https://cyr-ius.github.io/security-review-mcp/fr/usage/standards/) gérées dans l'interface web et transmises à l'assistant IA avant qu'il code (prompt, outils `get_development_standards` / `list_development_standards`, ressources) |
| **Vulnérabilités** | base OSV (PyPI, npm, Maven) importée hors ligne ou [mise à jour chaque jour par le contrôleur](https://cyr-ius.github.io/security-review-mcp/fr/usage/dependencies/#mise-a-jour-automatique-par-le-controleur), proxy facultatif |
| **Transport** | stdio ou HTTP, avec jetons Bearer stockés en base (CLI `token`) et TLS (mutuel ou auto-signé) facultatifs |
| **Déploiement** | serveur MCP et contrôleur (API REST, interface web) [séparés](https://cyr-ius.github.io/security-review-mcp/fr/getting-started/kubernetes/) sur une base partagée, migrations Alembic, exemples Docker Compose et Kubernetes |
| **Enrôlement** | un projet [demande son jeton ou un accès supplémentaire](https://cyr-ius.github.io/security-review-mcp/fr/getting-started/http/#enrolement-un-projet-demande-son-jeton) (outil MCP `request_enrollment` ou CLI `enroll`), un administrateur valide la demande |
| **Interface web** | en anglais, français ou espagnol : tableau de bord, triage, gestion des [règles, checklists, jetons projet, langue des rapports, proxy sortant (OSV et SSO) et mises à jour OSV](https://cyr-ius.github.io/security-review-mcp/fr/usage/web-interface/), [comptes utilisateurs](https://cyr-ius.github.io/security-review-mcp/fr/usage/web-interface/#comptes-utilisateurs) locaux ou SSO, seuls à ouvrir l'interface (les jetons servent au MCP et à l'API REST ; compte `admin` initial dans les logs), [connexion SSO OpenID Connect](https://cyr-ius.github.io/security-review-mcp/fr/usage/web-interface/#connexion-sso-openid-connect) facultative, [configurable dans l'interface](https://cyr-ius.github.io/security-review-mcp/fr/usage/web-interface/#configurer-le-sso-dans-linterface), avec création des comptes à la volée et [role mapping](https://cyr-ius.github.io/security-review-mcp/fr/usage/web-interface/#role-mapping) par groupe et par projet |

Détail : [prompts et outils](https://cyr-ius.github.io/security-review-mcp/fr/usage/prompts-tools/),
[scan du code complet](https://cyr-ius.github.io/security-review-mcp/fr/usage/code-scan/),
[dépendances](https://cyr-ius.github.io/security-review-mcp/fr/usage/dependencies/),
[gate](https://cyr-ius.github.io/security-review-mcp/fr/ci-cd/gate/),
[SARIF](https://cyr-ius.github.io/security-review-mcp/fr/ci-cd/sarif/),
[tendances](https://cyr-ius.github.io/security-review-mcp/fr/ci-cd/trends/).

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

Autres cas : [installation hors ligne](https://cyr-ius.github.io/security-review-mcp/fr/getting-started/installation/),
[Claude et autres hôtes](https://cyr-ius.github.io/security-review-mcp/fr/getting-started/host/),
[HTTP, authentification et TLS](https://cyr-ius.github.io/security-review-mcp/fr/getting-started/http/),
[Docker et Docker Compose avec PostgreSQL](https://cyr-ius.github.io/security-review-mcp/fr/getting-started/docker/),
[architecture et Kubernetes](https://cyr-ius.github.io/security-review-mcp/fr/getting-started/kubernetes/),
[variables `SECREVIEW_*`](https://cyr-ius.github.io/security-review-mcp/fr/reference/configuration/).

## Limites

Le scan par motifs produit des pistes, avec des faux positifs. Il ne remplace ni un SAST, ni une
analyse SCA complète, ni une relecture humaine. Voir
[sécurité et limites](https://cyr-ius.github.io/security-review-mcp/fr/reference/security/).

## Contribuer

```bash
uv sync --extra dev && uv run pytest && uv run ruff check .
```

Le développement se fait sur `dev`, et une version est publiée en poussant un tag `vX.Y.Z`
sur `master`. Voir le [guide de contribution](https://cyr-ius.github.io/security-review-mcp/fr/contributing/)
et [`AGENTS.md`](AGENTS.md) (consignes pour les agents IA).
