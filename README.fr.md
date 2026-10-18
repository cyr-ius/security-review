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
| **Outils** | checklists, `scan_code`, `scan_dependencies`, enregistrement et lecture des rapports, [propositions de statut](https://cyr-ius.github.io/security-review-mcp/fr/usage/prompts-tools/#statut-dun-finding) (`propose_finding_status` : un agent ne ferme jamais un finding), posture et gate projet, export SARIF, tendances, gestion des règles |
| **CLI** | `security-review-mcp` (serveur MCP, `enroll`, [`scan-deps`](https://cyr-ius.github.io/security-review-mcp/fr/advanced/dependencies/#scan-avec-un-serveur-partage-hook-de-commit) pour un hook de commit) et `security-review-controller` (`serve`, `db`, `code scan`, `deps scan`, `advisories`, `rules`, `token`, `user`, `audit`), codes de sortie 0 / 1 / 2 |
| **Pipelines** | [`security-review-ci`](https://cyr-ius.github.io/security-review-mcp/fr/usage/gate/#client-de-pipeline-security-review-ci) (`gate`, `sarif`, `trend`) : client léger de l'API REST pour Jenkins, GitLab ou GitHub, avec un jeton `ci` restreint aux projets sélectionnés, sans pilote de base |
| **Règles** | Plus de 120 règles et plus de 75 items de checklist : Python, Java, Angular / Node.js, Docker, Kubernetes, configuration, GitLab CI, Jenkins, Spring, FastAPI, copiés en base au premier lancement, plus vos [règles internes](https://cyr-ius.github.io/security-review-mcp/fr/advanced/rules/) (import/export TOML en CLI ou dans l'interface web) |
| **Normes de développement** | [conventions par technologie](https://cyr-ius.github.io/security-review-mcp/fr/advanced/standards/) gérées dans l'interface web (import/export TOML) et transmises à l'assistant IA avant qu'il code (prompt, outils `get_development_standards` / `list_development_standards`, ressources) |
| **Vulnérabilités** | manifestes, lockfiles et [SBOM CycloneDX](https://cyr-ius.github.io/security-review-mcp/fr/advanced/dependencies/#sbom-cyclonedx-dependances-transitives) comparés à une base OSV (PyPI, npm, Maven) importée hors ligne ou [mise à jour chaque jour par le contrôleur](https://cyr-ius.github.io/security-review-mcp/fr/advanced/dependencies/#mise-a-jour-automatique-par-le-controleur), proxy facultatif |
| **Transport** | HTTP (serveur partagé) ou stdio (mode local), avec jetons Bearer stockés en base (CLI `token`), avec [expiration et renouvellement](https://cyr-ius.github.io/security-review-mcp/fr/advanced/http/#expiration-et-renouvellement-des-jetons), et TLS (éventuellement mutuel) facultatifs |
| **Audit et métriques** | [journal d'audit](https://cyr-ius.github.io/security-review-mcp/fr/advanced/audit-metrics/#journal-daudit) des décisions de triage, des jetons et des enrôlements, et [métriques Prometheus](https://cyr-ius.github.io/security-review-mcp/fr/advanced/audit-metrics/#metriques-prometheus) sur `/metrics` (jeton `metrics`) |
| **Déploiement** | serveur MCP et contrôleur (API REST, interface web) [séparés](https://cyr-ius.github.io/security-review-mcp/fr/advanced/architecture/) sur une base partagée, migrations Alembic, exemples Docker Compose et Kubernetes |
| **Enrôlement** | un projet [demande son jeton ou un accès supplémentaire](https://cyr-ius.github.io/security-review-mcp/fr/advanced/http/#enrolement-un-projet-demande-son-jeton) (outil MCP `request_enrollment` ou CLI `enroll`), un administrateur valide la demande |
| **Interface web** | en anglais, français ou espagnol : tableau de bord, [triage par une personne](https://cyr-ius.github.io/security-review-mcp/fr/usage/web-interface/#triage-des-findings) (motif, approbateur et expiration des risques acceptés et faux positifs), [liste des findings ouverts par projet](https://cyr-ius.github.io/security-review-mcp/fr/usage/web-interface/#ecrans) pour une revue par un expert, gestion des [règles, checklists, jetons (par projet ou pour tous les projets), langue des rapports, proxy sortant (OSV et OIDC) et mises à jour OSV](https://cyr-ius.github.io/security-review-mcp/fr/usage/web-interface/), [comptes utilisateurs](https://cyr-ius.github.io/security-review-mcp/fr/usage/web-interface/#comptes-utilisateurs) locaux ou OIDC, seuls à ouvrir l'interface (les jetons servent au MCP et à l'API REST ; compte `admin` initial dans les logs), [connexion OIDC OpenID Connect](https://cyr-ius.github.io/security-review-mcp/fr/advanced/sso/) facultative, [configurable dans l'interface](https://cyr-ius.github.io/security-review-mcp/fr/advanced/sso/#configurer-le-sso-dans-linterface), avec création des comptes à la volée, et [rôles, groupes et permissions](https://cyr-ius.github.io/security-review-mcp/fr/advanced/access-control/) (groupes rapprochés par leur nom du claim des groupes OIDC, rôles par projet donnés aux groupes, jamais directement aux comptes) |

Détail : [prompts et outils](https://cyr-ius.github.io/security-review-mcp/fr/usage/prompts-tools/),
[scan du code complet](https://cyr-ius.github.io/security-review-mcp/fr/advanced/code-scan/),
[dépendances](https://cyr-ius.github.io/security-review-mcp/fr/advanced/dependencies/),
[gate](https://cyr-ius.github.io/security-review-mcp/fr/usage/gate/),
[SARIF](https://cyr-ius.github.io/security-review-mcp/fr/advanced/sarif/),
[tendances](https://cyr-ius.github.io/security-review-mcp/fr/advanced/trends/).

## Démarrage rapide

Le produit repose sur **deux services** qui partagent une base : le **serveur MCP**
(`security-review-mcp`), utilisé par les agents et la CI, et le **contrôleur**
(`security-review-controller`), utilisé par les personnes : interface web, API REST, jetons et
comptes. Voir [deux services, deux rôles](https://cyr-ius.github.io/security-review-mcp/fr/#deux-services-deux-roles).

```bash
pip install security-review-mcp        # Python ≥ 3.14 ; extra [postgres] pour PostgreSQL

# depuis le même répertoire (fichier SQLite partagé)
security-review-controller db upgrade                              # schéma (Alembic)
security-review-controller user create admin --group administrators   # compte de l'interface web
security-review-controller token create --label alice              # jeton de l'agent
security-review-controller serve --port 8080                       # interface /ui et API REST
security-review-mcp --transport streamable-http --port 8000        # endpoint /mcp

security-review-ci gate --url http://localhost:8080 --project portal  # bloquer un pipeline (jeton ci : SECREVIEW_TOKEN)
```

Configuration de l'hôte (VS Code avec jeton, `.vscode/mcp.json` ; Claude et `.mcp.json` : voir
[configuration de l'hôte](https://cyr-ius.github.io/security-review-mcp/fr/getting-started/host/)) :

```json
{
  "servers": {
    "security-review": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer ${input:secreview-token}" }
    }
  },
  "inputs": [
    { "id": "secreview-token", "type": "promptString", "description": "Token", "password": true }
  ]
}
```

Pas à pas : [mise en service du serveur](https://cyr-ius.github.io/security-review-mcp/fr/getting-started/deploy/),
[connexion de l'hôte](https://cyr-ius.github.io/security-review-mcp/fr/getting-started/host/) (VS Code, Claude, enrôlement).
Autres cas : [installation hors ligne](https://cyr-ius.github.io/security-review-mcp/fr/advanced/installation/),
[mode local stdio](https://cyr-ius.github.io/security-review-mcp/fr/advanced/stdio/),
[HTTP, authentification et TLS](https://cyr-ius.github.io/security-review-mcp/fr/advanced/http/),
[images Docker](https://cyr-ius.github.io/security-review-mcp/fr/advanced/docker/#images-publiees) (`ghcr.io/cyr-ius/security-review-mcp`, `docker.io/cyrius44/security-review-mcp`) et [Docker Compose avec PostgreSQL](https://cyr-ius.github.io/security-review-mcp/fr/advanced/docker/#docker-compose-avec-postgresql),
[architecture et Kubernetes](https://cyr-ius.github.io/security-review-mcp/fr/advanced/architecture/),
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

## Sécurité et licence

Signalez une vulnérabilité en privé, comme décrit dans [`SECURITY.md`](SECURITY.md). Le projet
est distribué sous [licence Apache 2.0](LICENSE).
