![Security Review MCP : un finding signalé dans le code](https://raw.githubusercontent.com/cyr-ius/security-review/master/docs/assets/banner.svg)

# Security Review MCP

![licence] ![Python] ![Angular] [![ci::status]][ci::github] [![pypi::version]][pypi::web] [![docker::pulls]][docker::hub] [![documentation::badge]][documentation::web]

[licence]: https://img.shields.io/github/license/cyr-ius/security-review?label=Licence&color=blue
[python]: https://img.shields.io/badge/Python-3.14%2B-blue?logo=python
[angular]: https://img.shields.io/badge/Angular-22-blue?logo=angular
[ci::status]: https://img.shields.io/github/actions/workflow/status/cyr-ius/security-review/tests.yml?branch=dev&label=Tests&color=blue&logo=github
[ci::github]: https://github.com/cyr-ius/security-review/actions
[pypi::version]: https://img.shields.io/pypi/v/security-review?color=blue&logo=pypi&logoColor=white
[pypi::web]: https://pypi.org/project/security-review/
[docker::pulls]: https://img.shields.io/docker/pulls/cyrius44/security-review-mcp.svg?logo=docker
[docker::hub]: https://hub.docker.com/r/cyrius44/security-review-mcp
[documentation::badge]: https://img.shields.io/badge/Documentation-MkDocs-green?logo=materialformkdocs
[documentation::web]: https://cyr-ius.github.io/security-review/fr/

Serveur MCP pour la **revue de code orientée sécurité** (failles et mauvaises configurations),
utilisable depuis VS Code / Copilot, Claude ou un agent CI/CD. Il fournit des prompts de revue,
des checklists, un scan par motifs avec des analyses Tree-sitter ciblées des flux requête vers SQL (Python, Java, Go, C#, Rust, Node.js), DOM Angular et origines de messages non vérifiées,
une analyse de dépendances hors ligne et une base de rapports (SQLite ou PostgreSQL) exploitable
en pipeline.

📖 **Documentation complète : <https://cyr-ius.github.io/security-review/fr/>**

🇬🇧 [English version](README.md)

## Capacités

| | |
|---|---|
| **Prompts** | `security-review`, `api-security-review`, `configuration-review`, `codebase-review`, `dependency-review`, `triage-report`, `development-standards` |
| **Outils** | checklists, `scan_code`, `scan_dependencies`, enregistrement et lecture des rapports avec leur [couverture de checklist](https://cyr-ius.github.io/security-review/fr/usage/prompts-tools/#couverture-de-la-revue) (regroupés par un [nom de projet normalisé](https://cyr-ius.github.io/security-review/fr/usage/prompts-tools/#nom-du-projet)), [propositions de statut](https://cyr-ius.github.io/security-review/fr/usage/prompts-tools/#statut-dun-finding) (`propose_finding_status` : un agent ne ferme jamais un finding), posture et gate projet, export SARIF, tendances, gestion des règles |
| **CLI** | `security-review-mcp` (serveur MCP, `enroll`) et `security-review-controller` (`serve`, `db`, `advisories`, `rules`, `token`, `user`, `audit`), codes de sortie 0 / 1 / 2 |
| **Pipelines** | [`security-review-ci`](https://cyr-ius.github.io/security-review/fr/usage/gate/#client-de-pipeline-security-review-ci) (`gate`, `sarif`, `trend`, [`scan-code`](https://cyr-ius.github.io/security-review/fr/advanced/code-scan/), [`scan-deps`](https://cyr-ius.github.io/security-review/fr/advanced/dependencies/#scan-dans-un-pipeline-security-review-ci-scan-deps), qui enregistrent leurs rapports par l'API) : client léger de l'API REST pour Jenkins, GitLab ou GitHub, avec un jeton `ci` restreint aux projets sélectionnés, sans pilote de base, [installé seul](https://cyr-ius.github.io/security-review/fr/usage/gate/#installation) sans Python (`uv tool install security-review-ci`) ; sur un poste de travail (hook de commit), avec un [jeton `mcp` ou `ci` personnel](https://cyr-ius.github.io/security-review/fr/advanced/dependencies/#scan-depuis-un-poste-de-travail-hook-de-commit) |
| **Règles** | Plus de 200 règles et plus de 120 items de checklist : Python, Java, Go, C#, Rust, backend TypeScript / Node.js, Angular, Docker, Kubernetes, configuration, GitLab CI, Jenkins, Spring, FastAPI, [injection de prompt visant les assistants IA](https://cyr-ius.github.io/security-review/fr/usage/rules/#regles-par-defaut-par-plateforme) (caractères cachés, instructions injectées ; hook de [garde de lecture](https://cyr-ius.github.io/security-review/fr/advanced/read-guard/) pour Claude Code), copiés en base au premier lancement, plus vos propres [règles](https://cyr-ius.github.io/security-review/fr/usage/rules/) et [checklists](https://cyr-ius.github.io/security-review/fr/usage/checklists/) (import/export TOML en CLI ou dans l'interface web) |
| **Normes de développement** | [conventions par technologie](https://cyr-ius.github.io/security-review/fr/usage/standards/) gérées dans l'interface web (import/export TOML) et transmises à l'assistant IA avant qu'il code (prompt, outils `get_development_standards` / `list_development_standards`, ressources) |
| **Vulnérabilités** | manifestes, lockfiles et [SBOM CycloneDX](https://cyr-ius.github.io/security-review/fr/advanced/dependencies/#sbom-cyclonedx-dependances-transitives) comparés à une base OSV (PyPI, npm, Maven, Go, crates.io, NuGet) importée hors ligne ou [mise à jour chaque jour par le contrôleur](https://cyr-ius.github.io/security-review/fr/advanced/dependencies/#mise-a-jour-automatique-par-le-controleur), proxy facultatif |
| **Transport** | HTTP (mode partagé) ou stdio (mode local), avec jetons Bearer stockés en base (CLI `token`), avec [expiration et renouvellement](https://cyr-ius.github.io/security-review/fr/advanced/http/#expiration-et-renouvellement-des-jetons), et TLS (éventuellement mutuel) facultatifs |
| **Audit et métriques** | [journal d'audit](https://cyr-ius.github.io/security-review/fr/advanced/audit-metrics/#journal-daudit) des décisions de triage, des jetons et des enrôlements, et [métriques Prometheus](https://cyr-ius.github.io/security-review/fr/advanced/audit-metrics/#metriques-prometheus) sur `/metrics` (jeton `metrics`) |
| **Connecteurs** | [findings envoyés vers d'autres outils](https://cyr-ius.github.io/security-review/fr/connectors/) : Jira et ServiceNow intégrés, [connecteurs tiers](https://cyr-ius.github.io/security-review/fr/connectors/third-party/) pour tout autre système (registre de vulnérabilités, GRC...) ; chaque connecteur activé dans l'interface web, à la main ou automatiquement au-dessus d'un seuil de sévérité, un enregistrement par problème |
| **Déploiement** | serveur MCP et contrôleur (API REST, interface web) [séparés](https://cyr-ius.github.io/security-review/fr/advanced/architecture/) sur une base partagée, migrations Alembic, exemples Docker Compose et Kubernetes |
| **Enrôlement** | un client MCP sans jeton [demande son projet](https://cyr-ius.github.io/security-review/fr/advanced/http/#enrolement-demander-le-projet) (outil MCP `request_enrollment` ou CLI `enroll`), un administrateur le valide, puis l'utilisateur crée un jeton MCP personnel dans l'interface web ; un jeton refusé reçoit un `401` qui indique comment en obtenir un nouveau |
| **Interface web** | en anglais, français ou espagnol : tableau de bord, [triage par une personne](https://cyr-ius.github.io/security-review/fr/usage/web-interface/#triage-des-findings) (approbateur des risques acceptés et faux positifs, motif et expiration des risques acceptés), [acceptations de risque](https://cyr-ius.github.io/security-review/fr/usage/web-interface/#acceptations-de-risque) à renouveler ou supprimer, avec commentaires en ajout seul, [liste des findings ouverts par projet](https://cyr-ius.github.io/security-review/fr/usage/web-interface/#ecrans) pour une revue par un expert, gestion des [règles, checklists, jetons (par projet ou pour tous les projets), langue des rapports, proxy sortant (OSV et OIDC) et mises à jour OSV](https://cyr-ius.github.io/security-review/fr/usage/web-interface/), [comptes utilisateurs](https://cyr-ius.github.io/security-review/fr/usage/web-interface/#comptes-utilisateurs) locaux ou OIDC, seuls à ouvrir l'interface (les jetons sont destinés aux machines : agents MCP, pipelines, scripts ; [jetons API](https://cyr-ius.github.io/security-review/fr/usage/web-interface/#jetons-api) personnels ou de rôle pour l'API REST et le Swagger, [jetons MCP personnels](https://cyr-ius.github.io/security-review/fr/usage/web-interface/#jetons-mcp-personnels) sur les projets de l'utilisateur, avec le rôle `mcp-user` ; compte `admin` initial dans les logs), [connexion OIDC OpenID Connect](https://cyr-ius.github.io/security-review/fr/advanced/sso/) facultative, [configurable dans l'interface](https://cyr-ius.github.io/security-review/fr/advanced/sso/#configurer-le-sso-dans-linterface), avec création des comptes à la volée, et [rôles, groupes et permissions](https://cyr-ius.github.io/security-review/fr/advanced/access-control/) (groupes rapprochés par leur nom du claim des groupes OIDC, rôles par projet donnés aux groupes, jamais directement aux comptes) |

Détail : [fonctionnement d'une revue](https://cyr-ius.github.io/security-review/fr/usage/how-it-works/) (règles, checklists, normes, `AGENTS.md`),
[prompts et outils](https://cyr-ius.github.io/security-review/fr/usage/prompts-tools/),
[scan du code complet](https://cyr-ius.github.io/security-review/fr/advanced/code-scan/),
[dépendances](https://cyr-ius.github.io/security-review/fr/advanced/dependencies/),
[gate](https://cyr-ius.github.io/security-review/fr/usage/gate/),
[SARIF](https://cyr-ius.github.io/security-review/fr/advanced/sarif/),
[tendances](https://cyr-ius.github.io/security-review/fr/advanced/trends/).

## Démarrage rapide

Le produit repose sur **deux services** qui partagent une base : le **serveur MCP**
(`security-review-mcp`), utilisé par les agents et la CI, et le **contrôleur**
(`security-review-controller`), utilisé par les personnes : interface web, API REST, jetons et
comptes. Voir [deux services, deux rôles](https://cyr-ius.github.io/security-review/fr/#deux-services-deux-roles).

```bash
uv venv && source .venv/bin/activate
uv pip install security-review         # Python ≥ 3.14 ; extra [postgres] pour PostgreSQL

# depuis le même répertoire (fichier SQLite partagé)
security-review-controller db upgrade                              # schéma (Alembic)
security-review-controller user create admin --group administrators   # compte de l'interface web
security-review-controller token create --label alice              # jeton de l'agent
security-review-controller serve --port 8080                       # interface /ui et API REST
security-review-mcp serve --port 8000                              # endpoint /mcp (HTTP streamable)

security-review-ci gate --url http://localhost:8080 --project portal  # bloquer un pipeline (jeton ci : SECREVIEW_TOKEN)
```

Configuration de l'hôte (VS Code avec jeton, `.vscode/mcp.json` ; Claude et `.mcp.json` : voir
[configuration de l'hôte](https://cyr-ius.github.io/security-review/fr/getting-started/host/)) :

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

Pas à pas : [mise en service du serveur](https://cyr-ius.github.io/security-review/fr/getting-started/deploy/),
[connexion de l'hôte](https://cyr-ius.github.io/security-review/fr/getting-started/host/) (VS Code, Claude, enrôlement).
Autres cas : [installation hors ligne](https://cyr-ius.github.io/security-review/fr/advanced/installation/),
[mode local (stdio)](https://cyr-ius.github.io/security-review/fr/getting-started/stdio/),
[HTTP, authentification et TLS](https://cyr-ius.github.io/security-review/fr/advanced/http/),
[images Docker](https://cyr-ius.github.io/security-review/fr/advanced/docker/#images-publiees) (`ghcr.io/cyr-ius/security-review`, `docker.io/cyrius44/security-review`) et [Docker Compose avec PostgreSQL](https://cyr-ius.github.io/security-review/fr/advanced/docker/#docker-compose-avec-postgresql),
[architecture et Kubernetes](https://cyr-ius.github.io/security-review/fr/advanced/architecture/),
[variables `SECREVIEW_*`](https://cyr-ius.github.io/security-review/fr/reference/configuration/).

## Limites

Le scan produit des pistes, avec des faux positifs. Ses analyses Tree-sitter ne couvrent que des flux
locaux simples, dans un seul fichier. Il ne remplace ni un SAST ou une analyse SCA complète, ni une relecture humaine. Voir
[sécurité et limites](https://cyr-ius.github.io/security-review/fr/reference/security/).

## Contribuer

```bash
uv sync --extra dev && uv run pytest && uv run ruff check .
```

Le développement se fait sur `dev`, et une version est publiée en poussant un tag `vX.Y.Z`
sur `master`. Voir le [guide de contribution](https://cyr-ius.github.io/security-review/fr/contributing/)
et [`AGENTS.md`](AGENTS.md) (consignes pour les agents IA).

## Sécurité et licence

Signalez une vulnérabilité en privé, comme décrit dans [`SECURITY.md`](SECURITY.md). Le projet
est distribué sous [licence Apache 2.0](LICENSE).
