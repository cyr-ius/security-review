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
[docker::pulls]: https://img.shields.io/docker/pulls/cyrius44/security-review.svg?logo=docker
[docker::hub]: https://hub.docker.com/r/cyrius44/security-review
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
| **Outils** | checklists, `scan_code`, `scan_dependencies`, enregistrement et lecture des rapports avec leur [couverture de checklist](https://cyr-ius.github.io/security-review/fr/review/prompts-tools/#couverture-de-la-revue) (regroupés par un [nom de projet normalisé](https://cyr-ius.github.io/security-review/fr/review/prompts-tools/#nom-du-projet)), [propositions de statut](https://cyr-ius.github.io/security-review/fr/review/prompts-tools/#statut-dun-finding) (`propose_finding_status` : un agent ne ferme jamais un finding), posture et gate projet, export SARIF, tendances, gestion des règles |
| **CLI** | `security-review-mcp` (serveur MCP : `serve`, `local` pour le mode local) et `security-review-controller` (`serve`, `db`, `advisories`, `rules`, `token`, `user`, `audit`), codes de sortie 0 / 1 / 2 |
| **Pipelines** | [`security-review-ci`](https://cyr-ius.github.io/security-review/fr/advanced/architecture/ci/) (`gate`, `sarif`, `trend`, [`scan-code`](https://cyr-ius.github.io/security-review/fr/review/analysis/code-scan/), [`scan-deps`](https://cyr-ius.github.io/security-review/fr/review/analysis/dependencies/#scan-dans-un-pipeline-security-review-ci-scan-deps), qui enregistrent leurs rapports par l'API) : client léger de l'API REST pour Jenkins, GitLab ou GitHub, avec un jeton `ci` restreint aux projets sélectionnés, sans pilote de base, [installé seul](https://cyr-ius.github.io/security-review/fr/advanced/architecture/ci/#installation) sans Python (`uv tool install security-review-ci`, ou [depuis le serveur Controller](https://cyr-ius.github.io/security-review/fr/advanced/architecture/ci/#depuis-le-serveur-controller) sans PyPI) ; sur un poste de travail (hook de commit), avec un [jeton `ci` personnel](https://cyr-ius.github.io/security-review/fr/review/analysis/dependencies/#scan-depuis-un-poste-de-travail-hook-de-commit) ; [`agent-review`](https://cyr-ius.github.io/security-review/fr/advanced/architecture/ci/#revue-de-chaque-commit-par-un-agent) : revue de chaque commit par l'agent de code du développeur (Claude Code, Copilot ou Codex) |
| **Règles** | Plus de 200 règles et plus de 120 items de checklist : Python, Java, Go, C#, Rust, backend TypeScript / Node.js, Angular, Docker, Kubernetes, configuration, GitLab CI, Jenkins, Spring, FastAPI, [injection de prompt visant les assistants IA](https://cyr-ius.github.io/security-review/fr/review/rules/#regles-par-defaut-par-plateforme) (caractères cachés, instructions injectées ; [garde de lecture](https://cyr-ius.github.io/security-review/fr/review/analysis/read-guard/) `security-review-ci guard`, hook pour Claude Code, Copilot ou Codex), copiés en base au premier lancement, plus vos propres [règles](https://cyr-ius.github.io/security-review/fr/review/rules/) et [checklists](https://cyr-ius.github.io/security-review/fr/review/checklists/) (import/export TOML en CLI ou dans l'interface web) |
| **Normes de développement** | [conventions par technologie](https://cyr-ius.github.io/security-review/fr/review/standards/) gérées dans l'interface web (import/export TOML) et transmises à l'assistant IA avant qu'il code (prompt, outils `get_development_standards` / `list_development_standards`, ressources) |
| **Vulnérabilités** | manifestes, lockfiles et [SBOM CycloneDX](https://cyr-ius.github.io/security-review/fr/review/analysis/dependencies/#sbom-cyclonedx-dependances-transitives) comparés à une base OSV (PyPI, npm, Maven, Go, crates.io, NuGet) importée hors ligne ou [mise à jour chaque jour par le serveur Controller](https://cyr-ius.github.io/security-review/fr/review/analysis/dependencies/#mise-a-jour-automatique-par-le-serveur-controller), proxy facultatif |
| **Transport** | HTTP (mode partagé) ou stdio (mode local), avec jetons Bearer stockés en base (CLI `token`), avec [expiration et renouvellement](https://cyr-ius.github.io/security-review/fr/advanced/bearer-tokens/#expiration-et-renouvellement-des-jetons), et [TLS](https://cyr-ius.github.io/security-review/fr/advanced/tls/) (éventuellement mutuel) |
| **Audit et métriques** | [journal d'audit](https://cyr-ius.github.io/security-review/fr/usage/audit-metrics/) des décisions de triage, des jetons et des demandes de projet, et [métriques Prometheus](https://cyr-ius.github.io/security-review/fr/reference/metrics/) sur `/metrics` (jeton `metrics`) |
| **Connecteurs** | [findings envoyés vers d'autres outils](https://cyr-ius.github.io/security-review/fr/usage/connectors/) : Jira et ServiceNow intégrés, [connecteurs tiers](https://cyr-ius.github.io/security-review/fr/usage/connectors/third-party/) pour tout autre système (registre de vulnérabilités, GRC...) ; chaque connecteur activé dans l'interface web, à la main ou automatiquement au-dessus d'un seuil de sévérité, un enregistrement par problème |
| **Déploiement** | serveur MCP et serveur Controller (API REST, interface web) [séparés](https://cyr-ius.github.io/security-review/fr/advanced/architecture/) sur une base partagée, migrations Alembic, exemples Docker Compose et Kubernetes |
| **Enrôlement** | un client MCP sans jeton est [invité à créer un jeton MCP personnel](https://cyr-ius.github.io/security-review/fr/advanced/architecture/mcp-server/#enrolement-jeton-personnel-et-demande-de-projet) dans l'interface web ; ensuite l'outil MCP `request_project` crée le projet de la revue, ou le demande (ou l'accès à un projet existant) pour qu'un administrateur le valide, ce qui en donne l'accès à l'utilisateur ; un jeton refusé reçoit un `401` qui indique comment en obtenir un nouveau |
| **Connexion OAuth** | facultative, activée depuis l'interface web : l'hôte MCP n'a besoin d'aucun jeton, il [se connecte par le navigateur](https://cyr-ius.github.io/security-review/fr/advanced/mcp-oauth/) (OAuth 2.1 avec PKCE, le serveur Controller comme serveur d'autorisation) et agit comme un jeton MCP personnel de l'utilisateur |
| **Interface web** | en anglais, français ou espagnol : tableau de bord, [triage par une personne](https://cyr-ius.github.io/security-review/fr/usage/triage/) (approbateur des risques acceptés et faux positifs, motif et expiration des risques acceptés), [acceptations de risque](https://cyr-ius.github.io/security-review/fr/usage/triage/#acceptations-de-risque) à renouveler ou supprimer, avec commentaires en ajout seul, [liste des findings ouverts par projet](https://cyr-ius.github.io/security-review/fr/usage/#pages) pour une revue par un expert, gestion des [règles, checklists, jetons (par projet ou pour tous les projets), paramètres généraux (langue des rapports, adresse du serveur Controller), proxy sortant (OSV et OIDC) et mises à jour OSV](https://cyr-ius.github.io/security-review/fr/usage/), [comptes utilisateurs](https://cyr-ius.github.io/security-review/fr/usage/user-accounts/) locaux ou OIDC, seuls à ouvrir l'interface (les jetons sont destinés aux machines : agents MCP, pipelines, scripts ; [jetons API](https://cyr-ius.github.io/security-review/fr/usage/tokens/#jetons-api) personnels ou de rôle pour l'API REST et le Swagger, [jetons MCP personnels](https://cyr-ius.github.io/security-review/fr/usage/tokens/#jetons-mcp-et-ci-personnels) sur les projets de l'utilisateur, avec le rôle `mcp-user` ; compte `admin` initial dans les logs), [connexion OIDC OpenID Connect](https://cyr-ius.github.io/security-review/fr/usage/sso/) facultative, [configurable dans l'interface](https://cyr-ius.github.io/security-review/fr/usage/sso/#configurer-le-oidc-dans-linterface), avec création des comptes à la volée, et [rôles, groupes et permissions](https://cyr-ius.github.io/security-review/fr/usage/access-control/) (groupes rapprochés par leur nom du claim des groupes OIDC, rôles par projet donnés aux groupes, jamais directement aux comptes) |

Détail : [fonctionnement d'une revue](https://cyr-ius.github.io/security-review/fr/review/) (règles, checklists, normes, `AGENTS.md`),
[prompts et outils](https://cyr-ius.github.io/security-review/fr/review/prompts-tools/),
[analyse du code complet](https://cyr-ius.github.io/security-review/fr/review/analysis/code-scan/),
[dépendances](https://cyr-ius.github.io/security-review/fr/review/analysis/dependencies/),
[gate](https://cyr-ius.github.io/security-review/fr/review/gate/),
[SARIF](https://cyr-ius.github.io/security-review/fr/advanced/reports/sarif/),
[tendances](https://cyr-ius.github.io/security-review/fr/advanced/architecture/ci/#rapport-de-tendance).

## Démarrage rapide

Le produit repose sur **deux services** qui partagent une base : le **serveur MCP**
(`security-review-mcp`), utilisé par les agents et la CI, et le **serveur Controller**
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

security-review-ci gate --url http://localhost:8080 --project portal  # bloquer un pipeline (jeton ci : SECREVIEW_CI_TOKEN)
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
Autres cas : [installation hors ligne](https://cyr-ius.github.io/security-review/fr/advanced/deployment/installation/),
[mode local (stdio)](https://cyr-ius.github.io/security-review/fr/getting-started/stdio/),
[Jetons Bearer](https://cyr-ius.github.io/security-review/fr/advanced/bearer-tokens/), [TLS](https://cyr-ius.github.io/security-review/fr/advanced/tls/),
[images Docker](https://cyr-ius.github.io/security-review/fr/advanced/deployment/docker/#images-publiees) (`ghcr.io/cyr-ius/security-review`, `docker.io/cyrius44/security-review`) et [Docker Compose avec PostgreSQL](https://cyr-ius.github.io/security-review/fr/advanced/deployment/docker/#docker-compose-avec-postgresql),
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
