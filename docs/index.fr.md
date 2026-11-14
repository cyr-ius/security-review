# Security Review

**Le serveur Security Review effectue des revues de code sécurité assistées par l'IA en proposant
un serveur MCP.**

Security Review fait des assistants IA de vos développeurs des relecteurs sécurité qui
appliquent vos règles, et donne à votre équipe sécurité une vue centrale de tout ce qu'ils
trouvent.

Vos équipes écrivent déjà du code avec des assistants IA (GitHub Copilot, Claude, Cursor...).
Security Review se branche sur ces assistants par **MCP** (Model Context Protocol, le standard
ouvert qui permet à un assistant d'utiliser des outils externes). Chaque changement peut alors
être relu pour détecter les failles et les mauvaises configurations **au moment où le code est
écrit**, et chaque résultat est enregistré au même endroit, où votre équipe sécurité le lit, le
trie et en assure le suivi.

## Pourquoi l'adopter

- **La sécurité dès la première ligne de code.** Les failles sont trouvées dans l'éditeur, par
  le développeur, quand leur correction coûte le moins cher, et non des semaines plus tard lors
  d'un audit ou en production.
- **Vos exigences, appliquées par chaque assistant.** L'équipe sécurité gère au même endroit les
  [règles de scan](review/rules.md), les [checklists de revue](review/checklists.md) et les [normes de développement](review/standards.md) ; chaque assistant de
  chaque projet reçoit les mêmes, sans former chaque développeur.
- **Une vue centrale et durable.** Les rapports sont conservés dans une base de données (SQLite
  ou PostgreSQL). L'[interface web](usage/index.md) montre, pour chaque projet, les findings ouverts, la posture
  de sécurité et son évolution dans le temps ([rapport de tendance](advanced/architecture/ci.md#rapport-de-tendance)).
- **Les personnes décident, pas l'IA.** Un assistant peut seulement *proposer* de clore un
  finding. Une acceptation de risque ou un faux positif est décidé par une personne connectée,
  enregistrée comme approbateur ; une acceptation de risque porte aussi un motif et une date
  d'expiration, selon votre politique : chaque décision est traçable pour un
  audit ([triage des findings](usage/triage.md)).
- **Intégré à votre chaîne de livraison.** Une [gate](review/gate.md) bloque un déploiement tant que des findings
  graves restent ouverts ; les résultats s'exportent en [SARIF](advanced/reports/sarif.md) (GitHub code scanning, Jenkins) ;
  les [dépendances](review/analysis/dependencies.md) sont vérifiées avec une base de vulnérabilités OSV, même sans accès Internet.
- **Relié aux outils de l'entreprise.** [Authentification unique (OIDC)](usage/sso.md) avec votre fournisseur
  d'identité, [rôles et projets de chaque compte](usage/access-control.md), envoi des findings vers
  [Jira ou ServiceNow](usage/connectors/index.md),
  [journal d'audit transmis à syslog, métriques Prometheus](usage/audit-metrics.md).
- **Votre code reste chez vous.** Le produit est auto-hébergé : le serveur MCP n'établit aucune
  connexion sortante, les secrets sont masqués avant stockage, et il s'installe hors ligne. Il
  est open source (licence Apache 2.0). Voir [Sécurité et limites](reference/security.md).
- **Une large couverture.** Des règles pour Python (FastAPI), Java (Spring), TypeScript /
  Node.js, Angular, Go, C#, Rust, les fichiers de configuration et les pipelines CI (GitLab CI,
  Jenkins...), ainsi que la détection d'instructions cachées destinées aux assistants IA.

## Comment ça marche, en trois étapes

1. **Le développeur demande une revue** (« relis mes changements côté sécurité »). L'assistant
   suit la méthode de revue du serveur : prompts, checklists, scan par motifs.
2. **L'assistant enregistre son rapport** : chaque finding avec sa sévérité, son fichier, sa
   preuve et une recommandation.
3. **L'équipe sécurité trie** les findings dans l'interface web, et le pipeline vérifie avec la
   gate qu'aucun finding grave ne reste ouvert avant de déployer.

## Par où continuer

La documentation suit l'ordre d'une mise en œuvre. **Démarrage**, **Revue de sécurité** et
**Application** contiennent ce qu'il faut pour travailler ; **Avancé** regroupe les détails et les fonctions facultatives.

| Étape | Page |
|---|---|
| 1. Déployer le serveur Controller et le serveur MCP (Docker Compose ou Kubernetes), créer les premiers comptes | [Mise en service du serveur](getting-started/deploy.md) |
| 2. Connecter VS Code ou Claude, obtenir un jeton | [Connexion de l'hôte](getting-started/host.md) |
| 3. Demander à l'agent de faire les revues et de suivre les normes | [Le fichier AGENTS.md](getting-started/agents-md.md) |
| 4. Lancer une revue | [Fonctionnement d'une revue](review/index.md) (règles, checklists), [Prompts et outils](reference/prompts-tools.md) |
| 5. Consulter et trier les rapports | [Interface web](usage/index.md) |
| 6. Bloquer un déploiement sur des findings ouverts | [Gate](review/gate.md) |

| Pour aller plus loin (Avancé) | Page |
|---|---|
| Docker, Kubernetes, PostgreSQL, sans conteneur | [Architecture](advanced/architecture/index.md), [Docker](advanced/deployment/docker.md), [Kubernetes](advanced/deployment/kubernetes.md), [Installation manuelle](advanced/deployment/manual-install.md) |
| Jetons restreints à un projet, enrôlement, renouvellement, TLS | [Jetons Bearer](advanced/bearer-tokens.md), [Enrôlement](advanced/architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet), [TLS](advanced/tls.md) |
| Se connecter avec le fournisseur d'identité de l'entreprise | [Connexion OIDC](usage/sso.md) |
| Scanner tout un dépôt, les dépendances, ajouter les règles de mon entreprise | [Analyse du code complet](review/analysis/code-scan.md), [Analyse des dépendances](review/analysis/dependencies.md), [Règles](review/rules.md) |
| SARIF, tendances, journal d'audit, Prometheus | [Export SARIF](advanced/reports/sarif.md), [Rapport de tendance](advanced/architecture/ci.md#rapport-de-tendance), [Journal d'audit](usage/audit-metrics.md), [Métriques Prometheus](reference/metrics.md) |

!!! warning "Ce que couvre l'analyse statique"
    Avec le [moteur OpenGrep](review/analysis/opengrep.md) (image `-opengrep`), Security Review
    fait une **analyse statique (SAST)** qui suit le flux de données dans un fichier, d'une
    fonction à l'autre : 147 règles, dont 60 de propagation (taint), sur Java, Python,
    JavaScript/TypeScript, C#, Go et Rust,
    [mesurées sur l'OWASP Benchmark](reference/detection-benchmark.md). Sans lui, le scan par
    motifs ne produit que des **pistes**, avec des faux positifs. Aucun des deux ne suit un flux
    d'un fichier à l'autre, ni ne voit la logique métier ou un contrôle absent :
    cela reste le travail de la revue par l'IA et d'une relecture humaine. Ce n'est pas non plus
    une analyse SCA complète. Voir [Sécurité et limites](reference/security.md).
