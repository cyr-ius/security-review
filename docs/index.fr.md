# Security Review

**Security Review fait des assistants IA de vos développeurs des relecteurs sécurité qui
appliquent vos règles, et donne à votre équipe sécurité une vue centrale de tout ce qu'ils
trouvent.**

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
  d'identité, [groupes et rôles](usage/access-control.md), envoi des findings vers
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

## Ce que contient le produit

Un **serveur MCP** pour la **revue de code orientée sécurité** (failles et mauvaises
configurations). Il fournit à l'hôte (VS Code, Copilot, Claude, agent CI/CD) :

- des **prompts** structurés pour lancer une revue ;
- des **outils** : checklists, scan rapide par motifs, enregistrement et consultation de rapports ;
- une **base de données** (SQLite par défaut, PostgreSQL possible) qui stocke les rapports et
  leurs findings.

via la commande `security-review-mcp`

Un **serveur Controller** qui permet l'**administration et la gestion des contrôles** (le Controller est facultatif)
Il fournit aux administrateurs et analystes en cybersécurité :

 - la **consultation des rapports** d'analyse de sécurité
 - la possibilité d'effectuer des **revues de sécurité** et d'**acceptation de risque**
 - l'ajout, la modification et la suppression des **règles et des checklists**
 - l'ajout de **standards de développement**
 - la **gestion** de vos communautés de développeurs
 - des **connecteurs** tiers pour assurer un suivi (Jira, Service Now, ...)

via la commande `security-review-controller`

Une **commande CI** pour l'injection dans les pipelines (tels que Jenkins, etc.) et permet :

 - **scan du dépôt** complet
 - **gate** de déploiement avec blocage si des findings sont ouverts
 - export SARIF et **rapport** de tendance
 - **analyse des dépendances**

via la commande `security-review-ci`

## Démarrage rapide (mode partagé)

Le dépôt fournit un fichier `docker-compose.yml` prêt à l'emploi dans `examples/docker/`. Ce
bloc démarre tout (PostgreSQL, serveur Controller, serveur MCP), réinitialise le mot de passe du compte
`admin` et crée un jeton pour votre agent :

```bash
mkdir security-review-mcp && cd security-review-mcp
curl -fsSLO https://raw.githubusercontent.com/cyr-ius/security-review/{{ release_tag }}/examples/docker/docker-compose.yml
(umask 077 && printf 'POSTGRES_PASSWORD=%s\nSECREVIEW_SECRET_KEY=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" > .env)
docker compose up -d --wait
docker compose exec controller security-review-controller user reset-password admin   # mot de passe affiché une fois
docker compose exec controller security-review-controller token create --label alice   # jeton mcp, affiché une fois
# interface web : http://127.0.0.1:8080/ui/   endpoint MCP : http://127.0.0.1:8000/mcp
```

Déclarez ensuite le serveur MCP dans votre hôte, par exemple dans VS Code avec
`.vscode/mcp.json` (le seul fichier où VS Code peut demander le jeton), et collez le jeton
quand VS Code le demande :

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

Dans le chat, lancez le prompt `security-review` (ou `codebase-review` pour tout le dépôt).
L'agent lit le code, s'appuie sur les checklists et enregistre son rapport avec
`save_security_report`.
Connectez-vous à l'interface web avec le compte `admin` pour le consulter et le trier.

Les ports sont ouverts sur toutes les interfaces du serveur, en HTTP simple. Avant que l'équipe
s'en serve, pensez à mettre en œuvre vos certificats pour activer le HTTPS. Voir [Mise en service du serveur](getting-started/deploy.md).

## Par où continuer

La documentation suit l'ordre d'une mise en œuvre. **Démarrage**, **Revue de sécurité** et
**Application** contiennent ce qu'il faut pour travailler ; **Avancé** regroupe les détails et les fonctions facultatives.

| Étape | Page |
|---|---|
| 1. Déployer le serveur Controller et le serveur MCP (Docker Compose ou Kubernetes), créer les premiers comptes | [Mise en service du serveur](getting-started/deploy.md) |
| 2. Connecter VS Code ou Claude, obtenir un jeton | [Connexion de l'hôte](getting-started/host.md) |
| 3. Lancer une revue | [Fonctionnement d'une revue](review/index.md) (règles, checklists, `AGENTS.md`), [Prompts et outils](review/prompts-tools.md) |
| 4. Consulter et trier les rapports | [Interface web](usage/index.md) |
| 5. Bloquer un déploiement sur des findings ouverts | [Gate](review/gate.md) |

| Pour aller plus loin (Avancé) | Page |
|---|---|
| Docker, Kubernetes, PostgreSQL, sans conteneur | [Architecture](advanced/architecture/index.md), [Docker](advanced/deployment/docker.md), [Kubernetes](advanced/deployment/kubernetes.md), [Installation manuelle](advanced/deployment/manual-install.md) |
| Jetons restreints à un projet, enrôlement, renouvellement, TLS | [Jetons Bearer](advanced/bearer-tokens.md), [Enrôlement](advanced/architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet), [TLS](advanced/tls.md) |
| Se connecter avec le fournisseur d'identité de l'entreprise | [Connexion OIDC](usage/sso.md) |
| Scanner tout un dépôt, les dépendances, ajouter les règles de mon entreprise | [Analyse du code complet](review/analysis/code-scan.md), [Analyse des dépendances](review/analysis/dependencies.md), [Règles](review/rules.md) |
| SARIF, tendances, journal d'audit, Prometheus | [Export SARIF](advanced/reports/sarif.md), [Rapport de tendance](advanced/architecture/ci.md#rapport-de-tendance), [Journal d'audit](usage/audit-metrics.md), [Métriques Prometheus](reference/metrics.md) |

!!! warning "Ce n'est pas un SAST"
    Le scan par motifs produit des **pistes** et des faux positifs. Il ne remplace ni un SAST,
    ni une analyse SCA complète, ni une relecture humaine. Voir
    [Sécurité et limites](reference/security.md).
