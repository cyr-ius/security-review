# security-review-mcp

Serveur MCP pour la **revue de code orientée sécurité** (failles et mauvaises configurations).
Il fournit à l'hôte (VS Code, Copilot, Claude, agent CI/CD) :

- des **prompts** structurés pour lancer une revue ;
- des **outils** : checklists, scan rapide par motifs, enregistrement et consultation de rapports ;
- une **base de données** (SQLite par défaut, PostgreSQL possible) qui stocke les rapports et
  leurs findings.

Il s'accompagne d'une **ligne de commande** pour les pipelines : scan du dépôt complet, gate de
déploiement, export SARIF, analyse des dépendances et rapport de tendance.

## Deux services, deux rôles

Le produit se compose de **deux programmes**, installés par le même paquet. Ils ne s'appellent
jamais : ils partagent la même **base de données**, où sont stockés les rapports, les règles et
les jetons.

```text
 agents (VS Code, Claude), CI ─────▶ serveur MCP ──┐
                                                   ├──▶ base de données (SQLite ou PostgreSQL)
 personnes (navigateur), admins ──▶ contrôleur ────┘
```

| | Serveur MCP | Contrôleur |
|---|---|---|
| Commande | `security-review-mcp` | `security-review-controller` |
| Utilisé par | les agents IA et les pipelines CI | les personnes : équipe sécurité, développeurs, administrateurs |
| Ce qu'il fait | fournit à l'agent les prompts de revue, les checklists, le scan par motifs, et enregistre ses rapports | affiche et trie les rapports dans l'**interface web** (`/ui/`), sert l'API REST, crée le schéma, gère les jetons et les comptes utilisateurs |
| Exposition | aux agents et à la CI (endpoint `/mcp`) | de préférence sur un réseau interne |

En résumé : **l'agent parle au serveur MCP, les personnes utilisent le contrôleur.** Pour une
équipe, on déploie **les deux** : sans contrôleur, personne ne peut lire les rapports dans un
navigateur, décider d'un finding, ni créer les jetons des agents.

!!! tip "Quel mode choisir ?"
    - **Serveur partagé (HTTP)**, le cas recommandé : le serveur MCP et le contrôleur tournent
      sur une machine ou dans des conteneurs, chaque développeur et chaque pipeline s'y
      connecte avec un jeton, et les rapports sont centralisés. Commencez par là.
    - **Mode local (stdio)**, réservé à des cas précis : l'hôte (VS Code, Claude) lance
      lui-même `security-review-mcp` sur le poste du développeur, sans réseau, sans jeton ni
      contrôleur. Pratique pour essayer les prompts seul ou hors ligne, mais les rapports
      restent dans une base locale que personne d'autre ne voit. Voir
      [Mode local (stdio)](advanced/stdio.md).

## Démarrage rapide (serveur HTTP)

Sur une machine, depuis le **même répertoire** (les deux processus partagent le fichier SQLite
`./security_reports.db` ; passez à PostgreSQL dès qu'ils tournent sur des machines
différentes) :

```bash
pip install security-review-mcp

# 1. Contrôleur : schéma, premier administrateur, jeton de l'agent
security-review-controller db upgrade
security-review-controller user create admin --role admin   # mot de passe affiché une fois
security-review-controller token create --label alice      # jeton mcp, affiché une fois

# 2. Lancer les deux services (deux terminaux)
security-review-controller serve --host 127.0.0.1 --port 8080
# interface web : http://127.0.0.1:8080/ui/
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
# endpoint MCP : http://127.0.0.1:8000/mcp
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

Dans le chat, lancez le prompt `security-review` (ou `codebase-review` pour tout le dépôt) :
l'agent lit le code, s'appuie sur les checklists et enregistre son rapport avec
`save_security_report`. Connectez-vous à l'interface web avec le compte `admin` pour le
consulter et le trier.

Ce démarrage rapide est un essai sur une machine. Pour ouvrir le serveur à une équipe (TLS,
PostgreSQL, Docker Compose, jetons pour chaque développeur), suivez
[Mise en service du serveur](getting-started/deploy.md).

## Par où continuer

La documentation suit l'ordre d'une mise en œuvre. **Démarrage** et **Utilisation** contiennent
ce qu'il faut pour travailler ; **Avancé** regroupe les détails et les fonctions facultatives.

| Étape | Page |
|---|---|
| 1. Installer le paquet sur le serveur | [Installation](getting-started/installation.md) |
| 2. Lancer le contrôleur et le serveur MCP, créer les premiers comptes | [Mise en service du serveur](getting-started/deploy.md) |
| 3. Connecter VS Code ou Claude, obtenir un jeton | [Connexion de l'hôte](getting-started/host.md) |
| 4. Lancer une revue | [Prompts et outils](usage/prompts-tools.md) |
| 5. Consulter et trier les rapports | [Interface web](usage/web-interface.md) |
| 6. Bloquer un déploiement sur des findings ouverts | [Gate](usage/gate.md) |

| Pour aller plus loin (Avancé) | Page |
|---|---|
| Docker, Kubernetes, PostgreSQL | [Architecture et déploiement](advanced/architecture.md), [Docker](advanced/docker.md) |
| Jetons restreints à un projet, enrôlement, renouvellement, TLS | [Serveur HTTP, authentification et TLS](advanced/http.md) |
| Se connecter avec le fournisseur d'identité de l'entreprise | [Connexion SSO](advanced/sso.md) |
| Scanner tout un dépôt, les dépendances, ajouter les règles de mon entreprise | [Scan du code complet](advanced/code-scan.md), [Analyse des dépendances](advanced/dependencies.md), [Règles internes](advanced/rules.md) |
| SARIF, tendances, journal d'audit, Prometheus | [Export SARIF](advanced/sarif.md), [Rapport de tendance](advanced/trends.md), [Journal d'audit et métriques](advanced/audit-metrics.md) |

!!! warning "Ce n'est pas un SAST"
    Le scan par motifs produit des **pistes** et des faux positifs. Il ne remplace ni un SAST,
    ni une analyse SCA complète, ni une relecture humaine. Voir
    [Sécurité et limites](reference/security.md).
