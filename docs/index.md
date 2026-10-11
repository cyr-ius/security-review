# security-review-mcp

Serveur MCP pour la **revue de code orientée sécurité** (failles et mauvaises configurations).
Il fournit à l'hôte (VS Code, Copilot, Claude, agent CI/CD) :

- des **prompts** structurés pour lancer une revue ;
- des **outils** : checklists, scan rapide par motifs, enregistrement et consultation de rapports ;
- une **base de données** (SQLite par défaut, PostgreSQL possible) qui stocke les rapports et
  leurs findings.

Il s'accompagne d'une **ligne de commande** pour les pipelines : scan du dépôt complet, gate de
déploiement, export SARIF, analyse des dépendances et rapport de tendance.

## Démarrage rapide

```bash
pip install security-review-mcp
security-review-mcp            # transport stdio : l'hôte lance le processus
```

Puis déclarez le serveur dans votre hôte, par exemple `.vscode/mcp.json` :

```json
{
  "servers": {
    "security-review": {
      "type": "stdio",
      "command": "security-review-mcp"
    }
  }
}
```

Dans le chat, lancez le prompt `security-review` (ou `codebase-review` pour tout le dépôt) :
l'agent relit le code, s'appuie sur les checklists et enregistre son rapport en base avec
`save_security_report`.

## Par où continuer

| Je veux… | Page |
|---|---|
| Installer le serveur, y compris hors ligne | [Installation](demarrage/installation.md) |
| Le brancher sur VS Code ou Claude | [Configuration de l'hôte](demarrage/hote.md) |
| Monter un serveur partagé sécurisé | [Serveur HTTP, authentification et TLS](demarrage/http.md) |
| Connaître les prompts et outils exposés | [Prompts et outils](utilisation/prompts-outils.md) |
| Bloquer un déploiement sur des findings ouverts | [Gate](ci-cd/gate.md) |
| Ajouter les règles de mon entreprise | [Règles internes](utilisation/regles.md) |

!!! warning "Ce n'est pas un SAST"
    Le scan par motifs produit des **pistes** et des faux positifs. Il ne remplace ni un SAST,
    ni une analyse SCA complète, ni une relecture humaine. Voir
    [Sécurité et limites](reference/securite.md).
