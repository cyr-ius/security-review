# Mode local (stdio)

En **mode local**, l'hôte (VS Code, Claude…) lance lui-même `security-review-mcp local` sur le
poste du développeur et dialogue avec lui par stdin / stdout : pas de réseau, pas de jeton, pas de
serveur Controller.

```mermaid
flowchart LR
    dev(["Développeur"]) --> agent
    subgraph ws["Poste du développeur"]
        agent["Assistant IA<br/>VS Code, Claude"] -- "stdio" --> mcp["Serveur MCP<br/>security-review-mcp<br/>(processus lancé par l'assistant)"]
        mcp --> sqlite[("Base SQLite<br/>locale")]
    end
```

## Configuration de l'hôte

C'est la seule étape : avec [uv](https://docs.astral.sh/uv/getting-started/installation/) sur le
poste, il n'y a rien à installer ni à lancer à la main. À son premier démarrage, l'hôte
télécharge le paquet `security-review` depuis PyPI avec `uvx` (Python 3.14 compris si besoin),
puis lance lui-même le serveur chaque fois qu'il en a besoin.

VS Code, GitHub Copilot et Claude lisent le même fichier `.mcp.json` à la racine du dépôt :

```json
{
  "mcpServers": {
    "security-review": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "security-review=={{ release_version }}", "security-review-mcp", "local"]
    }
  }
}
```

Pour modifier un réglage, ajoutez des variables `SECREVIEW_*` dans un objet `env` à côté de `args` (voir
[Configuration](../reference/configuration.md#serveur-mcp)).

Ouvrez ensuite le chat de l'hôte et lancez le prompt `security-review`.

Sans `uvx` (paquet installé, poste hors ligne, sources, conteneur) : voir
[Installation : autres cas](../advanced/deployment/installation.md).

## Base de données

Le serveur crée une base SQLite sur le poste
(`~/.local/share/security-review-mcp/security_reports.db`, ou sous `$XDG_DATA_HOME` quand elle
est définie). C'est le seul fichier écrit par le serveur : supprimez-le pour effacer toute trace.
Pour la placer ailleurs, ajoutez `--database-url` après `local` dans `args` (SQLite uniquement,
chemin absolu après `sqlite:///`) :

```json
"args": ["--from", "security-review=={{ release_version }}", "security-review-mcp", "local",
         "--database-url", "sqlite:////home/me/data/security_reports.db"]
```

## Rapport des findings (SECURITY_REPORT.md)

Sans interface web, demandez les findings du projet à l'assistant, par exemple :

- *« Montre-moi les findings de sécurité de ce projet »*
- *« Écris les findings de sécurité dans SECURITY_REPORT.md »*

Le rapport liste les findings ouverts, le plus grave d'abord, une ligne par finding. Vous pouvez
aussi demander :

- **le détail** de chaque finding (description, extrait de code, recommandation) : le rapport
  est alors bien plus long ;
- **les findings résolus** (corrigés, acceptés, faux positifs).

Le serveur n'écrit jamais sur le disque : c'est l'assistant qui écrit `SECURITY_REPORT.md`, et
l'hôte vous demande d'approuver l'écriture. Le fichier contient des extraits de code : ajoutez-le
au `.gitignore` s'il ne doit pas être commité.

## Triage en mode local

Sans interface web, vous triez les findings dans la conversation.

1. Donnez votre décision à l'assistant avec vos mots, par exemple :
    - *« La ligne 12 de app/db.py est un faux positif : la requête est paramétrée »*
    - *« Accepte le risque du #42 jusqu'au 30 juin : outil interne »*
2. Votre hôte affiche une confirmation : findings, statut, motif et date d'expiration.
3. Le statut ne change que si vous confirmez. Vous êtes enregistré comme approbateur.

!!! warning "Refusez une confirmation que vous n'avez pas demandée."

L'hôte doit gérer l'elicitation MCP (Claude Code, VS Code). Sinon, l'assistant peut seulement
proposer un statut.

Détails : [décision du développeur en mode local](../review/prompts-tools.md#decision-du-developpeur-en-mode-local).
