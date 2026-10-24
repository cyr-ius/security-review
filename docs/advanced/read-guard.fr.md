# Garde de lecture des assistants IA

Le code qu'un assistant lit peut tenter d'en prendre le contrôle : texte caché par des
caractères invisibles, commentaires adressés à l'assistant, demandes d'écarter un finding. Le
serveur MCP ne voit que ce que l'agent lui envoie, après que l'assistant a lu les fichiers avec
ses propres outils. Pour vérifier un fichier **avant** que l'assistant le lise, lancez la garde
de lecture côté hôte : un [hook Claude Code](https://code.claude.com/docs/en/hooks) fourni en
exemple dans `examples/agent-hooks/`.

## Ce qu'elle fait

Avant chaque `Read` de l'assistant, le hook analyse le fichier localement avec les
[règles `AI-*`](../usage/rules.md#regles-par-defaut-par-plateforme) du paquet (sans accès réseau, sans
contrôleur), puis :

| Résultat | Décision | Ce que reçoit l'assistant |
|---|---|---|
| Rien trouvé | La lecture continue | Le fichier |
| Texte caché (`AI-001` à `AI-003` : Unicode tags, contrôles bidirectionnels, caractères de largeur nulle) | **Refusée** (`deny`) | Les lignes trouvées seulement, caractères cachés affichés en `<U+XXXX>`, et la consigne de signaler une injection de prompt possible |
| Texte adressé à un assistant seulement (`AI-004`, `AI-005`) | **La personne est consultée** (`ask`) | Le fichier si la personne accepte ; les lignes trouvées et l'avertissement dans tous les cas |

Le fichier n'est jamais modifié : le texte est la preuve de l'attaque, et c'est la personne qui
décide. Un marqueur `secreview:ignore` ne fait pas taire la garde : il fait partie du fichier non
fiable. Les fichiers de plus de 2 Mio ne sont pas analysés, et une erreur du hook laisse la
lecture continuer (un filet de sécurité, pas une gate : la [gate](../usage/gate.md) reste dans le
pipeline).

## Installation

1. Copiez `examples/agent-hooks/read_guard.py` dans `.claude/hooks/` du dépôt (ou de
   `~/.claude/` pour tous les projets).
2. Fusionnez `examples/agent-hooks/settings.json` dans `.claude/settings.json` :

    ```json
    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Read",
            "hooks": [
              {
                "type": "command",
                "command": "uv run --quiet --script \"$CLAUDE_PROJECT_DIR/.claude/hooks/read_guard.py\"",
                "timeout": 30
              }
            ]
          }
        ]
      }
    }
    ```

Le script déclare sa dépendance (`security-review-mcp`, version 1.1.0 ou suivante) dans son
en-tête : `uv run --script` l'installe dans un environnement en cache. Sans `uv`, ou hors ligne,
lancez-le avec le Python d'un environnement où le paquet est installé (`"command": "python3
.claude/hooks/read_guard.py"`).

## Limites

- Seul l'outil `Read` est contrôlé : un fichier affiché par une commande shell (`cat`) ou un
  outil de recherche, ou une page web, ne passe pas par le hook.
- Les règles sont un premier filtre : un texte adressé à un assistant peut être formulé d'une
  infinité de façons. La [règle de donnée non fiable](../usage/prompts-tools.md#statut-dun-finding)
  des prompts de revue et le fait qu'[un agent ne ferme jamais un finding](../reference/security.md#securite-du-serveur-lui-meme)
  restent les protections principales.
- L'exemple vise Claude Code. Un autre hôte qui offre un hook avant la lecture d'un fichier peut
  réutiliser `check()` : elle prend un chemin et renvoie la décision.
