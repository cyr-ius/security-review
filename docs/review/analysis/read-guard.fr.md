# Garde de lecture des assistants IA

Le code qu'un assistant lit peut tenter d'en prendre le contrôle : texte caché par des
caractères invisibles, commentaires adressés à l'assistant, demandes d'écarter un finding. Le
serveur MCP ne voit que ce que l'agent lui envoie, après que l'assistant a lu les fichiers avec
ses propres outils. Pour vérifier un fichier **avant** que l'assistant le lise, lancez la garde
de lecture côté hôte : la commande `guard` du [client de pipeline](../../advanced/architecture/ci.md)
`security-review-ci`, appelée par un hook de l'agent de code avant chaque appel d'outil.

## Ce qu'elle fait

Avant l'appel d'outil, `security-review-ci guard` lit l'événement du hook sur son entrée
standard, trouve les fichiers que l'appel lit et les analyse localement avec les
[règles `AI-*`](../rules.md#regles-par-defaut-par-plateforme) (sans accès réseau, sans
contrôleur, sans jeton), puis :

| Résultat | Décision | Ce que reçoit l'assistant |
|---|---|---|
| Rien trouvé | L'appel continue | Le fichier |
| Texte caché (`AI-001` à `AI-003` : Unicode tags, contrôles bidirectionnels, caractères de largeur nulle) | **Refusée** (`deny`) | Les lignes trouvées seulement, caractères cachés affichés en `<U+XXXX>`, et la consigne de signaler une injection de prompt possible |
| Texte adressé à un assistant seulement (`AI-004`, `AI-005`) | **La personne est consultée** (`ask`) | Le fichier si la personne accepte ; les lignes trouvées et l'avertissement dans tous les cas |

Les fichiers lus par un appel sont :

- l'argument `file_path` ou `path` d'un outil de lecture (`Read` de Claude Code, `view` de
  Copilot CLI) ;
- les fichiers existants passés à une commande qui les affiche (`cat`, `head`, `tail`, `less`,
  `more`, `nl`, `bat`, `sed`, `awk`, `grep`, `egrep`, `rg`) dans la ligne de commande d'un outil
  shell (`Bash`), 20 au plus ; `sed -i`, qui modifie le fichier, n'est pas contrôlé, pour que le
  fichier puisse être nettoyé.

Le fichier n'est jamais modifié : le texte est la preuve de l'attaque, et c'est la personne qui
décide. Un marqueur `secreview:ignore` ne fait pas taire la garde : il fait partie du fichier non
fiable. Chaque extrait garde 60 caractères autour de la correspondance, pour que le reste de la
ligne (un secret, par exemple) n'atteigne pas l'assistant. Les fichiers de plus de 2 Mio ne sont
pas analysés, et une erreur de la garde (événement ou fichier illisible) laisse l'appel continuer
avec le code de sortie `0` : c'est un filet de sécurité, pas une gate (la [gate](../gate.md)
reste dans le pipeline).

## Agents de code

`--agent` donne le format de l'événement du hook et de la décision :

| `--agent` | Événement lu | Décision écrite |
|---|---|---|
| `claude` (par défaut) | `tool_name`, `tool_input` de Claude Code | `hookSpecificOutput` avec `permissionDecision` `deny` ou `ask` |
| `copilot` | `toolName`, `toolArgs` de Copilot CLI (`tool_name` et `tool_input` sont aussi acceptés) | `permissionDecision` `deny` ou `ask` |
| `codex` | `tool_name`, `tool_input` de Codex CLI, qui lit les fichiers avec son shell | `hookSpecificOutput` avec `permissionDecision` `deny` ; pour un texte adressé à un assistant, `additionalContext` seulement : Codex ne peut pas consulter la personne, la lecture continue donc avec l'avertissement |

## Installation

1. Installez le client sur le poste : `uv tool install security-review-ci` (voir
   [Installation](../../advanced/architecture/ci.md#installation)).
2. Pour Claude Code, fusionnez `examples/agent-hooks/settings.json` dans `.claude/settings.json`
   du dépôt (ou `~/.claude/settings.json` pour tous les projets) :

    ```json
    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Read|Bash",
            "hooks": [
              {
                "type": "command",
                "command": "security-review-ci guard --agent claude",
                "timeout": 30
              }
            ]
          }
        ]
      }
    }
    ```

Pour Copilot CLI et Codex CLI, déclarez `security-review-ci guard --agent copilot` ou
`--agent codex` comme hook avant appel d'outil dans la configuration de l'agent ; le dépôt ne
fournit que l'exemple de Claude Code.

## Limites

- Seuls les outils de lecture et les commandes de lecture d'un outil shell sont contrôlés : un
  outil de recherche, un fichier lu par un script, un tube depuis une autre commande ou une page
  web ne passent pas par la garde.
- Les règles sont une copie des règles `AI-*` par défaut : une règle modifiée par un
  administrateur dans l'interface web ne s'applique pas à la garde, qui fonctionne sans le
  contrôleur.
- Les règles sont un premier filtre : un texte adressé à un assistant peut être formulé d'une
  infinité de façons. La [règle de donnée non fiable](../prompts-tools.md#statut-dun-finding)
  des prompts de revue et le fait qu'[un agent ne ferme jamais un finding](../../reference/security.md#securite-du-serveur-lui-meme)
  restent les protections principales.
