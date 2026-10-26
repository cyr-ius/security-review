# Normes centralisées

Les [normes de développement](../review/standards.md) vivent dans le serveur, pas dans les dépôts.
Cette page explique ce que cela change, et comment y renvoyer un agent depuis `AGENTS.md`.

## Ce que le serveur conserve

- Les normes sont stockées **en base**, comme les règles. Elles ne sont pas dans votre dépôt.
- Un administrateur les écrit dans l'écran **Normes** de l'interface web. Il peut aussi les
  importer depuis un fichier TOML.
- Chaque norme indique ses technologies et ses motifs de fichiers (`*.py`, `angular.json`).
- Tous les projets reçoivent les mêmes normes. Une mise à jour s'applique tout de suite à tous
  les agents.

Avantage : vous écrivez vos conventions **une fois**, pour toute l'organisation. Chaque dépôt
n'a plus besoin de les recopier.

## Aucun skill à maintenir

Sans le serveur, partager des conventions avec les agents passe en général par des **skills** ou
des fichiers d'instructions : un skill Claude Code, des instructions Copilot, des règles
Cursor... Chaque agent a son propre format, et chaque fichier doit être copié dans chaque dépôt ou
sur chaque poste, puis tenu à jour partout.

Les normes centralisées évitent cela pour les conventions :

| Skills ou fichiers d'instructions | Normes centralisées |
|---|---|
| Un format par agent | Tout agent MCP (Claude Code, GitHub Copilot, Codex, Cursor...) les lit par le serveur `security-review` |
| Copiés dans chaque dépôt ou sur chaque poste | Écrites une fois, dans l'écran **Normes** |
| Mis à jour à la main partout | Une mise à jour s'applique tout de suite à tous les agents |
| Tous chargés, ou choisis par l'agent | Sélectionnées par technologie ou par fichier (`*.py`, `angular.json`) |

Un skill reste utile pour ce qui n'est pas une convention : une procédure, un script, un
déroulé propre à l'équipe. Les normes ne remplacent que les règles de code.

## Comment en parler dans `AGENTS.md`

- **Ne recopiez pas les normes** dans `AGENTS.md`. Elles divergeraient vite.
- Dites à l'agent de les demander au serveur avant de coder.
- Citez les outils et ressources utiles : `get_development_standards`,
  `list_development_standards`, `standard://{slug}`.
- Gardez dans `AGENTS.md` ce qui est **propre au dépôt** : commandes de test, structure,
  exceptions locales.
- En cas de conflit, dites qui gagne. Par exemple : « `AGENTS.md` prévaut sur les normes du
  serveur ».

Exemple de section :

```markdown
## Conventions de code
Les normes de développement sont fournies par le serveur MCP `security-review`.
Consultez-les avant d'écrire du code :
- outil `get_development_standards` (par technologie ou par fichier) ;
- outil `list_development_standards` pour voir le catalogue ;
- ressource `standard://python` pour lire une norme précise.
Ce fichier ne garde que les règles propres à ce dépôt. En cas de conflit, il prévaut.
```

Une norme ne peut jamais affaiblir la sécurité. Si c'est le cas, l'agent garde le comportement
sûr et signale le conflit.
