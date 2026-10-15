# Normes de développement

Les **normes de développement** sont les conventions de votre organisation pour chaque
technologie (Python, Angular, FastAPI, Spring…) : nommage, structure, typage, tests, gestion des
erreurs, dépendances, sécurité. Les administrateurs les rédigent dans
l'[interface web](interface-web.md#ecrans) ; le serveur MCP les transmet à l'assistant IA du
développeur **avant qu'il écrive du code**, pour que le code produit les respecte dès le départ.

Elles complètent la revue de sécurité : les normes guident l'écriture, les prompts de revue
contrôlent le résultat.

## Contenu d'une norme

| Champ | Rôle |
|---|---|
| Identifiant (`slug`) | Nom court et stable, en minuscules : `python`, `angular`, `node.js`, `c++`. Il sert dans l'URL de la ressource `standard://<slug>` et ne peut pas être changé |
| Titre, description | Affichés dans la liste et dans le catalogue transmis à l'assistant |
| Technologies | Noms et alias reconnus, séparés par des virgules (`python, fastapi`). L'identifiant est toujours reconnu |
| Motifs de fichiers | Globs qui révèlent la technologie (`*.py`, `pyproject.toml`, `angular.json`, `Dockerfile*`). Sans tenir compte de la casse, un motif contenant `/` (`.github/workflows/*`) est comparé au chemin complet, les autres au nom du fichier |
| Contenu | Les règles, en Markdown (50 000 caractères au plus) |
| Active | Une norme désactivée reste visible des administrateurs mais n'est plus servie aux assistants |

Exemple de contenu :

```markdown
### Style
- PEP 8, longueur de ligne 100, formatage `ruff format`.
- Annotations de type sur toutes les fonctions publiques.

### Erreurs
- Pas de `except Exception` silencieux : journaliser puis relancer.

### Tests
- Un test `pytest` par comportement modifié ; pas d'accès réseau.
```

Rédigez des règles **courtes, vérifiables et impératives** : l'assistant reçoit le texte tel
quel. Une norme ne doit jamais affaiblir la sécurité ; le prompt demande d'ailleurs à
l'assistant de garder le comportement sûr et de signaler le conflit le cas échéant.

## Côté développeur (MCP)

| Élément | Rôle |
|---|---|
| Prompt `development-standards` | Arguments `technologies` (par ex. `python, angular`), `files` (par ex. `pyproject.toml, angular.json`), `task`, `context`, tous facultatifs. Avec des technologies ou des fichiers, le prompt contient les normes correspondantes ; sans argument, il contient le catalogue et demande à l'assistant de détecter la pile de l'espace de travail puis d'appeler `get_development_standards` |
| Outil `list_development_standards` | Catalogue des normes actives (sans le contenu) |
| Outil `get_development_standards` | Normes à appliquer pour une liste de `technologies` et/ou de `files` (Markdown par défaut, ou JSON). Indique aussi les technologies qu'aucune norme ne couvre |
| Ressource `standards://catalog` | Catalogue, en Markdown |
| Ressource `standard://{slug}` | Une norme, en Markdown |

Exemple de demande à l'assistant : « Applique les normes de développement (prompt
`development-standards`) puis ajoute l'endpoint de recherche. »

Les normes sont lues en base à chaque appel : une modification faite dans l'interface web
s'applique immédiatement à toutes les instances du serveur MCP. Elles ne sont pas limitées par
projet : tout client autorisé sur `/mcp` les lit.

## Gestion (interface web et API REST)

L'écran **Normes** de l'interface web liste les normes avec leurs technologies et motifs de
fichiers, et permet de rechercher et de lire chacune. Tout utilisateur connecté les consulte ;
seuls les administrateurs les créent, les modifient, les désactivent ou les suppriment.

| Méthode | Route | Rôle requis |
|---|---|---|
| `GET` | `/api/v1/standards` | tout rôle web (les normes désactivées ne sont listées qu'aux administrateurs) |
| `GET` | `/api/v1/standards/{slug}` | tout rôle web |
| `POST` | `/api/v1/standards` | `admin` (`409` si l'identifiant existe déjà) |
| `PUT` | `/api/v1/standards/{slug}` | `admin` (l'identifiant ne change pas) |
| `DELETE` | `/api/v1/standards/{slug}` | `admin` |

```bash
curl -X POST https://secreview.example.com/api/v1/standards \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"slug": "python", "title": "Normes Python", "technologies": ["python", "fastapi"],
       "file_patterns": ["*.py", "pyproject.toml"], "content": "- PEP 8, ruff, typage."}'
```

## Limites

- 200 normes au plus ; 32 technologies et 32 motifs de fichiers par norme.
- Recherche par l'outil ou le prompt : 50 technologies et 500 noms de fichiers au plus, et
  `SECREVIEW_MAX_CONTENT_CHARS` caractères au total.
- Le contenu est du texte transmis à l'assistant : n'y mettez ni secret ni donnée sensible.
