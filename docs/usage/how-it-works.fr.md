# Fonctionnement d'une revue

Cette page explique comment le serveur contrôle la sécurité du code. Elle dit à quel moment
chaque contrôle intervient. Elle montre aussi comment guider l'agent avec un fichier
`AGENTS.md`.

## Les trois briques

Le serveur fournit trois types de contenu. L'agent IA s'en sert. Une personne prend les
décisions finales.

| Brique | Ce que c'est | Qui l'utilise | Quand |
|---|---|---|---|
| **Normes** | Les conventions de code de votre organisation, par technologie | L'agent | **Avant** d'écrire le code |
| **Règles** | Des motifs qui repèrent les lignes suspectes (scan automatique) | L'outil `scan_code` et le scan du pipeline | **Pendant** la revue et en CI |
| **Checklists** | Des points à vérifier à la main, un par un | L'agent | **Pendant** la revue |

Les trois briques sont stockées en base. Les administrateurs les modifient dans l'interface
web. Un changement s'applique à tous les agents, sans redémarrage.

### Les règles : un SAST léger

- Une règle est une expression régulière. Elle porte un identifiant (`PY-004`), une gravité
  et une CWE.
- Quelques règles vont plus loin. Elles suivent le trajet d'une donnée dans un fichier, avec
  Tree-sitter (`PY-026`, `NG-021`, `JV-019`, et les flux SQL en Go, C#, Rust et Node.js :
  `GO-019`, `CS-021`, `RS-015`, `TS-016`).
- Une correspondance est une **piste**, pas une faille. L'agent doit la confirmer en lisant le
  code.
- Aucun résultat ne veut pas dire « code sûr ». Ce n'est pas un SAST complet.

Détail des règles : [Règles](rules.md).

### Les checklists : le regard de l'expert

- Une checklist couvre un **domaine** : `python`, `java`, `angular`, `api`, `config`, `cicd`,
  `dependencies`.
- Chaque item dit quoi chercher. Exemple : « chaque requête est filtrée par le tenant du
  jeton ».
- Les checklists couvrent ce qu'un motif ne voit pas : la logique métier, les droits, les flux
  entre fichiers.
- La checklist `*` contient les points valables pour tous les langages, et la checklist
  `company` les exigences de votre organisation. Elles s'ajoutent à **toutes** les revues.

Détail des checklists : [Checklists](checklists.md).

### Les normes : bien écrire dès le départ

- Une norme décrit comment coder dans une technologie : nommage, tests, erreurs, sécurité.
- L'agent la lit avant de coder. Le code suit vos conventions dès la première version.
- Une norme ne remplace pas la revue. Elle réduit le nombre de findings.

Détail des normes : [Normes de développement](standards.md).

## Le déroulé d'une revue

Chaque prompt de revue donne à l'agent la même méthode, en cinq étapes :

1. **Comprendre le code.** L'agent repère les entrées (requêtes, fichiers, messages) et les
   points sensibles (SQL, commandes, HTML).
2. **Lancer le scan.** L'agent appelle `scan_code`. Il reçoit des pistes. Il les vérifie une
   par une dans le code.
3. **Parcourir les checklists.** L'agent vérifie chaque item. Il note le résultat : `ok`,
   `issue`, `not_applicable` ou `not_verifiable`.
4. **Décrire les failles.** Pour chaque faille confirmée, il donne la gravité, la CWE, le
   fichier, la ligne et un correctif.
5. **Enregistrer le rapport.** L'agent appelle `save_security_report` **une seule fois**. Il
   déclare aussi ce qu'il a vérifié (la [couverture](prompts-tools.md#couverture-de-la-revue)).

Ensuite, une personne trie les findings dans l'[interface web](web-interface.md#triage-des-findings).
L'agent peut seulement **proposer** un statut. Il ne ferme jamais un finding.

## Quel contrôle, à quel moment

| Moment | Contrôle | Déclenché par |
|---|---|---|
| Avant de coder | Normes (`development-standards`, `get_development_standards`) | Le développeur ou l'agent |
| Revue d'un changement | Règles (`scan_code`) + checklists du langage + `*` et `company` | Le développeur (prompt) ou l'agent (outils) |
| Revue d'une API ou d'une configuration | Règles + checklist `api`, ou `config` et `cicd` | Le développeur (prompt) |
| Revue des dépendances | Base de vulnérabilités OSV (`scan_dependencies`) + checklist `dependencies` | Le développeur (prompt) ou l'agent (outil) |
| Revue du dépôt complet | Résultats de `security-review-ci scan-code` + toutes les checklists utiles | Le développeur (prompt) |
| Pipeline CI | Règles sur tout le dépôt (`scan-code`), dépendances (`scan-deps`), [gate](gate.md) | Le pipeline, sans agent |
| Après la revue | Triage, acceptation d'un risque | Une personne, dans l'interface web |

## Comment le système choisit les règles

Le choix est **automatique**. Il dépend du langage du code scanné.

- L'agent passe le langage à `scan_code` : `python`, `java`, `typescript`, `config`...
- Le serveur garde les règles de ce langage. Il ajoute les règles valables partout (`GEN-*`,
  par exemple les secrets en dur).
- Certains langages héritent d'autres règles. Un fichier `gitlab-ci` reçoit aussi les règles
  `yaml` et `config`.
- Une règle désactivée par un administrateur n'est jamais appliquée.
- Une ligne marquée `secreview:ignore` n'est pas cachée. Elle revient dans `suppressed`, et
  l'agent juge si l'exception est justifiée.

En CI, `security-review-ci scan-code` déduit le langage de chaque fichier à partir de son
nom (`.py`, `Dockerfile`, `Jenkinsfile`...). Voir [Scan du code complet](../advanced/code-scan.md).

## Comment le système choisit les checklists

Le choix dépend du **prompt** lancé, puis du jugement de l'agent.

| Prompt | Checklists incluses |
|---|---|
| `security-review` | Celles du langage, puis `api` |
| `api-security-review` | `api` |
| `configuration-review` | `config`, plus `cicd` si les fichiers ressemblent à un pipeline |
| `dependency-review` | `dependencies` |
| `codebase-review` | Celles des langages, puis `api`, `config` et `cicd` |

- Les checklists `*` et `company` sont ajoutées à tous les prompts.
- Le prompt nomme ensuite les **autres** checklists disponibles, y compris vos domaines internes.
- L'agent récupère avec `get_review_checklist` celles qui concernent le code. Exemple : un
  projet Python avec un `Dockerfile` reçoit `python`, puis l'agent demande `config`.
- **Sans prompt**, rien n'est inclus d'avance. L'agent doit appeler `list_checklists` puis
  `get_review_checklist` lui-même. Votre `AGENTS.md` doit le lui demander (voir plus bas).

À l'enregistrement, le serveur compare la couverture déclarée aux checklists actives. Un item
oublié est marqué `not_covered`. Une personne voit ainsi si la revue a sauté des points.

## Comment le système choisit les normes

- L'agent donne ses technologies (`python`, `angular`) ou des noms de fichiers
  (`pyproject.toml`, `angular.json`).
- Le serveur renvoie chaque norme active dont une technologie ou un motif de fichier
  correspond.
- Il signale aussi les technologies qu'aucune norme ne couvre.

## Prompts et outils : qui lance quoi

**Un agent ne peut jamais lancer un prompt MCP.** Un prompt est une commande que le
développeur choisit dans son hôte. Exemples : `/mcp__security-review__security-review` dans
Claude Code, `/mcp.security-review.security-review` dans VS Code.

L'agent, lui, appelle des **outils**. Le serveur lui indique quels outils utiliser pour une
revue. Il peut donc refaire une partie du travail des prompts seul.

| Prompt | L'agent peut-il faire l'équivalent seul ? |
|---|---|
| `development-standards` | Oui, avec `get_development_standards` |
| `security-review` | Oui, avec `scan_code`, `get_review_checklist` et `save_security_report` |
| `api-security-review`, `configuration-review` | Oui, avec les mêmes outils, si `AGENTS.md` cite les checklists `api`, `config` et `cicd` |
| `dependency-review` | En partie, avec `scan_dependencies`, si `AGENTS.md` le demande |
| `codebase-review` | **Non**, reste à la main du développeur |
| `triage-report` | **Non**, reste à la main du développeur |

Pourquoi ces deux prompts restent manuels :

- `codebase-review` relit tout le dépôt. C'est long. Il part en général des résultats de
  `security-review-ci scan-code`, lancé par le développeur ou la CI.
- `triage-report` requalifie un rapport existant. C'est une démarche de décision. Le
  développeur choisit le rapport et le moment.

Le prompt apporte plus que les outils seuls : les checklists déjà incluses, la méthode
complète et les règles anti-injection. Pour une revue importante, préférez le prompt.

## Le fichier `AGENTS.md`

### Pourquoi il est indispensable

- L'agent ne lance pas les prompts. Sans consigne, il ne pense pas toujours à faire la revue.
- `AGENTS.md` est lu par l'agent au début de chaque session. Il lui dit **quand** utiliser le
  serveur, et **comment**.
- Il fixe le **nom du projet**. Tous les rapports arrivent au même endroit. Le gate, les
  tendances et la posture fonctionnent sur ce nom.
- Sans nom fixé, chaque agent en invente un. Les rapports se dispersent et le gate ne voit pas
  tout.

Le serveur normalise le nom (minuscules, `-` comme séparateur). `Shop API` et `shop_api`
donnent `shop-api`. Voir [Nom du projet](prompts-tools.md#nom-du-projet). Écrivez quand même le
nom exact pour éviter toute ambiguïté.

Certains hôtes lisent un autre fichier : `CLAUDE.md` pour Claude Code,
`.github/copilot-instructions.md` pour GitHub Copilot. Faites-les pointer vers `AGENTS.md`.
Vous gardez ainsi une seule source.

### Exemple simple

Un projet `shop-api` en Python (FastAPI), avec un `Dockerfile` :

```markdown
# Consignes pour les agents IA

## Projet
- Nom du projet pour le serveur MCP `security-review` : `shop-api`.
- Utilisez toujours ce nom dans `save_security_report`.

## Avant d'écrire du code
- Appelez `get_development_standards` avec les technologies du changement
  (ex. `python`, `fastapi`) ou les fichiers touchés (`pyproject.toml`).
- Appliquez ces normes. Signalez tout écart avec sa raison.

## Avant de déclarer une tâche terminée
1. Appelez `scan_code` sur chaque fichier modifié. Vérifiez chaque piste dans le code.
2. Appelez `get_review_checklist` pour `python`, `api`, `*` et `company`.
   Ajoutez `config` si le `Dockerfile` change.
3. Si `pyproject.toml` ou `uv.lock` change, appelez `scan_dependencies`.
4. Appelez `save_security_report` une seule fois :
   projet `shop-api`, `review_type` `security-review`, branche et commit,
   `checklist_results` et `scan_rules` remplis.
5. Corrigez les findings `critical` et `high` avant de terminer.
6. Ne changez jamais un statut. Utilisez `propose_finding_status` avec un motif.

Si le serveur `security-review` ne répond pas, dites-le. Ne prétendez pas avoir fait la revue.
```

Et un `CLAUDE.md` minimal qui renvoie vers ce fichier :

```markdown
Les consignes du projet sont dans `AGENTS.md`. Suivez-les intégralement.

@AGENTS.md
```

## Les normes stockées dans le serveur

### Ce que le serveur conserve

- Les normes sont stockées **en base**, comme les règles. Elles ne sont pas dans votre dépôt.
- Un administrateur les écrit dans l'écran **Normes** de l'interface web. Il peut aussi les
  importer depuis un fichier TOML.
- Chaque norme indique ses technologies et ses motifs de fichiers (`*.py`, `angular.json`).
- Tous les projets reçoivent les mêmes normes. Une mise à jour s'applique tout de suite à tous
  les agents.

Avantage : vous écrivez vos conventions **une fois**, pour toute l'organisation. Chaque dépôt
n'a plus besoin de les recopier.

### Comment en parler dans `AGENTS.md`

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
