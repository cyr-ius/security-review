# Fonctionnement d'une revue

Cette page explique comment l'agent effectue sa revue de sécurité sur le code. Elle explique à
quel moment chaque contrôle intervient. Elle précise comment guider l'agent avec un fichier
`AGENTS.md`.

## Les trois briques

Le serveur fournit trois types de contenu. L'agent IA s'en sert. Une personne prend les
décisions finales.

| Brique | Ce que c'est | Qui l'utilise | Quand |
|---|---|---|---|
| **Règles** | Des motifs qui repèrent les lignes suspectes (scan automatique) | L'outil `scan_code` et le scan du pipeline | **Pendant** la revue et en CI |
| **Checklists** | Des points à vérifier à la main, un par un | L'agent | **Pendant** la revue |
| **Normes** | Les conventions de code de votre organisation, par technologie | L'agent | **Avant** d'écrire le code |

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

- Une checklist couvre un **domaine** : `python`, `java`, `go`, `csharp`, `rust`, `angular`,
  `node`, `api`, `config`, `cicd`, `dependencies`.
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

Ensuite, une personne trie les findings dans l'[interface web](triage.md).
L'agent peut seulement **proposer** un statut. Il ne ferme jamais un finding.

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

## Les prompts

Les prompts sont à la disposition du développeur via l'agent disponible dans son IDE.

| Prompt | Ce qu'il fait |
|---|---|
| `development-standards` | Donne à l'agent les normes de développement de sa pile, avant d'écrire le code |
| `security-review` | Revue générale du code (Python, Java, Go, C#, Rust, TypeScript/Node.js, Angular) |
| `api-security-review`, `configuration-review` | Revue d'une API REST (OWASP API Top 10), ou d'une configuration (Dockerfile, CI/CD, YAML...) |
| `dependency-review` | Revue des manifestes et lockfiles (chaîne d'approvisionnement) |
| `codebase-review` | Revue de tout le dépôt, pas seulement d'un diff |
| `triage-report` | Requalifie les findings d'un rapport enregistré |

Pour une revue importante, préférez le prompt.

## Le fichier `AGENTS.md`

!!! danger "Remplissez le fichier `AGENTS.md`"
    C'est la seule façon pour que l'agent fasse les revues de sécurité **automatiquement**, sans
    que le développeur ait à lancer un prompt avant chaque commit.

### Pourquoi il est indispensable

- L'agent ne lance pas les prompts. Sans consigne, il ne pense pas toujours à faire la revue.
- `AGENTS.md` est lu par l'agent au début de chaque session. Il lui dit **quand** utiliser le
  serveur, et **comment**.
- Il fixe le **nom du projet**. Tous les rapports arrivent au même endroit. Le gate, les
  tendances et la posture fonctionnent sur ce nom.
- Sans nom fixé, chaque agent en invente un. Les rapports se dispersent et le gate ne voit pas
  tout.

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

!!! warning "Normes de développement"
    Les normes de développement sont stockées dans le serveur : citez-les dans `AGENTS.md` sans les
    recopier. Voir comment rédiger le fichier `AGENTS.md` dans la section Avancé :
    [Comment en parler dans `AGENTS.md`](../advanced/stored-standards.md#comment-en-parler-dans-agentsmd).

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
