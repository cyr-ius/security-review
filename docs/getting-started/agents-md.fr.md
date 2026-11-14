# Le fichier AGENTS.md

L'agent lit `AGENTS.md`, à la racine du dépôt, au début de chaque session. C'est là que vous lui
demandez de faire les revues de sécurité et de suivre les normes de votre organisation.

!!! danger "Sans ce fichier, pas de revue automatique"
    L'agent ne lance pas les prompts de lui-même. Sans consigne, il ne pense pas toujours à la
    revue, et le développeur doit la demander avant chaque commit.

## Ce qu'il contient

| Section | Pourquoi |
|---|---|
| **Le nom du projet** | Tous les rapports arrivent au même endroit : le gate, les tendances et la posture fonctionnent sur ce nom. Sans lui, chaque agent en invente un |
| **Avant d'écrire du code** | L'agent récupère les [normes de développement](../review/standards.md) auprès du serveur |
| **Avant de terminer une tâche** | L'agent fait la revue de sécurité et enregistre le rapport |
| **Ce qui est propre au dépôt** | Commandes de test, structure, exceptions locales |

## Exemple

Copiez ce fichier à la racine du dépôt et remplacez seulement `<nom-du-projet>`. Il convient
à tous les langages : l'agent choisit les normes et les checklists d'après les fichiers qu'il
modifie.

```markdown
# Consignes pour les agents IA

## Projet
- Nom du projet pour le serveur MCP `security-review` : `<nom-du-projet>`.
- Utilisez toujours ce nom dans `save_security_report`.

## Avant d'écrire du code
- Appelez `get_development_standards` avec les fichiers que vous allez modifier
  (ou les technologies du changement).
- Appliquez ces normes. Signalez tout écart avec sa raison.
- Ne recopiez pas les normes ici : le serveur les fournit à jour.

## Avant de déclarer une tâche terminée
1. Appelez `scan_code` sur chaque fichier modifié. Vérifiez chaque piste dans le code.
2. Appelez `list_checklists`, puis `get_review_checklist` pour :
   - le langage de chaque fichier modifié et `*` ;
   - `api` si des routes ou des endpoints changent ;
   - `config` si un Dockerfile, un fichier YAML ou de configuration change ;
   - `cicd` si un pipeline CI/CD change.
3. Si un manifeste, un lockfile ou un SBOM change, appelez `scan_dependencies` sur chacun
   et parcourez la checklist `dependencies`.
4. Appelez `save_security_report` une seule fois : projet `<nom-du-projet>`,
   `review_type` `security-review`, branche et commit, `checklist_results` et `scan_rules` remplis.
5. Corrigez les findings `critical` et `high` avant de terminer.
6. Ne changez jamais un statut. Utilisez `propose_finding_status` avec un motif.

Si le serveur `security-review` ne répond pas, dites-le. Ne prétendez pas avoir fait la revue.

## Propre à ce dépôt
- Ajoutez ici vos commandes de test et vos exceptions locales.
- En cas de conflit avec les normes du serveur, ce fichier prévaut.
```

## Les autres hôtes

Certains hôtes lisent un autre fichier : `CLAUDE.md` pour Claude Code,
`.github/copilot-instructions.md` pour GitHub Copilot. Faites-les pointer vers `AGENTS.md` pour
garder une seule source. Par exemple, `CLAUDE.md` :

```markdown
Les consignes du projet sont dans `AGENTS.md`. Suivez-les intégralement.

@AGENTS.md
```

## Les normes restent dans le serveur

Ne recopiez pas les normes dans `AGENTS.md` : un administrateur les écrit une fois dans la page
**Normes**, et une mise à jour s'applique tout de suite à tous les agents. Une norme ne peut
jamais affaiblir la sécurité : en cas de conflit, l'agent garde le comportement sûr.

**Pour aller plus loin :** [normes de développement](../review/standards.md),
[fonctionnement d'une revue](../review/index.md).
