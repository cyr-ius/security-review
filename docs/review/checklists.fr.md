# Checklists

Une checklist liste les points que l'agent vérifie **à la main**, un par un, pendant une revue.
Elle couvre ce qu'une [règle](rules.md) ne voit pas : la logique métier, les droits d'accès, les
flux entre fichiers. Chaque item dit quoi chercher, par exemple « chaque requête est filtrée par
le tenant du jeton ».

Comme les règles, les checklists sont stockées dans la **base de données** : toutes les
instances du serveur qui partagent la base utilisent les mêmes items, et vos équipes sécurité
les ajoutent ou les modifient **sans toucher au code**.

## Domaines

Une checklist couvre un **domaine**. Le serveur fournit des items par défaut, copiés en base au
premier démarrage, pour ces domaines :

| Domaine | Exemples de points |
|---|---|
| `*` | Points valables pour tous les langages : divulgation d'informations par les sorties, les journaux, les erreurs ou les réponses d'API ; secrets absents des journaux (jetons, mots de passe, URL avec identifiants) et masqués avant stockage et dans les extraits renvoyés |
| `python`, `java`, `go`, `csharp`, `rust` | Pièges du langage et des frameworks |
| `angular`, `node` | Front-end, et backend TypeScript et JavaScript |
| `api` | Validation des jetons OAuth/OIDC, webhooks, flux métier sensibles, désynchronisation HTTP, injection CRLF, upload de fichiers |
| `config` | Durcissement Kubernetes, RBAC, en-têtes du proxy, WAF, connexions chiffrées vers les services (LDAPS...), instructions des assistants IA |
| `cicd` | Secrets et injection de script dans les pipelines, isolation des runners, gates de sécurité |
| `dependencies` | Versions vulnérables connues, intégrité des lockfiles, confusion de dépendances, code exécuté à l'installation |

`get_review_checklist` et l'écran **Checklists** de l'interface web les affichent en entier.

Vous pouvez créer n'importe quel autre domaine (lettres minuscules, chiffres, `-` et `_`,
31 caractères au plus). Deux domaines sont particuliers et ajoutés à **chaque** prompt de
revue, quel que soit le langage :

- `*` contient les points valables pour tous les langages (comme une règle avec
  `languages = ["*"]`) ;
- `company` contient les exigences de votre organisation.

## Checklists des prompts de revue

| Prompt | Checklists intégrées |
|---|---|
| `security-review` | Celles de `language` (`python`, `java`, `go`, `csharp`, `rust`, `angular` et `node` pour `typescript` et `javascript`, `config` et `cicd` pour les pipelines), puis `api` |
| `codebase-review` | Celles de `languages`, puis `api`, `config` et `cicd` |
| `api-security-review` | `api` |
| `configuration-review` | `config`, plus `cicd` quand les fichiers ressemblent à un pipeline |
| `dependency-review` | `dependencies` |

Les checklists `*` et `company` sont ajoutées à chaque prompt. Les autres domaines, internes compris, sont
nommés à la fin des checklists : l'agent récupère avec `get_review_checklist` ceux qui
s'appliquent au code qu'il relit. Sans prompt, l'agent appelle lui-même `list_checklists` puis
`get_review_checklist` (voir [Fonctionnement d'une revue](index.md#comment-le-systeme-choisit-les-checklists)).

L'agent déclare ensuite le résultat de chaque point parcouru dans `save_security_report` ; un
item d'un domaine utilisé mais non déclaré est enregistré comme `not_covered`
([couverture de la revue](prompts-tools.md#couverture-de-la-revue)).

## Créer un item de checklist

Un item a ces champs :

| Champ | Contenu |
|---|---|
| `domain` | Domaine de l'item (`*`, `company`, `python`, ou un nouveau domaine) |
| `id` | Identifiant unique, en majuscules avec au moins un tiret, par exemple `ACME-CL-01` (50 caractères au plus). Les agents le citent dans leurs rapports : ne le réutilisez jamais pour un autre point. Il doit être unique tous domaines confondus, et un nouvel item ne peut pas utiliser le préfixe d'une famille par défaut (`PY`, `GEN`, `API`... : [réservés](rules.md#commande-rules)) |
| `title` | Nom court du point (300 caractères au plus) |
| `what_to_look_for` | Ce que l'agent doit vérifier (5000 caractères au plus) |
| `cwe` | Facultatif, par exemple `CWE-639` |

### Depuis l'interface web

L'écran **Checklists** (permission `rules.manage`) liste tous les items, avec recherche, tri et
filtres par domaine et origine. Les administrateurs créent, modifient ou suppriment les items
personnalisés. Un item par défaut peut être modifié, mais pas supprimé ; un item par défaut
modifié n'est plus mis à jour par les nouvelles versions du serveur. Chaque changement
s'applique aussitôt et est repris dans les prompts de revue.

### Avec un pack TOML

Les entrées `[[checklist]]` d'un [pack TOML](rules.md#format-dun-pack) ajoutent ou remplacent
des items par identifiant :

```toml
[[checklist]]
domain = "company"                           # "company" et "*" sont ajoutés à TOUS les prompts de revue
id = "ACME-CL-01"
title = "Tenant isolation"
what_to_look_for = "Every query is filtered by the tenant of the token."
cwe = "CWE-639"
```

```bash
security-review-controller rules import examples/rules/company.toml   # importer un pack
security-review-controller rules delete ACME-CL-01                    # supprimer un item personnalisé
```

Le pack s'importe avec `security-review-controller rules import` ou avec le bouton **Importer**
de l'écran **Checklists**, qui exporte aussi les items personnalisés ou modifiés
(`security-review-checklists.toml`) ; voir
[import et export](rules.md#import-et-export-dans-linterface-web).

### Avec l'API REST

| Méthode | Route | Rôle |
|---|---|---|
| `GET` | `/api/v1/checklists` | Liste les items stockés (origine, modifié ou non) et les erreurs de chargement |
| `POST` | `/api/v1/checklists` | Crée un item : corps `{"domain", "id", "title", "what_to_look_for", "cwe"}` |
| `PUT` | `/api/v1/checklists/{domain}/{id}` | Modifie un item |
| `DELETE` | `/api/v1/checklists/{domain}/{id}` | Supprime un item personnalisé |

Toutes les routes exigent la permission `rules.manage`.

!!! warning "Contenu de confiance"
    Le texte des items est lu par les agents à chaque revue : comme les règles, c'est un contenu
    **de confiance** que seuls les administrateurs modifient. Versionnez vos packs dans un dépôt
    relu.
