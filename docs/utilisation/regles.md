# Règles internes

Vos équipes sécurité peuvent ajouter des règles de scan et des items de checklist, et activer ou
désactiver n'importe quelle règle, **sans toucher au code**. Ces règles internes sont stockées
dans la **base de données** : toutes les instances du serveur qui partagent la base les
appliquent.

On les gère avec la commande `security-review-mcp rules` (import et export de packs TOML,
activation, désactivation, suppression) ou depuis l'écran **Règles** de
l'[interface web](interface-web.md).

```bash
security-review-mcp rules import examples/rules/company.toml   # importer un pack
security-review-mcp rules list --custom                        # vérifier
```

## Commande `rules`

| Commande | Rôle |
|---|---|
| `rules list [--language L] [--custom] [--format text\|json]` | Liste les règles intégrées et internes avec leur origine et leur état (`enabled` / `disabled`) |
| `rules import PATH… [--replace]` | Importe des packs TOML (fichiers, ou dossiers dont les `*.toml` sont lus par ordre alphabétique) |
| `rules export [-o FICHIER]` | Exporte tout le contenu interne en un pack TOML réimportable |
| `rules disable ID…` / `rules enable ID…` | Désactive ou réactive des règles **intégrées ou internes** |
| `rules delete ID…` | Supprime des règles internes ou des items de checklist |

- L'import est **tout ou rien** : si une entrée est invalide, rien n'est importé et la commande
  liste les erreurs (code de sortie `2`).
- Sans `--replace`, l'import ajoute ou remplace les entrées par identifiant et ajoute les
  identifiants de `disabled_rules` aux règles déjà désactivées. Avec `--replace`, le contenu
  interne est d'abord vidé : la base correspond alors exactement aux packs importés (pratique
  pour versionner les règles dans un dépôt revu et les déployer depuis la CI).
- `enable`, `disable` et `delete` refusent un identifiant inconnu sans rien modifier. Une règle
  intégrée ne peut pas être supprimée, seulement désactivée.
- La commande ne suit pas les liens symboliques ; un pack est limité à 256 Kio.

```bash
security-review-mcp rules disable PY-008            # règle intégrée trop bruyante
security-review-mcp rules export -o rules.toml      # sauvegarde ou revue
security-review-mcp rules import --replace rules.toml
```

## Format d'un pack

Un pack TOML est le format d'échange de `rules import` et `rules export` :

```toml
disabled_rules = ["PY-008"]                  # règles désactivées (intégrées ou internes)

[[rules]]
id = "ACME-001"                              # identifiant unique, ex. ACME-001 (50 caractères max.)
title = "Connexion JDBC directe"
severity = "medium"                          # critical | high | medium | low | info
cwe = "CWE-400"                              # optionnel
languages = ["java"]                         # ou ["*"]
pattern = '''DriverManager\.getConnection\s*\('''
advice = "Utiliser la DataSource gérée."
ignore_case = true                           # optionnel (vrai par défaut)

[[checklist]]
domain = "company"                           # "company" est ajouté à TOUS les prompts de revue
id = "ACME-CL-01"
title = "Isolation des tenants"
what_to_look_for = "Chaque requête est filtrée par le tenant du jeton."
cwe = "CWE-639"
```

Un exemple complet est fourni dans `examples/rules/company.toml`.

## Comportement

- Un `id` identique à une règle intégrée la **remplace** ; supprimer cette règle interne
  rétablit la règle intégrée.
- Un nouveau `domain` est immédiatement utilisable avec `get_review_checklist`.
- Une modification (CLI, interface web) est prise en compte par chaque serveur en cours
  d'exécution **en quelques secondes**, sans redémarrage ; l'outil `reload_rules` et le bouton
  **Recharger** de l'interface l'appliquent immédiatement.
- Une règle stockée qui ne passe plus la validation est **ignorée et signalée** (outil
  `list_rules`, champ `load_errors`) ; si la base est inaccessible, seules les règles intégrées
  s'appliquent.
- Les motifs avec quantificateurs imbriqués (`(a+)+`), trop longs (500 caractères) ou qui
  matchent la chaîne vide sont refusés. Les lignes de plus de 2000 caractères sont tronquées
  avant analyse.
- `code scan` applique aussi les règles internes de la base configurée par
  `SECREVIEW_DATABASE_URL`.

!!! warning "Contenu de confiance"
    Les règles internes sont du contenu **de confiance** : seuls les opérateurs qui ont accès à
    la base (CLI) et le rôle `admin` de l'interface web peuvent les modifier. Versionnez les
    packs dans un dépôt revu et déployez-les avec `rules import --replace`.

## Règles intégrées par plateforme

En plus des règles Python, Java, Angular et configuration : **GitLab CI** (`GL-*`),
**Jenkinsfile** (`JK-*`), **CI/CD commun** (`CI-*`), **Spring** (`SP-*`) et **FastAPI** (`FA-*`).

Langages acceptés par `scan_code` : `python`, `java`, `typescript`, `javascript`, `angular`,
`config`, `yaml`, `docker`, `gitlab-ci`, `jenkins` (alias : `jenkinsfile`, `groovy`, `gitlab`,
`yml`...). Une checklist `cicd` est ajoutée automatiquement aux revues de pipelines.

## Supprimer un faux positif

Ajoutez un commentaire sur la ligne concernée :

```python
subprocess.run(cmd, shell=True)  # secreview:ignore PY-004 commande figée, aucune entrée utilisateur
```

Sans identifiant, toutes les règles de la ligne sont ignorées.

Les suppressions ne sont **pas cachées** : `scan_code` les renvoie dans `suppressed`, et les
prompts demandent à l'agent de signaler toute suppression injustifiée (un auteur de MR pourrait
sinon masquer une faille).
