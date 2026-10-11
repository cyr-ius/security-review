# Règles internes

Toutes les règles de scan et les checklists sont stockées dans la **base de données** : toutes
les instances du serveur qui partagent la base appliquent les mêmes règles. Vos équipes sécurité
peuvent ajouter des règles de scan et des items de checklist, modifier les règles par défaut et
activer ou désactiver n'importe quelle règle, **sans toucher au code**.

Les règles se gèrent avec la commande `security-review-mcp rules` (import et export de packs
TOML, activation, désactivation, suppression) ou depuis l'écran **Règles** de
l'[interface web](interface-web.md). Les items de checklist se gèrent depuis l'écran
**Checklists** de cette interface, ou avec les packs TOML de la commande `rules`.

## Règles par défaut

Le serveur est livré avec un jeu de règles et de checklists par défaut, décrit dans le fichier
`default_rules.toml` du paquet (même format qu'un [pack](#format-dun-pack)).

- **Au premier lancement** (création de la base par le serveur ou par une commande CLI), ce
  contenu est copié en base.
- **À chaque démarrage**, les règles par défaut ajoutées par une nouvelle version du serveur
  sont ajoutées, et celles qu'elle a corrigées sont mises à jour, **sauf si un administrateur
  les a modifiées** : une règle modifiée n'est jamais écrasée.
- Une règle par défaut peut être **modifiée** (motif, sévérité, conseil...) ou **désactivée**,
  mais pas supprimée. `rules list` l'affiche alors avec l'origine `modified` (`modified: true`
  en JSON).
- Si la base est inaccessible ou n'a jamais été initialisée, le serveur applique directement
  les règles du fichier : le scan ne tourne jamais sans règles.
- Pour revenir aux règles par défaut, utilisez `rules import --replace` (voir plus bas).

```bash
security-review-mcp rules import examples/rules/company.toml   # importer un pack
security-review-mcp rules list --custom                        # vérifier
```

## Commande `rules`

| Commande | Rôle |
|---|---|
| `rules list [--language L] [--custom] [--format text\|json]` | Liste toutes les règles avec leur origine (`builtin`, `modified`, `custom`) et leur état (`enabled` / `disabled`) |
| `rules import PATH… [--replace]` | Importe des packs TOML (fichiers, ou dossiers dont les `*.toml` sont lus par ordre alphabétique) |
| `rules export [-o FICHIER]` | Exporte en un pack TOML réimportable ce qui diffère des valeurs par défaut (règles personnalisées ou modifiées, règles désactivées) |
| `rules disable ID…` / `rules enable ID…` | Désactive ou réactive des règles **par défaut ou personnalisées** |
| `rules delete ID…` | Supprime des règles personnalisées ou des items de checklist personnalisés |

- L'import est **tout ou rien** : si une entrée est invalide, rien n'est importé et la commande
  liste les erreurs (code de sortie `2`).
- Sans `--replace`, l'import ajoute ou remplace les entrées par identifiant et ajoute les
  identifiants de `disabled_rules` aux règles déjà désactivées. Avec `--replace`, le contenu
  stocké est d'abord **remis aux valeurs par défaut** (règles et checklists personnalisées
  supprimées, modifications annulées, toutes les règles réactivées) : la base correspond alors
  aux règles par défaut plus les packs importés (pratique pour versionner les règles dans un
  dépôt revu et les déployer depuis la CI).
- `enable`, `disable` et `delete` refusent un identifiant inconnu sans rien modifier. Une règle
  ou un item de checklist par défaut ne peut pas être supprimé : désactivez ou modifiez-le.
- La commande ne suit pas les liens symboliques ; un pack est limité à 256 Kio.

```bash
security-review-mcp rules disable PY-008            # règle par défaut trop bruyante
security-review-mcp rules export -o rules.toml      # sauvegarde ou revue
security-review-mcp rules import --replace rules.toml
```

## Format d'un pack

Un pack TOML est le format d'échange de `rules import` et `rules export` :

```toml
disabled_rules = ["PY-008"]                  # règles désactivées (par défaut ou personnalisées)

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

- Un `id` identique à une règle par défaut la **modifie** (elle apparaît alors comme
  `modified` et n'est plus mise à jour par les nouvelles versions du serveur).
- Un nouveau `domain` est immédiatement utilisable avec `get_review_checklist`.
- Une modification (CLI, interface web) est prise en compte par chaque serveur en cours
  d'exécution **en quelques secondes**, sans redémarrage ; l'outil `reload_rules` et le bouton
  **Recharger** de l'écran Règles l'appliquent immédiatement. Les changements effectués dans
  l'écran Checklists rechargent immédiatement le registre.
- Une règle stockée qui ne passe plus la validation est **ignorée et signalée** (outil
  `list_rules`, champ `load_errors`) ; si la base est inaccessible, les règles par défaut du
  fichier `default_rules.toml` s'appliquent.
- Les motifs avec quantificateurs imbriqués (`(a+)+`), trop longs (500 caractères) ou qui
  matchent la chaîne vide sont refusés. Les lignes de plus de 2000 caractères sont tronquées
  avant analyse.
- `code scan` applique les règles de la base configurée par `SECREVIEW_DATABASE_URL`.

!!! warning "Contenu de confiance"
    Les règles internes sont du contenu **de confiance** : seuls les opérateurs qui ont accès à
    la base (CLI) et le rôle `admin` de l'interface web peuvent les modifier. Versionnez les
    packs dans un dépôt revu et déployez-les avec `rules import --replace`.

## Règles par défaut par plateforme

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
