# Règles internes

Vos équipes sécurité peuvent ajouter des règles de scan et des items de checklist **sans toucher
au code**, avec des fichiers TOML :

```bash
export SECREVIEW_RULES_DIR=/etc/security-review-mcp/rules.d
cp examples/rules/company.toml "$SECREVIEW_RULES_DIR/"
```

## Format

Chaque fichier `*.toml` du dossier est chargé (ordre alphabétique) :

```toml
disabled_rules = ["PY-008"]                  # désactiver une règle intégrée trop bruyante

[[rules]]
id = "ACME-001"                              # identifiant unique, ex. ACME-001
title = "Connexion JDBC directe"
severity = "medium"                          # critical | high | medium | low | info
cwe = "CWE-400"                              # optionnel
languages = ["java"]                         # ou ["*"]
pattern = '''DriverManager\.getConnection\s*\('''
advice = "Utiliser la DataSource gérée."

[[checklist]]
domain = "company"                           # "company" est ajouté à TOUS les prompts de revue
id = "ACME-CL-01"
title = "Isolation des tenants"
what_to_look_for = "Chaque requête est filtrée par le tenant du jeton."
cwe = "CWE-639"
```

## Comportement

- Un `id` identique à une règle intégrée la **remplace**.
- Un nouveau `domain` est immédiatement utilisable avec `get_review_checklist`.
- Une entrée invalide est **ignorée et signalée** (outil `list_rules`, champ `load_errors`) :
  un fichier cassé n'empêche jamais le démarrage.
- Après modification, appelez `reload_rules` : pas de redémarrage nécessaire.
- Dans l'interface web, le rôle `admin` peut aussi créer, modifier, supprimer et activer ou
  désactiver les règles personnalisées. Les nouvelles règles sont écrites dans
  `web-managed.toml`; une règle existante est mise à jour dans son fichier source, et sa
  suppression la retire de tous les packs. Les commentaires TOML sont conservés lors des mises
  à jour. Chaque mutation recharge automatiquement le registre; le bouton **Recharger** prend
  en compte les modifications faites directement sur disque. Configurez `SECREVIEW_RULES_DIR`
  pour activer cette gestion. Les règles intégrées restent en lecture seule dans l'interface.
- Les motifs avec quantificateurs imbriqués (`(a+)+`), trop longs ou qui matchent la chaîne vide
  sont refusés. Les lignes de plus de 2000 caractères sont tronquées avant analyse.

!!! warning "Contenu de confiance"
    Les fichiers de règles sont du contenu **de confiance** : réservez l'écriture du dossier aux
    administrateurs (et versionnez-le dans un dépôt revu).

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
