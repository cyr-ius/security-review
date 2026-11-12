# Mesure de la détection

La capacité du scan à détecter des vulnérabilités, mesurée sur
l'[OWASP Benchmark](https://owasp.org/www-project-benchmark/), et ce que cette mesure ne dit pas.
Elle porte sur un scan du code complet par le serveur Controller avec le
[moteur OpenGrep](../review/analysis/opengrep.md) activé (image `-opengrep`), où les deux moteurs
tournent : les règles par motifs intégrées et les règles OpenGrep par défaut.

## Ce qu'est le scan

| Moteur | Analyse | Rôle |
|---|---|---|
| [Règles intégrées](../review/rules.md) (toujours actives) | Motifs ligne par ligne (expressions régulières) | Pistes : algorithmes faibles, appels risqués, secrets, configuration. Larges, avec des faux positifs |
| [Règles OpenGrep](../review/analysis/opengrep.md#regles-par-defaut) (image `-opengrep`) | Arbre syntaxique, et flux de données pour les 60 règles de propagation (taint) | Analyse statique (SAST) : une valeur lue dans la requête est suivie jusqu'à un appel dangereux, un assainissement en chemin l'arrête |

L'analyse de propagation suit une valeur **dans un fichier** : à travers les variables, la
construction de chaînes, les listes et les dictionnaires, et à travers les fonctions du fichier
(`--taint-intrafile`, `SECREVIEW_OPENGREP_TAINT_INTRAFILE`). Elle ne suit pas une valeur d'un
fichier à l'autre (contrôleur, puis service, puis couche d'accès aux données). La revue par l'IA, guidée par les
[checklists](../review/checklists.md), et une relecture humaine couvrent ces flux, la logique
métier et les contrôles absents (autorisation, par exemple).

## Résultats

Score de l'OWASP Benchmark : **taux de vrais positifs (TPR) moins taux de faux positifs (FPR)**,
par catégorie, puis moyenne des catégories. Un outil qui signale tout, ou rien, obtient 0 %.

| Benchmark | Cas de test | Règles intégrées | Règles OpenGrep | Les deux moteurs |
|---|---|---|---|---|
| Java 1.2 | 2 740 | 23 % | 59 % | **67 %** (TPR 85 %, FPR 19 %) |
| Python 0.1 | 1 230 | 16 % | 31 % | **45 %** (TPR 77 %, FPR 31 %) |

Mesuré le 12/11/2026 avec OpenGrep 1.31.0 et `--taint-intrafile`, et les règles du commit
`0a0614b1` (147 règles OpenGrep, règles intégrées de `default_rules.toml`). Sans
`--taint-intrafile`, Java obtient 51 % (TPR 84 %, FPR 34 %) : suivre la valeur dans les méthodes
d'aide d'un cas de test montre quand elles renvoient une constante. Python est inchangé.

### Java, par catégorie (les deux moteurs)

| Catégorie | CWE | TPR | FPR | Score |
|---|---|---|---|---|
| Injection de commande | 78 | 63 % | 35 % | 27 % |
| Chiffrement faible | 327 | 75 % | 0 % | 75 % |
| Hachage faible | 328 | 69 % | 0 % | 69 % |
| Injection LDAP | 90 | 89 % | 22 % | 67 % |
| Traversée de chemin | 22 | 82 % | 31 % | 51 % |
| Cookie non sécurisé | 614 | 100 % | 0 % | 100 % |
| Injection SQL | 89 | 94 % | 26 % | 68 % |
| Violation de frontière de confiance | 501 | 87 % | 47 % | 40 % |
| Aléa faible | 330 | 100 % | 0 % | 100 % |
| Injection XPath | 643 | 93 % | 15 % | 78 % |
| Cross-site scripting | 79 | 89 % | 32 % | 57 % |

### Python, par catégorie (les deux moteurs)

| Catégorie | CWE | TPR | FPR | Score |
|---|---|---|---|---|
| Injection de commande | 78 | 54 % | 100 % | -46 % |
| Injection de code | 94 | 100 % | 100 % | 0 % |
| Désérialisation | 502 | 100 % | 33 % | 67 % |
| Hachage faible | 328 | 100 % | 0 % | 100 % |
| Injection LDAP | 90 | 50 % | 0 % | 50 % |
| Traversée de chemin | 22 | 65 % | 43 % | 22 % |
| Redirection ouverte | 601 | 77 % | 43 % | 34 % |
| Cookie non sécurisé | 614 | 100 % | 0 % | 100 % |
| Injection SQL | 89 | 60 % | 0 % | 60 % |
| Violation de frontière de confiance | 501 | 50 % | 26 % | 24 % |
| Aléa faible | 330 | 100 % | 0 % | 100 % |
| Injection XPath | 643 | 63 % | 31 % | 32 % |
| Cross-site scripting | 79 | 58 % | 29 % | 29 % |
| Entités externes XML | 611 | 100 % | 35 % | 65 % |

## Lecture des résultats

- **La plupart des faux positifs restants viennent des conditions et des conteneurs.** Un cas
  de test est sûr quand la valeur est abandonnée ou remplacée en chemin (une branche jamais
  prise, un élément de liste qui n'est pas celui relu, une valeur remplacée dans un
  dictionnaire). OpenGrep n'évalue pas les conditions et ne distingue pas les clés d'un
  conteneur : un tel cas est signalé, et laissé à la revue. Les méthodes d'aide qui renvoient une
  constante ne sont plus signalées, puisque l'analyse suit les fonctions du fichier.
- **Les deux moteurs se complètent.** Les règles OpenGrep strictes ne signalent un hachage ou un
  aléa faible que pour un secret nommé (mot de passe, jeton, clé) ; les règles intégrées, larges,
  signalent chaque usage, ce qu'attend le benchmark. Le gate ne bloque pas ces pistes de
  sévérité moyenne à son seuil par défaut.
- **L'injection de code et l'injection de commande en Python** ont un score faible. Les règles
  intégrées signalent chaque `eval` ou `exec`, quelle que soit l'origine de la valeur. La
  catégorie des commandes n'a que 7 cas sûrs, tous signalés parce que la valeur est abandonnée en
  chemin : chaque faux positif pèse lourd.
- **Le benchmark est synthétique.** Ses cas de test sont de petites servlets ou routes Flask,
  avec un flux chacune. Un score ne prédit pas les résultats sur une vraie application. Les
  règles sont écrites pour être génériques : aucun changement ne cible un idiome du benchmark.

## Précision sur du code réel

Chaque changement des règles par défaut est aussi vérifié sur des projets open source qui ne
sont pas des tests : une nouvelle alerte doit y être un vrai problème, sinon la règle est
corrigée. Le corpus couvre WebGoat, Spring PetClinic, Django, Flask, Express, OWASP Juice Shop,
eShopOnWeb, Gitea et une application Rust (Axum, SQLx), plus des projets Python hors web
(httpie, black, pip, uvicorn), sur lesquels les arguments de la ligne de commande et
l'environnement ne sont pas des sources.

## Méthode

1. Scanner le code du benchmark avec les règles OpenGrep par défaut du langage
   (`opengrep scan --json --taint-intrafile --config src/security_review_mcp/rules/opengrep/<language> <benchmark>`),
   et chaque fichier de test avec les règles intégrées (`scanner.scan_content_detailed`).
2. Un cas de test est **signalé** quand un finding sur son fichier porte la CWE de sa catégorie,
   ou une CWE fille (338 pour 330, 95 pour 94, 77 pour 78, 80 pour 79, 326 pour 327, 916 pour
   328).
3. Comparer avec `expectedresults-<version>.csv` du benchmark : une vraie vulnérabilité signalée
   est un vrai positif, un cas sûr signalé un faux positif. Le score est calculé par catégorie,
   puis moyenné.

Ce décompte retient un finding par sa CWE et son fichier, comme les scorecards du benchmark ;
il ne vérifie pas la ligne.
