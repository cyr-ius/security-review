# Prompts et outils

Pour comprendre quand s'appliquent les règles, les checklists et les normes, et comment écrire
le fichier `AGENTS.md` d'un projet, voir [Fonctionnement d'une revue](index.md).

## Prompts

| Prompt | Usage | Arguments |
|---|---|---|
| `security-review` | Revue générale de code Python, Java, Go, C#, Rust, TypeScript/Node.js ou Angular (`language` : un ou plusieurs langages, par exemple `python, angular`) | `language`, `code`, `context`, `focus`, `report_language` |
| `api-security-review` | API REST (OWASP API Top 10) | `framework`, `code`, `context`, `focus`, `report_language` |
| `configuration-review` | Dockerfile, CI/CD, Spring, YAML, properties | `config_type`, `content`, `context`, `focus`, `report_language` |
| `codebase-review` | Revue du **dépôt complet** (pas seulement un diff) | `languages`, `scan_results`, `context`, `focus`, `report_language` |
| `dependency-review` | Manifestes et lockfiles (supply chain) | `ecosystem`, `files`, `context`, `report_language` |
| `triage-report` | Re-qualifier les findings d'un rapport stocké | `report_id`, `context`, `report_language` |
| `development-standards` | Donne à l'assistant les [normes de développement](standards.md) de sa pile **avant d'écrire du code** | `technologies`, `files`, `task`, `context` |

Si `code` est vide, le prompt demande à l'agent de relire les fichiers de son espace de travail.
Chaque prompt de revue commence par appeler `request_project` (l'agent s'arrête quand le projet
est seulement demandé) et se termine par l'instruction d'appeler `save_security_report` une
seule fois ; `development-standards` n'enregistre rien.

Chaque prompt de revue intègre les checklists de son domaine (selon les langages pour
`security-review` et `codebase-review`, alias comme `py` ou `ts` acceptés) et les checklists
`*` (tous les langages) et `company`, puis nomme les autres checklists disponibles, domaines internes compris, que l'agent
récupère avec `get_review_checklist` quand elles s'appliquent
([détails](checklists.md#checklists-des-prompts-de-revue)).

### Langue des rapports

`report_language` fixe la langue de la réponse de l'agent et des champs rédigés du rapport
enregistré (résumé, périmètre, titres, descriptions, recommandations), par exemple `French`,
`fr` ou `pt-BR`. Sans cet argument, le prompt reprend
[`SECREVIEW_REPORT_LANGUAGE`](../reference/configuration.md#serveur-mcp) quand elle est définie, sinon la
langue choisie par un administrateur dans l'écran [**Général**](../usage/index.md#ecrans)
de l'interface web ; si aucune n'est définie, l'agent choisit (en général la langue de la
conversation).

Un agent qui fait la revue **sans prompt**, avec les seuls outils (cas courant : un prompt MCP
est une commande lancée par l'utilisateur, l'agent ne peut pas l'appeler lui-même), reçoit la
même langue configurée (variable, sinon écran **Général**) dans les résultats de
`get_review_checklist` (section « Report language ») et de `scan_code` (champ
`report_language`, `null` si l'agent choisit).

Le code, les extraits, les chemins, les identifiants de règles, les références CWE / OWASP et
les valeurs fixes attendues par les outils (sévérité, catégorie, statut) restent inchangés :
le gate, l'export SARIF et les tendances fonctionnent quelle que soit la langue.

La valeur n'accepte que des lettres, espaces, `-`, `_` et parenthèses (40 caractères au plus),
pour qu'elle ne puisse pas transporter d'instructions ; sinon le prompt est refusé.

## Outils

| Outil | Rôle |
|---|---|
| `list_checklists` / `get_review_checklist` | Checklists par domaine : `python`, `java`, `angular`, `node`, `go`, `csharp`, `rust`, `api`, `config`, `cicd`, `dependencies` et domaines internes |
| `scan_code` | Scan rapide par motifs et analyses Tree-sitter ciblées des flux requête vers SQL (Python, Java, Go, C#, Rust, Node.js), DOM Angular et origines de messages non vérifiées (pistes à vérifier, **pas** un SAST complet). Extraits masqués, caractères invisibles affichés en `<U+XXXX>` |
| `save_security_report` | **Enregistre le rapport et ses findings en base** |
| `get_security_report` | Relit un rapport (Markdown par défaut, ou JSON) |
| `list_security_reports` | Liste filtrable par projet / niveau de risque / type de revue, avec pagination |
| `propose_finding_status` | **Propose** `fixed`, `accepted` ou `false_positive` avec un motif ; ne change jamais le statut ([statut d'un finding](#statut-dun-finding)) |
| `get_project_security_posture` | Findings ouverts par sévérité (utile comme garde-fou CI) |
| `check_project_gate` | Gate CI : `passed` est faux tant qu'un finding **ouvert** atteint le seuil `fail_on` |
| `export_sarif` | Export SARIF 2.1.0 d'un rapport ou d'un projet |
| `get_trend_report` | Tendance d'un projet : nouveaux / corrigés, backlog, score de risque, MTTR |
| `scan_dependencies` | Analyse d'un manifeste, d'un lockfile ou d'un SBOM CycloneDX : versions vulnérables + hygiène |
| `get_advisory_status` | Taille et âge de la base de vulnérabilités |
| `request_project` | Appelé avant une revue avec `project` : `accessible` quand le jeton l'atteint, `created` pour un nouveau projet quand l'utilisateur porte `projects.create` (il en devient membre), sinon `requested` avec `next_steps` (un administrateur valide le projet, ce qui en donne l'accès à l'utilisateur) ; jamais de jeton ([enrôlement](../advanced/architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)) |
| `list_development_standards` / `get_development_standards` | [Normes de développement](standards.md) : catalogue, puis normes à appliquer pour des technologies ou des noms de fichiers |
| `list_rules` / `reload_rules` | Règles actives ([par défaut et personnalisées](rules.md), stockées en base), erreurs de chargement, rechargement immédiat |

Sur le transport HTTP, un jeton restreint ne peut utiliser les outils de rapports que sur ses
projets autorisés ; `reload_rules` lui est refusé (voir
[jetons restreints à un projet](../advanced/bearer-tokens.md#jetons-restreints-a-un-projet)).
Un jeton associé à plusieurs projets peut utiliser les outils de rapports sur chacun d'eux. Un
[jeton MCP personnel](../usage/tokens.md#jetons-mcp-et-ci-personnels) atteint les projets de son
utilisateur : pour un autre projet, `request_project` le crée ou le demande.

### Serveur d'enrôlement

Sur le transport HTTP, un client qui se connecte **sans jeton** atteint un serveur restreint, du
même nom, **sans aucun outil**, qui n'expose que (un jeton inconnu, révoqué ou expiré reçoit
plutôt un `401`, voir [jeton refusé](../advanced/architecture/mcp-server.md#jeton-refuse-se-reconnecter)) :

| Élément | Rôle |
|---|---|
| Prompts `security-review`, `api-security-review`, `configuration-review`, `codebase-review`, `dependency-review` | Sans argument ; invitent l'utilisateur à se connecter à l'interface web (`SECREVIEW_PUBLIC_URL` + `/ui`), à créer un jeton MCP personnel et à l'ajouter à la configuration de l'hôte, au lieu de lancer la revue |

Les instructions qu'il envoie à la connexion, affichées par l'hôte, donnent les mêmes étapes et
l'adresse de l'interface web, tirée de l'URL enregistrée par le serveur Controller (sa
`SECREVIEW_PUBLIC_URL`, ou l'écran
[Général](../usage/index.md#ecrans)) ; sans elle, aucun lien n'est donné.

Voir [l'enrôlement](../advanced/architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet).

## Ressources

- `report://{report_id}` : un rapport enregistré ;
- `checklist://{domain}` : la checklist d'un domaine ;
- `standards://catalog` : le catalogue des [normes de développement](standards.md) ;
- `standard://{slug}` : une norme de développement.

## Rapport enregistré

`save_security_report` reçoit :

- `project` (normalisé, voir [nom du projet](#nom-du-projet)), `summary` ;
- une liste de `findings` : `title`, `severity`, `description`, et optionnellement `cwe`,
  `owasp`, `file_path`, `line_start`, `line_end`, `evidence`, `recommendation`, `category` ;
- `repository`, `branch`, `commit_sha`, `reviewer`, `scope` ;
- `review_type` : le type de revue, indiqué par chaque prompt de revue (voir ci-dessous) ;
- `author` : inutile, le serveur prend l'utilisateur d'un jeton personnel (voir
  [auteur d'un rapport](#auteur-dun-rapport)) ;
- `checklist_results` et `scan_rules` : la couverture de la revue (voir
  [couverture de la revue](#couverture-de-la-revue)).

Chaque champ est borné : `repository` (500 caractères), `branch` (200), `commit_sha` (64),
`reviewer` (200), et chaque texte (`summary`, `scope`, et `description`, `evidence` et
`recommendation` d'un finding) à `SECREVIEW_MAX_CONTENT_CHARS` ; une valeur plus longue fait
refuser le rapport.

Le **niveau de risque** du rapport est calculé (sévérité maximale des findings). Le paramètre
`risk_level` peut seulement le relever, jamais le baisser.

Un finding déjà signalé par un rapport précédent du projet le remplace et garde la décision
prise sur lui : le résultat donne `recurring_findings` et `carried_decisions` (voir
[finding signalé de nouveau](../usage/triage.md#finding-signale-de-nouveau)).

### Nom du projet

Rapports, jetons, rôles et gates sont regroupés par nom de projet. Le serveur **normalise**
chaque nom de projet qu'il reçoit (outils MCP, API REST, client de pipeline, CLI), pour que les
membres d'une équipe qui nomment différemment le même dépôt atteignent le même projet :

- le nom est mis en minuscules (après normalisation Unicode NFKC) ;
- une URL de remote git ou un chemin ne garde que son dernier segment, sans `.git` ;
- toute suite de caractères autres que lettres et chiffres (espaces, points, soulignés, tirets,
  ponctuation) devient un seul `-`, retiré aux deux extrémités.

| Nom donné | Projet enregistré |
|---|---|
| `security-review-mcp`, `Security Review MCP`, `security_review_mcp` | `security-review-mcp` |
| `cyr-ius/security-review-mcp`, `https://github.com/cyr-ius/security-review-mcp.git` | `security-review-mcp` |
| `git@github.com:cyr-ius/Security_Review_MCP.git` | `security-review-mcp` |

Un nom sans lettre ni chiffre, ou de plus de 200 caractères une fois normalisé, est refusé.
Comme seul le nom du dépôt est gardé, deux dépôts de même nom dans des organisations ou groupes
différents partagent un projet : donnez un nom distinct à l'un d'eux.

### Type de revue

Chaque prompt de revue indique au modèle le `review_type` à transmettre : les rapports et leurs
findings se distinguent et se filtrent ainsi dans l'[interface web](../usage/index.md) et dans
`list_security_reports` :

| `review_type` | Fixé par |
|---|---|
| `security-review` | prompt `security-review` |
| `api-security-review` | prompt `api-security-review` |
| `configuration-review` | prompt `configuration-review` |
| `dependency-review` | prompt `dependency-review` |
| `codebase-review` | prompt `codebase-review` |
| `code-scan` | `security-review-ci scan-code --save` |
| `dependency-scan` | `security-review-ci scan-deps --save`, `security-review-mcp scan-deps --save` |
| `other` | toute autre revue (manuelle, sans prompt) |

Le champ est facultatif : un rapport enregistré sans lui n'a pas de type. Toute autre valeur est
refusée. Le type est déclaré par le client : il étiquette et filtre les rapports, il n'accorde
jamais de droit et ne change pas une gate.

### Auteur d'un rapport

L'auteur d'un rapport est l'utilisateur du jeton qui l'a enregistré : l'agent et la CLI n'ont
pas à le préciser. Chaque rapport porte deux champs :

| Champ | Rempli par | Valeur |
|---|---|---|
| `author` | le serveur | Nom de l'utilisateur web propriétaire du jeton personnel (`mcp` ou `ci`) qui a enregistré le rapport, quelle que soit la valeur passée par le client. Seulement pour un jeton sans utilisateur (jeton créé par un administrateur), c'est la valeur déclarée par le client (`author` de `save_security_report`, `--author` des scans CLI), s'il y en a une ; les prompts de revue demandent à l'agent de ne pas la passer. |
| `submitted_by` | le serveur | Libellé du jeton Bearer qui a enregistré le rapport (vide en stdio et avec la CLI). Le client ne peut pas le modifier. |

`author` fait au plus 200 caractères : lettres, chiffres, espaces et `. @ _ + - ' ,` uniquement
(ni Markdown ni HTML, car il est recopié dans l'export Markdown) ; une valeur vide n'est pas
enregistrée. Avec un jeton personnel, il est **authentifié** ; déclaré par le client d'un jeton sans
utilisateur, il ne l'est pas et indique seulement à qui s'adresser. Il sert à filtrer les
rapports dans l'[interface web](../usage/index.md) ; `submitted_by` indique quel jeton a
réellement envoyé le rapport. Seul qui détient `users.manage` ou `tokens.manage` voit
l'`author`, dans l'interface web et l'API REST ; les autres voient le libellé du jeton. Une fois
enregistré, les outils, ressources et prompts MCP ne le renvoient jamais (`author` vaut `null`
dans `list_security_reports` et `get_security_report`, et n'apparaît pas dans le Markdown), et
l'argument `author` de `list_security_reports` est ignoré.

### Couverture de la revue

Les prompts de revue demandent à l'agent de déclarer ce qu'il a réellement vérifié, pour
qu'une personne distingue une revue sans problème d'une revue qui a sauté la checklist :

| Champ | Contenu |
|---|---|
| `checklist_results` | Chaque point de checklist parcouru, avec son résultat : `ok` (vérifié, rien trouvé), `issue` (signalé par un finding), `not_applicable`, `not_verifiable` (le code relu ne suffisait pas pour en juger) |
| `scan_rules` | L'identifiant de règle de chaque piste renvoyée par `scan_code`, confirmée ou écartée |

Le serveur les contrôle avec les règles et checklists actives quand il enregistre le rapport :

- un point de checklist ou une règle inconnus ne sont **pas enregistrés** et sont cités dans les
  `warnings` de la réponse ; le rapport n'est jamais refusé pour cela ;
- l'intitulé et le domaine de chaque point viennent du serveur, pas de l'agent ;
- chaque point d'un domaine de checklist utilisé par la revue mais non déclaré est enregistré en
  `not_covered`, et listé dans `coverage.not_covered` de la réponse ;
- un `rule_id` de finding qui ressemble à un identifiant de règle ou de checklist (`PY-004`,
  `ACME-CL-01`) sans correspondre à aucun reçoit un avertissement ; les identifiants d'avis
  (`GHSA-...`, `CVE-...`) ne sont pas contrôlés ;
- un rapport sans aucun résultat de checklist reçoit un avertissement : sa couverture est
  inconnue.

Au plus 500 résultats de checklist et 500 règles par rapport. La couverture est **déclarée par
l'agent** : elle montre ce que l'agent dit avoir fait, pas une preuve ; une règle de `scan_rules`
citée par aucun finding est une piste que l'agent a écartée. Les scans CLI ne déclarent pas de
couverture. La page du rapport dans l'[interface web](../usage/index.md) et l'export Markdown
l'affichent.

### Statut d'un finding

Un finding est `open` à son enregistrement. **Un agent ne le ferme jamais** : le code relu est
une entrée non fiable, et une injection de prompt dans un commentaire pourrait sinon amener
l'agent à neutraliser ses propres findings et à débloquer la [gate](gate.md). Le serveur rend
aussi visible le texte caché dans ce qu'il renvoie à l'agent et signale les instructions
injectées ([injection de prompt](../reference/security.md#securite-du-serveur-lui-meme)).

- `propose_finding_status` enregistre une **proposition** (`fixed`, `accepted` ou
  `false_positive`) avec le motif de l'agent (10 à 1000 caractères, secrets masqués) et le label
  de son jeton. Le statut, la posture et la gate ne changent pas. Une nouvelle proposition
  remplace la précédente. Elle est écrite dans le [journal d'audit](../usage/audit-metrics.md),
  comme la décision qui suit.
- Une personne qui a le rôle `triager` ou `admin` l'applique ou la rejette dans
  l'[interface web](../usage/triage.md). `accepted` et `false_positive`
  exigent un motif, un approbateur (l'utilisateur connecté) et une date d'expiration ; à partir
  de cette date, le finding est de nouveau compté comme ouvert.

C'est vrai pour tous les rôles de jeton, `admin` compris : le serveur MCP n'a aucun outil qui
change un statut.

!!! info "Masquage des secrets"
    Les secrets présents dans `summary`, `description`, `evidence` et `recommendation`
    (mots de passe, tokens, `SECRET_KEY`, clés AWS, jetons GitHub, GitLab, Slack, Google, Stripe
    et npm, JWT, clés privées, identifiants dans les URL) sont masqués
    avant stockage. Les niveaux de permission (`read`, `write`, `none`, comme dans
    `id-token: write` de GitHub Actions) ne sont pas des secrets et sont conservés. C'est un
    filet de sécurité : l'agent doit aussi éviter de les recopier.
