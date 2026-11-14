# Serveur MCP

Le **serveur MCP** (`security-review-mcp`) est le processus des agents IA : il leur fournit les
prompts de revue, les checklists, le scan par motifs et les normes de développement, et
enregistre leurs rapports. Il n'appelle jamais le [serveur Controller](controller.md) : les deux
partagent la base (voir [Architecture](index.md)).

## Ce qu'il sert

| Route | Utilisée par | Identifiant |
|---|---|---|
| `/mcp` | les agents : [prompts, outils et ressources](../../reference/prompts-tools.md) | jeton `mcp` (personnel ou non), jeton `admin`, ou jeton d'accès [OAuth](../mcp-oauth.md) |
| `/mcp` sans jeton | un agent pas encore connecté : [serveur d'enrôlement](../../reference/prompts-tools.md#serveur-denrolement), qui explique comment obtenir un jeton ; avec la [connexion OAuth](../mcp-oauth.md), un `401` qui la démarre | aucun |
| `/.well-known/oauth-protected-resource/mcp` | les hôtes, avec la [connexion OAuth](../mcp-oauth.md) active : métadonnées de la ressource protégée (RFC 9728), qui désignent le serveur Controller comme serveur d'autorisation (404 sinon) | aucun |
| `/healthz` | sondes (`HEALTHCHECK` Docker, Kubernetes) | aucun |

Il ne sert aucune page web, aucune autre route de l'API REST, et aucune route qui écrit sans
jeton.

## Deux transports

| Transport | Commande | Usage |
|---|---|---|
| HTTP streamable | `security-review-mcp serve` (défaut de l'image, port `8000`) | [mode partagé](../../getting-started/deploy.md) : tous les agents de l'équipe, avec un jeton |
| stdio | `security-review-mcp local` | [mode local](../../getting-started/stdio.md) : lancé par l'hôte sur un poste, base SQLite locale, sans jeton |

## Démarrage

En HTTP, `security-review-mcp serve` :

1. **vérifie** le schéma de la base et refuse de démarrer (code `2`) tant que le serveur Controller ne
   l'a pas migré : il ne migre jamais (voir [Migrations du schéma](../database.md#migrations-du-schema)) ;
2. vérifie les réglages TLS, charge les règles de la base ;
3. sert `/mcp`. Tant qu'aucun jeton n'existe, il reste **fermé** : un client n'atteint que
   le serveur d'enrôlement, sauf si le serveur écoute sur localhost ou avec
   `SECREVIEW_ALLOW_UNAUTHENTICATED=true` (voir [Jetons Bearer](../bearer-tokens.md)) ;
4. entretient un **battement de cœur** en base : toutes les 5 secondes, et aussitôt (au plus une
   fois par seconde) quand une requête d'un agent commence ou se termine, avec son nom d'hôte, sa
   version, l'état de la délégation de `scan_code` au serveur Controller, le plus grand nombre de
   requêtes simultanées depuis le battement précédent par famille (scans de code : `scan_code`,
   `start_codebase_scan` ; scans de dépendances : `scan_dependencies` ; rapports et triage :
   `save_security_report`, `propose_finding_status`, `propose_opengrep_rule`, `request_project` ;
   lectures : les autres outils, les prompts et les ressources), et les agents qui lui ont envoyé
   une requête dans les 5 dernières minutes (50 au plus). Un agent est une clé opaque (un HMAC de
   l'identifiant de son jeton et du nom de son client, avec un secret tiré au démarrage du
   processus : ni réversible, ni comparable d'un serveur à l'autre) et le nom et la version que
   son client MCP donne au début de la session (`clientInfo`) ; jamais le nom d'une personne ni
   d'un jeton. Le serveur Controller l'affiche
   sur la page [**Activité**](../../usage/activity.md). Il le supprime à son arrêt ;
   un serveur disparu sans s'arrêter quitte la page au bout de 30 secondes.

En stdio, `security-review-mcp local` migre lui-même sa base locale.

## Ce que reçoit un agent

| Client | Réponse |
|---|---|
| Sans jeton | le [serveur d'enrôlement](../../reference/prompts-tools.md#serveur-denrolement) : aucun outil, des prompts qui expliquent comment obtenir un jeton ; `401` tant que l'URL publique du serveur Controller est inconnue |
| Jeton inconnu, révoqué ou expiré | `401` qui indique à l'utilisateur où créer un nouveau jeton ([jeton refusé](#jeton-refuse-se-reconnecter)) |
| Jeton `mcp` ou `admin` valide | tous les prompts, outils et ressources, sur les projets du jeton ([jetons restreints à un projet](../bearer-tokens.md#jetons-restreints-a-un-projet)) |

Les jetons et les règles sont lus en base : un jeton créé ou révoqué sur le serveur Controller
s'applique à la requête suivante, une règle modifiée en 5 secondes.

## Prompts, outils et ressources

Cette section est la référence technique de ce que le serveur MCP expose à un client muni d'un
jeton valide (en stdio, à l'hôte local). Quand s'en servir pendant une revue :
[Prompts et outils](../../reference/prompts-tools.md).

À la connexion, le serveur envoie des **instructions** que l'hôte montre au modèle : quel prompt
lance une revue, `request_project` avant de relire, `save_security_report` une seule fois à la
fin, et `propose_finding_status` qui ne change jamais un statut.

### Prompts

Un prompt est une commande lancée par l'utilisateur dans l'hôte : le serveur renvoie le texte de
la revue, que l'agent suit ensuite. Chaque argument est une chaîne facultative.

| Prompt | Arguments | Renvoie |
|---|---|---|
| `security-review` | `language` (un ou plusieurs, séparés par des virgules : `python, angular` ; alias `py`, `ts` acceptés), `code`, `context`, `focus`, `report_language` | Revue du code avec les checklists des langages |
| `api-security-review` | `framework` (`FastAPI`, `Spring Boot`, `Express`…), `code`, `context`, `focus`, `report_language` | Revue d'une API REST selon l'OWASP API Security Top 10 |
| `configuration-review` | `config_type` (`Dockerfile`, `GitLab CI`, `Jenkinsfile`…), `content`, `context`, `focus`, `report_language` | Revue de fichiers Docker, CI/CD, Spring, YAML ou properties |
| `codebase-review` | `languages`, `scan_results` (sortie JSON de `security-review-ci scan-code . --project <name> --format json`), `context`, `focus`, `report_language` | Revue du dépôt entier, à partir des résultats du scan ([fichiers lus, règles, checklists, consommation de tokens](../../review/analysis/code-scan.md#ce-que-fait-codebase-review)) |
| `dependency-review` | `ecosystem` (`PyPI`, `npm`, `Maven`, `Go`, `crates.io`, `NuGet` ; vide : tous), `files`, `context`, `report_language` | Revue des manifestes et lockfiles |
| `triage-report` | `report_id` (obligatoire, entier), `context`, `report_language` | Requalification des findings d'un rapport enregistré, inclus en Markdown sans son auteur |
| `development-standards` | `technologies`, `files` (séparés par des virgules ou des retours à la ligne), `task`, `context` | Les [normes de développement](../../review/standards.md) de la pile (le catalogue si les deux listes sont vides) ; n'enregistre rien |

- Un `code`, `content` ou `files` vide demande à l'agent de lire les fichiers de son espace de
  travail.
- Les cinq prompts de revue commencent par `request_project` et se terminent par un appel unique
  à `save_security_report`. Le contenu fourni par l'utilisateur est encadré, pour être lu comme
  une donnée et non comme des instructions.
- `report_language` : lettres, espaces, `-`, `_` et parenthèses, 40 caractères au plus ; sans
  lui, `SECREVIEW_REPORT_LANGUAGE`, sinon la page **Général**
  ([langue des rapports](../../reference/prompts-tools.md#langue-des-rapports)).
- Un argument invalide renvoie l'erreur MCP `INVALID_PARAMS` avec sa raison : `report_language`
  refusé, `scan_results` ou `task` + `context` au-delà de `SECREVIEW_MAX_CONTENT_CHARS`, rapport
  hors des projets du jeton, norme inconnue.

### Outils

Chaque outil est marqué **lecture seule** (`readOnlyHint`) ou **écriture** (jamais destructeur :
aucun outil ne supprime de données). Une erreur attendue (entrée invalide, objet inconnu, projet
que le jeton n'atteint pas) est renvoyée au modèle comme erreur d'outil avec sa raison ; le
message de toute autre erreur lui est masqué.

**Checklists, scan et règles**

| Outil | Type | Paramètres | Renvoie |
|---|---|---|---|
| `list_checklists` | lecture seule | aucun | Domaines (intégrés et internes) avec leur nombre d'éléments |
| `get_review_checklist` | lecture seule | `domain` | La checklist en Markdown, suivie de la langue des rapports si elle est configurée |
| `scan_code` | lecture seule | `content` (au plus `SECREVIEW_MAX_CONTENT_CHARS`), `language` (`python`, `java`, `typescript`, `javascript`, `angular`, `go`…) | `matches` (règle, ligne, extrait masqué), `suppressed` (lignes marquées `secreview:ignore`), compteurs, `engines` (`rules`, `opengrep` quand il est [délégué au serveur Controller](../../review/analysis/opengrep.md#scans-de-fragments-scan_code)), `controller_error`, `report_language` ; des pistes à vérifier, pas un SAST complet |
| `start_codebase_scan` | écriture | `project`, `scope` (`all` par défaut, `code` ou `deps`) | `scan_code_command` et `scan_deps_command` (selon `scope`) (`security-review-ci` lancé avec `uvx`, ticket à usage unique sur l'entrée standard), `expires_at` ; demande la délégation de `scan_code` ([scan lancé par l'agent](../../review/analysis/code-scan.md#scan-lance-par-lagent-start_codebase_scan)) |
| `list_rules` | lecture seule | `language` (facultatif) | Règles actives, `disabled_rules`, `load_errors` des règles internes |
| `reload_rules` | écriture | aucun | Relit aussitôt les règles en base (sinon en 5 secondes) ; refusé à un jeton restreint à des projets |

**Normes de développement**

| Outil | Type | Paramètres | Renvoie |
|---|---|---|---|
| `list_development_standards` | lecture seule | aucun | Slug, titre, description, technologies et motifs de fichiers de chaque norme, sans son contenu |
| `get_development_standards` | lecture seule | `technologies` (50 au plus, 50 caractères chacune), `files` (500 noms au plus, 500 caractères chacun), `format` (`markdown` ou `json`) | Les normes retenues par technologie ou nom de fichier, et les technologies qu'aucune norme ne couvre ; au moins une technologie ou un fichier est requis |

**Projets et rapports**

| Outil | Type | Paramètres | Renvoie |
|---|---|---|---|
| `request_project` | écriture | `project` | `status` : `accessible`, `created`, `joined` ou `requested` avec `next_steps` ([enrôlement](#enrolement-jeton-personnel-et-demande-de-projet)) ; jamais de jeton |
| `save_security_report` | écriture | `project`, `summary`, `findings` (au plus `SECREVIEW_MAX_FINDINGS_PER_REPORT`) ; facultatifs `repository`, `branch`, `commit_sha`, `reviewer`, `scope`, `risk_level` (ne peut que relever le risque calculé), `review_type`, `author`, `checklist_results` (500 au plus), `scan_rules` (500 au plus) | Identifiant du rapport, niveau de risque, comptes par sévérité et couverture de la revue ([rapport enregistré](../../reference/prompts-tools.md#rapport-enregistre)) |
| `get_security_report` | lecture seule | `report_id`, `format` (`markdown` par défaut, ou `json`) | Le rapport et ses findings, sans son auteur |
| `list_security_reports` | lecture seule | `project`, `risk_level`, `review_type`, `limit` (1 à 100, `20` par défaut), `offset` | Les rapports, du plus récent au plus ancien, sans leur auteur (`author` : obsolète, ignoré) |
| `propose_finding_status` | écriture | `finding_id`, `status` (`fixed`, `accepted` ou `false_positive`), `reason` (10 à 1 000 caractères) | Le finding avec sa proposition ; son statut ne change pas tant qu'une personne n'a pas décidé ([statut d'un finding](../../reference/prompts-tools.md#statut-dun-finding)) |
| `propose_opengrep_rule` | écriture | `project`, `rule_id`, `content` (une règle YAML, au plus 256 Kio), `reason` (10 à 1 000 caractères), `test_code` (au plus `SECREVIEW_MAX_CONTENT_CHARS`) | La proposition en attente et `next_steps` ; la règle n'est installée qu'après l'approbation d'une personne ([règles proposées par les agents](../../review/analysis/opengrep.md#regles-proposees-par-les-agents)) |

**Posture, gate, exports et tendances**

| Outil | Type | Paramètres | Renvoie |
|---|---|---|---|
| `get_project_security_posture` | lecture seule | `project` | Findings ouverts par sévérité, pire sévérité ouverte |
| `check_project_gate` | lecture seule | `project`, `fail_on` (`high` par défaut), `report_id` (facultatif) | `passed` faux tant qu'un finding ouvert atteint `fail_on` ([gate](../../review/gate.md)) |
| `export_sarif` | lecture seule | `report_id` **ou** `project`, `include_resolved` (`false` par défaut) | Un journal SARIF 2.1.0 ; pour un projet, chaque finding une fois (dernier rapport) |
| `get_trend_report` | lecture seule | `project`, `days` (1 à 1 095, `90` par défaut), `granularity` (`day`, `week` par défaut, `month`), `format` | Findings nouveaux et corrigés, stock ouvert, score de risque, MTTR |

**Dépendances**

| Outil | Type | Paramètres | Renvoie |
|---|---|---|---|
| `scan_dependencies` | lecture seule | `content` (au plus `SECREVIEW_MAX_DEPENDENCY_CHARS` ; au-delà, utilisez `security-review-ci scan-deps`), `filename` (choisit l'analyseur : `uv.lock`, `package-lock.json`, `pom.xml`, `bom.json`…) | Versions vulnérables et findings d'hygiène ; vérifiez d'abord `vulnerability_check` : s'il ne vaut pas `performed`, une liste vide ne veut pas dire sûr ([dépendances](../../review/analysis/dependencies.md)) |
| `get_advisory_status` | lecture seule | aucun | Taille, écosystèmes et âge du dernier import de la base de vulnérabilités |

**Périmètre d'un jeton.** Avec un jeton restreint à des projets (jeton personnel compris), chaque
outil qui désigne un projet, un rapport ou un finding vérifie que le jeton l'atteint, et
`list_security_reports` ne renvoie que les rapports de ses projets. `save_security_report`
refuse un autre projet et renvoie vers `request_project`. Les outils sans projet (checklists,
scan, normes, dépendances) répondent à tout jeton. En stdio, il n'y a aucune restriction.

### Ressources

Les ressources sont en lecture seule, en Markdown (`text/markdown`), et suivent le même
périmètre que les outils.

| URI | Nom | Contenu |
|---|---|---|
| `report://{report_id}` | `security-report` | Un rapport enregistré et ses findings, sans son auteur (`report_id` : un nombre, dans les projets du jeton) |
| `checklist://{domain}` | `review-checklist` | La checklist d'un domaine, comme `get_review_checklist` sans la langue des rapports |
| `standards://catalog` | `development-standards` | Le catalogue des normes de développement |
| `standard://{slug}` | `development-standard` | Une norme de développement, avec son contenu |

Un objet inconnu renvoie une erreur « ressource introuvable », un identifiant invalide une
erreur de ressource.

Le [serveur d'enrôlement](../../reference/prompts-tools.md#serveur-denrolement), servi à un client
sans jeton, n'expose aucun de ces outils ni ressources : seulement les cinq prompts de revue,
sans argument, qui expliquent comment obtenir un jeton.

## Ce qu'il ne fait jamais

- Il ne fait **aucune connexion sortante** (la base OSV est importée par le serveur Controller), et ne
  charge aucun module du serveur Controller. Seule exception, désactivée par défaut : `scan_code`
  [délégué au serveur Controller](../../review/analysis/opengrep.md#scans-de-fragments-scan_code)
  (`SECREVIEW_SCANCODE_DELEGATED` sur le serveur Controller, ou l'interrupteur de la page
  **Activité**), avec le jeton de l'agent, et `start_codebase_scan`, qui demande de la même façon un
  [ticket de scan](../../review/analysis/code-scan.md#scan-lance-par-lagent-start_codebase_scan).
- Ses outils **ne lisent jamais le disque** à partir d'un chemin donné par le client : ils
  travaillent sur le contenu transmis.
- Toute entrée est bornée (`SECREVIEW_MAX_CONTENT_CHARS`, `SECREVIEW_MAX_FINDINGS_PER_REPORT`,
  `SECREVIEW_MAX_MCP_REQUEST_MB`, 64 Kio pour un client sans jeton), et les secrets sont masqués
  avant stockage.
- Il **ne change jamais le statut d'un finding** : `propose_finding_status` enregistre seulement
  une proposition, qu'une personne valide dans l'interface web.
- Il **n'installe jamais une règle de scan** : `propose_opengrep_rule` enregistre seulement la
  règle en base ; le serveur Controller l'installe après l'approbation d'une personne.
- En stdio, stdout est réservé au protocole MCP : les journaux vont sur stderr.

Voir [Sécurité et limites](../../reference/security.md).

## Exposition et réplicas

Exposez le serveur MCP avec TLS ([intégré ou reverse proxy](../tls.md)) aux postes des
développeurs. Derrière un reverse proxy ou un Ingress, réglez `SECREVIEW_FORWARDED_ALLOW_IPS`,
sinon tous les clients partagent l'adresse du proxy dans le journal d'audit des demandes de
projet.

Les sessions MCP (HTTP streamable) vivent dans la mémoire du processus qui les a ouvertes : avant
de lancer plusieurs réplicas, envoyez toutes les requêtes d'une session au même réplica
(affinité sur l'en-tête `Mcp-Session-Id`, voir [Kubernetes](../deployment/kubernetes.md#plusieurs-replicas)).

Les variables du serveur MCP : [Configuration](../../reference/configuration.md#serveur-mcp).

| Commande | Rôle |
|---|---|
| `serve` | Lance le serveur MCP du mode partagé (HTTP streamable) ([installation manuelle](../deployment/manual-install.md#5-lancer-le-serveur-mcp)) |
| `local` | Lance le serveur MCP du mode local (stdio) ([mode local](../../getting-started/stdio.md)) |

Toutes leurs options : [Ligne de commande](../../reference/cli.md#security-review-mcp).

## Enrôlement : jeton personnel et demande de projet

Le serveur MCP **ne crée jamais de jeton** et n'écrit rien pour un client sans jeton. Le
serveur d'enrôlement répond dès que l'URL publique du serveur Controller est connue
([`SECREVIEW_PUBLIC_URL`](../../reference/configuration.md#interface-web-et-sessions) ou la page
**Général**), même avant la création du premier jeton (sauf sur un
[serveur ouvert](../bearer-tokens.md), qui n'a pas besoin de jeton) : sans cette URL, il ne
pourrait pas dire où créer un jeton, et un client sans jeton reçoit donc `401`. Avec la
[connexion OAuth](../mcp-oauth.md) active, il reçoit le `401` qui lance la connexion. Les demandes
de projet (`request_project`) sont toujours disponibles.

1. **Jeton personnel.** Un client MCP qui se connecte **sans** en-tête `Authorization` n'est
   pas rejeté : il atteint un serveur MCP restreint (même nom `security-review`) **sans aucun
   outil**, dont les prompts sont nommés comme les revues (`security-review`,
   `codebase-review`…). Ils invitent l'utilisateur à se connecter à l'interface web (son URL
   vient de la base, où le serveur Controller recopie sa
   [`SECREVIEW_PUBLIC_URL`](../../reference/configuration.md#interface-web-et-sessions), suivie de `/ui`, ou la page
   **Général** l'enregistre ; relue au plus toutes les 30 secondes ; aucune :
   pas de lien), à créer un
   **jeton MCP personnel** dans **Mon compte** (voir
   [jetons MCP personnels](../../usage/tokens.md#jetons-mcp-et-ci-personnels)) et à le placer dans
   la [configuration de l'hôte](../../getting-started/host.md#obtenir-un-jeton). Le jeton atteint
   les projets que l'utilisateur peut lire, et n'enregistre de rapport ni de proposition que sur
   ceux de `reports.write`, relus à chaque requête.
2. **Projet de la revue.** Chaque prompt de revue commence par l'outil `request_project`, avec
   le nom du projet (en général le nom du dépôt) :
    - le jeton peut déjà enregistrer des rapports sur le projet (`reports.write`) : `accessible`,
      la revue continue ;
    - le projet est nouveau et l'utilisateur porte `projects.create` : il est **créé**
      immédiatement, avec sa lecture et son écriture pour l'utilisateur, et la revue continue ;
    - le projet existe, l'utilisateur ne le lit pas encore et porte `projects.autojoin` : il le
      **rejoint** immédiatement (`joined`, lecture et écriture, jamais le tri), sauf si un utilisateur portant
      `projects.create` a [bloqué son adhésion automatique](../../usage/projects.md#blocage-de-ladhesion-automatique),
      et la revue continue. Un utilisateur lit au plus 200 projets de cette façon ;
    - sinon la réponse est `requested`, et l'agent s'arrête avant la revue, pour qu'aucune revue
      ne soit perdue. Un nouveau projet est **en attente** : ce n'est pas encore un projet et il
      ne donne aucun accès. Pour un projet qui existe déjà, y compris un projet que l'utilisateur
      lit sans `reports.write`, l'utilisateur **demande l'accès** de la même façon (jamais immédiatement, même avec `projects.create`, sauf avec `projects.autojoin`). La réponse est la même
      dans les deux cas, pour ne pas révéler quels projets existent. Un utilisateur dépose une
      demande par projet ; rien n'est enregistré pour un jeton sans utilisateur sur un projet
      existant, ni pour un utilisateur qui y écrit déjà.
3. **Validation.** Un utilisateur qui porte `projects.create` (entre autres le rôle `admin`)
   valide ou refuse la demande dans la section **Projets en attente** de la page **Projets**,
   où chaque demande est marquée **Nouveau projet** ou **Demande d'accès**, ou en CLI
   (`existing` : `true` pour une demande d'accès). Valider une demande d'accès demande aussi
   `users.manage`, comme donner un rôle : `projects.create` seul n'ouvre jamais
   un projet existant.

    ```bash
    security-review-controller project list          # demandeur, adresse, expiration
    security-review-controller project approve 3     # id de la liste
    security-review-controller project reject 4
    ```

    La validation donne au **demandeur** la lecture et l'écriture du projet (voir
    [membres](../../usage/projects.md#membres)), créé pour un nouveau projet : son
    jeton personnel atteint le projet dès la requête suivante, sans reconfiguration. Une demande
    que personne n'a validée sous `SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS` (7 jours par défaut)
    est supprimée.

`save_security_report` refuse un projet que le jeton n'atteint pas et renvoie vers
`request_project`. Quand un utilisateur portant `projects.create`
[crée le projet](../../usage/projects.md#creation-dun-projet) depuis la page **Projets**, sa propre
demande en attente est soldée ; celles des autres utilisateurs deviennent des demandes d'accès.

Garde-fous : au plus 20 demandes sont en attente à la fois, un utilisateur (ou un jeton sans
utilisateur) demande au plus 5 projets par heure, et une demande en attente expire après
`SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS`. Chaque demande, validation, refus et expiration est
écrit dans le [journal d'audit](../audit-log.md) (`enrollment.requested`,
`enrollment.approved`, `enrollment.rejected`, avec le jeton, l'utilisateur demandeur et
l'adresse cliente). `SECREVIEW_ENROLLMENT`, qui désactivait l'enrôlement, est ignorée (le
serveur MCP journalise un avertissement quand elle est définie).

## Jeton refusé : se reconnecter

Un client dont le jeton est **inconnu, révoqué ou expiré** reçoit `401` sur `/mcp`
(`error="invalid_token"`) : la description invite l'utilisateur à se connecter à l'interface web
(avec son URL quand elle est connue, comme ci-dessus) et à créer un nouveau jeton MCP personnel,
puis à le remplacer dans la [configuration de l'hôte](../../getting-started/host.md#obtenir-un-jeton).
Un tel client n'atteint jamais les outils de revue ni le serveur d'enrôlement. Le refus est
journalisé en avertissement par le serveur MCP (`Rejected unauthenticated request` /
`Rejected expired token`).

Avec la [connexion OAuth](../mcp-oauth.md) active, ce `401` porte aussi le paramètre
`resource_metadata` dans son défi `WWW-Authenticate`, pour qu'un hôte qui gère OAuth se
reconnecte seul, et une requête sans jeton reçoit le même `401` (sans `error`) au lieu du
serveur d'enrôlement.

Quand le serveur Controller ne propose pas de jeton MCP personnel (`SECREVIEW_PERSONAL_MCP_TOKENS=false`
ou `SECREVIEW_PERSONAL_TOKENS_ENABLED=false`, enregistré en base à son démarrage), la description du `401`, les instructions et les prompts du
serveur d'enrôlement invitent l'utilisateur à se connecter par la connexion OAuth, ou à demander
un jeton MCP à un administrateur, plutôt qu'à créer un jeton personnel.
