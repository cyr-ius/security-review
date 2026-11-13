# Interface web

L'interface web permet de suivre la sécurité de vos projets : consulter les rapports enregistrés
par les agents et les pipelines, voir les findings ouverts et décider de leur sort (le
[triage](triage.md)). Elle est facultative et fournie par le serveur Controller
(`security-review-controller`).

## Se connecter

Ouvrez l'adresse du serveur Controller suivie de `/ui/` (par exemple
`https://secreview.example.com/ui/`) et connectez-vous avec votre
[compte utilisateur](user-accounts.md) : identifiant et mot de passe, ou la connexion de votre
entreprise (OIDC) quand elle est configurée. Un jeton n'ouvre jamais l'interface : les jetons
sont destinés aux agents et aux pipelines.

Une page manque ? Vous n'avez pas sa permission : demandez-la à un administrateur (voir
[permissions](access-control.md#permissions)).

## Se repérer

- La **barre latérale** regroupe les pages en quatre sections : **Supervision** (projets),
  **Revue** (findings et acceptations de risque, avec `reports.read`),
  **Référentiel** (règles, checklists, normes, base OSV) et **Administration**. Vous ne voyez que les
  pages permis par vos permissions. **Findings** affiche le nombre de findings ouverts dans les
  projets que vous lisez.
- Le **champ de recherche** au milieu de la barre du haut (Ctrl+K, ⌘K sur Mac) cherche dans les
  findings et les rapports de vos projets, et propose les projets dont le nom contient le texte
  (ouvrir le projet, ses findings ou ses rapports). Pendant la saisie, la liste affiche les
  premiers findings ouverts (5) et les derniers rapports (3) trouvés, avec le nombre de findings
  correspondants ; Entrée ouvre la première suggestion :

    | Saisie | Pour |
    |---|---|
    | `sql injection` | Rechercher le texte dans les findings (titre, règle, CWE, fichier, description, projet, branche) ou dans les rapports |
    | `#report:12` | Ouvrir le rapport 12 |
    | `xss #report:12` | Ouvrir le rapport 12 en recherchant « xss » dans ses findings |
    | `#finding:34` | Ouvrir le finding 34 dans son rapport |
    | `#report:texte`, `xss #finding:*` | Rechercher uniquement dans les rapports, ou dans les findings |
    | `#report:*`, `#finding:*`, `*` | Lister tous les rapports, tous les findings, ou proposer les deux |
    | `sql project:shop` | Uniquement dans le projet `shop` |
    | `severity:high,critical` (ou `sev:`) | Uniquement ces sévérités (niveau de risque des rapports) |
    | `status:accepted` | Les findings de ce statut (`open`, `fixed`, `accepted`, `false_positive`) au lieu des ouverts |
    | `rule:PY-004`, `cwe:89` | Recherchés comme du texte |

    Filtres et texte se combinent dans n'importe quel ordre : `sql project:shop sev:high #finding:*`.
    Un seul `#report:` ou `#finding:` par recherche ; le reste du texte est recherché. Une valeur
    de filtre inconnue (`sev:urgent`) est recherchée comme du texte. Un nom de projet saisi en
    entier passe en premier. Les findings exigent `reports.read`.
- En haut à droite, choisissez la langue (anglais, français, espagnol) et le thème
  (automatique, clair, sombre). La langue ne change que l'interface : celle des rapports se règle
  dans **Général**.
- En bas de la barre : **Mon compte** (mot de passe, jetons personnels) et la version, un lien
  vers **À propos**.
- Cliquez sur l'en-tête d'une colonne pour trier un tableau ; le navigateur mémorise le tri.
- **Projets**, **Findings**, **Rapports** et **Journal d'audit** relisent leurs données quand vous
  revenez sur l'onglet du navigateur, pour afficher les revues enregistrées entre-temps (pas après
  **Afficher plus**, ni sur **Findings** une fois un finding trié sur la page : **Actualiser** le
  fait alors). Les pages de réglages et de référentiel, modifiées seulement sur la page elle-même,
  n'ont pas de bouton **Actualiser**.
- Le point d'interrogation cerclé à côté d'un titre ouvre la page de cette documentation qui
  explique la page (en français pour une interface en français, sinon en anglais).
- Si le serveur Controller ne répond plus, la page **Backend indisponible** s'ouvre : elle vérifie
  de nouveau d'elle-même (après 5 s, puis avec un délai doublé à chaque échec, jusqu'à 60 s, en pause
  tant que l'onglet est masqué) ou quand vous cliquez sur **Réessayer**, et vous ramène à votre page
  dès qu'il répond de nouveau.

## Pages

**Supervision**

| Page | À quoi elle sert |
|---|---|
| **Projets** | Tous les projets avec leurs findings ouverts par sévérité. Le point de départ : ouvrir un projet, **Revoir les findings ouverts** de tous les projets, valider les **Projets en attente** demandés par les agents |
| **Projet** | Tendance, findings ouverts les plus graves et le plus ancien, export SARIF, **Tous les rapports** du projet |

**Revue** : **Findings** et **Acceptations de risque** pour les utilisateurs qui ont `reports.read` (sur les projets qu'ils lisent) ; **Rapports** pour tout utilisateur (sur les projets qu'il lit), ouvert depuis le champ de recherche (`#report:*`) ou **Tous les rapports** d'un projet

| Page | À quoi elle sert |
|---|---|
| **Findings** (**Findings à revoir**) | Tous les findings ouverts d'un projet ou de tous les projets, une seule fois chacun, du plus grave au moins grave : c'est là que se fait le triage. Le champ de recherche (titre, règle, CWE, fichier, description, projet, branche) restreint la liste ; les filtres de statut, de sévérité et de type de revue acceptent plusieurs valeurs |
| **Acceptations de risque** | Les risques acceptés, avec leur date d'expiration, filtrés par état et par sévérité (plusieurs valeurs chacun) |
| **Rapports**, **Rapport** | Toutes les revues enregistrées, filtrées par un ou plusieurs projets et niveaux de risque, et le détail de chacune : résumé, [couverture de la revue](../review/prompts-tools.md#couverture-de-la-revue), findings (recherche par texte, filtres de sévérité et de statut), téléchargement Markdown et SARIF |

**Référentiel**, modifié par les administrateurs (**Exporter** et **Importer** échangent les règles, checklists et normes en fichiers TOML)

| Page | À quoi elle sert |
|---|---|
| **Règles** | Les règles du scan de code, un onglet par moteur : **Règles par motifs** ([règles](../review/rules.md)) et **Règles OpenGrep**, avec les règles proposées par les agents ([OpenGrep](../review/analysis/opengrep.md#gestion-des-regles-depuis-linterface-web)) |
| **Checklists** | Les points de contrôle suivis par les agents ([checklists](../review/checklists.md)) |
| **Normes** | Les normes de développement données aux assistants IA ([normes](../review/standards.md)) |
| **Base OSV** | État et mise à jour de la base de vulnérabilités, téléchargement automatique (activation, intervalle), choix des écosystèmes téléchargés ([dépendances](../review/analysis/dependencies.md#mise-a-jour-automatique-par-le-serveur-controller)) (`settings.manage`) |

Dans le formulaire d'édition, les champs de texte long (contenu d'une norme, conseil d'une
règle, point de contrôle d'une checklist) ont un bouton plein écran : le texte s'ouvre dans un
grand éditeur, à côté de son aperçu Markdown (**Édition**, **Côte à côte** ou **Aperçu**) ; côte
à côte, les deux volets défilent ensemble. Les modifications sont reportées dans le formulaire,
qui les enregistre ou les annule.

**Administration**

| Page | À quoi elle sert |
|---|---|
| **Général** | Langue des rapports, adresse du serveur Controller (et délégation de `scan_code` à celle-ci) et proxy sortant (téléchargement OSV et connexion OIDC) ; tant que l'adresse est inconnue, un bandeau en haut de chaque page y renvoie |
| **Utilisateurs**, **Rôles** | Les comptes, leurs rôles et leurs projets ([rôles et permissions](access-control.md)) |
| **Jetons** | Les jetons des agents et des pipelines ([jetons](tokens.md)) |
| **Clients MCP** | Les clients MCP qui se connectent par le navigateur ([connexion OAuth](../advanced/mcp-oauth.md#administration)) : activation de la connexion, clients enregistrés et accès approuvés, révocation (`tokens.manage`) |
| **Connexions** | La connexion d'entreprise ([connexion OIDC](sso.md)) |
| **Connecteurs** | Envoi des findings vers Jira, ServiceNow... ([connecteurs](connectors/index.md)) |
| **Activité** | Ce qui tourne en ce moment, et les moteurs de scan avec leur révocation (`settings.manage`) : voir [Activité](#activite) |
| **Journal d'audit** | Qui a fait quoi : décisions de triage, jetons, demandes de projet ([journal d'audit](audit-metrics.md)) ; ouvert par le bouton **Journal d'audit** d'**Activité**, dans le menu seulement pour les comptes qui ont `audit.read` sans `settings.manage` |

### Activité

La page **Activité** (`settings.manage`) montre ce qui tourne en ce moment et se recharge toutes
les 2 secondes tant qu'elle est visible :

- le **Diagramme d'activité** : les agents, les pipelines, les serveurs MCP, les serveurs
  Controller et les moteurs de scan, avec les scans en cours ;
- la section **Moteurs de scan** : les [moteurs de scan](../advanced/architecture/scan-engine.md#administration)
  enrôlés auprès du serveur Controller (version, adresse, dernière activité) et leur révocation.

Le bouton **Journal d'audit**, à côté d'**Actualiser**, ouvre le [journal d'audit](audit-metrics.md)
(`audit.read`). L'ancienne adresse `/ui/scan-engines` mène à cette page.

## Points d'attention

- **Un agent ne ferme jamais un finding.** Une icône de robot clignotante dans la colonne
  **Proposition** signale un statut proposé par un agent : une personne qui a la permission de
  triage l'applique ou le rejette.
- **Un risque accepté expire.** Passé sa date, le finding compte de nouveau comme ouvert (gate,
  tendances) : consultez régulièrement **Acceptations de risque**.
- **Le secret d'un jeton n'est affiché qu'une fois.** Copiez-le tout de suite. S'il est perdu ou
  divulgué, **Renouvelez**-le (l'ancien secret peut rester valable pendant un délai de grâce) ou
  révoquez-le.
- **Supprimer un projet supprime tous ses rapports et findings**, sans retour possible.
- **Un projet en attente expire** : une demande non validée à temps est supprimée.
- **Les règles et points de checklist par défaut** se modifient ou se désactivent, mais ne se
  suppriment pas ; un changement s'applique tout de suite aux revues suivantes.
- **Un champ verrouillé** dans les réglages est défini par une variable d'environnement, toujours
  prioritaire ([réglages enregistrés en base](../advanced/architecture/controller.md#reglages-enregistres-en-base)).
- **Un compte OIDC supprimé** n'est pas recréé à sa prochaine connexion, tant qu'un
  administrateur n'a pas cliqué sur **Autoriser à nouveau** dans **Utilisateurs**.

## Voir aussi

- [Triage des findings](triage.md) : décisions sur les findings, criticité, acceptations de risque ;
- [Jetons](tokens.md) : rôles des jetons, jetons API, jetons MCP et CI personnels ;
- [Comptes utilisateurs](user-accounts.md) : comptes locaux et OIDC, politique de mots de passe.
