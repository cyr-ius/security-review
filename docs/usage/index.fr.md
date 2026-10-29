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

- La **barre latérale** regroupe les pages en quatre sections : **Supervision** (projets et
  rapports), **Revue** (findings et acceptations de risque, avec `reports.read`),
  **Référentiel** (règles, checklists, normes) et **Administration**. Vous ne voyez que les
  pages permis par vos permissions. **Findings** affiche le nombre de findings ouverts dans les
  projets que vous lisez.
- En haut à droite, choisissez la langue (anglais, français, espagnol) et le thème
  (automatique, clair, sombre). La langue ne change que l'interface : celle des rapports se règle
  dans **Général**.
- En bas de la barre : **Mon compte** (mot de passe, jetons personnels) et la version, un lien
  vers **À propos**.
- Cliquez sur l'en-tête d'une colonne pour trier un tableau ; le navigateur mémorise le tri.
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
| **Rapports**, **Rapport** | Toutes les revues enregistrées, filtrées par un ou plusieurs projets et niveaux de risque, et le détail de chacune : résumé, [couverture de la revue](../review/prompts-tools.md#couverture-de-la-revue), findings, téléchargement Markdown et SARIF |

**Revue**, pour les utilisateurs qui ont `reports.read` (sur les projets qu'ils lisent)

| Page | À quoi elle sert |
|---|---|
| **Findings** (**Findings à revoir**) | Tous les findings ouverts d'un projet ou de tous les projets, une seule fois chacun, du plus grave au moins grave : c'est là que se fait le triage. Les filtres de statut, de sévérité et de type de revue acceptent plusieurs valeurs |
| **Acceptations de risque** | Les risques acceptés, avec leur date d'expiration, filtrés par état et par sévérité (plusieurs valeurs chacun) |

**Référentiel**, modifié par les administrateurs (**Exporter** et **Importer** échangent des fichiers TOML)

| Page | À quoi elle sert |
|---|---|
| **Règles** | Les motifs du scan de code ([règles](../review/rules.md)) |
| **Checklists** | Les points de contrôle suivis par les agents ([checklists](../review/checklists.md)) |
| **Normes** | Les normes de développement données aux assistants IA ([normes](../review/standards.md)) |

Dans le formulaire d'édition, les champs de texte long (contenu d'une norme, conseil d'une
règle, point de contrôle d'une checklist) ont un bouton plein écran : le texte s'ouvre dans un
grand éditeur, à côté de son aperçu Markdown (**Édition**, **Côte à côte** ou **Aperçu**) ; côte
à côte, les deux volets défilent ensemble. Les modifications sont reportées dans le formulaire,
qui les enregistre ou les annule.

**Administration**

| Page | À quoi elle sert |
|---|---|
| **Général** | Langue des rapports, adresse du serveur Controller et proxy sortant (téléchargement OSV et connexion OIDC) ; tant que l'adresse est inconnue, un bandeau en haut de chaque page y renvoie |
| **Utilisateurs**, **Groupes**, **Rôles** | Les comptes et ce qu'ils peuvent faire ([rôles, groupes et permissions](access-control.md)) |
| **Jetons** | Les jetons des agents et des pipelines ([jetons](tokens.md)) |
| **Connexions** | La connexion d'entreprise ([connexion OIDC](sso.md)) |
| **Base OSV** | État et mise à jour de la base de vulnérabilités ([dépendances](../review/analysis/dependencies.md#mise-a-jour-automatique-par-le-serveur-controller)) |
| **Connecteurs** | Envoi des findings vers Jira, ServiceNow... ([connecteurs](connectors/index.md)) |
| **Journal d'audit** | Qui a fait quoi : décisions de triage, jetons, demandes de projet ([journal d'audit](audit-metrics.md)) |

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
