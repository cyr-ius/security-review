# Connecteurs

Un **connecteur** envoie les findings vers un autre outil de vos équipes : un ticket dans **Jira**
ou **ServiceNow**, une entrée dans un registre de vulnérabilités, un élément dans un outil de suivi
interne... Ce que le connecteur crée dans cet outil est l'**enregistrement** du finding.

| Connecteur | Enregistrement | Page |
|---|---|---|
| Jira (Cloud ou Data Center) | Ticket | [Jira](jira.md) |
| ServiceNow | Incident (ou enregistrement d'une autre table) | [ServiceNow](servicenow.md) |
| Tiers | Ce que crée le connecteur | [Connecteurs tiers](third-party.md) |

Les variables, les garanties et l'API REST sont dans
[Connecteurs en détail](../../advanced/connectors.md).

## Activation

L'écran **Connecteurs** (Administration) affiche une carte par connecteur, avec son état
(**Inactif**, **À configurer**, **Actif**), son nombre de projets, un **interrupteur** et une
**roue crantée** pour ses paramètres :

1. onglet **Connexion** : l'adresse de l'outil et le compte à utiliser, puis **Tester la
   connexion** ;
2. onglet **Projets** : pour chaque projet, sa **destination** dans l'outil (une clé de projet
   Jira, un groupe d'affectation ServiceNow...) et son **Envoi automatique** (**À la main
   uniquement**, ou à partir d'une sévérité : **high et au-dessus**...) ;
3. l'interrupteur active le connecteur.

Chaque connecteur est **désactivé par défaut** : rien ne sort tant qu'un administrateur ne l'a pas
activé.

## Envoi d'un finding

- **À la main** : une personne qui peut trier le projet voit un bouton **Envoyer vers Jira** (un
  par connecteur) sur chaque finding d'un projet doté d'une destination. Une fois
  l'enregistrement créé, le finding affiche sa clé, avec un lien vers l'enregistrement.
- **Automatiquement** : les findings du projet de sévérité égale ou supérieure à son seuil sont
  envoyés toutes les quelques minutes, les plus graves d'abord.

Un finding signalé de nouveau par un rapport ultérieur réutilise l'enregistrement de la première
occurrence : aucun doublon n'est créé.

## Points d'attention

- **L'envoi est à sens unique** : le statut du finding n'est jamais modifié depuis
  l'enregistrement. Une personne le décide toujours au [triage](../triage.md).
- **Utilisez un compte aux droits réduits** dans l'outil : créer des enregistrements suffit.
- **Les secrets ne sont jamais réaffichés** (`***`) : laissez `***` pour garder celui enregistré.
  Changer l'adresse de l'outil redemande ses secrets.
- **Un échec** (identifiants refusés, projet inconnu...) s'affiche sur le finding avec sa cause ;
  l'envoi automatique réessaie quelques fois.
- **Seul le serveur Controller** se connecte à ces outils ; l'opérateur peut verrouiller tous les
  connecteurs.
