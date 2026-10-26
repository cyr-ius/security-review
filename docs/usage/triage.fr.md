# Triage des findings

Trier un finding, c'est décider de son sort. La décision est toujours prise par une
**personne** connectée à l'interface web : un agent peut seulement proposer un statut, jamais
l'appliquer. Le détail de l'API REST, des limites et des réglages est dans
[Triage par l'API REST](../advanced/triage-api.md).

| Statut | Signification | Ce qui est demandé | Expire |
|---|---|---|---|
| **Ouvert** | À traiter | Rien | — |
| **Corrigé** | Le code a été corrigé | Rien | — |
| **Risque accepté** | Le problème est connu et toléré | Un **Motif** et une **Date d'expiration** (90 jours par défaut), ou **Sans expiration** | Oui, à sa date |
| **Faux positif** | Le code n'est pas vulnérable | Un **Motif** facultatif | Jamais |

À savoir :

- **Proposition d'un agent** : affichée sur le finding dans un encadré distinct, avec son auteur,
  sa date et son motif. **Appliquer** la reprend (le formulaire s'ouvre pour une acceptation ou
  un faux positif), **Rejeter** la supprime. Le motif vient d'un agent qui a lu le code :
  vérifiez-le avant de l'appliquer.
- **Les findings peu graves** (`low` et `info` par défaut) s'acceptent par une simple
  validation, sans motif ni date.
- **Une acceptation expirée compte de nouveau comme ouverte** partout : listes, posture,
  [gate](gate.md), SARIF, tendance. La carte indique que la décision a expiré.
- La personne qui décide est enregistrée comme **approbateur**, et chaque décision est inscrite
  au [journal d'audit](audit-metrics.md). Toute décision supprime la proposition en
  attente.
- Un trieur peut aussi envoyer un finding vers Jira ou ServiceNow quand son projet a une
  destination ([connecteurs](../connectors/index.md#envoi-dun-finding)).

## Finding signalé de nouveau

Quand un rapport ultérieur signale de nouveau le même problème (même projet, règle, fichier et
titre, quelle que soit la ligne), il n'ajoute pas un second finding à revoir : la nouvelle
occurrence **remplace** la précédente.

- Une **acceptation** ou un **faux positif** encore valide est repris, avec son motif, son
  approbateur et sa date d'expiration, de même que les commentaires et une criticité relevée.
  La gate ne bloque pas de nouveau.
- Un finding **corrigé** qui revient est de nouveau **ouvert**.
- L'occurrence précédente reste dans son ancien rapport, marquée **Signalé de nouveau : voir le
  finding #N**, et ne peut plus être triée.
- Les listes, compteurs, gate et tendance ne comptent que la dernière occurrence ; le délai de
  correction part de la première.
- Un finding qu'un rapport ultérieur ne signale plus n'est **pas** fermé : la revue d'un diff ne
  voit pas tout le code. Marquez-le **Corrigé** vous-même.

## Criticité d'un finding

Un analyste peut **relever** la criticité donnée par un rapport, par exemple quand le code est
exposé à Internet ou manipule des données sensibles : **Relever la criticité**, en haut de la
carte, demande la **Nouvelle criticité** et une **Justification**. La criticité relevée compte
alors partout, et le niveau de risque du rapport monte avec elle.

Une criticité ne descend jamais sous celle du rapport : l'analyste peut seulement y revenir pour
annuler la hausse. Pour clore un finding jugé moins grave, acceptez le risque.

## Acceptations de risque

L'écran **Acceptations de risque** liste les risques acceptés, y compris expirés, de
l'expiration la plus proche à la plus lointaine : c'est là qu'on les renouvelle, avant ou après
leur fin.

- **Commentaires** : l'historique de l'acceptation, du plus ancien au plus récent. Le motif est
  le premier commentaire. Un commentaire **ne peut être ni modifié ni supprimé**, et reste
  attaché au finding même quand l'acceptation est supprimée.
- **Changer la date d'expiration** renouvelle l'acceptation avec le même motif ; vous en devenez
  l'approbateur.
- **Supprimer l'acceptation** rouvre le finding.

## Ce qui expire et ce qui est supprimé

| Quoi | Comportement |
|---|---|
| Acceptation de risque | Prend fin à sa date d'expiration (un an au plus) : le finding compte de nouveau comme ouvert, jusqu'à son renouvellement |
| Faux positif, acceptation **Sans expiration** | N'expirent jamais : ils durent jusqu'à ce que quelqu'un rouvre le finding |
| Proposition d'un agent | Supprimée par toute décision sur le finding, ou par **Rejeter** |
| Occurrence précédente d'un finding signalé de nouveau | Conservée dans son rapport, mais plus comptée |
| Rapport sans findings | Supprimé après 90 jours par défaut, sauf le dernier rapport de chaque projet ([conservation](../reference/configuration.md#conservation-des-rapports-sans-findings)) |
| Rapport avec findings, commentaires | Jamais supprimés automatiquement, quel que soit le statut des findings |
| Journal d'audit | Événements conservés un an par défaut ([conservation](audit-metrics.md#conservation)) |

Les durées ci-dessus sont celles par défaut : un administrateur peut les changer
([configuration](../reference/configuration.md)).
