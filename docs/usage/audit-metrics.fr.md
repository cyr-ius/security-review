# Journal d'audit

Le **journal d'audit** enregistre qui a changé quoi dans security-review-mcp : les décisions de
triage, les jetons, les comptes et leurs droits, les projets, les connexions. Il répond aux
questions d'un audit (« qui a accepté ce risque ? », « qui a créé ce jeton ? »).

Chaque événement, l'API, la ligne de commande et les variables sont dans
[Journal d'audit en détail](../advanced/audit-log.md). Les métriques Prometheus sont dans
[Métriques Prometheus](../reference/metrics.md).

## Ce qui est enregistré

| Domaine | Exemples d'événements |
|---|---|
| Findings | Décision de triage, proposition d'un agent, commentaire, criticité relevée, envoi par un connecteur |
| Jetons | Création, renouvellement, révocation, changement de projets |
| Comptes et droits | Connexions et échecs de connexion, déconnexions, rôles, groupes et leurs membres |
| Projets | Demande par un agent, validation, refus, création, suppression |
| Réglages | Serveur syslog, adresse du contrôleur, connecteurs |

Chaque événement donne sa date, son **auteur** (une personne `user:<nom>`, un jeton
`token:<label>`, la ligne de commande `cli`...), sa cible, son projet et ses détails.

## Consulter le journal

Les administrateurs le consultent dans l'écran **Journal d'audit** : du plus récent au plus
ancien, avec des filtres par événement et par projet, une recherche dans les détails et
**Afficher plus** pour les événements plus anciens.

## Conservation

Les événements sont conservés **un an** par défaut, puis supprimés automatiquement chaque jour.
Un administrateur peut changer cette durée ou borner le nombre d'événements conservés
([conservation en détail](../advanced/audit-log.md#conservation)).

## Envoi vers syslog

Pour garder les événements hors de la base (SIEM, journal central), le contrôleur peut aussi les
envoyer un par un à un serveur syslog. Dans l'écran **Journal d'audit**, le bouton **Syslog** (à
côté de **Actualiser**) ouvre la fenêtre **Envoi vers syslog** : **Aucun envoi**, ou **Défini
ici** avec l'adresse du serveur et sa facility. Le changement s'applique en quelques secondes.

Préférez une adresse chiffrée (`tls://hôte:port`) : `udp://` et `tcp://` envoient les événements
en clair ([syslog en détail](../advanced/audit-log.md#envoi-vers-syslog)).

## Points d'attention

- **Personne ne modifie ni ne supprime un événement**, hormis la purge automatique de la
  conservation.
- **Le journal ne contient jamais de secret** : ni jeton, ni mot de passe ; les textes libres
  sont masqués comme les rapports.
- **Les événements écrits avant l'activation de l'envoi syslog ne sont pas envoyés.**
- **Un champ verrouillé dans la fenêtre** est défini par une variable d'environnement, toujours
  prioritaire.
