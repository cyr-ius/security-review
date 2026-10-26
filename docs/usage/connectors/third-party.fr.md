# Connecteurs tiers

Un connecteur peut être ajouté pour n'importe quel autre outil : un registre de vulnérabilités,
une plateforme GRC, un outil de suivi interne... Il fonctionne comme les connecteurs intégrés :
même interrupteur, même connexion, mêmes destinations et mêmes garanties (voir
[Connecteurs](index.md)).

## Installer un connecteur

Un connecteur tiers est un paquet Python que l'opérateur installe à côté du contrôleur, puis
**autorise** explicitement : l'installer ne suffit pas. Les commandes sont dans
[Connecteurs en détail](../../advanced/connectors.md#connecteurs-tiers) ; l'écriture d'un connecteur
est décrite dans [Écrire un connecteur](../../contributing/connectors.md).

Une fois autorisé, il apparaît dans l'écran **Connecteurs** sous forme de carte marquée **Tiers**,
désactivé tant qu'un administrateur ne l'a pas activé.

!!! warning "Attention"
    Un connecteur s'exécute dans le contrôleur, avec ses droits : n'installez et n'autorisez que
    du code de confiance, comme toute dépendance.
