# Connecteurs tiers

Un paquet Python peut ajouter un connecteur vers n'importe quel autre système : un registre de
vulnérabilités, une plateforme GRC, un outil de suivi interne... Il a le même interrupteur, la
même connexion, les mêmes destinations et les mêmes garanties que les connecteurs intégrés (voir
[Connecteurs](index.md)).

## Installer un connecteur

Un connecteur publié par un paquet Python (point d'entrée du groupe
`security_review_mcp.connectors`) s'installe à côté du contrôleur, puis s'**autorise** par le nom
de son point d'entrée : installer un paquet ne suffit pas.

```bash
uv pip install secreview-acme-connector         # in the image or the environment of the controller
SECREVIEW_CONNECTORS_PLUGINS=acme               # comma separated
SECREVIEW_ACME_URL=https://risk.acme.example/api
SECREVIEW_ACME_API_KEY=...
```

Le contrôleur charge les connecteurs autorisés au démarrage et refuse de démarrer si l'un
manque, est écrit pour une autre version de l'API, ou déclare une variable du serveur lui-même
(`SECREVIEW_<TYPE>_<CHAMP>` ne doit pas être un réglage existant). L'écran **Connecteurs**
l'affiche sous forme de carte marquée **Tiers**, désactivé tant qu'il n'a pas été activé. Un
connecteur s'exécute dans le contrôleur avec ses droits : n'installez et n'autorisez que du code
de confiance, comme toute dépendance.
