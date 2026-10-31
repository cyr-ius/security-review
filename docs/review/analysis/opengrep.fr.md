# Moteur OpenGrep

Le Controller peut lancer OpenGrep comme second moteur d'analyse statique lors d'un scan de code complet
(`security-review-ci scan-code`). Le scanner intégré reste actif et inchangé. Les scans de fragments
(`scan_code`) ne lancent aucun processus externe.

## Construction de l'image

OpenGrep est optionnel dans l'image Docker. Construisez l'image avec une version amont explicitement épinglée :

```sh
docker build --build-arg OPENGREP_VERSION=v1.16.0 -t security-review-mcp .
```

Choisissez et validez la version adaptée à votre déploiement. Si l'argument est vide, OpenGrep n'est pas
installé dans l'image et le moteur reste désactivé.

## Activation

Configurez les variables d'environnement suivantes sur le Controller :

| Variable | Valeur par défaut | Description |
| --- | --- | --- |
| `SECREVIEW_OPENGREP_ENABLED` | `false` | Active OpenGrep pour les scans de code complet |
| `SECREVIEW_OPENGREP_BINARY` | `/usr/local/bin/opengrep` | Chemin de l'exécutable OpenGrep |
| `SECREVIEW_OPENGREP_RULES_DIR` | `/var/lib/secreview/rules/opengrep` | Répertoire des packs de règles YAML |
| `SECREVIEW_OPENGREP_TIMEOUT_SECONDS` | `600` | Durée maximale d'un scan OpenGrep |

Installez les packs de règles dans le répertoire configuré, par exemple en montant un répertoire administré
sur `/var/lib/secreview/rules/opengrep`. Les règles ne sont ni téléchargées automatiquement ni intégrées
à l'image applicative. Le répertoire doit contenir au moins un fichier `.yml` ou `.yaml`.

Lorsque le moteur est activé, le Controller écrit les sources déjà reçues du client CI dans un répertoire
temporaire privé, exécute OpenGrep sans shell, analyse sa sortie JSON puis supprime l'espace de travail.
Les résultats sont convertis au format de findings existant et intégrés au même rapport et au même export
SARIF que les résultats du scanner natif. Les identifiants des règles OpenGrep sont préfixés par
`OPENGREP:`.

## Sécurité opérationnelle

- Exécutez le Controller avec l'utilisateur non privilégié `secreview` déjà utilisé par l'image.
- Réservez la gestion des packs de règles aux administrateurs ; leur mise à jour est une opération sensible.
- Appliquez des limites CPU, mémoire et processus au conteneur. Le délai maximal est appliqué par l'adaptateur,
  mais ne remplace pas les limites de ressources du conteneur.
- Ne montez aucun secret applicatif ni chemin hôte sans rapport avec le scan dans l'espace de travail.
- Le Controller n'exécute pas les sources analysées. Il écrit toutefois les contenus reçus dans un répertoire
  temporaire afin qu'OpenGrep puisse les lire.
- Si OpenGrep est activé mais que le binaire ou les règles sont absents, ou si le scan échoue, le scan de code
  échoue explicitement au lieu de signaler silencieusement un succès limité au scanner natif.

## Gestion des règles depuis l’interface web

Le Controller propose une page de gestion authentifiée à l’adresse `/ui/opengrep-rules`.
Les utilisateurs disposant de `rules.read` peuvent consulter les fichiers YAML du répertoire
`SECREVIEW_OPENGREP_RULES_DIR`. Ceux disposant de `rules.manage` peuvent créer, modifier,
valider et supprimer ces fichiers. Chaque fichier géré contient exactement une règle et son
identifiant YAML doit correspondre à celui du fichier. Toute écriture est validée avec
`opengrep validate <fichier>` avant un remplacement atomique. Le Controller ne télécharge
aucun pack de règles et ne suit aucune source distante à la place de l’administrateur.
