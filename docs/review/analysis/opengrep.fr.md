# Moteur OpenGrep

Le serveur Controller lance OpenGrep comme second moteur d'analyse statique lors d'un scan de code complet
(`security-review-ci scan-code`). Le scanner intégré reste actif et inchangé. Les scans de fragments
(`scan_code`) ne lancent aucun processus externe.

## Image Docker

L'[image `-opengrep`](../../advanced/deployment/docker.md#images-publiees) (`latest-opengrep`,
`X.Y.Z-opengrep`) contient une version épinglée d'OpenGrep dans `/usr/local/bin/opengrep`, vérifiée par son
empreinte SHA-256 à la construction (cible `opengrep` du `Dockerfile`) : utilisez-la pour le serveur
Controller. L'image par défaut ne contient pas OpenGrep et définit `SECREVIEW_OPENGREP_ENABLED=false`. Avec une installation du paquet
PyPI, installez OpenGrep vous-même et définissez `SECREVIEW_OPENGREP_BINARY` s'il n'est pas dans
`/usr/local/bin`.

## Configuration

Le moteur est activé par défaut (sauf dans l'image Docker par défaut, sans OpenGrep), mais il ne s'exécute qu'une fois au moins une règle YAML installée : sans
règle, `scan-code` n'exécute que le scanner intégré. Définissez `SECREVIEW_OPENGREP_ENABLED=false` pour le
désactiver. Variables d'environnement du serveur Controller :

| Variable | Valeur par défaut | Description |
| --- | --- | --- |
| `SECREVIEW_OPENGREP_ENABLED` | `true` | Active OpenGrep pour les scans de code complet |
| `SECREVIEW_OPENGREP_BINARY` | `/usr/local/bin/opengrep` | Chemin de l'exécutable OpenGrep |
| `SECREVIEW_OPENGREP_RULES_DIR` | `/var/lib/secreview/rules/opengrep` | Répertoire des packs de règles YAML |
| `SECREVIEW_OPENGREP_TIMEOUT_SECONDS` | `600` | Durée maximale d'un scan OpenGrep |
| `SECREVIEW_OPENGREP_MAX_CONCURRENT_SCANS` | `1` | Scans OpenGrep simultanés dans un processus du serveur Controller ; un scan au-delà est refusé avec `503` et `Retry-After` |
| `SECREVIEW_OPENGREP_JOBS` | `2` | Cœurs utilisés par un scan OpenGrep (`--jobs`) |
| `SECREVIEW_OPENGREP_MAX_MEMORY_MB` | `2048` | Mémoire en Mio d'un scan OpenGrep (`--max-memory`, `0` : sans limite) |

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
- Appliquez des limites CPU, mémoire et processus au conteneur. Le délai maximal, le nombre de scans
  simultanés, ainsi que les cœurs et la mémoire d'un scan sont appliqués par l'adaptateur (à l'expiration du
  délai, OpenGrep et ses processus de travail sont arrêtés), mais ne remplacent pas les limites de ressources
  du conteneur.
- Si OpenGrep est occupé par d'autres scans ou indisponible, `scan-code` reçoit une réponse `503` :
  relancez plus tard.
- Ne montez aucun secret applicatif ni chemin hôte sans rapport avec le scan dans l'espace de travail.
- Le Controller n'exécute pas les sources analysées. Il écrit toutefois les contenus reçus dans un répertoire
  temporaire afin qu'OpenGrep puisse les lire.
- Si des règles sont installées mais que le binaire OpenGrep est absent, ou si le scan échoue, le scan de code
  échoue explicitement au lieu de signaler silencieusement un succès limité au scanner natif.

## Gestion des règles depuis l’interface web

Le Controller propose une page de gestion authentifiée à l’adresse `/ui/opengrep-rules`.
Les utilisateurs disposant de `rules.read` peuvent consulter les fichiers YAML du répertoire
`SECREVIEW_OPENGREP_RULES_DIR`. Ceux disposant de `rules.manage` peuvent créer, modifier,
valider et supprimer ces fichiers. Chaque fichier géré contient exactement une règle et son
identifiant YAML doit correspondre à celui du fichier. Toute écriture est validée avec
`opengrep validate <fichier>` avant un remplacement atomique. Le Controller ne télécharge
aucun pack de règles et ne suit aucune source distante à la place de l’administrateur.
