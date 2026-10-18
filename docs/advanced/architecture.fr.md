# Architecture et déploiement

Un serveur partagé se compose de **deux processus** indépendants qui partagent la même base de
données. Ils peuvent tourner dans deux conteneurs, deux pods ou sur deux machines.

```text
 agents, CI ──▶ ┌──────────────────────┐            ┌──────────────────────────┐ ◀── navigateur,
                │ serveur MCP          │            │ contrôleur               │     admins
                │ security-review-mcp  │            │ security-review-         │
                │ /mcp, /api/v1/enroll │            │ controller serve         │
                │ /healthz             │            │ /api/v1, /ui, /healthz   │
                └──────────┬───────────┘            └────────────┬─────────────┘
                           └──────────── PostgreSQL ─────────────┘
```

| | Serveur MCP | Contrôleur |
|---|---|---|
| Commande | `security-review-mcp --transport streamable-http` | `security-review-controller serve` |
| Sert | `/mcp`, enrôlement public `POST /api/v1/enroll`, `/healthz` | API REST `/api/v1`, interface `/ui`, `/healthz` |
| Jetons acceptés | rôles `mcp` et `admin` | rôles `reader`, `triager` et `admin` ; `ci` sur les seules routes de pipeline `/api/v1/ci/` |
| Routes sans jeton | enrôlement, `/healthz` | fichiers de `/ui`, documentation de l'API, `/healthz` (lecture seule) |
| Schéma de la base | vérifie seulement | migre (sauf `SECREVIEW_DB_AUTO_UPGRADE=false`) |
| Exposition conseillée | agents et CI, avec TLS | réseau interne ou accès restreint aux administrateurs |

Les deux processus ne s'appellent jamais : tout passe par la base. Un jeton créé ou révoqué sur
le contrôleur s'applique à la requête suivante du serveur MCP. Une règle modifiée est rechargée
en quelques secondes. Une demande d'enrôlement déposée sur le serveur MCP apparaît dans l'écran
**Jetons** du contrôleur.

L'enrôlement est servi par le serveur MCP parce que le client ne connaît que son URL. Le
contrôleur n'expose ainsi **aucune route d'écriture sans authentification**.

!!! note "Base partagée"
    Avec SQLite, les deux processus doivent tourner sur la même machine et partager le fichier.
    Dès qu'ils sont dans des pods ou sur des machines différents, utilisez PostgreSQL
    (extra `postgres`, image construite avec `--build-arg EXTRAS=postgres`).

En stdio (poste développeur), seul `security-review-mcp` est nécessaire : il crée et migre sa
base locale lui-même.

## Migrations du schéma

Le schéma est géré par des migrations [Alembic](https://alembic.sqlalchemy.org/), embarquées
dans le paquet (aucun fichier `alembic.ini` à fournir) :

```bash
security-review-controller db upgrade   # crée ou migre le schéma, puis amorce les règles par défaut
security-review-controller db status    # {"current": "0001", "head": "0001", "up_to_date": true}
```

- `db status` renvoie le code `1` si le schéma n'est pas à jour : pratique pour un script ou
  une sonde.
- Le **serveur MCP HTTP ne migre jamais** : il refuse de démarrer (code `2`, message
  `run security-review-controller db upgrade first`) tant que la base n'est pas à la révision
  attendue. Sous Kubernetes, le pod redémarre jusqu'à ce que la migration soit faite.
- Le contrôleur, le serveur MCP stdio et les commandes CLI migrent au démarrage, sauf avec
  `SECREVIEW_DB_AUTO_UPGRADE=false`. Ils vérifient alors seulement le schéma. Désactivez la
  migration automatique quand une tâche dédiée s'en charge (service `migrate` de Docker
  Compose, init container Kubernetes) : une seule migration à la fois.

## Docker Compose

`docker-compose.yml` démarre PostgreSQL, la migration, le contrôleur et le serveur MCP : voir
[Docker](docker.md#docker-compose-avec-postgresql).

## Kubernetes

L'exemple
[`examples/kubernetes/security-review.yaml`](https://github.com/cyr-ius/security-review-mcp/blob/master/examples/kubernetes/security-review.yaml)
déploie les deux processus sur une base PostgreSQL existante :

```bash
kubectl create namespace secreview
kubectl -n secreview create secret generic secreview-db \
    --from-literal=SECREVIEW_DATABASE_URL='postgresql+psycopg2://secreview:<password>@<host>:5432/secreview'
kubectl -n secreview create secret generic secreview-controller \
    --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
kubectl -n secreview apply -f examples/kubernetes/security-review.yaml
kubectl -n secreview exec deploy/secreview-controller -c controller -- security-review-controller user reset-password admin   # mot de passe admin initial
```

Il contient :

- un **Deployment `secreview-controller`** (une réplique, stratégie `Recreate`) dont l'init
  container lance `security-review-controller db upgrade` à chaque déploiement ;
- un **Deployment `secreview-mcp`**, qui vérifie seulement le schéma ;
- le **Secret `secreview-controller`**, créé à la main, avec `SECREVIEW_SECRET_KEY` : le
  système de fichiers racine est en lecture seule, le contrôleur ne peut donc pas écrire son
  `SECREVIEW_SECRET_KEY_FILE` ; sans lui, les sessions web prendraient fin à chaque
  redémarrage et ne seraient pas partagées entre réplicas (voir
  [Connexion et sessions](../usage/web-interface.md#connexion-et-sessions)) ;
- un Service par processus, des sondes `readiness` et `liveness` sur `/healthz`, des
  conteneurs non root en système de fichiers en lecture seule, sans capacité Linux ;
- une **NetworkPolicy** qui limite l'accès au contrôleur aux pods du namespace et à
  l'ingress controller (adaptez son label).

Remplacez l'image (`registry.example.com/security-review-mcp:pg`) par la vôtre, construite avec
l'extra `postgres`. Exposez le Service `secreview-mcp` aux agents et à la CI par un Ingress avec
TLS. Gardez le contrôleur interne (`kubectl port-forward`, VPN ou Ingress restreint aux
administrateurs). Derrière l'Ingress, réglez `SECREVIEW_FORWARDED_ALLOW_IPS` (en commentaire dans
la ConfigMap) sur la plage d'adresses des pods de l'ingress controller : sinon tous les clients
partagent leur adresse pour la limitation des connexions et les limites d'enrôlement. Les
commandes d'administration s'exécutent dans son pod :

```bash
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token list --pending
```

Pour la [mise à jour quotidienne des avis OSV](dependencies.md#mise-a-jour-automatique-par-le-controleur),
décommentez `SECREVIEW_OSV_AUTO_UPDATE` (et au besoin `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY`
et `NO_PROXY`, dans le Secret `secreview-controller` si le proxy contient des identifiants) sur
le conteneur `controller`, et autorisez sa sortie vers osv.dev ou votre miroir (ou le proxy) si une NetworkPolicy d'egress s'applique. Le serveur MCP
n'a besoin d'aucune sortie. La documentation Swagger de l'API REST (`/api/docs`) reste
désactivée tant que vous ne décommentez pas `SECREVIEW_SWAGGER_ENABLED`.

!!! warning "Plusieurs réplicas du serveur MCP"
    Les sessions MCP (transport streamable HTTP) sont gardées en mémoire par le pod qui les a
    ouvertes. Avant d'augmenter `replicas`, configurez l'Ingress pour envoyer toutes les
    requêtes d'une session au même pod (affinité sur l'en-tête `Mcp-Session-Id`, ou à défaut
    affinité par cookie ou par adresse). Le contrôleur peut, lui, avoir plusieurs réplicas, à
    condition que la migration soit faite par une seule tâche (`SECREVIEW_DB_AUTO_UPGRADE=false`
    sur les réplicas).
