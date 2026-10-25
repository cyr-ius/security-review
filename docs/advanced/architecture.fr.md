# Architecture et déploiement

En mode partagé, le serveur se compose de **deux processus** indépendants qui partagent la même base de
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
| Commande | `security-review-mcp serve --transport streamable-http` | `security-review-controller serve` |
| Sert | `/mcp`, enrôlement public `POST /api/v1/enroll`, `/healthz` | API REST `/api/v1`, interface `/ui`, `/healthz` |
| Identifiants acceptés | jetons `mcp` et `admin` | sessions web (utilisateurs), jetons `admin` et `api` ; jetons `ci` sur les seules routes de pipeline `/api/v1/ci/` (gate, SARIF, tendance, scans) |
| Routes sans jeton | enrôlement, `/healthz` | fichiers de `/ui`, documentation de l'API, `/healthz` (lecture seule) |
| Schéma de la base | vérifie seulement | migre (sauf `SECREVIEW_DB_AUTO_UPGRADE=false`) |
| Exposition conseillée | agents et CI, avec TLS | réseau interne ou accès restreint aux administrateurs |

Les deux processus ne s'appellent jamais : tout passe par la base. Un jeton créé ou révoqué sur
le contrôleur s'applique à la requête suivante du serveur MCP. Une règle modifiée est rechargée
en quelques secondes. Un projet demandé sur le serveur MCP attend sa validation dans
l'écran **Projets** du contrôleur.

L'enrôlement est servi par le serveur MCP parce que le client ne connaît que son URL. Le
contrôleur n'expose ainsi **aucune route d'écriture sans authentification**.

!!! note "Base partagée"
    Avec SQLite, les deux processus doivent tourner sur la même machine et partager le fichier.
    Dès qu'ils sont dans des pods ou sur des machines différents, utilisez PostgreSQL
    (extra `postgres` du paquet PyPI, inclus dans l'image), déployé avec
    [Docker Compose](docker.md#docker-compose-avec-postgresql) ou [Kubernetes](kubernetes.md#deploiement).

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
  `SECREVIEW_DB_AUTO_UPGRADE=false`. Ils vérifient alors seulement le schéma. Avec Docker
  Compose, le contrôleur migre à son démarrage ; sous Kubernetes, c'est son init container.
- Sur PostgreSQL, une migration prend un verrou consultatif (advisory lock) : des instances qui
  démarrent ensemble (plusieurs réplicas, un `db upgrade` lancé à la main) s'attendent, et la
  suivante trouve le schéma à jour. Ne désactivez la migration automatique que pour la confier à
  une tâche dédiée.
