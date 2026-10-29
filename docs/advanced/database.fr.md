# Base de données

Le serveur Controller et le serveur MCP partagent une même base : rapports et findings, règles,
comptes, empreintes des jetons, réglages et journal d'audit. Cette page regroupe ce qui la
concerne : choix du moteur, migrations du schéma, conservation, sauvegarde et mise à niveau. Les
variables sont listées dans [Configuration](../reference/configuration.md#base-de-donnees-et-journaux).

## SQLite ou PostgreSQL

- En [mode local (stdio)](../getting-started/stdio.md), c'est-à-dire le mode tout-en-un d'un
  poste de développeur, seule une base SQLite est acceptée. Le serveur MCP local crée et migre
  lui-même sa base SQLite.

    Une base SQLite est créée par défaut dans le dossier de données de l'utilisateur :
    `~/.local/share/security-review-mcp/security_reports.db`.

    Pour changer l'emplacement de la base SQLite, démarrez le serveur MCP local avec la commande
    `security-review-mcp local --database-url sqlite:////home/me/security_reports.db`.

- En mode partagé, vous pouvez utiliser une base PostgreSQL si vous séparez le serveur MCP et le
  serveur Controller. Pour cela, passez la variable d'environnement aux deux processus :

```bash
SECREVIEW_DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/secreview
security-review-controller serve
```

!!! note "Base partagée"
    Avec SQLite, les deux processus doivent tourner sur la même machine et partager le même fichier.
    Dès qu'ils sont dans des pods ou sur des machines différents, utilisez PostgreSQL.

## Migrations du schéma

Le schéma est géré par des migrations [Alembic](https://alembic.sqlalchemy.org/), embarquées
dans le paquet (aucun fichier `alembic.ini` à fournir) :

```bash
security-review-controller db upgrade   # crée ou migre le schéma, puis amorce les règles par défaut
security-review-controller db status    # {"current": "0032", "head": "0032", "up_to_date": true}
```

- `db status` renvoie le code `1` si le schéma n'est pas à jour : pratique pour un script ou
  une sonde.
- Le **serveur MCP HTTP ne migre jamais** : il refuse de démarrer (code `2`, message
  `run security-review-controller db upgrade first`) tant que la base n'est pas à la révision
  attendue. Sous Kubernetes, le pod redémarre jusqu'à ce que la migration soit faite.
- Le serveur Controller, le serveur MCP stdio et les commandes CLI migrent au démarrage : avec Docker
  Compose et Kubernetes, le serveur Controller migre à son démarrage, il n'y a rien à faire.
- Sur PostgreSQL, une migration prend un verrou consultatif (advisory lock) : des instances qui
  démarrent ensemble (plusieurs réplicas, un `db upgrade` lancé à la main) s'attendent, et la
  suivante trouve le schéma à jour.
- La version 10 (révision `0039`) transforme les groupes d'utilisateurs web en rôles des
  utilisateurs et en correspondances OIDC, en gardant les droits de chaque compte, et supprime les
  rôles `triager` et `mcp-user` (les jetons API de ces rôles sont révoqués). Elle **ne peut pas
  être rétrogradée** : sauvegardez la base avant la mise à niveau.

### Tâche de migration dédiée

Par défaut, rien n'est à configurer. `SECREVIEW_DB_AUTO_UPGRADE=false` ne sert qu'à un
exploitant qui sort les migrations de l'application, par exemple quand :

- le compte de base de données de l'application n'a pas le droit de modifier le schéma (pas de
  DDL) : une tâche lance `security-review-controller db upgrade` avec un compte privilégié ;
- une nouvelle image ne doit pas modifier le schéma d'elle-même : la migration est lancée après
  une sauvegarde, ou pendant une fenêtre de maintenance.

Le serveur Controller, le serveur MCP stdio et les commandes CLI vérifient alors seulement le schéma :
comme le serveur MCP HTTP, ils refusent de démarrer (code `2`) tant que `db upgrade` n'a pas été
lancé.

## Conservation des rapports sans findings

Le serveur Controller supprime ces rapports dès qu'ils ont plus de
`SECREVIEW_EMPTY_REPORT_RETENTION_DAYS` jours (`90` par défaut) : au démarrage, puis
chaque jour. Le dernier rapport de chaque projet est toujours conservé, si bien qu'un projet ne
disparaît jamais de la liste, et un rapport avec des findings n'est jamais supprimé, quel que
soit leur statut. `0` désactive la purge.

La même purge peut être lancée à la demande, par exemple depuis une tâche planifiée quand le
serveur Controller ne tourne pas :

```bash
security-review-controller db prune              # conservation de SECREVIEW_EMPTY_REPORT_RETENTION_DAYS
security-review-controller db prune --days 30    # une autre durée, pour cette exécution seulement
# {"retention_days": 30, "deleted": 4}
```

Les événements du journal d'audit ont leur propre conservation : voir
[Journal d'audit](audit-log.md#conservation).

## Sauvegarde de PostgreSQL

Avec [Docker Compose](deployment/docker.md#docker-compose-avec-postgresql), le volume
`secreview-pg` contient les rapports, les comptes et les empreintes des jetons. Exportez-le
régulièrement (cron, timer systemd) et conservez les fichiers hors du serveur, lisibles par vous
seul :

```bash
(umask 077 && docker compose exec -T db pg_dump -U secreview -d secreview -Fc > ~/secreview-$(date +%F).dump)
# Restaurer un export (les services sont arrêtés pendant la restauration)
docker compose stop mcp controller
docker compose exec -T db pg_restore -U secreview -d secreview --clean --if-exists --no-owner < ~/secreview-2026-10-25.dump
docker compose start controller mcp
```

## Mise à niveau de PostgreSQL

Une version majeure de PostgreSQL ne lit pas les fichiers de données de la précédente. Pour
passer un volume `secreview-pg` de PostgreSQL 17 à 18, exportez la base avec l'ancienne image,
recréez le volume puis restaurez l'export :

```bash
# 1. Avec le fichier Compose précédent (postgres:17-alpine, montage sur /var/lib/postgresql/data)
docker compose stop mcp controller
(umask 077 && docker compose exec -T db pg_dump -U secreview -d secreview -Fc > ~/secreview.dump)
docker compose down

# 2. Vérifier l'export (il liste les tables), puis recréer le volume : l'export est désormais
#    la seule copie des données
docker compose run --rm -T --no-deps --entrypoint pg_restore db --list < ~/secreview.dump | grep 'TABLE DATA'
docker volume rm security-review-mcp_secreview-pg

# 3. Avec le fichier Compose actuel (postgres:18-alpine, montage sur /var/lib/postgresql)
docker compose up -d db
docker compose exec -T db pg_restore -U secreview -d secreview --clean --if-exists --no-owner < ~/secreview.dump
docker compose up -d
```

Le serveur Controller applique ensuite au démarrage les révisions Alembic en attente, s'il y en a. L'export
contient les rapports, les empreintes des mots de passe et des jetons : gardez-le hors du dépôt
(lisible par vous seul, `umask 077`) et supprimez-le une fois la restauration vérifiée.

Sous Kubernetes, le StatefulSet de `postgres.yaml` est un point de départ : en production,
préférez une base managée ou un opérateur, qui gèrent la réplication, les sauvegardes et les
mises à niveau (voir [Kubernetes](deployment/kubernetes.md)).
