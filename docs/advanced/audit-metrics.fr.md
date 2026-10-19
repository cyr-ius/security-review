# Journal d'audit et métriques

Le contrôleur tient un **journal d'audit** des changements qui touchent à la sécurité et sert
des **métriques Prometheus** sur `/metrics`. Les deux lisent la base partagée avec le serveur
MCP : toutes les répliques répondent la même chose.

## Journal d'audit

Chaque changement ci-dessous écrit un événement dans la même transaction que le changement
lui-même : un événement existe exactement quand le changement a été validé.

| Action | Écrite quand |
|---|---|
| `finding.status_changed` | Une personne enregistre une décision de triage dans l'interface web (`PATCH /api/v1/findings/{id}`) : statut précédent, nouveau statut, motif, date d'expiration et proposition d'agent tranchée |
| `finding.status_proposed` | Un agent propose un statut avec `propose_finding_status` (jamais appliqué) |
| `finding.proposal_rejected` | Un trieur rejette la proposition d'un agent |
| `finding.commented` | Une personne commente un finding (`POST /api/v1/findings/{id}/comments`) : le commentaire, secrets masqués |
| `finding.severity_changed` | Un analyste de sécurité relève la criticité d'un finding, ou rétablit celle du rapport (`PATCH /api/v1/findings/{id}/severity`) : criticité précédente, nouvelle et d'origine, justification |
| `token.created` | Un jeton est créé (CLI `token create`, écran **Jetons**) |
| `token.rotated` | Le secret d'un jeton est remplacé (`token rotate`, bouton **Renouveler**), avec le délai de grâce |
| `token.revoked` | Un jeton est révoqué |
| `token.projects_changed` | Un administrateur change les projets d'un jeton (bouton **Projets** de l'écran **Jetons**), avec les projets précédents (`null` : tous les projets) |
| `enrollment.requested` | Un client demande un projet ([enrôlement](http.md#enrolement-demander-le-projet)), avec le demandeur, son adresse et si une nouvelle demande a été déposée (`requested`) |
| `enrollment.approved` | Un utilisateur portant `projects.create` valide un projet en attente (son groupe dans le détail) |
| `enrollment.rejected` | Un utilisateur refuse un projet en attente, ou il expire (acteur `enrollment`, `reason` : `expired`) |
| `role.created`, `role.updated`, `role.deleted` | Un administrateur crée, modifie (avec les permissions précédentes) ou supprime un [rôle](access-control.md#roles) |
| `group.created`, `group.updated`, `group.deleted` | Un administrateur crée, renomme ou modifie, ou supprime un [groupe](access-control.md#groupes) ; la validation d'un enrôlement crée un [groupe de projet](access-control.md#groupes-de-projet) manquant (`project` dans le détail) |
| `group.roles_changed`, `group.members_changed` | Un administrateur remplace les rôles (avec leurs projets) ou les membres (identifiants ajoutés et retirés) d'un groupe |
| `project.created` | Un utilisateur avec `projects.create` [crée un projet](access-control.md#creation-dun-projet) (son groupe de projet et l'identifiant de l'utilisateur dans le détail) |
| `project.deleted` | Un utilisateur avec `projects.delete` [supprime un projet](access-control.md#suppression-dun-projet) (nombre de rapports, de findings et de jetons, groupes supprimés ou modifiés dans le détail) |
| `user.groups_changed` | Un administrateur remplace les groupes donnés à un compte, par exemple pour l'ajouter à un [groupe de projet](access-control.md#groupes-de-projet) (identifiants de groupes ajoutés et retirés) |
| `user.roles_changed` | Anciens rôles directs d'un compte (`roles` : `rôle` ou `rôle:projet,projet`) : plus enregistré depuis que les comptes n'ont plus de rôle propre, gardé dans l'historique |
| `user.login` | Un utilisateur web se connecte (méthode `password` ou `oidc`, adresse) |
| `user.login_failed` | Une connexion échoue : mot de passe incorrect, connexion OIDC refusée (méthode, adresse, et l'identifiant seulement s'il est valide) |
| `user.logout` | Un utilisateur web se déconnecte avec **Déconnexion** (adresse) |
| `audit_syslog.changed` | Le [serveur syslog](#envoi-vers-syslog) est modifié sur la page **Journal d'audit** (adresse et *facility* définies, `null` : valeur enregistrée supprimée) |

Chaque événement porte sa date, son **acteur**, sa cible (`finding` et son id, `token` et son
id, `project` et son nom), le projet quand il y en a un, et des détails en JSON.
L'acteur est :

- `user:<nom>` : une personne connectée à l'interface web (compte local ou OIDC) ;
- `token:<label>` : un jeton Bearer (agent, client de l'API, jeton administrateur) ;
- `cli` : une commande `security-review-controller` ;
- `anonymous` : l'endpoint public d'enrôlement, ou une connexion échouée ;
- `stdio` : un agent connecté au serveur MCP en stdio.

Les détails ne contiennent jamais de secret : aucun jeton, aucun mot de passe, et le texte libre
(motifs, demandeur) est masqué comme dans les rapports. Personne ne modifie un événement : aucun
outil MCP ni aucune route ne les change.

### Consulter le journal

Les administrateurs le consultent dans l'écran **Journal d'audit** de l'interface web (filtres
par événement et par projet), avec `GET /api/v1/audit` (permission `audit.read` ; paramètres `action`,
`project`, `actor`, `since`, `limit`, `offset`, du plus récent au plus ancien) ou en ligne de
commande :

```bash
security-review-controller audit list --action token.rotated --since 2026-10-01
security-review-controller audit list --project shop-api --actor user:alice --limit 20
# {"total": 1, "events": [{"id": 12, "created_at": "…", "action": "finding.status_changed",
#   "actor": "user:alice", "target_type": "finding", "target_id": "42", "project": "shop-api",
#   "details": {"previous_status": "open", "status": "accepted", "reason": "…", …}}]}
```

`--limit` (et le paramètre `limit`) est plafonné par `SECREVIEW_MAX_LIST_LIMIT`.

### Conservation

`serve` supprime les événements de plus de `SECREVIEW_AUDIT_RETENTION_DAYS` jours (`365` par
défaut), au démarrage puis chaque jour ; `0` conserve tous les événements. Avec
`SECREVIEW_AUDIT_MAX_EVENTS` (`0` par défaut, sans limite), la même purge ne garde ensuite qu'au
plus ce nombre d'événements, en supprimant les plus anciens. La même purge se lance à la demande :

```bash
security-review-controller audit prune              # SECREVIEW_AUDIT_RETENTION_DAYS et SECREVIEW_AUDIT_MAX_EVENTS
security-review-controller audit prune --days 730   # une autre durée, pour cette exécution seulement
# {"retention_days": 730, "max_events": 0, "deleted": 0}
security-review-controller audit prune --max-events 100000
```

### Envoi vers syslog

Le contrôleur peut aussi envoyer chaque événement à un serveur syslog, pour le conserver hors de
la base (SIEM, journal central). Désactivé par défaut :

```bash
SECREVIEW_AUDIT_SYSLOG_ADDRESS=udp://syslog.example.com:514   # ou tcp://hôte:port, unix:///dev/log
SECREVIEW_AUDIT_SYSLOG_FACILITY=local0                        # par défaut
```

Les administrateurs (permission `settings.manage`) peuvent aussi le régler sur la page **Journal
d'audit** de l'interface web, avec le bouton **Syslog** à côté de **Actualiser** (icône d'envoi
cochée quand les événements sont envoyés, barrée sinon ; son infobulle indique le serveur). Il
ouvre la fenêtre **Envoi vers syslog** : **Aucun envoi** ou **Défini ici** (`udp://hôte:port` ou
`tcp://hôte:port`), et la *facility*. **Une variable définie est
prioritaire** : son champ est alors verrouillé, et une valeur définie là auparavant est ignorée
(**Supprimer** l'efface) ; un `SECREVIEW_AUDIT_SYSLOG_ADDRESS` vide compte comme non défini. Une
valeur définie là s'applique en une dizaine de secondes, sans redémarrage ; la modification est
elle-même inscrite au journal d'audit (`audit_syslog.changed`). À l'arrêt de l'envoi, les
événements en attente, cette modification comprise, partent d'abord vers l'ancien serveur : le
SIEM voit qui l'a arrêté. Un socket Unix est un fichier du déploiement : il se règle uniquement
par la variable. Par l'API : `GET` et `PUT /api/v1/settings/audit-syslog` avec `address` et
`facility` (`null` supprime la valeur enregistrée, un champ absent est inchangé, un champ dont la
variable est définie est refusé avec 422).

Chaque événement est un message de sévérité `info`, étiqueté `secreview-audit`, dont le corps est
l'événement en JSON, avec les mêmes champs que `audit list` :

```
<134>secreview-audit: {"action":"user.login","actor":"user:alice","created_at":"…","details":{"address":"10.0.0.8","method":"password"},"id":12,"project":null,"target_id":"2","target_type":"user"}
```

- Le contrôleur envoie les événements de **tous** les processus, serveur MCP et CLI compris,
  depuis la base : le serveur MCP ne fait toujours aucune connexion sortante. Un événement part
  environ 5 à 15 secondes après son écriture ; l'historique antérieur à l'activation de l'envoi
  (au démarrage ou dans l'interface web) n'est pas envoyé.
- Chaque événement est envoyé **une fois**, même avec plusieurs répliques du contrôleur : l'id du
  dernier événement envoyé est conservé en base, et une réplique l'avance avant d'envoyer. Un lot
  dont l'envoi échoue est journalisé et n'est pas renvoyé (au plus une fois).
- Ni TLS ni proxy : pour chiffrer, envoyez à un relais local (`rsyslog`, `syslog-ng`, Fluent Bit)
  qui transmet en TLS. Une variable invalide arrête `serve` au démarrage ; une adresse invalide
  est refusée par l'interface web.

## Métriques Prometheus

`GET /metrics` sur le **contrôleur** répond au format texte de Prometheus (`0.0.4`). Le serveur
MCP n'a pas d'endpoint de métriques. Il faut un jeton de rôle `metrics`, qui n'atteint rien
d'autre (ni l'API REST, ni MCP), ou `admin` :

```bash
security-review-controller token create --label prometheus --role metrics --expires-in-days 365
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/metrics
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: security-review
    scheme: https
    authorization:
      credentials_file: /etc/prometheus/secreview-token
    static_configs:
      - targets: ["secreview.example.com"]
```

| Métrique | Labels | Valeur |
|---|---|---|
| `secreview_build_info` | `version` | `1` |
| `secreview_projects` | | Projets ayant des rapports |
| `secreview_reports` | | Rapports stockés |
| `secreview_findings` | `status` | Findings par statut effectif (une décision expirée compte comme `open`) |
| `secreview_open_findings` | `severity` | Findings ouverts par sévérité |
| `secreview_project_open_findings` | `project`, `severity` | Findings ouverts de chaque projet |
| `secreview_finding_proposals_pending` | | Propositions d'agents en attente d'une personne |
| `secreview_tokens` | `role`, `state` | Jetons par rôle et état (`active`, `expired`) |
| `secreview_tokens_expiring_soon` | | Jetons actifs qui expirent dans les 14 jours |
| `secreview_project_enrollments_pending` | | Projets demandés par un enrôlement, en attente de validation |
| `secreview_web_users` | `auth_source` | Comptes web (`local`, `oidc`) |
| `secreview_advisories` | | Avis de la base |
| `secreview_advisory_last_update_timestamp_seconds` | | Fin du dernier téléchargement OSV réussi (absente avant le premier) |
| `secreview_auth_rejections_total` | `reason` | Requêtes rejetées par l'authentification du processus qui répond, depuis son démarrage : `invalid_token`, `token_expired`, `insufficient_scope` |

Toutes les valeurs sauf `secreview_auth_rejections_total` viennent de la base. Les métriques
contiennent des nombres et des noms de projets, jamais un finding, un label de jeton ou un
secret ; les valeurs des labels sont échappées, si bien qu'un nom de projet ne peut pas ajouter
de lignes à la réponse. `SECREVIEW_METRICS_ENABLED=false` désactive l'endpoint (`404`).

Exemples d'alertes : `secreview_tokens_expiring_soon > 0`,
`secreview_open_findings{severity="critical"} > 0`,
`time() - secreview_advisory_last_update_timestamp_seconds > 2 * 86400`,
`rate(secreview_auth_rejections_total{reason="invalid_token"}[5m]) > 1`.
