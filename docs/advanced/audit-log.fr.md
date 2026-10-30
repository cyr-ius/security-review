# Journal d'audit en détail

La page [journal d'audit](../usage/audit-metrics.md) décrit le journal dans l'interface web.
Cette page donne chaque événement, l'API, la ligne de commande et les variables.

Le serveur Controller tient un **journal d'audit** des changements qui touchent à la sécurité. Il lit
la base partagée avec le serveur MCP : toutes les répliques répondent la même chose. Les
métriques du serveur Controller sont dans [Métriques Prometheus](../reference/metrics.md).

Chaque changement ci-dessous écrit un événement dans la même transaction que le changement
lui-même : un événement existe exactement quand le changement a été validé.

| Action | Écrite quand |
|---|---|
| `finding.status_changed` | Une personne enregistre une décision de triage dans l'interface web (`PATCH /api/v1/findings/{id}`) : statut précédent, nouveau statut, motif, date d'expiration et proposition d'agent tranchée |
| `finding.status_proposed` | Un agent propose un statut avec `propose_finding_status` (jamais appliqué) |
| `finding.proposal_rejected` | Un trieur rejette la proposition d'un agent |
| `finding.commented` | Une personne commente un finding (`POST /api/v1/findings/{id}/comments`) : le commentaire, secrets masqués |
| `finding.severity_changed` | Un analyste de sécurité relève la criticité d'un finding, ou rétablit celle du rapport (`PATCH /api/v1/findings/{id}/severity`) : criticité précédente, nouvelle et d'origine, justification |
| `token.created` | Un jeton est créé (CLI `token create`, page **Jetons**) |
| `token.rotated` | Le secret d'un jeton est remplacé (`token rotate`, bouton **Renouveler**), avec le délai de grâce |
| `token.revoked` | Un jeton est révoqué |
| `token.projects_changed` | Un administrateur change les projets d'un jeton (bouton **Projets** de la page **Jetons**), avec les projets précédents (`null` : tous les projets) |
| `enrollment.requested` | L'agent d'un utilisateur demande un projet avec `request_project` ([enrôlement](architecture/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)), avec le jeton pour acteur, l'utilisateur demandeur, son adresse, si une nouvelle demande a été déposée (`requested`) et si le projet existait déjà (`existing` : une demande d'accès) |
| `enrollment.approved` | Un utilisateur portant `projects.create` valide un projet en attente (`granted_to` : le demandeur, dans le détail) ; le projet est ajouté au demandeur avec `reports.read` et `reports.write` (`user.projects_changed`) |
| `enrollment.rejected` | Un utilisateur refuse un projet en attente, ou il expire (acteur `enrollment`, `reason` : `expired`) |
| `role.created`, `role.updated`, `role.deleted` | Un administrateur crée, modifie (avec les permissions précédentes) ou supprime un [rôle](../usage/access-control.md#roles) |
| `group.*`, `user.groups_changed` | Changements des groupes d'utilisateurs web, supprimés en version 10 : gardés dans l'historique |
| `oidc.mappings_changed` | Un administrateur remplace les [correspondances OIDC](../usage/sso.md#correspondances-oidc) (claims ajoutés et retirés), une connexion associe une valeur de `SECREVIEW_OIDC_ADMIN_GROUPS` (acteur `oidc`), ou la suppression d'un projet les modifie |
| `project.created` | Un utilisateur avec `projects.create` [crée un projet](../usage/projects.md#creation-dun-projet), ou son agent avec `request_project` (acteur : le jeton) (l'identifiant de l'utilisateur et ses permissions `reports.read` et `reports.write` dans le détail) |
| `project.joined` | Un utilisateur avec `projects.autojoin` rejoint un projet existant par `request_project` (acteur : le jeton) (l'identifiant de l'utilisateur et ses permissions `reports.read` et `reports.write` dans le détail) |
| `project.autojoin_changed` | Un utilisateur avec `projects.create` [bloque ou autorise de nouveau l'adhésion automatique](../usage/projects.md#blocage-de-ladhesion-automatique) à un projet (`blocked` dans le détail) |
| `project.deleted` | Un utilisateur avec `projects.delete` [supprime un projet](../usage/projects.md#suppression-dun-projet) (nombre de rapports, de findings, de membres et de jetons, correspondances OIDC modifiées dans le détail) |
| `user.roles_changed` | Un administrateur remplace les rôles d'un compte (identifiants de rôle ajoutés et retirés) ; une connexion garde les claims OIDC du dernier détenteur de `users.manage` (acteur `oidc`) |
| `user.projects_changed` | Un administrateur remplace les projets d'un compte (ou ses droits sur tous les projets), ou les [membres](../usage/projects.md#membres) d'un projet, ou une demande de projet ajoute un projet avec sa lecture et son écriture (`projet=droits` de chaque projet, projets retirés) |
| `user.roles_changed` | Anciens rôles directs d'un compte (`roles` : `rôle` ou `rôle:projet,projet`) : plus enregistré depuis que les comptes n'ont plus de rôle propre, gardé dans l'historique |
| `user.login` | Un utilisateur web se connecte (méthode `password` ou `oidc`, adresse) |
| `user.login_failed` | Une connexion échoue : mot de passe incorrect, connexion OIDC refusée (méthode, adresse, et l'identifiant seulement s'il est valide) |
| `user.logout` | Un utilisateur web se déconnecte avec **Déconnexion** (adresse) |
| `audit_syslog.changed` | Le [serveur syslog](#envoi-vers-syslog) est modifié sur la page **Journal d'audit** (adresse et *facility* définies, `null` : valeur enregistrée supprimée) |
| `controller_url.changed` | L'URL publique du serveur Controller, dont l'interface web est donnée aux agents sans jeton, est modifiée dans la page **Général**, ou recopiée depuis `SECREVIEW_PUBLIC_URL` par le serveur Controller au démarrage (acteur `environment`) ; `null` : valeur enregistrée supprimée |
| `oauth.client_registered` | Un client MCP s'enregistre pour la [connexion OAuth](mcp-oauth.md) (acteur `anonymous`, nom du client) |
| `oauth.grant_approved` / `oauth.grant_denied` | Un utilisateur web autorise ou refuse un client MCP sur la page **Connecter un client MCP** |
| `oauth.grant_revoked` | Une autorisation OAuth est révoquée : dans **Mon compte**, sur la page **Jetons** (une ou toutes), par le client (`/revoke`), ou avec son utilisateur |
| `oauth.refresh_reused` | Un jeton de rafraîchissement déjà remplacé est présenté à nouveau : l'autorisation est révoquée |
| `mcp_oauth.changed` | La [connexion OAuth](mcp-oauth.md) est activée ou désactivée, ou son point d'accès MCP changé, dans l'interface web |

Chaque événement porte sa date, son **acteur**, sa cible (`finding` et son id, `token` et son
id, `project` et son nom), le projet quand il y en a un, et des détails en JSON.
L'acteur est :

- `user:<nom>` : une personne connectée à l'interface web (compte local ou OIDC) ;
- `token:<label>` : un jeton Bearer (agent, client de l'API, jeton administrateur) ;
- `cli` : une commande `security-review-controller` ;
- `anonymous` : une connexion échouée ;
- `stdio` : un agent connecté au serveur MCP en stdio.

Les détails ne contiennent jamais de secret : aucun jeton, aucun mot de passe, et le texte libre
(motifs, demandeur) est masqué comme dans les rapports. Personne ne modifie un événement : aucun
outil MCP ni aucune route ne les change.

## Consulter le journal

Les administrateurs le consultent dans la page **Journal d'audit** de l'interface web (filtres
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

## Conservation

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

## Envoi vers syslog

Le serveur Controller peut aussi envoyer chaque événement à un serveur syslog, pour le conserver hors de
la base (SIEM, journal central). Désactivé par défaut :

```bash
SECREVIEW_AUDIT_SYSLOG_ADDRESS=udp://syslog.example.com:514   # ou tcp://hôte:port, tls://hôte:port, unix:///dev/log
SECREVIEW_AUDIT_SYSLOG_FACILITY=local0                        # par défaut
```

Pour chiffrer les événements, utilisez `tls://hôte:port` (syslog sur TLS, RFC 5425, port 6514
par défaut) : le serveur Controller vérifie le certificat du serveur et son nom d'hôte avec les autorités
du système, ou avec `SECREVIEW_AUDIT_SYSLOG_CAFILE` (autorité de certification interne, variable
uniquement). Chaque message est alors précédé de sa longueur (*octet counting*), comme l'exige la
RFC 5425 : sur rsyslog, `imtcp` avec `StreamDriver.Mode="1"` ; sur syslog-ng, la source
`syslog()` avec `transport("tls")`.

Les administrateurs (permission `settings.manage`) peuvent aussi le régler sur la page **Journal
d'audit** de l'interface web, avec le bouton **Syslog** à côté de **Actualiser** (icône d'envoi
cochée quand les événements sont envoyés, barrée sinon ; son infobulle indique le serveur). Il
ouvre la fenêtre **Envoi vers syslog** : **Aucun envoi** ou **Défini ici** (`udp://hôte:port`,
`tcp://hôte:port` ou `tls://hôte:port`), et la *facility*. **Une variable définie est
prioritaire** : son champ est alors verrouillé, et une valeur définie là auparavant est ignorée
(**Supprimer** l'efface) ; un `SECREVIEW_AUDIT_SYSLOG_ADDRESS` vide compte comme non défini. Une
valeur définie là s'applique en une dizaine de secondes, sans redémarrage ; la modification est
elle-même inscrite au journal d'audit (`audit_syslog.changed`). À l'arrêt de l'envoi, les
événements en attente, cette modification comprise, partent d'abord vers l'ancien serveur : le
SIEM voit qui l'a arrêté. Un socket Unix est un fichier du déploiement : il se règle uniquement
par la variable, comme le fichier d'autorité de TLS. Par l'API : `GET` et `PUT /api/v1/settings/audit-syslog` avec `address` et
`facility` (`null` supprime la valeur enregistrée, un champ absent est inchangé, un champ dont la
variable est définie est refusé avec 422).

Chaque événement est un message de sévérité `info`, étiqueté `secreview-audit`, dont le corps est
l'événement en JSON, avec les mêmes champs que `audit list` :

```
<134>secreview-audit: {"action":"user.login","actor":"user:alice","created_at":"…","details":{"address":"10.0.0.8","method":"password"},"id":12,"project":null,"target_id":"2","target_type":"user"}
```

- Le serveur Controller envoie les événements de **tous** les processus, serveur MCP et CLI compris,
  depuis la base : le serveur MCP ne fait toujours aucune connexion sortante. Un événement part
  environ 5 à 15 secondes après son écriture ; l'historique antérieur à l'activation de l'envoi
  (au démarrage ou dans l'interface web) n'est pas envoyé.
- Chaque événement est envoyé **une fois**, même avec plusieurs répliques du serveur Controller : l'id du
  dernier événement envoyé est conservé en base, et une réplique l'avance avant d'envoyer. Un lot
  dont l'envoi échoue est journalisé et n'est pas renvoyé (au plus une fois).
- `udp://` et `tcp://` envoient les événements en clair : réservez-les à un réseau de confiance
  ou à un relais local, et utilisez `tls://` sinon. Pas de proxy. Un certificat refusé est
  journalisé comme un envoi en échec (le lot n'est pas renvoyé). Une variable invalide, ou un
  fichier d'autorité introuvable, arrête `serve` au démarrage ; une adresse invalide est refusée
  par l'interface web.
