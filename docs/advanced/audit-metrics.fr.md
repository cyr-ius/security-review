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
| `token.created` | Un jeton est créé (CLI `token create`, écran **Jetons**) |
| `token.rotated` | Le secret d'un jeton est remplacé (`token rotate`, bouton **Renouveler**), avec le délai de grâce |
| `token.revoked` | Un jeton est révoqué |
| `token.projects_changed` | Un administrateur change les projets d'un jeton (bouton **Projets** de l'écran **Jetons**), avec les projets précédents (`null` : tous les projets) |
| `enrollment.requested` | Un client demande un jeton ou un projet de plus ([enrôlement](http.md#enrolement-un-projet-demande-son-jeton)), avec le demandeur et son adresse |
| `enrollment.approved` | Un administrateur approuve une demande |
| `enrollment.rejected` | Un administrateur rejette une demande |

Chaque événement porte sa date, son **acteur**, sa cible (`finding` et son id, `token` et son
id, `enrollment` et l'id de la demande), le projet quand il y en a un, et des détails en JSON.
L'acteur est :

- `user:<nom>` : une personne connectée à l'interface web (compte local ou SSO) ;
- `token:<label>` : un jeton Bearer (agent, client de l'API, jeton administrateur) ;
- `cli` : une commande `security-review-controller` ;
- `anonymous` : l'endpoint public d'enrôlement ;
- `stdio` : un agent connecté au serveur MCP en stdio.

Les détails ne contiennent jamais de secret : aucun jeton, aucun mot de passe, et le texte libre
(motifs, demandeur) est masqué comme dans les rapports. Personne ne modifie un événement : aucun
outil MCP ni aucune route ne les change.

### Consulter le journal

Les administrateurs le consultent dans l'écran **Journal d'audit** de l'interface web (filtres
par événement et par projet), avec `GET /api/v1/audit` (rôle `admin` ; paramètres `action`,
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
défaut), au démarrage puis chaque jour ; `0` conserve tous les événements. La même purge se lance
à la demande :

```bash
security-review-controller audit prune              # conservation de SECREVIEW_AUDIT_RETENTION_DAYS
security-review-controller audit prune --days 730   # une autre durée, pour cette exécution seulement
# {"retention_days": 730, "deleted": 0}
```

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
| `secreview_tokens` | `role`, `state` | Jetons par rôle et état (`active`, `expired`, `pending`) |
| `secreview_tokens_expiring_soon` | | Jetons actifs qui expirent dans les 14 jours |
| `secreview_enrollment_requests_pending` | | Demandes d'enrôlement en attente d'un administrateur |
| `secreview_web_users` | `auth_source` | Comptes web (`local`, `oidc`) |
| `secreview_advisories` | | Avis de la base |
| `secreview_advisory_last_update_timestamp_seconds` | | Fin du dernier téléchargement OSV réussi (absente avant le premier) |
| `secreview_auth_rejections_total` | `reason` | Requêtes rejetées par l'authentification du processus qui répond, depuis son démarrage : `invalid_token`, `token_expired`, `enrollment_pending`, `insufficient_scope` |

Toutes les valeurs sauf `secreview_auth_rejections_total` viennent de la base. Les métriques
contiennent des nombres et des noms de projets, jamais un finding, un label de jeton ou un
secret ; les valeurs des labels sont échappées, si bien qu'un nom de projet ne peut pas ajouter
de lignes à la réponse. `SECREVIEW_METRICS_ENABLED=false` désactive l'endpoint (`404`).

Exemples d'alertes : `secreview_tokens_expiring_soon > 0`,
`secreview_open_findings{severity="critical"} > 0`,
`time() - secreview_advisory_last_update_timestamp_seconds > 2 * 86400`,
`rate(secreview_auth_rejections_total{reason="invalid_token"}[5m]) > 1`.
