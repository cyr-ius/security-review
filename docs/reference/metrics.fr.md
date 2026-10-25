# Métriques Prometheus

Les métriques sont lues dans la base partagée avec le serveur MCP : toutes les répliques du
contrôleur répondent la même chose (voir aussi le [journal d'audit](../advanced/audit-metrics.md)).

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
| `secreview_project_enrollments_pending` | | Projets demandés par les agents MCP des utilisateurs, en attente de validation |
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
