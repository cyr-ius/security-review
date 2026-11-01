# Triage par l'API REST

La page [triage](../../usage/triage.md) décrit les décisions dans l'interface web. Cette page donne
les limites, les réglages et les appels de l'API REST.

## Qui peut décider

Seule une **session** (compte local ou OIDC, voir [comptes utilisateurs](../../usage/user-accounts.md))
avec la permission `findings.triage` peut changer un statut, relever une criticité ou commenter :
un jeton Bearer, même `admin`, reçoit `403`. Un agent ne fait que proposer un statut avec l'outil
MCP `propose_finding_status` (voir [statut d'un finding](../../review/prompts-tools.md#statut-dun-finding)).

## Limites et réglages

| Élément | Limite | Réglage |
|---|---|---|
| **Motif** d'une acceptation | 10 à 1000 caractères ; facultatif pour un faux positif (10 à 1000 s'il est saisi) | — |
| **Date d'expiration** | 90 jours par défaut, au plus `SECREVIEW_MAX_DISMISSAL_DAYS` (`365`) | [configuration](../../reference/configuration.md) |
| **Sans expiration** | Permis pour une acceptation sauf avec `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false` ; un faux positif n'expire jamais | [configuration](../../reference/configuration.md) |
| Simple validation | Sous `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY` (`medium` par défaut), une acceptation ne demande ni motif ni date ; variable vide : toute acceptation les demande | [configuration](../../reference/configuration.md) |
| **Justification** d'une criticité | 10 à 1000 caractères | — |
| Commentaire | 2000 caractères au plus, secrets masqués | — |

## Statut d'un finding

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42 \
  -d '{"status": "accepted", "reason": "Internal tool, not exposed to the Internet", "expires_on": "2027-01-31"}'
# {"id": 42, "status": "accepted", "status_approver": "alice", "status_expires_at": "2027-01-31T00:00:00Z", …}
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/findings/42/proposal    # rejette la proposition de l'agent
```

**Ouvert** et **Corrigé** acceptent un motif facultatif. Un motif absent ou trop court, une date
d'expiration passée ou trop lointaine, ou une date d'expiration pour `open` / `fixed` reçoit
`422`. Sans `expires_on`, un faux positif n'expire jamais, une acceptation non plus, sauf si
`SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false` (`422`) ; `GET /api/v1/me` renvoie
`permanent_acceptance` pour indiquer si l'appelant peut le faire. Sous
`SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY`, `reason` et `expires_on` sont facultatifs pour
`accepted` (`{"status": "accepted"}` suffit) ; `GET /api/v1/me` renvoie ce seuil dans
`risk_acceptance_min_severity` (`null` : toute acceptation les exige).

## Finding signalé de nouveau

Le serveur reconnaît un problème à son empreinte : projet, règle ou CWE, fichier et titre, sans
le numéro de ligne, comme en [SARIF](sarif.md). Un finding de catégorie `dependency` avec un
`rule_id` ignore son titre : un avis (`GHSA-`, `CVE-`, `PYSEC-`...) est reconnu à son seul
identifiant, quel que soit le fichier (un scan le signale sur le lockfile, une revue sur le
manifeste), et une règle d'hygiène (`DEP-*`) à son identifiant et au nom du fichier. Quand une règle trouve plusieurs lignes d'un
fichier, les occurrences sont appariées dans l'ordre des lignes si leur nombre n'a pas changé
(le code a bougé), sinon seulement sur la même ligne : une nouvelle occurrence n'hérite jamais de
la décision prise sur une autre, elle est ouverte. Une proposition d'agent en attente
(acceptation ou faux positif) est reprise aussi.

L'occurrence précédente ne peut plus être triée (`422`) ni envoyée par un connecteur (`409`). La
tendance et le délai de correction partent de la première occurrence (`first_seen_at`).
`save_security_report` et les scans du pipeline renvoient `recurring_findings` (findings déjà
signalés par un rapport précédent) et `carried_decisions` (décisions reprises sur eux).

## Criticité d'un finding

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42/severity \
  -d '{"severity": "critical", "reason": "Endpoint reachable without authentication"}'
# {"id": 42, "severity": "critical", "original_severity": "medium", "severity_changed_by": "alice", …}
```

Une criticité plus basse ou inchangée, ou une justification absente, reçoit `422`. L'export
Markdown et `get_security_report` affichent la criticité du rapport, l'analyste, la date et la
justification ; le changement est inscrit au journal d'audit (`finding.severity_changed`).

## Acceptations de risque et commentaires

```bash
curl -H "Authorization: Bearer $SESSION" \
  "https://secreview.example.com/api/v1/risk-acceptances?project=shop-api"
# {"project": "shop-api", "total": 1, "acceptances": [{"id": 42, "status": "accepted", "expired": false, "comments_total": 1, …}]}
curl -H "Authorization: Bearer $SESSION" https://secreview.example.com/api/v1/findings/42/comments
# [{"id": 7, "finding_id": 42, "author": "alice", "body": "Renew it after the audit", "created_at": "…"}]
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42/comments -d '{"body": "Renew it after the audit"}'
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42 -d '{"status": "open"}'    # supprimer l'acceptation
```

`GET /api/v1/risk-acceptances` accepte `limit` (plafonné par `SECREVIEW_MAX_LIST_LIMIT`) et
`offset` ; sans `project`, il liste tous les projets que l'appelant peut lire. La page s'ouvre
aussi à l'adresse `/ui/risk-acceptances`.

Aucune route de l'API ne modifie ni ne supprime un commentaire. Toute personne qui lit le projet
voit les commentaires ; chacun est inscrit au journal d'audit (`finding.commented`). Accepter un
risque, ou l'accepter de nouveau avec un autre motif, ajoute le motif aux commentaires ; changer
la date d'expiration n'en ajoute aucun.
