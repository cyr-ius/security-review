# Triage des findings

Le statut d'un finding est décidé par une **personne** ; un agent ne fait que le proposer (outil
MCP `propose_finding_status`, voir [statut d'un finding](prompts-tools.md#statut-dun-finding)).
Un trieur peut aussi envoyer un finding vers Jira ou ServiceNow (**Envoyer vers Jira**), quand
son projet a une destination : voir [connecteurs](../connectors/index.md#envoi-dun-finding).

- **Proposition d'un agent** : affichée sur le finding dans un encadré distinct, avec son auteur
  (label du jeton), sa date et son motif. Le motif peut venir du code relu : vérifiez-le.
  **Appliquer** enregistre `fixed` immédiatement, ou ouvre le formulaire ci-dessous pour
  `accepted` et `false_positive` ; **Rejeter** supprime la proposition. Aucun des deux ne change
  le statut à lui seul.
- **Risque accepté** : la liste des statuts ouvre un formulaire qui demande
  un **Motif** (10 à 1000 caractères) et une **Date d'expiration** (90 jours par défaut, au plus
  `SECREVIEW_MAX_DISMISSAL_DAYS`). L'utilisateur connecté est enregistré comme approbateur ; la
  carte affiche l'approbateur, le motif et la fin de validité. À partir de la date d'expiration,
  le finding est de nouveau compté comme ouvert (filtre de statut, posture,
  [gate](gate.md), SARIF, tendance) et la carte indique que la décision a expiré. Pour
  **Risque accepté**, la case **Sans expiration** supprime la date : le risque reste accepté
  jusqu'à ce que quelqu'un rouvre le finding (désactivée par
  `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false`).
- **Faux positif** : le formulaire ne demande qu'un **Motif** facultatif (10 à 1000 caractères
  s'il est saisi), sans date d'expiration : un faux positif dit que le code n'est pas vulnérable, il reste jusqu'à ce que
  quelqu'un rouvre le finding. L'utilisateur connecté est enregistré comme approbateur.
- **Risque accepté** sous `SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY` (`medium` par défaut, donc
  un finding `low` ou `info`) : une simple validation, enregistrée immédiatement sans motif ni
  date d'expiration. Variable vide : toute acceptation passe par le formulaire ci-dessus.
- **Ouvert** et **Corrigé** sont enregistrés immédiatement (motif facultatif par l'API). Toute
  décision supprime la proposition en attente.

Seule une session (compte local ou OIDC) peut accepter un risque ou marquer un faux positif : un
jeton Bearer, même `admin`, reçoit `403`. Par l'API REST :

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42 \
  -d '{"status": "accepted", "reason": "Internal tool, not exposed to the Internet", "expires_on": "2027-01-31"}'
# {"id": 42, "status": "accepted", "status_approver": "alice", "status_expires_at": "2027-01-31T00:00:00Z", …}
curl -X DELETE -H "Authorization: Bearer $SESSION" \
  https://secreview.example.com/api/v1/findings/42/proposal    # rejette la proposition de l'agent
```

Un motif absent ou trop court, une date d'expiration passée ou trop lointaine, ou une date
d'expiration pour `open` / `fixed` reçoit `422`. Sans `expires_on`, un faux positif n'expire
jamais, une acceptation non plus, sauf si `SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED=false` (`422`) ; `GET /api/v1/me` renvoie
`permanent_acceptance` pour indiquer si l'appelant peut le faire. Sous
`SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY`, `reason` et `expires_on` sont facultatifs pour
`accepted` (`{"status": "accepted"}` suffit) ; `GET /api/v1/me` renvoie ce seuil dans
`risk_acceptance_min_severity` (`null` : toute acceptation les exige).

## Finding signalé de nouveau

Un rapport ultérieur du projet qui signale de nouveau le même problème n'ajoute pas un second
finding à revoir : le serveur le reconnaît à son empreinte (projet, règle ou CWE, fichier et
titre, sans le numéro de ligne, comme en [SARIF](../advanced/sarif.md)) et la nouvelle
occurrence remplace la précédente.

- Une **acceptation** ou un **faux positif** encore valide est repris sur la nouvelle
  occurrence, avec son motif, son approbateur et sa date d'expiration ; de même pour une
  proposition d'agent en attente de l'un d'eux, une criticité relevée par un analyste et les
  commentaires. La gate ne bloque pas de nouveau.
- Un finding **corrigé** qui revient est de nouveau **ouvert**.
- Quand une règle trouve plusieurs lignes d'un fichier, les occurrences sont appariées dans
  l'ordre des lignes si leur nombre n'a pas changé (le code a bougé), sinon seulement sur la
  même ligne : une nouvelle occurrence n'hérite jamais de la décision prise sur une autre, elle
  est ouverte.
- L'occurrence précédente reste dans son rapport, marquée **Signalé de nouveau : voir le
  finding #N** ; elle ne peut plus être triée (`422` par l'API) ni envoyée par un
  connecteur (`409`).
- **Findings à revoir**, la posture, la [gate](gate.md) du projet, le SARIF, les compteurs et
  la tendance ne comptent que la dernière occurrence ; la tendance et le délai de correction
  partent de la première occurrence du problème (`first_seen_at`).
- Un finding qu'un rapport ultérieur ne signale plus n'est pas fermé : la revue d'un diff ne
  voit pas tout le code.

`save_security_report` et les scans du pipeline renvoient `recurring_findings` (findings déjà
signalés par un rapport précédent) et `carried_decisions` (décisions reprises sur eux).

## Criticité d'un finding

Un analyste de sécurité (une personne qui a la permission `findings.triage`) peut **relever** la
criticité donnée par un rapport, par exemple quand le code est exposé à Internet ou que les
données sont sensibles. **Relever la criticité**, en haut de la carte, ouvre un formulaire qui
demande la **Nouvelle criticité** et une **Justification** (10 à 1000 caractères). La carte
affiche ensuite la criticité du rapport, l'analyste, la date et la justification ; l'export
Markdown et `get_security_report` les affichent aussi, et le changement est inscrit au journal
d'audit (`finding.severity_changed`).

La criticité relevée compte partout (filtres, posture, [gate](gate.md), SARIF, tendance), et le
niveau de risque du rapport monte avec elle. Une criticité ne descend jamais sous celle du
rapport : un analyste peut seulement y revenir, avec une justification, pour annuler la hausse.
Pour clore un finding jugé moins grave, acceptez le risque. Seule une session peut le faire : un
jeton Bearer, même `admin`, reçoit `403` ; une criticité plus basse ou inchangée, ou une
justification absente, reçoit `422`.

```bash
curl -X PATCH -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/findings/42/severity \
  -d '{"severity": "critical", "reason": "Endpoint reachable without authentication"}'
# {"id": 42, "severity": "critical", "original_severity": "medium", "severity_changed_by": "alice", …}
```

## Acceptations de risque

L'écran **Acceptations de risque** (`/ui/risk-acceptances`, ou par projet depuis les écrans
**Projets** et **Projet**) liste les risques acceptés, y compris expirés, pour les renouveler
avant ou après leur fin de validité. Dans les détails d'une acceptation :

- **Commentaires** : tous les commentaires, du plus ancien au plus récent, avec leur auteur et
  leur date. Le motif de l'acceptation est le premier : accepter un risque, ou l'accepter de
  nouveau avec un autre motif, l'ajoute aux commentaires. Toute personne qui lit le projet les
  voit. Un commentaire **ne peut être ni modifié
  ni supprimé** : aucune route de l'API ne le fait. Ils restent attachés au finding quand son
  acceptation est supprimée.
- **Ajouter un commentaire** (2000 caractères au plus, secrets masqués) enregistre l'utilisateur
  connecté comme auteur, également dans le journal d'audit (`finding.commented`).
- **Changer la date d'expiration** enregistre de nouveau l'acceptation avec le même motif et la
  nouvelle date (mêmes limites que ci-dessus, **Sans expiration** compris), sans ajouter de
  commentaire : l'utilisateur connecté en devient l'approbateur.
- **Supprimer l'acceptation** rouvre le finding, après confirmation.

Comme une acceptation, un commentaire demande une session avec la permission `findings.triage` :
un jeton Bearer reçoit `403`. Par l'API REST :

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
`offset` ; sans `project`, il liste tous les projets que l'appelant peut lire.
