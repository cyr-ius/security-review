# Jetons

Les **jetons** sont destinés aux machines : agents MCP, pipelines CI/CD, Prometheus, scripts
d'administration. Les **personnes** utilisent un [compte utilisateur](user-accounts.md), seul à
ouvrir l'interface web, avec les droits de ses groupes
([Rôles, groupes et permissions](../advanced/access-control.md)). Il n'existe pas de jeton de
lecture ou de triage : pour donner à une personne la lecture ou le triage, ajoutez son compte à
un groupe.

## Rôles d'un jeton

Chaque jeton porte un rôle fixe, qui détermine les endpoints qu'il atteint. Un jeton créé sans
rôle est `mcp`.

| Rôle | Usage (écran **Jetons**) | `/mcp` | API REST | Changement de statut |
|---|---|---|---|---|
| `mcp` (défaut) | MCP | ✅ | — (routes de pipeline pour un jeton personnel) | — |
| `admin` | CLI uniquement | ✅ | ✅ | `open`, `fixed` ¹ |
| `api` | API REST — Swagger et scripts ([jetons API](#jetons-api)) | — | ✅ avec les permissions de son rôle ou de son utilisateur | `open`, `fixed` ¹ avec `findings.triage` |
| `ci` | Pipeline CI/CD — gate, SARIF, tendance et scans | — | routes de pipeline seulement (`/api/v1/ci/`), dont les scans qui enregistrent des rapports | — |
| `metrics` | CLI seulement | — | `/metrics` seulement ([Prometheus](../reference/metrics.md)) | — |

¹ `accepted` et `false_positive` exigent une personne connectée à l'interface avec la
permission `findings.triage` ([triage des findings](triage.md)). Sur `/mcp`, aucun rôle ne
change un statut : les agents ne font que le proposer.

Un jeton `mcp` peut être restreint à des projets avec `--project` (répétable) ; un jeton `ci`
l'est toujours (voir [jeton `ci`](../advanced/ci.md#jeton-ci-et-projets-visibles) et
[jetons restreints à un projet](../advanced/bearer-tokens.md#jetons-restreints-a-un-projet)). Création,
expiration, renouvellement et révocation en CLI : [Jetons Bearer](../advanced/bearer-tokens.md).

## Jeton `admin`

Un jeton `admin` appelle toute l'API REST, par exemple depuis un script d'administration, mais
**n'ouvre pas l'interface** (la page de connexion ne propose que les comptes) :

```bash
security-review-controller token create --label ops-script --role admin
# {"id": "…", "label": "ops-script", "role": "admin", "project": null, "created_at": "…", "token": "UJB7…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/projects
```

L'API REST liste les findings d'un projet sur l'ensemble de ses rapports, ouverts par défaut,
du plus grave au moins grave (filtres `status`, `severity` et `review_type`, `limit` plafonné par
`SECREVIEW_MAX_LIST_LIMIT`, `total` donne le nombre de findings correspondants pour paginer).
Sans `project`, elle liste les findings de tous les projets que lit l'appelant
(`"project": null`) :

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/findings?project=shop-api&status=open&limit=50"
# {"project": "shop-api", "total": 12, "findings": [{"id": 42, "severity": "critical", "report_id": 7, "project": "shop-api", "branch": "main", "commit_sha": "abc123", "review_type": "codebase-review", "report_created_at": "…", …}, …]}
```

`GET /api/v1/reports` liste les rapports (filtres `project`, `risk_level`, `review_type` et
`author`), chacun avec son `author` et son `submitted_by`. L'`author` n'est renvoyé, filtré,
recherché et trié que pour un appelant qui détient `users.manage` ou `tokens.manage` : pour les
autres, il vaut `null` (dans le rapport et son export Markdown aussi) et le filtre `author` est
ignoré :

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://secreview.example.com/api/v1/reports?project=shop-api&author=alice@example.com"
```

Révoquez-le avec `security-review-controller token revoke ops-script`. Chaque changement de
statut est journalisé avec le label du jeton ou du compte :

```
INFO security_review_mcp.web: Finding 42 set to fixed by ops-script
```

et écrit dans le [journal d'audit](../advanced/audit-metrics.md)
(`GET /api/v1/audit`, permission `audit.read`), avec l'acteur `token:ops-script` ou
`user:<nom>`.

## Jetons API

Un jeton `api` appelle l'API REST, depuis un script ou depuis la documentation Swagger
(`/api/docs`, bouton **Authorize**), avec les droits du contrôle d'accès, lus à chaque requête.
Il n'atteint jamais `/mcp` et n'ouvre jamais l'interface. Il en existe deux sortes :

- **Jeton personnel** : créé par un utilisateur pour lui-même, avec l'**Usage** **API REST —
  Swagger et scripts** (voir [jetons personnels](#jetons-personnels)). Il porte les droits
  actuels du compte, qui viennent de ses groupes : il n'atteint plus rien dès que le compte les
  perd.
- **Jeton de rôle** : créé par un administrateur (`tokens.manage`) dans l'écran **Jetons**, avec
  l'**Usage** **API REST** et un **Rôle**. Il porte les permissions de ce rôle sur ses projets
  (tous les projets, ou une liste quand le rôle ne détient que des permissions par projet). Un
  rôle utilisé par un jeton ne peut pas être supprimé.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "swagger", "expires_in_days": 30}'
# {"id": "…", "label": "alice:swagger", "role": "api", "personal": true, "access_role_id": null, …, "token": "Zq3…"}
curl -H "Authorization: Bearer $TOKEN" https://secreview.example.com/api/v1/me
# {"client": "alice:swagger", "role": "api", "permissions": {"reports.read": ["shop-api"]}, …}
```

## Jetons créés depuis l'interface

Un jeton ne donne jamais plus que ce que détient son créateur : créer un jeton, changer ses
projets, renouveler son secret ou le révoquer demande `reports.read` sur tous les projets du
jeton, avant et après un changement de ses projets, et, pour un jeton `api` de rôle, chaque
permission de son rôle sur ces projets. L'écran **Jetons** ne liste que les jetons des projets
que l'utilisateur lit.

## Jetons personnels

Un utilisateur crée ses propres jetons dans **Mon compte** > **Jetons personnels**, avec l'un
de deux usages :

| Usage | Rôle | Atteint | Exige |
|---|---|---|---|
| **API REST — Swagger et scripts** | `api` | l'API REST, avec les droits du compte | — |
| **MCP / CI — agent et security-review-ci** | `mcp` | `/mcp` et les routes de pipeline, sur les projets que le compte peut lire | `mcp_tokens.create` |

Un jeton `ci` personnel (routes de pipeline seulement) n'y est plus proposé : le jeton `mcp` les
couvre (voir [plus bas](#jetons-mcp-et-ci-personnels)).

Tout jeton personnel suit les mêmes règles :

- un au plus par usage par défaut (`SECREVIEW_PERSONAL_TOKENS_PER_USER`) : révoquez-le pour en
  créer un autre ;
- label `<utilisateur>:<label>`, avec un `:` qu'aucun autre label de jeton ne peut contenir, et
  validité bornée par `SECREVIEW_TOKEN_MAX_DAYS` ;
- ses droits sont ceux du compte, lus à chaque requête ; il s'arrête tant que le compte doit
  changer un mot de passe défini par un administrateur, et il est supprimé avec le compte ;
- personne ne peut le renouveler ni changer ses projets ; un administrateur peut le révoquer
  depuis l'écran **Jetons**.

### Jetons MCP et CI personnels

Un jeton `mcp` personnel connecte l'agent MCP de l'utilisateur. Il n'est proposé que quand les
groupes du compte portent `mcp_tokens.create` (rôle `mcp-user`, voir
[Rôles](../advanced/access-control.md#roles) ; `403` sans elle) ; un jeton déjà créé continue de
fonctionner quand le compte la perd, et un administrateur le révoque au besoin. Il atteint les
projets que le compte peut lire (`reports.read` de ses groupes) : tous les projets quand l'un de
ses groupes lit tous les projets, aucun quand il n'en a pas. La colonne **Projets** les affiche,
de même que l'écran **Jetons** pour les administrateurs.

Pour un projet qu'il n'atteint pas, un administrateur donne au compte l'accès au projet (un
groupe qui le lit), ou l'utilisateur le crée depuis **Projets** s'il est nouveau et qu'il porte
`projects.create` (voir [Création d'un projet](../advanced/access-control.md#creation-dun-projet)).
L'agent le demande lui-même avec `request_project` avant une revue : un nouveau projet est créé
aussitôt quand l'utilisateur porte `projects.create`, sinon il attend une validation, qui en
donne l'accès à l'utilisateur ([enrôlement](../advanced/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)). Quand le serveur refuse le jeton (inconnu, révoqué ou expiré), l'agent
reçoit un `401` qui invite l'utilisateur à se reconnecter pour en créer un nouveau.

Un jeton `mcp` personnel vaut aussi jeton `ci` personnel sur les routes de pipeline : un seul
`SECREVIEW_TOKEN` sur le poste sert à la fois à l'agent MCP et à
[`security-review-ci`](../advanced/ci.md) : **Mon compte** ne propose donc plus de jeton `ci`
personnel. L'API en crée encore un pour séparer les deux usages (il n'atteint jamais `/mcp`), et
ceux déjà créés restent listés jusqu'à leur révocation. Un rapport enregistré par l'un ou l'autre est soumis par le
jeton (`alice:laptop`), et son utilisateur en est l'auteur (voir
[scan depuis un poste de travail](../advanced/dependencies.md#scan-depuis-un-poste-de-travail-hook-de-commit)).
Un jeton `mcp` créé par un administrateur sur l'écran **Jetons** reste un jeton d'agent MCP
seulement.

```bash
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "mcp"}'
# {"id": "…", "label": "alice:laptop", "role": "mcp", "personal": true, …, "token": "Zq3…"}
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  https://secreview.example.com/api/v1/me/tokens -d '{"label": "laptop", "role": "ci"}'
# {"id": "…", "label": "alice:laptop", "role": "ci", "personal": true, …, "token": "Zq3…"}
```
