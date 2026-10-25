# Gate CI/CD

Sans agent ni client MCP, un job Jenkins, GitLab ou GitHub peut bloquer un déploiement tant que
des findings critiques restent ouverts. La commande `security-review-ci gate` le fait par l'API
REST du contrôleur, avec un [jeton `ci`](../advanced/ci.md#jeton-ci-et-projets-visibles) : elle ne nécessite que
Python 3.14 sur l'agent de build (ni pilote de base, ni SQLModel, ni URL de base). La CLI du
contrôleur (`security-review-controller`) n'a aucune commande de pipeline.

```bash
security-review-ci gate --project portal --fail-on high
# code de sortie : 0 = passe, 1 = bloqué, 2 = erreur (projet/rapport introuvable, hors du jeton,
# contrôleur injoignable, jeton refusé)
# options : --report-id N pour ne juger qu'un rapport
```

Le client, son installation, le jeton `ci` et des exemples de pipeline pour GitHub Actions,
GitLab CI, Jenkins, Azure Pipelines, Bitbucket Pipelines et CircleCI : voir
[Client de pipeline (CI/CD)](../advanced/ci.md).

Un finding sort du blocage quand une personne le passe à `fixed`, `accepted` ou
`false_positive` dans l'[interface web](triage.md) : la
décision reste tracée en base avec son motif et son approbateur. Un agent peut seulement
proposer un statut (`propose_finding_status`), ce qui ne débloque pas la gate. Une acceptation
ou un faux positif expire : à partir de sa date d'expiration, le finding bloque de nouveau. Une
décision est reprise sur le même problème signalé par un rapport ultérieur
([finding signalé de nouveau](triage.md#finding-signale-de-nouveau)) : la gate du rapport
suivant ne bloque pas sur un risque accepté. Le code de sortie de `scan-code` et `scan-deps`, en
revanche, compte toutes les correspondances au-dessus de son seuil (voir le
[pipeline type](../advanced/ci.md#pipeline-type)).
