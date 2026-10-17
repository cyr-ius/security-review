# Rapport de tendance

Le [client de pipeline](../usage/gate.md#client-de-pipeline-security-review-ci) affiche le
rapport de tendance d'un projet par l'API REST du contrôleur, avec un jeton `ci` :

```bash
security-review-ci trend --project mon-projet --days 90 --granularity week --format markdown
```

Options : `--granularity day|week|month` (défaut `week`), `--format markdown|json`
(défaut `markdown`), `--days` (défaut 90).

Pour chaque période :

- findings nouveaux et corrigés ;
- backlog ouvert ;
- score de risque (critical 10, high 5, medium 2, low 1) et direction (marge de ±10 % sur les
  deux dernières périodes).

Sur l'ensemble : délai moyen de correction (MTTR) par sévérité, plus ancien finding ouvert, CWE
les plus fréquentes.

Le même rapport est disponible côté MCP avec l'outil `get_trend_report`.
