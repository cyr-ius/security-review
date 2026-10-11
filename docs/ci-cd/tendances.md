# Rapport de tendance

```bash
security-review-mcp trend --project mon-projet --days 90 --granularity week --format markdown
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

!!! note
    Les corrections faites avant la v1.2 n'ont pas de date : elles sont signalées en note.

Le même rapport est disponible côté MCP avec l'outil `get_trend_report`.
