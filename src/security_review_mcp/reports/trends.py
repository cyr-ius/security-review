"""Trend report: how the security posture of a project evolves over time."""

import statistics
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Literal

from sqlmodel import col, select

from ..storage.database import session_scope
from ..storage.models import SEVERITY_RANK, Finding, FindingStatus, SecurityReport, Severity
from ..storage.project_names import normalize_project

Granularity = Literal["day", "week", "month"]

MAX_BUCKETS = 120
# Weights of the risk score: the open backlog weighted by severity
RISK_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_CLOSED = (FindingStatus.FIXED, FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE)
_DISMISSED = (FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE)
STABLE_TOLERANCE = 0.10  # a change of less than 10% of the risk score is "stable"


@dataclass(frozen=True)
class TrendFinding:
    """The columns of a finding that the trend needs."""

    severity: Severity
    status: FindingStatus
    cwe: str | None
    created_at: datetime  # creation date of its report
    status_changed_at: datetime | None
    status_expires_at: datetime | None = None  # end of an acceptance or a false positive


@dataclass(frozen=True)
class TrendReport:
    """The columns of a report that the trend needs."""

    created_at: datetime
    risk_level: Severity


def aware(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime (SQLite returns naive values)."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def bucket_start(moment: datetime, granularity: Granularity) -> datetime:
    """Return the start of the day, ISO week (Monday) or month containing ``moment``."""
    day: date = moment.date()
    if granularity == "week":
        day = day - timedelta(days=day.weekday())
    elif granularity == "month":
        day = day.replace(day=1)
    return datetime(day.year, day.month, day.day, tzinfo=UTC)


def next_bucket(start: datetime, granularity: Granularity) -> datetime:
    """Return the start of the bucket that follows the one starting at ``start``."""
    if granularity == "day":
        return start + timedelta(days=1)
    if granularity == "week":
        return start + timedelta(days=7)
    year, month = (start.year + 1, 1) if start.month == 12 else (start.year, start.month + 1)
    return datetime(year, month, 1, tzinfo=UTC)


def _label(start: datetime, granularity: Granularity) -> str:
    """Return a readable label for a bucket."""
    if granularity == "month":
        return start.strftime("%Y-%m")
    return start.strftime("%Y-%m-%d")


def _empty_counts() -> dict[str, int]:
    """Return a zeroed counter for every severity."""
    return {severity.value: 0 for severity in Severity}


def _risk_score(open_counts: dict[str, int]) -> int:
    """Return the weighted risk score of an open backlog."""
    return sum(RISK_WEIGHTS[Severity(name)] * number for name, number in open_counts.items())


def _is_open_at(finding: TrendFinding, moment: datetime) -> bool:
    """Tell whether a finding existed and was not closed at ``moment``."""
    if aware(finding.created_at) > moment:
        return False
    if finding.status not in _CLOSED:
        return True  # open now (a reopened finding is counted as open throughout)
    expires = finding.status_expires_at
    if finding.status in _DISMISSED and expires is not None and aware(expires) <= moment:
        return True  # the acceptance or false positive had expired
    if finding.status_changed_at is None:
        return False  # closed before changes were dated: treated as closed from creation
    return aware(finding.status_changed_at) > moment


def _direction(scores: list[int]) -> str:
    """Compare the last two risk scores: improving, worsening, stable or insufficient_data."""
    if len(scores) < 2:
        return "insufficient_data"
    previous, last = scores[-2], scores[-1]
    if previous == 0:
        return "stable" if last == 0 else "worsening"
    change = (last - previous) / previous
    if change > STABLE_TOLERANCE:
        return "worsening"
    if change < -STABLE_TOLERANCE:
        return "improving"
    return "stable"


def compute_trend(
    findings: list[TrendFinding],
    reports: list[TrendReport],
    project: str,
    days: int = 90,
    granularity: Granularity = "week",
    now: datetime | None = None,
) -> dict:
    """Compute the trend of a project over the last ``days`` days.

    Raises:
        ValueError: If the parameters are invalid or would produce too many periods.
    """
    if granularity not in ("day", "week", "month"):
        raise ValueError("granularity must be day, week or month")
    if not 1 <= days <= 1095:
        raise ValueError("days must be between 1 and 1095")
    now = aware(now) if now else datetime.now(UTC)
    window_start = now - timedelta(days=days)

    buckets: list[tuple[datetime, datetime]] = []
    start = bucket_start(window_start, granularity)
    while start <= now:
        end = next_bucket(start, granularity)
        buckets.append((start, end))
        start = end
    if len(buckets) > MAX_BUCKETS:
        raise ValueError(
            f"Too many periods ({len(buckets)} > {MAX_BUCKETS}); use a coarser granularity"
        )

    rows = []
    scores: list[int] = []
    for start, end in buckets:
        evaluated_at = min(end, now + timedelta(microseconds=1))
        in_bucket = [r for r in reports if start <= aware(r.created_at) < end]
        new = _empty_counts()
        fixed = _empty_counts()
        dismissed = 0
        for finding in findings:
            if start <= aware(finding.created_at) < end:
                new[finding.severity.value] += 1
            changed = finding.status_changed_at
            if changed is not None and start <= aware(changed) < end:
                if finding.status == FindingStatus.FIXED:
                    fixed[finding.severity.value] += 1
                elif finding.status in _DISMISSED:
                    dismissed += 1
        open_counts = _empty_counts()
        for finding in findings:
            if _is_open_at(finding, evaluated_at):
                open_counts[finding.severity.value] += 1
        score = _risk_score(open_counts)
        scores.append(score)
        worst = max((r.risk_level for r in in_bucket), key=SEVERITY_RANK.get, default=None)
        rows.append(
            {
                "period": _label(start, granularity),
                "reports": len(in_bucket),
                "worst_report_risk": worst.value if worst else None,
                "new": new,
                "new_total": sum(new.values()),
                "fixed_total": sum(fixed.values()),
                "dismissed_total": dismissed,
                "open_at_end": open_counts,
                "open_total": sum(open_counts.values()),
                "risk_score": score,
            }
        )

    # Time to remediate: fixed findings whose fix falls in the window
    durations: dict[str, list[float]] = {}
    for finding in findings:
        changed = finding.status_changed_at
        if finding.status == FindingStatus.FIXED and changed is not None:
            if aware(changed) >= window_start:
                delta = aware(changed) - aware(finding.created_at)
                durations.setdefault(finding.severity.value, []).append(
                    max(delta.total_seconds(), 0) / 86400
                )
    mttr = {
        name: {
            "count": len(values),
            "mean_days": round(statistics.fmean(values), 1),
            "median_days": round(statistics.median(values), 1),
        }
        for name, values in sorted(
            durations.items(), key=lambda kv: -SEVERITY_RANK[Severity(kv[0])]
        )
    }

    currently_open = [f for f in findings if _is_open_at(f, now)]
    open_now = _empty_counts()
    oldest: dict[str, float] = {}
    for finding in currently_open:
        open_now[finding.severity.value] += 1
        age = (now - aware(finding.created_at)).total_seconds() / 86400
        oldest[finding.severity.value] = max(oldest.get(finding.severity.value, 0), age)
    top_cwes = Counter(f.cwe or "unknown" for f in currently_open).most_common(5)
    undated = sum(1 for f in findings if f.status in _CLOSED and f.status_changed_at is None)

    return {
        "project": project,
        "window_days": days,
        "granularity": granularity,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "direction": _direction(scores),
        "summary": {
            "reports_total": len(reports),
            "reports_in_window": sum(row["reports"] for row in rows),
            "new_findings": sum(row["new_total"] for row in rows),
            "fixed_findings": sum(row["fixed_total"] for row in rows),
            "dismissed_findings": sum(row["dismissed_total"] for row in rows),
            "open_now": open_now,
            "open_now_total": sum(open_now.values()),
            "risk_score_now": _risk_score(open_now),
            "oldest_open_days": {k: round(v, 1) for k, v in oldest.items()},
            "top_open_cwes": [{"cwe": cwe, "count": count} for cwe, count in top_cwes],
            "mttr_days": mttr,
        },
        "periods": rows,
        "notes": _notes(len(reports), undated),
        "risk_score_weights": {s.value: w for s, w in RISK_WEIGHTS.items()},
    }


def _notes(reports_total: int, undated_closed: int) -> list[str]:
    """Return caveats that change how the numbers must be read."""
    notes = []
    if reports_total == 0:
        notes.append("No report is stored for this project yet.")
    if undated_closed:
        notes.append(
            f"{undated_closed} closed finding(s) predate status dating: they are treated as "
            "closed from their creation and are excluded from MTTR."
        )
    notes.append(
        "Backlog counts findings of every stored report: a finding re-reported in a later "
        "report counts again until one of them is closed."
    )
    return notes


def get_trend(
    project: str,
    days: int = 90,
    granularity: Granularity = "week",
    now: datetime | None = None,
) -> dict:
    """Load the data of a project and compute its trend."""
    project = normalize_project(project)
    with session_scope() as session:
        finding_rows = session.exec(
            select(
                Finding.severity,
                Finding.status,
                Finding.cwe,
                SecurityReport.created_at,
                Finding.status_changed_at,
                Finding.status_expires_at,
            )
            .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
            .where(SecurityReport.project == project)
        ).all()
        report_rows = session.exec(
            select(SecurityReport.created_at, SecurityReport.risk_level).where(
                SecurityReport.project == project
            )
        ).all()
    findings = [TrendFinding(*row) for row in finding_rows]
    reports = [TrendReport(*row) for row in report_rows]
    return compute_trend(findings, reports, project, days, granularity, now)


def render_trend_markdown(trend: dict) -> str:
    """Render a trend as Markdown."""
    summary = trend["summary"]
    arrow = {
        "improving": "improving (risk score decreasing)",
        "worsening": "worsening (risk score increasing)",
        "stable": "stable",
        "insufficient_data": "insufficient data (fewer than two periods)",
    }[trend["direction"]]
    lines = [
        f"# Security trend - {trend['project']}",
        "",
        f"- **Window**: last {trend['window_days']} days, by {trend['granularity']}",
        f"- **Direction**: {arrow}",
        f"- **Risk score now**: {summary['risk_score_now']} "
        f"({summary['open_now_total']} open finding(s))",
        f"- **In the window**: {summary['new_findings']} new, {summary['fixed_findings']} fixed, "
        f"{summary['dismissed_findings']} dismissed, {summary['reports_in_window']} report(s)",
        "",
        "## Open now by severity",
        "",
        "| " + " | ".join(summary["open_now"]) + " |",
        "|" + "---|" * len(summary["open_now"]),
        "| " + " | ".join(str(v) for v in summary["open_now"].values()) + " |",
    ]
    if summary["mttr_days"]:
        lines += [
            "",
            "## Time to remediate (days)",
            "",
            "| Severity | Fixed | Mean | Median |",
            "|---|---|---|---|",
        ]
        for name, data in summary["mttr_days"].items():
            lines.append(
                f"| {name} | {data['count']} | {data['mean_days']} | {data['median_days']} |"
            )
    if summary["oldest_open_days"]:
        oldest = ", ".join(f"{k}: {v} d" for k, v in summary["oldest_open_days"].items())
        lines += ["", f"**Oldest open finding by severity**: {oldest}"]
    if summary["top_open_cwes"]:
        top = ", ".join(f"{item['cwe']} ({item['count']})" for item in summary["top_open_cwes"])
        lines += ["", f"**Most frequent open weaknesses**: {top}"]
    lines += [
        "",
        "## Periods",
        "",
        "| Period | Reports | New | Fixed | Dismissed | Open at end | Risk score |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in trend["periods"]:
        lines.append(
            f"| {row['period']} | {row['reports']} | {row['new_total']} | {row['fixed_total']} | "
            f"{row['dismissed_total']} | {row['open_total']} | {row['risk_score']} |"
        )
    lines += ["", "## Notes", ""] + [f"- {note}" for note in trend["notes"]]
    weights = ", ".join(f"{k}={v}" for k, v in trend["risk_score_weights"].items())
    lines.append(f"- Risk score weights: {weights}.")
    return "\n".join(lines) + "\n"
