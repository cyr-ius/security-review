"""Prometheus metrics of the controller (``GET /metrics``, text exposition format 0.0.4).

The values are read from the database at each scrape, so every replica of the controller
answers the same thing, except ``secreview_auth_rejections_total`` which counts the requests
rejected by the process that answers. The endpoint is reached with a ``metrics`` token (only this
endpoint) or an ``admin`` one; it exposes counts and project names, never a finding, a token or a
secret. Written by hand: the server adds no dependency.
"""

from collections.abc import Iterable
from datetime import timedelta

from sqlmodel import func, select

from . import __version__, access_control, advisories, http_server, services, token_store
from .database import session_scope
from .models import AdvisoryUpdate, Severity, WebUser, as_utc

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
# Active tokens counted by secreview_tokens_expiring_soon
TOKEN_EXPIRY_WARNING = timedelta(days=14)
# Reasons of secreview_auth_rejections_total, always exposed (0 until the first rejection)
REJECTION_REASONS = ("invalid_token", "token_expired", "insufficient_scope")

Labels = dict[str, str]


def escape_label(value: str) -> str:
    """Escape a label value (backslash, double quote, line feed), as the format requires.

    Project names and token roles come from users: without escaping they could add lines or
    labels to the exposition.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _sample(name: str, value: float, labels: Labels | None = None) -> str:
    """One sample line."""
    text = ",".join(f'{key}="{escape_label(item)}"' for key, item in (labels or {}).items())
    number = int(value) if float(value).is_integer() else value
    return f"{name}{{{text}}} {number}" if text else f"{name} {number}"


def _family(
    name: str, kind: str, help_text: str, samples: Iterable[tuple[float, Labels | None]]
) -> list[str]:
    """The HELP and TYPE lines of a metric followed by its samples."""
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"]
    lines.extend(_sample(name, value, labels) for value, labels in samples)
    return lines


def _last_advisory_update() -> float | None:
    """Unix time of the end of the latest successful OSV download, or None."""
    with session_scope() as session:
        finished = session.exec(
            select(func.max(AdvisoryUpdate.finished_at)).where(AdvisoryUpdate.status == "success")
        ).one()
    return None if finished is None else as_utc(finished).timestamp()


def _web_users() -> dict[str, int]:
    """Web users by account type (local, oidc)."""
    with session_scope() as session:
        rows = session.exec(
            select(WebUser.auth_source, func.count()).group_by(WebUser.auth_source)  # type: ignore[arg-type]
        ).all()
    return dict(rows)


def render() -> str:
    """Return every metric in the Prometheus text exposition format."""
    projects = services.list_projects()
    statuses = services.finding_status_counts()
    tokens = token_store.token_counts(TOKEN_EXPIRY_WARNING)
    advisory = advisories.advisory_status()
    last_update = _last_advisory_update()
    severities = [severity.value for severity in Severity]

    open_by_severity = dict.fromkeys(severities, 0)
    for project in projects:
        for severity, count in project["open_findings_by_severity"].items():
            open_by_severity[severity] += count

    lines: list[str] = []
    lines += _family(
        "secreview_build_info",
        "gauge",
        "Version of the controller.",
        [(1, {"version": __version__})],
    )
    lines += _family(
        "secreview_projects", "gauge", "Projects with reports.", [(len(projects), None)]
    )
    lines += _family(
        "secreview_reports",
        "gauge",
        "Stored reports.",
        [(sum(project["reports_total"] for project in projects), None)],
    )
    lines += _family(
        "secreview_findings",
        "gauge",
        "Findings by effective status (an expired dismissal counts as open).",
        [(statuses[status], {"status": status}) for status in statuses if status != "proposed"],
    )
    lines += _family(
        "secreview_open_findings",
        "gauge",
        "Open findings by severity.",
        [(open_by_severity[severity], {"severity": severity}) for severity in severities],
    )
    lines += _family(
        "secreview_project_open_findings",
        "gauge",
        "Open findings of each project by severity.",
        [
            (
                project["open_findings_by_severity"].get(severity, 0),
                {
                    "project": project["project"],
                    "severity": severity,
                },
            )
            for project in projects
            for severity in severities
        ],
    )
    lines += _family(
        "secreview_finding_proposals_pending",
        "gauge",
        "Findings whose status proposed by an agent waits for a person.",
        [(statuses["proposed"], None)],
    )
    lines += _family(
        "secreview_tokens",
        "gauge",
        "Bearer tokens by role and state (active, expired).",
        [
            (count, {"role": role, "state": state})
            for (role, state), count in sorted(tokens["by_role_and_state"].items())
        ],
    )
    lines += _family(
        "secreview_tokens_expiring_soon",
        "gauge",
        f"Active tokens that expire within {TOKEN_EXPIRY_WARNING.days} days.",
        [(tokens["expiring_soon"], None)],
    )
    lines += _family(
        "secreview_project_enrollments_pending",
        "gauge",
        "Projects requested by an enrollment, waiting for an administrator.",
        [(access_control.pending_project_count(), None)],
    )
    lines += _family(
        "secreview_web_users",
        "gauge",
        "Web users by account type.",
        [(count, {"auth_source": source}) for source, count in sorted(_web_users().items())],
    )
    lines += _family(
        "secreview_advisories",
        "gauge",
        "Advisories in the database.",
        [(advisory["advisories"], None)],
    )
    if last_update is not None:
        lines += _family(
            "secreview_advisory_last_update_timestamp_seconds",
            "gauge",
            "End of the latest successful OSV download (Unix time).",
            [(round(last_update, 3), None)],
        )
    rejections = http_server.AUTH_REJECTIONS
    lines += _family(
        "secreview_auth_rejections_total",
        "counter",
        "Requests rejected by the bearer authentication of this process, by reason.",
        [(rejections.get(reason, 0), {"reason": reason}) for reason in REJECTION_REASONS],
    )
    return "\n".join(lines) + "\n"
