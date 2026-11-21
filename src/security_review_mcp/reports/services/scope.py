"""Project scope of a caller: the project of a report or finding, and its checks."""

from collections.abc import Collection

from sqlmodel import col, select

from ...storage.database import session_scope
from ...storage.models import (
    Finding,
    SecurityReport,
)
from ...storage.project_names import normalize_project
from .core import NotFoundError


def report_project(report_id: int) -> str:
    """Return the project of a report.

    Raises:
        NotFoundError: If the report does not exist.
    """
    with session_scope() as session:
        report = session.get(SecurityReport, report_id)
        if report is None:
            raise NotFoundError(f"Report {report_id} not found")
        return report.project


def finding_project(finding_id: int) -> str:
    """Return the project of the report that holds a finding.

    Raises:
        NotFoundError: If the finding does not exist.
    """
    with session_scope() as session:
        project = session.exec(
            select(SecurityReport.project)
            .join(Finding, col(Finding.report_id) == col(SecurityReport.id))
            .where(Finding.id == finding_id)
        ).first()
        if project is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        return project


def check_project_scope(allowed: Collection[str] | None, project: str) -> None:
    """Refuse a project outside the scope of a project-restricted caller.

    ``allowed`` holds the projects of the caller's token (None: no restriction). The error is
    the same as for a missing project, so a restricted caller cannot learn which projects exist.

    Raises:
        NotFoundError: If ``allowed`` is set and does not contain ``project``.
    """
    project = normalize_project(project)
    if allowed is not None and project not in allowed:
        raise NotFoundError(f"Project '{project}' not found")


def check_report_scope(allowed: Collection[str] | None, report_id: int) -> None:
    """Refuse a report outside the scope of a project-restricted caller (as if missing)."""
    if allowed is not None and report_project(report_id) not in allowed:
        raise NotFoundError(f"Report {report_id} not found")


def check_finding_scope(allowed: Collection[str] | None, finding_id: int) -> None:
    """Refuse a finding outside the scope of a project-restricted caller (as if missing)."""
    if allowed is not None and finding_project(finding_id) not in allowed:
        raise NotFoundError(f"Finding {finding_id} not found")
