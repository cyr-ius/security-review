"""Sending of the findings: destinations of the projects, exports, automatic sending.

A finding is sent by hand by a user who may triage its project, or automatically by a
background thread of the controller (ExportDispatcher) for the projects whose destination
(ConnectorTarget) has a severity threshold: every open finding at least that severe, of the reports
saved since the threshold was set.

The export row is inserted before the request (``sending``): its unique constraint is the claim
of the controller that sends it, so that two replicas never create two records. An issue found
again by a later report (same fingerprint, see sarif.fingerprint) reuses its record. Sending is
one way: an export never changes the status of a finding.
"""

import logging
import threading
from collections.abc import Callable, Collection
from datetime import datetime, timedelta
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, select

from ..config import Settings
from ..observability import audit
from ..reports.sarif import SarifItem, fingerprint
from ..reports.services import NotFoundError, _status_is
from ..rules.scanner import redact_secrets
from ..storage.database import session_scope
from ..storage.models import (
    SEVERITY_RANK,
    ConnectorTarget,
    ExportState,
    Finding,
    FindingExport,
    FindingExportPublic,
    FindingPublic,
    FindingStatus,
    SecurityReport,
    Severity,
    as_utc,
    utcnow,
)
from ..storage.project_names import normalize_project
from . import connections, registry
from .api import (
    MAX_EXPORT_URL_CHARS,
    MAX_KEY_CHARS,
    Connection,
    Connector,
    ConnectorError,
    ExportedFinding,
    FindingContent,
)
from .transport import ConnectionClient

logger = logging.getLogger("security_review_mcp.connectors")

MAX_SUMMARY_CHARS = 250
MAX_STORED_ERROR_CHARS = 500
# A claim older than this is taken over (controller stopped during the request)
STALE_CLAIM = timedelta(minutes=10)
# Automatic sending: findings per kind and per round, attempts of a failed finding and delay
# between them (doubled at each attempt)
BATCH_SIZE = 20
MAX_ATTEMPTS = 5
RETRY_DELAY = timedelta(minutes=15)
AUTO_ACTOR = "auto"


def validate_settings(settings: Settings) -> None:
    """Load the connectors and check the variables of their connections (controller start).

    Raises:
        ValueError: If an allowed connector is missing or invalid, a variable is invalid, or a
            variable of the former ticketing name is still set.
    """
    _refuse_former_variables()
    for connector in registry.connectors(settings).values():
        connections.validate_environment(connector)


class _FormerVariables(BaseSettings):
    """SECREVIEW_TICKETING_* variables, renamed SECREVIEW_CONNECTORS_* (environment, then the
    .env file of the controller)."""

    model_config = SettingsConfigDict(
        env_prefix="SECREVIEW_TICKETING_",
        env_file=Settings.model_config.get("env_file"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    enabled: str | None = None
    interval_seconds: str | None = None
    cafile: str | None = None
    plugins: str | None = None


def _refuse_former_variables() -> None:
    """Refuse to start while a SECREVIEW_TICKETING_* variable is set: ignoring it would drop a
    lock of the operator (SECREVIEW_TICKETING_ENABLED=false) without a word."""
    found = [name for name, value in _FormerVariables().model_dump().items() if value]
    if found:
        names = ", ".join(f"SECREVIEW_TICKETING_{name.upper()}" for name in found)
        raise ValueError(f"{names}: renamed SECREVIEW_CONNECTORS_* (see the Connectors page)")


def _connection(settings: Settings, connector: Connector) -> Connection:
    """The configured connection of ``connector``.

    Raises:
        ConnectorError: If the connector is switched off or its connection is not configured.
    """
    if not connections.enabled(connector, settings):
        raise ConnectorError("disabled", f"the {connector.name} connector is switched off")
    return connection_of(settings, connections.resolve(connector))


def connection_of(settings: Settings, state: connections.ConnectionState) -> Connection:
    """Connection of a set of values (stored or candidate), with its HTTP client.

    Raises:
        ConnectorError: If the connection is not configured.
    """
    connector = state.connector
    if not state.configured:
        raise ConnectorError("not_configured", f"the {connector.name} connection is not configured")
    client = ConnectionClient(
        settings,
        connector.name,
        state.base_url,
        connector.auth_headers(state.values),
        state.secrets(),
    )
    return Connection(base_url=state.base_url, values=dict(state.values), http=client)


def test_connection(settings: Settings, state: connections.ConnectionState) -> None:
    """Check a connection with the read-only request of its connector, switched on or not (to
    test it before switching it on), unless SECREVIEW_CONNECTORS_ENABLED is false.

    Raises:
        ConnectorError: If the connection cannot be used.
    """
    if not settings.connectors_enabled:
        raise ConnectorError(
            "disabled", "the connectors are locked off (SECREVIEW_CONNECTORS_ENABLED)"
        )
    connection = connection_of(settings, state)
    _guarded(state.connector, connection, lambda: state.connector.test_connection(connection))


def _guarded(connector: Connector, connection: Connection, call: Callable[[], Any]) -> Any:
    """Run a call of a connector; any other error than ConnectorError becomes ``invalid``,
    without its message (it may hold a value of the connection)."""
    try:
        return call()
    except ConnectorError as exc:
        scrub = getattr(connection.http, "scrub", None)
        if scrub is not None:
            raise ConnectorError(exc.code, scrub(str(exc))[:MAX_STORED_ERROR_CHARS]) from None
        raise
    except Exception:
        logger.exception("Connector %s failed", connector.kind)
        raise ConnectorError("invalid", f"{connector.name} connector failed") from None


# ── Content of a record ──────────────────────────────────────────────────────


def _clean(text: str | None) -> str:
    """Masked text of a field of the finding."""
    return redact_secrets(text or "").strip()


def build_content(item: SarifItem, settings: Settings) -> FindingContent:
    """What the record of a finding says: facts, masked texts of the report, fingerprint."""
    finding = item.finding
    title = _clean(finding.title)
    summary = f"[{finding.severity.value.upper()}] {item.project}: {title}"
    location = finding.file_path or "-"
    if finding.file_path and finding.line_start:
        location += f":{finding.line_start}"
    report_url = f"{settings.web_url}/reports/{item.report_id}" if settings.web_url else None
    facts = [
        ("Project", item.project),
        ("Severity", finding.severity.value),
        ("Location", location),
        ("Rule", finding.rule_id or "-"),
        ("CWE", finding.cwe or "-"),
        ("OWASP", finding.owasp or "-"),
        ("Branch", item.branch or "-"),
        ("Commit", item.commit_sha or "-"),
    ]
    if report_url:
        facts.append(("Report", report_url))
    sections = [
        (name, _clean(text))
        for name, text in (
            ("Description", finding.description),
            ("Evidence", finding.evidence),
            ("Recommendation", finding.recommendation),
        )
        if _clean(text)
    ]
    return FindingContent(
        finding_id=finding.id,
        project=item.project,
        severity=finding.severity.value,
        title=title,
        summary=summary[:MAX_SUMMARY_CHARS],
        facts=tuple((name, _clean(value)) for name, value in facts),
        sections=tuple(sections),
        fingerprint=fingerprint(item),
        report_url=report_url,
    )


def _check_created(connector: Connector, created: Any) -> ExportedFinding:
    """The record a connector returned, or ConnectorError when it is not usable."""
    if (
        not isinstance(created, ExportedFinding)
        or not isinstance(created.key, str)
        or not 0 < len(created.key) <= MAX_KEY_CHARS
        or not created.key.isprintable()
        or not isinstance(created.url, str)
        or not created.url.startswith("https://")
        or len(created.url) > MAX_EXPORT_URL_CHARS
        or any(c.isspace() or not c.isprintable() for c in created.url)
    ):
        raise ConnectorError("invalid", f"{connector.name} returned an invalid record")
    return created


# ── Destinations of the projects ─────────────────────────────────────────────


def _target_public(target: ConnectorTarget) -> dict[str, Any]:
    """A destination as returned by the API."""
    return {
        "project": target.project,
        "kind": target.kind,
        "destination": target.destination,
        "auto_min_severity": target.auto_min_severity,
        "auto_since": target.auto_since,
        "updated_at": target.updated_at,
        "updated_by": target.updated_by,
    }


def list_targets(projects: Collection[str] | None = None) -> list[dict[str, Any]]:
    """Destinations of every project (or of ``projects``), by project then kind."""
    with session_scope() as session:
        query = select(ConnectorTarget).order_by(
            col(ConnectorTarget.project), col(ConnectorTarget.kind)
        )
        if projects is not None:
            query = query.where(col(ConnectorTarget.project).in_(list(projects)))
        return [_target_public(row) for row in session.exec(query).all()]


def set_target(
    project: str,
    connector: Connector,
    destination: str,
    auto_min_severity: Severity | None,
    actor: str,
) -> dict[str, Any]:
    """Create or replace the destination of ``project`` in a system; the change is audited.

    Setting a threshold where there was none starts the automatic sending from now: the
    findings of older reports are only sent by hand.

    Raises:
        ValueError: If the project or the destination is invalid.
    """
    project = normalize_project(project)
    destination = connector.check_destination(destination)
    kind = connector.kind
    with session_scope() as session:
        target = session.exec(
            select(ConnectorTarget).where(
                ConnectorTarget.project == project, ConnectorTarget.kind == kind
            )
        ).first()
        if target is None:
            target = ConnectorTarget(project=project, kind=kind)
        if auto_min_severity is None:
            target.auto_since = None
        elif target.auto_min_severity is None:
            target.auto_since = utcnow()
        target.destination = destination
        target.auto_min_severity = auto_min_severity
        target.updated_at = utcnow()
        target.updated_by = actor[:200]
        session.add(target)
        audit.record(
            session,
            audit.AuditAction.CONNECTOR_TARGET_CHANGED,
            actor,
            "connector_target",
            kind,
            project=project,
            details={"destination": destination, "auto_min_severity": auto_min_severity},
        )
        session.flush()
        return _target_public(target)


def delete_target(project: str, kind: str, actor: str) -> None:
    """Delete the destination of ``project`` in a system (the records already sent are kept).

    Raises:
        NotFoundError: If the project has no destination in this system.
    """
    project = normalize_project(project)
    with session_scope() as session:
        target = session.exec(
            select(ConnectorTarget).where(
                ConnectorTarget.project == project, ConnectorTarget.kind == kind
            )
        ).first()
        if target is None:
            raise NotFoundError(f"Project {project} has no {kind} destination")
        session.delete(target)
        audit.record(
            session,
            audit.AuditAction.CONNECTOR_TARGET_CHANGED,
            actor,
            "connector_target",
            kind,
            project=project,
            details={"deleted": True},
        )


def destinations(settings: Settings, projects: Collection[str] | None) -> list[dict[str, str]]:
    """Projects (in ``projects``, None: all) and systems a finding can be sent to now."""
    ready = {
        kind
        for kind, connector in registry.connectors(settings).items()
        if connections.enabled(connector, settings) and connections.resolve(connector).configured
    }
    return [
        {"project": target["project"], "kind": target["kind"]}
        for target in list_targets(projects)
        if target["kind"] in ready
    ]


# ── Sending ──────────────────────────────────────────────────────────────────


def _item(session: Session, finding_id: int) -> SarifItem:
    """The finding with the context of its report.

    Raises:
        NotFoundError: If the finding does not exist.
    """
    row = session.exec(
        select(Finding, SecurityReport)
        .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
        .where(Finding.id == finding_id)
    ).first()
    if row is None:
        raise NotFoundError(f"Finding {finding_id} not found")
    finding, report = row
    return SarifItem(
        finding=FindingPublic.model_validate(finding, from_attributes=True),
        report_id=report.id or 0,
        project=report.project,
        repository=report.repository,
        branch=report.branch,
        commit_sha=report.commit_sha,
        created_at=report.created_at,
    )


def _destination(session: Session, project: str, kind: str) -> str:
    """Destination of ``project`` in a system.

    Raises:
        ConnectorError: If the project has none.
    """
    target = session.exec(
        select(ConnectorTarget).where(
            ConnectorTarget.project == project, ConnectorTarget.kind == kind
        )
    ).first()
    if target is None:
        raise ConnectorError("no_target", f"project {project} has no {kind} destination")
    return target.destination


class _AlreadySent(Exception):
    """The finding already has its record (``export_id``)."""

    def __init__(self, export_id: int) -> None:
        super().__init__(export_id)
        self.export_id = export_id


def _claim(finding_id: int, kind: str, project: str, digest: str, actor: str) -> int:
    """Insert (or take over) the export row of a finding in ``sending`` state; return its id.

    Raises:
        ConnectorError: ``in_progress`` when another request is sending it.
        _AlreadySent: When the finding already has its record.
    """
    now = utcnow()
    try:
        with session_scope() as session:
            row = FindingExport(
                finding_id=finding_id,
                kind=kind,
                project=project,
                fingerprint=digest,
                created_by=actor[:200],
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            return row.id or 0
    except IntegrityError:
        pass
    with session_scope() as session:
        row = session.exec(
            select(FindingExport).where(
                FindingExport.finding_id == finding_id, FindingExport.kind == kind
            )
        ).one()
        if row.state == ExportState.SENT:
            raise _AlreadySent(row.id or 0)
        if row.state == ExportState.SENDING and as_utc(row.updated_at) > now - STALE_CLAIM:
            raise ConnectorError("in_progress", "the finding is being exported")
        # Take the failed (or stale) row over, unless another controller just did
        taken = session.exec(  # type: ignore[call-overload]
            update(FindingExport)
            .where(
                col(FindingExport.id) == row.id,
                col(FindingExport.state) == row.state,
                col(FindingExport.updated_at) == row.updated_at,
            )
            .values(state=ExportState.SENDING, updated_at=now, created_by=actor[:200])
        )
        if taken.rowcount != 1:
            raise ConnectorError("in_progress", "the finding is being exported")
        return row.id or 0


def _finish(
    export_id: int,
    state: ExportState,
    actor: str,
    record: tuple[str, str | None] | None = None,
    error: str | None = None,
    created: bool = False,
) -> FindingExportPublic:
    """Store the outcome of a sending; a record that now exists is audited."""
    with session_scope() as session:
        row = session.get(FindingExport, export_id)
        if row is None:  # deleted with its project meanwhile
            raise NotFoundError("the finding was deleted")
        row.state = state
        row.updated_at = utcnow()
        row.attempts += 1
        row.error = None if error is None else error[:MAX_STORED_ERROR_CHARS]
        if record is not None:
            row.external_key, row.url = record
        session.add(row)
        if state == ExportState.SENT:
            audit.record(
                session,
                audit.AuditAction.FINDING_EXPORTED,
                actor,
                "finding",
                row.finding_id,
                project=row.project,
                details={"kind": row.kind, "record": row.external_key, "reused": not created},
            )
        session.flush()
        return FindingExportPublic.model_validate(row, from_attributes=True)


def _existing_record(project: str, kind: str, digest: str) -> tuple[str, str | None] | None:
    """Key and link of the record already created for the same issue of ``project``."""
    with session_scope() as session:
        row = session.exec(
            select(FindingExport)
            .where(
                FindingExport.project == project,
                FindingExport.kind == kind,
                FindingExport.fingerprint == digest,
                FindingExport.state == ExportState.SENT,
            )
            .order_by(col(FindingExport.id))
        ).first()
        if row is None or row.external_key is None:
            return None
        return row.external_key, row.url


def send_finding(
    finding_id: int, connector: Connector, actor: str, settings: Settings
) -> FindingExportPublic:
    """Create the record of a finding in a system (or return the one it already has).

    The record of an earlier occurrence of the same issue in the project is reused. A failure
    is stored on the finding, then raised.

    Raises:
        NotFoundError: If the finding does not exist.
        ConnectorError: If the connector is disabled or not configured, the project has no
            destination, the finding was reported again (its latest occurrence is sent), the
            finding is being exported, or the system refused it.
    """
    kind = connector.kind
    connection = _connection(settings, connector)
    with session_scope() as session:
        item = _item(session, finding_id)
        if item.finding.superseded_by is not None:
            raise ConnectorError(
                "superseded",
                f"the finding was reported again: send finding {item.finding.superseded_by}",
            )
        destination = _destination(session, item.project, kind)
    content = build_content(item, settings)
    try:
        export_id = _claim(finding_id, kind, item.project, content.fingerprint, actor)
    except _AlreadySent as sent:
        with session_scope() as session:
            row = session.get(FindingExport, sent.export_id)
            return FindingExportPublic.model_validate(row, from_attributes=True)
    existing = _existing_record(item.project, kind, content.fingerprint)
    if existing is not None:
        return _finish(export_id, ExportState.SENT, actor, existing)
    try:
        created = _check_created(
            connector,
            _guarded(
                connector,
                connection,
                lambda: connector.export_finding(connection, destination, content),
            ),
        )
    except ConnectorError as exc:
        _finish(export_id, ExportState.FAILED, actor, error=f"{exc.code}: {exc}")
        raise
    logger.info("Record %s created in %s for finding %d", created.key, kind, finding_id)
    return _finish(export_id, ExportState.SENT, actor, (created.key, created.url), created=True)


def pending_findings(kind: str, now: datetime | None = None, limit: int = BATCH_SIZE) -> list[int]:
    """Ids of the findings the automatic sending owes to a system, worst first.

    An open finding of a project whose destination has a threshold, at least that severe, of a
    report saved since the threshold was set, without a record, or whose last attempt failed
    long enough ago (the delay doubles at each attempt, up to MAX_ATTEMPTS).
    """
    now = now or utcnow()
    found: list[tuple[int, int]] = []
    with session_scope() as session:
        targets = session.exec(
            select(ConnectorTarget).where(
                ConnectorTarget.kind == kind, col(ConnectorTarget.auto_min_severity).is_not(None)
            )
        ).all()
        for target in targets:
            threshold = SEVERITY_RANK[Severity(target.auto_min_severity)]
            severities = [s for s, rank in SEVERITY_RANK.items() if rank >= threshold]
            rows = session.exec(
                select(Finding.id, Finding.severity, FindingExport)
                .join(SecurityReport, col(SecurityReport.id) == col(Finding.report_id))
                .outerjoin(
                    FindingExport,
                    (col(FindingExport.finding_id) == col(Finding.id))
                    & (col(FindingExport.kind) == kind),
                )
                .where(
                    SecurityReport.project == target.project,
                    col(SecurityReport.created_at) >= (target.auto_since or now),
                    col(Finding.severity).in_(severities),
                    _status_is(FindingStatus.OPEN, now),
                    col(Finding.superseded_by).is_(None),
                    (col(FindingExport.id).is_(None))
                    | (
                        (col(FindingExport.state) == ExportState.FAILED)
                        & (col(FindingExport.attempts) < MAX_ATTEMPTS)
                    ),
                )
                .order_by(col(Finding.id))
                .limit(limit)
            ).all()
            for finding_id, severity, export in rows:
                if export is not None:
                    wait = RETRY_DELAY * 2 ** max(export.attempts - 1, 0)
                    if as_utc(export.updated_at) + wait > now:
                        continue
                found.append((SEVERITY_RANK[Severity(severity)], finding_id))
    found.sort(key=lambda pair: (-pair[0], pair[1]))
    return [finding_id for _, finding_id in found[:limit]]


def dispatch(settings: Settings) -> dict[str, int]:
    """Send the findings the automatic sending owes, for each system switched on and
    configured; return the number of findings sent and of failures."""
    counts = {"sent": 0, "failed": 0}
    for kind, connector in registry.connectors(settings).items():
        if not connections.enabled(connector, settings):
            continue
        if not connections.resolve(connector).configured:
            continue
        for finding_id in pending_findings(kind):
            try:
                send_finding(finding_id, connector, AUTO_ACTOR, settings)
                counts["sent"] += 1
            except (ConnectorError, NotFoundError) as exc:
                logger.warning(
                    "Automatic %s export of finding %d failed: %s", kind, finding_id, exc
                )
                counts["failed"] += 1
    return counts


class ExportDispatcher:
    """Background thread of the controller that sends the findings owed to the
    connectors every SECREVIEW_CONNECTORS_INTERVAL_SECONDS.

    ``current`` returns the effective settings (a proxy changed in the web interface applies at
    the next round; the connections are read at each round).
    """

    def __init__(self, settings: Settings, current: Callable[[], Settings] | None = None) -> None:
        """Prepare the dispatcher; ``start`` launches the thread."""
        self.settings = settings
        self.current = current or (lambda: settings)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self.run, name="connectors", daemon=True)

    def run(self) -> None:
        """Send what is owed, then wait for the next round, until ``stop`` is called."""
        while not self._stop.wait(self.settings.connectors_interval_seconds):
            try:
                counts = dispatch(self.current())
                if counts["sent"] or counts["failed"]:
                    logger.info(
                        "Automatic exports: %d sent, %d failed", counts["sent"], counts["failed"]
                    )
            except Exception:
                logger.exception("Automatic export failed")

    def start(self) -> None:
        """Start the background thread."""
        logger.info(
            "Automatic export every %d s (connectors switched on only)",
            self.settings.connectors_interval_seconds,
        )
        self._thread.start()

    def stop(self) -> None:
        """Ask the thread to stop; a request in progress finishes or times out first."""
        self._stop.set()
