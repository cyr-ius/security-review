"""Forwarding of the audit events to a syslog server (controller, optional).

Every process writes its audit events in the database (see audit); only the controller connects
to the syslog server of ``SECREVIEW_AUDIT_SYSLOG_ADDRESS``, so the MCP server keeps making no
outgoing connection. A background thread reads the events added since the last forwarded one
and sends each as one JSON message.

The id of the last forwarded event is kept in the ``appsetting`` table (AUDIT_SYSLOG_CURSOR,
never shown in the web interface). A replica moves it forward with a conditional update before
sending a batch: when two replicas read the same batch, only one sends it. The delivery is at
most once: a batch whose sending fails is logged, not sent again. The first start forwards the
events created from then on, not the history.

``details`` is already masked and bounded by audit.record: no secret is sent.
"""

import json
import logging
import logging.handlers
import socket
import threading
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlmodel import col, func, select

from .audit import public_event
from .config import Settings
from .database import session_scope
from .models import AppSetting, AuditEvent, utcnow

logger = logging.getLogger(__name__)

# Key of the id of the last forwarded event in the appsetting table
AUDIT_SYSLOG_CURSOR = "audit_syslog_cursor"
# Events sent per batch, and seconds between two batches
BATCH_SIZE = 500
INTERVAL_SECONDS = 10.0
# An event is forwarded once it is that old, so that a transaction that committed a lower id
# a little later than a higher one is not skipped
SETTLE_SECONDS = 5
# Timeout of the connection to the syslog server (TCP)
CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_SYSLOG_PORT = 514
# Tag of the messages (RFC 3164 program name)
SYSLOG_TAG = "secreview-audit"
MAX_ADDRESS_CHARS = 500


def parse_address(value: str) -> tuple[str | tuple[str, int], socket.SocketKind]:
    """Return the address and socket type of ``udp://host[:port]``, ``tcp://host[:port]`` or
    ``unix:///path``.

    Raises:
        ValueError: If the address is not one of these forms.
    """
    text = value.strip()
    if len(text) > MAX_ADDRESS_CHARS or any(not c.isprintable() or c.isspace() for c in text):
        raise ValueError("SECREVIEW_AUDIT_SYSLOG_ADDRESS must be a short URL without spaces")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid SECREVIEW_AUDIT_SYSLOG_ADDRESS: {exc}") from None
    if parts.scheme == "unix":
        if parts.netloc or not parts.path.startswith("/"):
            raise ValueError("SECREVIEW_AUDIT_SYSLOG_ADDRESS: write unix:///path/of/the/socket")
        return parts.path, socket.SOCK_DGRAM
    if parts.scheme not in ("udp", "tcp") or not parts.hostname:
        raise ValueError(
            "SECREVIEW_AUDIT_SYSLOG_ADDRESS must be udp://host:port, tcp://host:port or "
            "unix:///path"
        )
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise ValueError("SECREVIEW_AUDIT_SYSLOG_ADDRESS must not have a path, a query or a user")
    kind = socket.SOCK_STREAM if parts.scheme == "tcp" else socket.SOCK_DGRAM
    return (parts.hostname, port or DEFAULT_SYSLOG_PORT), kind


def facility(name: str) -> int:
    """Syslog facility code of ``name`` (``local0``, ``auth``...).

    Raises:
        ValueError: If the name is not a syslog facility.
    """
    names = logging.handlers.SysLogHandler.facility_names
    key = name.strip().lower()
    if key not in names:
        raise ValueError(
            f"SECREVIEW_AUDIT_SYSLOG_FACILITY must be one of: {', '.join(sorted(names))}"
        )
    return names[key]


def validate_settings(settings: Settings) -> None:
    """Check the syslog settings when forwarding is enabled; raise ValueError."""
    if settings.audit_syslog_address:
        parse_address(settings.audit_syslog_address)
        facility(settings.audit_syslog_facility)


def format_event(event: dict[str, Any]) -> str:
    """One syslog message: the tag and the event as compact JSON (keys sorted)."""
    return f"{SYSLOG_TAG}: {json.dumps(event, sort_keys=True, separators=(',', ':'))}"


def claim_batch(limit: int = BATCH_SIZE) -> list[dict[str, Any]]:
    """Return the next events to forward and move the cursor past them.

    The first call stores the id of the newest event and returns nothing (the history is not
    sent). Another replica that moved the cursor first wins: the batch is then empty here.
    """
    with session_scope() as session:
        row = session.get(AppSetting, AUDIT_SYSLOG_CURSOR)
        if row is None:
            newest = session.exec(select(func.max(AuditEvent.id))).one() or 0
            session.add(
                AppSetting(key=AUDIT_SYSLOG_CURSOR, value=str(newest), updated_by="audit-syslog")
            )
            try:
                session.flush()
            except IntegrityError:
                session.rollback()  # created by another replica at the same time
            return []
        start = row.value
        settled = utcnow() - timedelta(seconds=SETTLE_SECONDS)
        rows = session.exec(
            select(AuditEvent)
            .where(col(AuditEvent.id) > int(start or 0), col(AuditEvent.created_at) <= settled)
            .order_by(col(AuditEvent.id))
            .limit(limit)
        ).all()
        if not rows:
            return []
        events = [public_event(event) for event in rows]
        moved = session.execute(
            update(AppSetting)
            .where(col(AppSetting.key) == AUDIT_SYSLOG_CURSOR, col(AppSetting.value) == start)
            .values(value=str(rows[-1].id), updated_at=utcnow(), updated_by="audit-syslog")
        )
        if moved.rowcount != 1:
            return []
        return events


def make_handler(settings: Settings) -> logging.handlers.SysLogHandler:
    """Syslog handler of the settings (connects at once for TCP and a Unix socket).

    Raises:
        ValueError: If the settings are invalid.
        OSError: If the server cannot be reached.
    """
    address, kind = parse_address(settings.audit_syslog_address or "")
    handler = logging.handlers.SysLogHandler(
        address=address,
        facility=facility(settings.audit_syslog_facility),
        socktype=kind,
        timeout=CONNECT_TIMEOUT_SECONDS,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler


class AuditForwarder:
    """Background thread of the controller that sends the new audit events to syslog."""

    def __init__(self, settings: Settings, interval: float = INTERVAL_SECONDS) -> None:
        """Prepare the forwarder; ``start`` launches the thread."""
        validate_settings(settings)
        self.settings = settings
        self.interval = interval
        self._handler: logging.handlers.SysLogHandler | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self.run, name="audit-syslog", daemon=True)

    def _send(self, events: list[dict[str, Any]]) -> None:
        """Send ``events``; raise OSError when the server cannot be reached."""
        if self._handler is None:
            self._handler = make_handler(self.settings)
        for event in events:
            self._write(self._handler, format_event(event))

    @staticmethod
    def _write(handler: logging.handlers.SysLogHandler, message: str) -> None:
        """Write one message with the priority of the facility (INFO severity).

        The socket is written directly rather than through ``emit``, which reports a failure
        to ``handleError`` (a traceback on stderr) instead of raising it.
        """
        if handler.socket is None:
            # A Unix socket that was not there yet is opened again here
            handler.createSocket()
            if handler.socket is None:
                raise ConnectionError("syslog socket unavailable")
        priority = handler.encodePriority(handler.facility, "info")
        payload = f"<{priority}>{message}".encode()
        if handler.unixsocket:
            handler.socket.send(payload)
        elif handler.socktype == socket.SOCK_DGRAM:
            handler.socket.sendto(payload, handler.address)
        else:
            handler.socket.sendall(payload + b"\n")

    def forward_once(self) -> int:
        """Forward one batch; return the number of events sent. An error is logged."""
        try:
            events = claim_batch()
        except Exception:
            logger.exception("Reading the audit events to forward failed")
            return 0
        if not events:
            return 0
        try:
            self._send(events)
        except OSError as exc:
            self.close()
            logger.error(
                "Forwarding of %d audit events to syslog failed (ids %s to %s): %s",
                len(events),
                events[0]["id"],
                events[-1]["id"],
                type(exc).__name__,
            )
            return 0
        return len(events)

    def run(self) -> None:
        """Forward at once, then every interval (and at once while batches are full)."""
        while not self._stop.is_set():
            if self.forward_once() < BATCH_SIZE:
                self._stop.wait(self.interval)

    def start(self) -> None:
        """Start the background thread."""
        logger.info("Audit events are forwarded to syslog")
        self._thread.start()

    def close(self) -> None:
        """Close the connection to the syslog server (opened again by the next batch)."""
        if self._handler is not None:
            self._handler.close()
            self._handler = None

    def stop(self) -> None:
        """Ask the thread to stop and close the connection."""
        self._stop.set()
        self.close()
