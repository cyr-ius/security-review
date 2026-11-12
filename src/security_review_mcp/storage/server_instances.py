"""Heartbeats of the running Controller and MCP server processes, shared through the database.

Each Controller process, and each MCP server of the HTTP transport, keeps a row of
``serverinstance`` up to date every HEARTBEAT_SECONDS, and at once (at most every
MIN_HEARTBEAT_SECONDS) when its activity changes; it deletes it when it stops cleanly. The
Scan engines page shows the processes whose heartbeat is younger than ACTIVE_SECONDS: an MCP
server with the scan_code calls it runs now, and whether it delegates them to the Controller
server. The rows of the processes gone without stopping are deleted after STALE_RETENTION.

Shared by the two processes: no network, no module of the controller. The MCP server never
migrates the schema: while the table is missing (Controller server not upgraded yet), its
heartbeat fails, is logged, and is tried again.
"""

import logging
import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlmodel import col, select

from .. import __version__
from .database import session_scope
from .models import ServerInstance, ServerKind, as_utc, utcnow

logger = logging.getLogger("security_review_mcp.instances")

HEARTBEAT_SECONDS = 5
# A burst of scan_code calls starting and ending shares one heartbeat
MIN_HEARTBEAT_SECONDS = 1.0
ACTIVE_SECONDS = 30
STALE_RETENTION = timedelta(days=1)
# Bound of the scan_code calls an MCP server reports (a gauge, never above its threads)
MAX_PROCESSING = 100_000


def register_instance(
    instance_id: str,
    kind: ServerKind,
    started_at: datetime,
    name: str = "",
    version: str = "",
) -> None:
    """Record a server process and delete the rows of the processes gone for a day."""
    now = utcnow()
    with session_scope() as session:
        stale = session.exec(
            select(ServerInstance).where(col(ServerInstance.heartbeat_at) < now - STALE_RETENTION)
        ).all()
        for instance in stale:
            session.delete(instance)
        session.add(
            ServerInstance(
                id=instance_id,
                kind=kind,
                name=name[:200],
                version=version[:40],
                started_at=started_at,
                heartbeat_at=now,
            )
        )


def heartbeat(
    instance_id: str,
    kind: ServerKind,
    started_at: datetime,
    name: str = "",
    version: str = "",
    **activity: Any,
) -> None:
    """Update the heartbeat of a server process and its ``activity`` (``delegated``,
    ``processing_fragments``), recording it again when its row is gone (deleted by another
    replica after a long pause, or a restored database)."""
    with session_scope() as session:
        instance = session.get(ServerInstance, instance_id)
        if instance is None:
            logger.info("Server instance record missing: recording it again")
            instance = ServerInstance(
                id=instance_id,
                kind=kind,
                name=name[:200],
                version=version[:40],
                started_at=started_at,
                heartbeat_at=utcnow(),
            )
        instance.heartbeat_at = utcnow()
        if "delegated" in activity:
            instance.delegated = bool(activity["delegated"])
        if "processing_fragments" in activity:
            instance.processing_fragments = max(
                0, min(int(activity["processing_fragments"]), MAX_PROCESSING)
            )
        session.add(instance)


def unregister_instance(instance_id: str) -> None:
    """Delete a server process that stops cleanly."""
    with session_scope() as session:
        instance = session.get(ServerInstance, instance_id)
        if instance is not None:
            session.delete(instance)


def active_instances(kind: ServerKind) -> list[dict[str, Any]]:
    """The processes of ``kind`` whose heartbeat is recent, the oldest first."""
    limit = utcnow() - timedelta(seconds=ACTIVE_SECONDS)
    with session_scope() as session:
        rows = session.exec(
            select(ServerInstance)
            .where(ServerInstance.kind == kind, col(ServerInstance.heartbeat_at) > limit)
            .order_by(col(ServerInstance.started_at))
        ).all()
        return [
            {
                "id": row.id,
                "name": row.name,
                "version": row.version,
                "started_at": as_utc(row.started_at),
                "heartbeat_at": as_utc(row.heartbeat_at),
                "delegated": row.delegated,
                "processing_fragments": row.processing_fragments,
            }
            for row in rows
        ]


class ServerHeartbeat:
    """Keep this process visible to every Controller replica through the shared database.

    ``delegated`` (MCP server) tells at each heartbeat whether scan_code goes to the Controller
    server; ``processing`` counts the scan_code calls running now and wakes the heartbeat, which
    reports the most calls run at once since the previous one.
    """

    def __init__(self, kind: ServerKind, delegated: Callable[[], bool] | None = None) -> None:
        self.kind = kind
        self.instance_id = uuid4().hex
        self.started_at = utcnow()
        self.name = socket.gethostname()[:200]
        self._delegated = delegated
        self._processing = 0
        # Most calls running at once since the last heartbeat: a call shorter than the delay
        # of the heartbeat still shows
        self._peak = 0
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name=f"{kind.value}-instance-heartbeat", daemon=True
        )

    def start(self) -> None:
        """Record this process now (a failure is retried by the heartbeat), then keep its
        heartbeat until it stops."""
        try:
            register_instance(self.instance_id, self.kind, self.started_at, self.name, __version__)
        except Exception:
            logger.exception("Could not record the %s instance; retrying", self.kind.value)
        self._thread.start()

    def stop(self) -> None:
        """Stop the heartbeat thread and delete this process from the active list."""
        self._stop.set()
        self._wake.set()
        if self._thread.ident is not None:  # start may have failed before the thread ran
            self._thread.join(timeout=HEARTBEAT_SECONDS + 1)
        try:
            unregister_instance(self.instance_id)
        except Exception:
            logger.exception("Could not delete the %s instance", self.kind.value)

    @contextmanager
    def processing(self) -> Iterator[None]:
        """Count a scan_code call as running while the block runs, waking the heartbeat when it
        starts and ends."""
        with self._lock:
            self._processing += 1
            self._peak = max(self._peak, self._processing)
        self._wake.set()
        try:
            yield
        finally:
            with self._lock:
                self._processing -= 1
            self._wake.set()

    def activity(self) -> dict[str, Any]:
        """What the heartbeat records besides its date."""
        with self._lock:
            processing, self._peak = self._peak, self._processing
        delegated = False
        if self._delegated is not None:
            try:
                delegated = self._delegated()
            except Exception:
                logger.exception("Could not read whether scan_code is delegated")
        return {"delegated": delegated, "processing_fragments": processing}

    def beat(self) -> None:
        """Write the heartbeat now."""
        heartbeat(
            self.instance_id,
            self.kind,
            self.started_at,
            self.name,
            __version__,
            **self.activity(),
        )

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(HEARTBEAT_SECONDS - MIN_HEARTBEAT_SECONDS)
            # A burst of changes shares one heartbeat
            if self._stop.wait(MIN_HEARTBEAT_SECONDS):
                return
            self._wake.clear()
            try:
                self.beat()
            except Exception:
                logger.exception("Could not update the %s instance heartbeat", self.kind.value)
