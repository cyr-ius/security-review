"""Heartbeats of the running Controller processes, shared through the database."""

import logging
import threading
from datetime import datetime, timedelta
from uuid import uuid4

from sqlmodel import col, select

from .database import session_scope
from .models import ControllerInstance, as_utc, utcnow

logger = logging.getLogger("security_review_mcp.controller.instances")

HEARTBEAT_SECONDS = 5
ACTIVE_SECONDS = 30
STALE_RETENTION = timedelta(days=1)


def register_instance(instance_id: str, started_at: datetime) -> None:
    """Register a Controller process and remove records left by processes gone for a day."""
    now = utcnow()
    with session_scope() as session:
        stale = session.exec(
            select(ControllerInstance).where(
                col(ControllerInstance.heartbeat_at) < now - STALE_RETENTION
            )
        ).all()
        for instance in stale:
            session.delete(instance)
        session.add(ControllerInstance(id=instance_id, started_at=started_at, heartbeat_at=now))


def heartbeat(instance_id: str, started_at: datetime) -> None:
    """Update the heartbeat of a Controller process, registering it again when its record is
    gone (purged by another replica after a long pause, or a restored database)."""
    with session_scope() as session:
        instance = session.get(ControllerInstance, instance_id)
        if instance is None:
            logger.info("Controller instance record missing: registering it again")
            instance = ControllerInstance(id=instance_id, started_at=started_at)
        instance.heartbeat_at = utcnow()
        session.add(instance)


def unregister_instance(instance_id: str) -> None:
    """Remove a Controller process that is shutting down cleanly."""
    with session_scope() as session:
        instance = session.get(ControllerInstance, instance_id)
        if instance is not None:
            session.delete(instance)


def active_instances() -> list[dict[str, object]]:
    """Return Controller processes with a recent heartbeat, oldest first."""
    limit = utcnow() - timedelta(seconds=ACTIVE_SECONDS)
    with session_scope() as session:
        rows = session.exec(
            select(ControllerInstance)
            .where(col(ControllerInstance.heartbeat_at) > limit)
            .order_by(col(ControllerInstance.started_at))
        ).all()
        return [
            {
                "id": row.id,
                "started_at": as_utc(row.started_at),
                "heartbeat_at": as_utc(row.heartbeat_at),
            }
            for row in rows
        ]


class ControllerHeartbeat:
    """Keep this process visible to every Controller replica through the shared database."""

    def __init__(self) -> None:
        self.instance_id = uuid4().hex
        self.started_at = utcnow()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="controller-instance-heartbeat", daemon=True
        )

    def start(self) -> None:
        """Register now, then refresh the heartbeat until the Controller stops."""
        register_instance(self.instance_id, self.started_at)
        self._thread.start()

    def stop(self) -> None:
        """Stop the heartbeat thread and remove this process from the active list."""
        self._stop.set()
        if self._thread.ident is not None:  # start may have failed before the thread ran
            self._thread.join(timeout=HEARTBEAT_SECONDS + 1)
        try:
            unregister_instance(self.instance_id)
        except Exception:
            logger.exception("Could not unregister the Controller instance")

    def _run(self) -> None:
        while not self._stop.wait(HEARTBEAT_SECONDS):
            try:
                heartbeat(self.instance_id, self.started_at)
            except Exception:
                logger.exception("Could not update the Controller instance heartbeat")
